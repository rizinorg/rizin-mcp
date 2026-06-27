// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Low-level asynchronous Rizin pipe.
//!
//! A [`RizinPipe`] owns a spawned `rizin -q0 <target>` process. All blocking
//! I/O happens on a dedicated worker thread so the async runtime is never
//! blocked; commands are submitted over a channel and answered via a oneshot.
//!
//! ## Protocol
//!
//! This mirrors the official `rz-pipe` bindings:
//!
//! 1. Spawn `rizin -q0 [extra...] <target>` with piped stdin/stdout.
//! 2. Rizin emits a single `NUL` byte once it is ready (the startup handshake).
//! 3. To run a command, write `"<cmd>\n"` to stdin, then read stdout up to the
//!    next `NUL`; the bytes before the `NUL` are the command output.
//!
//! Each command must be a single line: an embedded newline would be treated by
//! Rizin as a second command and would desynchronise the one-`NUL`-per-command
//! framing. Use `;` to chain commands on a single line instead.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::error::RizinError;

/// The byte Rizin uses to terminate each command's output in `-q0` mode.
const NUL: u8 = 0;

/// A unit of work sent to the worker thread.
struct Job {
    cmd: String,
    reply: oneshot::Sender<Result<String, RizinError>>,
}

/// An asynchronous handle to a running Rizin process.
pub struct RizinPipe {
    tx: mpsc::UnboundedSender<Job>,
    child: Mutex<Child>,
    alive: AtomicBool,
    cmd_timeout: Duration,
    // Kept so the worker thread is detached (not joined) when the pipe drops.
    _join: JoinHandle<()>,
}

impl RizinPipe {
    /// Spawn `rizin -q0 [extra_args...] <target>` and wait for it to become
    /// ready.
    ///
    /// `target` may be a filesystem path or any Rizin URI (e.g. `malloc://512`)
    /// or `-` for an empty session.
    ///
    /// # Errors
    /// Returns an error if the process cannot be spawned, the startup handshake
    /// fails, or Rizin does not become ready within `startup_timeout`.
    pub async fn spawn(
        binary: &str,
        target: &str,
        extra_args: &[String],
        startup_timeout: Duration,
        cmd_timeout: Duration,
    ) -> Result<Self, RizinError> {
        let mut child = Command::new(binary)
            .arg("-q0")
            .args(extra_args)
            .arg(target)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Rizin diagnostics go to *its* stderr, which is separate from the
            // MCP protocol channel (our stdout). Inherit so they appear in logs.
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|source| RizinError::Spawn {
                binary: binary.to_string(),
                source,
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| RizinError::Io("child process has no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RizinError::Io("child process has no stdout".into()))?;

        let (tx, rx) = mpsc::unbounded_channel::<Job>();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), RizinError>>();

        let join = std::thread::Builder::new()
            .name("rizin-pipe".into())
            .spawn(move || worker_loop(stdin, stdout, ready_tx, rx))
            .map_err(|e| RizinError::Io(format!("failed to spawn worker thread: {e}")))?;

        match tokio::time::timeout(startup_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                tx,
                child: Mutex::new(child),
                alive: AtomicBool::new(true),
                cmd_timeout,
                _join: join,
            }),
            Ok(Ok(Err(e))) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
            Ok(Err(_canceled)) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(RizinError::WorkerGone)
            }
            Err(_elapsed) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(RizinError::StartupTimeout {
                    secs: startup_timeout.as_secs(),
                })
            }
        }
    }

    /// Whether the session is still usable.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Kill the Rizin process and mark the session dead. Idempotent.
    fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
        }
    }

    /// Run a single Rizin command and return its textual output.
    ///
    /// # Errors
    /// Returns an error if the command is malformed, the session is dead, the
    /// worker is gone, or the command exceeds the configured timeout (in which
    /// case the Rizin process is killed and the session invalidated).
    pub async fn cmd(&self, cmd: &str) -> Result<String, RizinError> {
        validate_command(cmd)?;
        if !self.is_alive() {
            return Err(RizinError::SessionClosed);
        }
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job {
                cmd: cmd.to_string(),
                reply,
            })
            .map_err(|_| RizinError::WorkerGone)?;

        match tokio::time::timeout(self.cmd_timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(RizinError::WorkerGone),
            Err(_elapsed) => {
                // The worker is blocked reading a response that will never come
                // in time. Killing Rizin unblocks it; mark the session dead so
                // callers reopen.
                self.kill();
                Err(RizinError::CommandTimeout {
                    cmd: cmd.to_string(),
                    secs: self.cmd_timeout.as_secs(),
                })
            }
        }
    }
}

impl Drop for RizinPipe {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Dropping `tx` closes the channel, so the worker thread exits on its
        // own; we deliberately do not join it here.
    }
}

/// The worker thread main loop: perform the startup handshake, then service
/// jobs until the channel closes or the pipe breaks.
fn worker_loop(
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    ready_tx: oneshot::Sender<Result<(), RizinError>>,
    mut rx: mpsc::UnboundedReceiver<Job>,
) {
    let mut reader = BufReader::new(stdout);

    // Startup handshake: Rizin emits exactly one NUL byte once it is ready.
    let mut first = [0u8; 1];
    if let Err(e) = reader.read_exact(&mut first) {
        let _ = ready_tx.send(Err(RizinError::Handshake(e.to_string())));
        return;
    }
    if ready_tx.send(Ok(())).is_err() {
        return; // the spawner gave up; nothing to do
    }

    while let Some(job) = rx.blocking_recv() {
        let result = run_one(&mut stdin, &mut reader, &job.cmd);
        let broke = result.is_err();
        let _ = job.reply.send(result);
        if broke {
            // The pipe is desynchronised or closed; stop serving.
            break;
        }
    }
}

/// Write one command and read its framed response.
fn run_one(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    cmd: &str,
) -> Result<String, RizinError> {
    let line = format!("{}\n", cmd.trim_end_matches(['\n', '\r']));
    stdin
        .write_all(line.as_bytes())
        .map_err(|e| RizinError::Io(e.to_string()))?;
    stdin.flush().map_err(|e| RizinError::Io(e.to_string()))?;

    match read_payload(reader).map_err(|e| RizinError::Io(e.to_string()))? {
        Some(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        None => Err(RizinError::Io("rizin closed the pipe (EOF)".into())),
    }
}

/// Read bytes up to (and consuming) the next `NUL`, returning the payload
/// without the terminator. Returns `Ok(None)` on EOF before any byte.
///
/// Split out from [`run_one`] so the framing can be tested against in-memory
/// readers.
fn read_payload<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let n = reader.read_until(NUL, &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&NUL) {
        buf.pop();
    }
    Ok(Some(buf))
}

/// Reject commands that would corrupt the single-line, one-`NUL` framing.
///
/// # Errors
/// Returns [`RizinError::IllegalCommand`] if the command contains a `NUL`,
/// newline, or carriage return.
pub fn validate_command(cmd: &str) -> Result<(), RizinError> {
    if cmd.bytes().any(|b| b == NUL) || cmd.contains('\n') || cmd.contains('\r') {
        return Err(RizinError::IllegalCommand {
            cmd: cmd.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn read_payload_strips_terminator() {
        let mut c = Cursor::new(b"hello world\x00".to_vec());
        assert_eq!(read_payload(&mut c).unwrap().unwrap(), b"hello world");
    }

    #[test]
    fn read_payload_handles_consecutive_frames() {
        let mut c = Cursor::new(b"one\x00two\x00".to_vec());
        assert_eq!(read_payload(&mut c).unwrap().unwrap(), b"one");
        assert_eq!(read_payload(&mut c).unwrap().unwrap(), b"two");
        assert_eq!(read_payload(&mut c).unwrap(), None); // EOF
    }

    #[test]
    fn read_payload_eof_is_none() {
        let mut c = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_payload(&mut c).unwrap(), None);
    }

    #[test]
    fn validate_command_rejects_framing_breakers() {
        assert!(validate_command("pd 10").is_ok());
        assert!(validate_command("aa; afl").is_ok());
        assert!(validate_command("pd 10\nafl").is_err());
        assert!(validate_command("pd 10\r").is_err());
        assert!(validate_command("bad\0cmd").is_err());
    }

    proptest! {
        // Any payload with no NUL byte round-trips through the framing.
        #[test]
        fn framing_round_trip(payload in proptest::collection::vec(1u8..=255, 0..512)) {
            let mut framed = payload.clone();
            framed.push(NUL);
            let mut c = Cursor::new(framed);
            prop_assert_eq!(read_payload(&mut c).unwrap().unwrap(), payload);
        }

        // Several payloads frame and de-frame back in order.
        #[test]
        fn multi_frame_round_trip(
            payloads in proptest::collection::vec(
                proptest::collection::vec(1u8..=255, 0..64), 1..8)
        ) {
            let mut stream = Vec::new();
            for p in &payloads {
                stream.extend_from_slice(p);
                stream.push(NUL);
            }
            let mut c = Cursor::new(stream);
            for p in &payloads {
                prop_assert_eq!(read_payload(&mut c).unwrap().unwrap(), p.clone());
            }
            prop_assert_eq!(read_payload(&mut c).unwrap(), None);
        }

        // A command containing a newline or NUL is always rejected.
        #[test]
        fn newline_or_nul_always_rejected(prefix in "[ -~]{0,16}", suffix in "[ -~]{0,16}") {
            for sep in ['\n', '\r', '\0'] {
                let cmd = format!("{prefix}{sep}{suffix}");
                prop_assert!(validate_command(&cmd).is_err());
            }
        }
    }
}

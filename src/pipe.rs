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
//!
//! ## Status and diagnostics
//!
//! Rizin 0.10 reports the status of the previous command line through `_sj`,
//! which is queried after every command when the startup probe finds it. On
//! Unix, Rizin's stderr is read alongside stdout, so the diagnostics printed by
//! a command are returned with it; they are written before the `NUL` that ends
//! the command's output, so they are complete once that `NUL` arrives.

use std::io::{Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::error::RizinError;
use crate::status::{CmdOutput, CmdStatus, clean_messages};

/// The byte Rizin uses to terminate each command's output in `-q0` mode.
const NUL: u8 = 0;

/// Upper bound on the stderr text kept per command; `clean_messages` keeps far
/// less, this only bounds memory during a noisy command.
const STDERR_LIMIT: usize = 64 * 1024;

/// The command reporting the status of the previous command line.
const STATUS_CMD: &str = "_sj";

/// A unit of work sent to the worker thread.
struct Job {
    cmd: String,
    reply: oneshot::Sender<Result<CmdOutput, RizinError>>,
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
            // Read Rizin's diagnostics where that is supported; they are
            // forwarded to the server log. Elsewhere they go to *its* stderr,
            // which is separate from the MCP protocol channel (our stdout).
            .stderr(if cfg!(unix) {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
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
        let stderr = child.stderr.take();

        let (tx, rx) = mpsc::unbounded_channel::<Job>();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), RizinError>>();

        let join = std::thread::Builder::new()
            .name("rizin-pipe".into())
            .spawn(move || worker_loop(stdin, PipeIo::new(stdout, stderr), ready_tx, rx))
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

    /// Run a single Rizin command and return its output and status.
    ///
    /// # Errors
    /// Returns an error if the command is malformed, the session is dead, the
    /// worker is gone, or the command exceeds the configured timeout (in which
    /// case the Rizin process is killed and the session invalidated). A
    /// command Rizin reports as failed is not an error here.
    pub async fn exec(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
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

/// The worker thread main loop: perform the startup handshake, probe for
/// status reporting, then service jobs until the channel closes or the pipe
/// breaks.
fn worker_loop(
    mut stdin: ChildStdin,
    mut io: PipeIo,
    ready_tx: oneshot::Sender<Result<(), RizinError>>,
    mut rx: mpsc::UnboundedReceiver<Job>,
) {
    // Startup handshake: Rizin emits exactly one NUL byte once it is ready.
    match io.read_frame() {
        Ok(Some(_)) => {}
        Ok(None) => {
            let detail = io.take_stderr().join("\n");
            let reason = if detail.is_empty() {
                "rizin exited before it was ready".to_string()
            } else {
                format!("rizin exited before it was ready: {detail}")
            };
            let _ = ready_tx.send(Err(RizinError::Handshake(reason)));
            return;
        }
        Err(e) => {
            let _ = ready_tx.send(Err(RizinError::Handshake(e.to_string())));
            return;
        }
    }
    for line in io.take_stderr() {
        tracing::warn!(target: "rizin", "{line}");
    }

    // Before Rizin 0.10 `_sj` does not exist and prints nothing.
    let status_supported = match run_one(&mut stdin, &mut io, STATUS_CMD) {
        Ok((out, _)) => CmdStatus::from_status_json(&out).is_some(),
        Err(e) => {
            let _ = ready_tx.send(Err(RizinError::Handshake(e.to_string())));
            return;
        }
    };
    if !status_supported {
        tracing::info!("this rizin cannot report command status (needs 0.10+)");
    }

    if ready_tx.send(Ok(())).is_err() {
        return; // the spawner gave up; nothing to do
    }

    while let Some(job) = rx.blocking_recv() {
        let result = run_with_status(&mut stdin, &mut io, &job.cmd, status_supported);
        let broke = result.is_err();
        let _ = job.reply.send(result);
        if broke {
            // The pipe is desynchronised or closed; stop serving.
            break;
        }
    }
}

/// Run `cmd`, then query its status when Rizin can report it.
fn run_with_status(
    stdin: &mut ChildStdin,
    io: &mut PipeIo,
    cmd: &str,
    status_supported: bool,
) -> Result<CmdOutput, RizinError> {
    let (output, messages) = run_one(stdin, io, cmd)?;
    let status = if status_supported {
        let (out, _) = run_one(stdin, io, STATUS_CMD)?;
        CmdStatus::from_status_json(&out).unwrap_or(CmdStatus::Unknown)
    } else {
        CmdStatus::Unknown
    };
    for line in &messages {
        tracing::debug!(target: "rizin", "{line}");
    }
    Ok(CmdOutput {
        output,
        status,
        messages,
    }
    .with_legacy_status())
}

/// Write one command and read its framed response and diagnostics.
fn run_one(
    stdin: &mut ChildStdin,
    io: &mut PipeIo,
    cmd: &str,
) -> Result<(String, Vec<String>), RizinError> {
    // Diagnostics printed between commands belong to none of them.
    for line in io.take_stderr() {
        tracing::warn!(target: "rizin", "{line}");
    }
    let line = format!("{}\n", cmd.trim_end_matches(['\n', '\r']));
    stdin
        .write_all(line.as_bytes())
        .map_err(|e| RizinError::Io(e.to_string()))?;
    stdin.flush().map_err(|e| RizinError::Io(e.to_string()))?;

    match io.read_frame().map_err(|e| RizinError::Io(e.to_string()))? {
        Some(bytes) => Ok((
            String::from_utf8_lossy(&bytes).into_owned(),
            io.take_stderr(),
        )),
        None => Err(RizinError::Io("rizin closed the pipe (EOF)".into())),
    }
}

/// Splits Rizin's stdout into `NUL`-terminated frames.
///
/// Pure byte bookkeeping, kept apart from the I/O so it can be tested on its
/// own.
#[derive(Default)]
struct Framer {
    pending: Vec<u8>,
}

impl Framer {
    /// Append bytes read from stdout.
    fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// Take the next complete frame, without its terminator.
    fn next_frame(&mut self) -> Option<Vec<u8>> {
        let end = self.pending.iter().position(|&b| b == NUL)?;
        let mut frame: Vec<u8> = self.pending.drain(..=end).collect();
        frame.pop();
        Some(frame)
    }
}

/// Rizin's stdout, framed, and (on Unix) its stderr.
struct PipeIo {
    stdout: ChildStdout,
    stderr: Option<ChildStderr>,
    framer: Framer,
    stderr_buf: Vec<u8>,
}

impl PipeIo {
    fn new(stdout: ChildStdout, stderr: Option<ChildStderr>) -> Self {
        Self {
            stdout,
            stderr,
            framer: Framer::default(),
            stderr_buf: Vec::new(),
        }
    }

    /// Read up to the next `NUL`, returning the payload without it. Returns
    /// `Ok(None)` on EOF before a complete frame.
    fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = self.framer.next_frame() {
                // Diagnostics of this command were written before its NUL.
                self.drain_stderr()?;
                return Ok(Some(frame));
            }
            if !self.wait_and_read()? {
                self.drain_stderr()?;
                return Ok(None);
            }
        }
    }

    /// The diagnostics read since the last call, cleaned up.
    fn take_stderr(&mut self) -> Vec<String> {
        let raw = std::mem::take(&mut self.stderr_buf);
        clean_messages(&String::from_utf8_lossy(&raw))
    }

    fn keep_stderr(&mut self, bytes: &[u8]) {
        let room = STDERR_LIMIT.saturating_sub(self.stderr_buf.len());
        self.stderr_buf
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    /// Block until stdout has data and read it, reading stderr meanwhile so
    /// Rizin never blocks on a full stderr pipe. Returns `false` on stdout EOF.
    #[cfg(unix)]
    fn wait_and_read(&mut self) -> std::io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.stdout.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.stderr.as_ref().map_or(-1, |e| e.as_raw_fd()),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `fds` is a valid array of two pollfd entries; poll ignores
            // the negative fd of a closed stderr.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let ready = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
            if fds[1].revents & ready != 0 {
                self.read_stderr_once(&mut buf)?;
            }
            if fds[0].revents & ready != 0 {
                let n = self.stdout.read(&mut buf)?;
                if n == 0 {
                    return Ok(false);
                }
                self.framer.push(&buf[..n]);
                return Ok(true);
            }
        }
    }

    #[cfg(not(unix))]
    fn wait_and_read(&mut self) -> std::io::Result<bool> {
        let mut buf = [0u8; 64 * 1024];
        let n = self.stdout.read(&mut buf)?;
        if n == 0 {
            return Ok(false);
        }
        self.framer.push(&buf[..n]);
        Ok(true)
    }

    /// Read one chunk of stderr; closes it on EOF.
    #[cfg(unix)]
    fn read_stderr_once(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let Some(stderr) = self.stderr.as_mut() else {
            return Ok(());
        };
        let n = stderr.read(buf)?;
        if n == 0 {
            self.stderr = None;
        } else {
            let chunk = buf[..n].to_vec();
            self.keep_stderr(&chunk);
        }
        Ok(())
    }

    /// Read whatever stderr holds right now, without blocking.
    #[cfg(unix)]
    fn drain_stderr(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut buf = [0u8; 64 * 1024];
        while let Some(stderr) = self.stderr.as_ref() {
            let mut fd = libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: a single valid pollfd; a zero timeout never blocks.
            let rc = unsafe { libc::poll(&mut fd, 1, 0) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if rc == 0 || fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                break;
            }
            self.read_stderr_once(&mut buf)?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn drain_stderr(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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

    fn frames_of(stream: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut framer = Framer::default();
        let mut out = Vec::new();
        for piece in stream.chunks(chunk.max(1)) {
            framer.push(piece);
            while let Some(f) = framer.next_frame() {
                out.push(f);
            }
        }
        out
    }

    #[test]
    fn framer_strips_terminator() {
        assert_eq!(
            frames_of(b"hello world\x00", 64),
            vec![b"hello world".to_vec()]
        );
    }

    #[test]
    fn framer_handles_consecutive_frames() {
        assert_eq!(
            frames_of(b"one\x00two\x00", 64),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn framer_waits_for_the_terminator() {
        let mut framer = Framer::default();
        framer.push(b"partial");
        assert_eq!(framer.next_frame(), None);
        framer.push(b"\x00");
        assert_eq!(framer.next_frame(), Some(b"partial".to_vec()));
        assert_eq!(framer.next_frame(), None);
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
            prop_assert_eq!(frames_of(&framed, 64), vec![payload]);
        }

        // Several payloads frame and de-frame back in order, however the
        // stream is split into reads.
        #[test]
        fn multi_frame_round_trip(
            payloads in proptest::collection::vec(
                proptest::collection::vec(1u8..=255, 0..64), 1..8),
            chunk in 1usize..100,
        ) {
            let mut stream = Vec::new();
            for p in &payloads {
                stream.extend_from_slice(p);
                stream.push(NUL);
            }
            prop_assert_eq!(frames_of(&stream, chunk), payloads);
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

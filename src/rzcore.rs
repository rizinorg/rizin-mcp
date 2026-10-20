// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! In-process Rizin backend built on the C library ([`crate::ffi`]).
//!
//! This is the fast path: instead of spawning a `rizin` process and talking to
//! it over a pipe, it creates an `RzCore` in the same process and runs commands
//! through [`crate::ffi::Core::cmd_status`]. It exposes the same async `exec`
//! interface as [`crate::pipe::RizinPipe`], so the rest of the crate is
//! agnostic to which backend is in use.
//!
//! Because Rizin is not thread-safe, the core is created, used, and freed
//! entirely on one dedicated worker thread; callers submit commands over a
//! channel. Rizin also keeps process-global state, so at most one core may be
//! **alive** at a time: [`RizinCore`]'s `Drop` is synchronous (it waits for the
//! worker to free the core), and [`crate::session`] tears down the previous
//! session before opening a new one. Together these guarantee cores never
//! overlap.
//!
//! ## Cancellation caveat
//!
//! A command runs as a synchronous C call on the worker thread. If one hangs
//! (for example a pathological analysis, or a debugger/`!` shell escape invoked
//! through the raw command tool), it cannot be safely interrupted the way a
//! subprocess can be killed. On timeout the call returns
//! [`RizinError::CommandTimeout`] and the session is marked dead; the worker
//! may stay blocked until the C call returns, so its core is abandoned (freed
//! by the OS at exit) rather than joined. For workloads that need hard
//! cancellation, use the pipe backend.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::error::RizinError;
use crate::ffi;
use crate::status::CmdOutput;

/// How long `Drop` waits for the worker to free its core before abandoning it
/// (only relevant if a command is wedged inside librz).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// A command to run on the worker thread, with a channel for its result.
struct Job {
    cmd: String,
    reply: oneshot::Sender<Result<CmdOutput, RizinError>>,
}

/// An asynchronous handle to an in-process Rizin core.
pub struct RizinCore {
    /// `None` only while dropping. Sending closes the channel to stop the worker.
    tx: Option<mpsc::UnboundedSender<Job>>,
    alive: AtomicBool,
    cmd_timeout: Duration,
    /// The worker signals here once it has freed the core and is exiting. Wrapped
    /// in a `Mutex` purely so the handle is `Sync` (it is only ever touched from
    /// `Drop`, via `get_mut`, so no real locking occurs).
    done: Mutex<std_mpsc::Receiver<()>>,
}

impl RizinCore {
    /// Create a core, open `path` (a filesystem path or Rizin URI), and get it
    /// ready for commands.
    ///
    /// # Errors
    /// Returns an error if the core cannot be allocated, the target fails to
    /// open, or readiness is not reached within `startup_timeout`.
    pub async fn open(
        path: &str,
        write: bool,
        startup_timeout: Duration,
        cmd_timeout: Duration,
    ) -> Result<Self, RizinError> {
        let (tx, rx) = mpsc::unbounded_channel::<Job>();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), RizinError>>();
        let (done_tx, done_rx) = std_mpsc::channel::<()>();
        let path_owned = path.to_string();

        std::thread::Builder::new()
            .name("rizin-core".into())
            .spawn(move || worker_loop(path_owned, write, ready_tx, rx, done_tx))
            .map_err(|e| RizinError::Io(format!("failed to spawn worker thread: {e}")))?;

        match tokio::time::timeout(startup_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Self {
                tx: Some(tx),
                alive: AtomicBool::new(true),
                cmd_timeout,
                done: Mutex::new(done_rx),
            }),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_canceled)) => Err(RizinError::WorkerGone),
            Err(_elapsed) => Err(RizinError::StartupTimeout {
                secs: startup_timeout.as_secs(),
            }),
        }
    }

    /// Whether the session is still usable.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Run a single command and return its output and status.
    ///
    /// # Errors
    /// Returns an error if the session is dead, the worker is gone, the command
    /// contains an interior NUL, or it exceeds the configured timeout. A command
    /// Rizin reports as failed is not an error here.
    pub async fn exec(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
        if cmd.as_bytes().contains(&0) {
            return Err(RizinError::IllegalCommand {
                cmd: cmd.to_string(),
            });
        }
        if !self.is_alive() {
            return Err(RizinError::SessionClosed);
        }
        let tx = self.tx.as_ref().ok_or(RizinError::WorkerGone)?;
        let (reply, rx) = oneshot::channel();
        tx.send(Job {
            cmd: cmd.to_string(),
            reply,
        })
        .map_err(|_| RizinError::WorkerGone)?;

        match tokio::time::timeout(self.cmd_timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(RizinError::WorkerGone),
            Err(_elapsed) => {
                // The C call cannot be interrupted; refuse further work so the
                // server stays responsive instead of queueing behind it.
                self.alive.store(false, Ordering::SeqCst);
                Err(RizinError::CommandTimeout {
                    cmd: cmd.to_string(),
                    secs: self.cmd_timeout.as_secs(),
                })
            }
        }
    }
}

impl Drop for RizinCore {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::SeqCst);
        // Close the command channel so the worker stops and frees its core.
        self.tx.take();
        // Wait (briefly) for confirmation that the core is freed, so a
        // subsequent open never overlaps with this core. If a command is
        // wedged inside librz, give up and let the OS reclaim it at exit.
        if let Ok(rx) = self.done.get_mut() {
            let _ = rx.recv_timeout(SHUTDOWN_GRACE);
        }
    }
}

/// Worker thread: own the core for its entire lifetime, service commands.
fn worker_loop(
    path: String,
    write: bool,
    ready_tx: oneshot::Sender<Result<(), RizinError>>,
    mut rx: mpsc::UnboundedReceiver<Job>,
    done_tx: std_mpsc::Sender<()>,
) {
    // The core is created here and never leaves this thread.
    let core = match ffi::Core::new() {
        Some(c) => c,
        None => {
            let _ = ready_tx.send(Err(RizinError::Handshake(
                "rz_core_new returned null".into(),
            )));
            return;
        }
    };
    core.configure();

    match core.file_open_load(&path, write) {
        Ok(true) => {}
        Ok(false) => {
            let _ = ready_tx.send(Err(RizinError::FileNotFound(path)));
            return;
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    }

    if ready_tx.send(Ok(())).is_err() {
        return;
    }

    while let Some(job) = rx.blocking_recv() {
        let result = core.cmd_status(&job.cmd);
        let _ = job.reply.send(result);
    }

    // Free the core, then announce that shutdown is complete.
    drop(core);
    let _ = done_tx.send(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_nul_and_runs_commands() {
        // Open a tiny in-memory target so the session is live. `malloc://`
        // needs no file on disk.
        let core = RizinCore::open(
            "malloc://64",
            false,
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .await;
        if let Ok(core) = core {
            assert!(core.is_alive());
            // Interior NUL is rejected.
            let err = core.exec("p8 4\0px").await;
            assert!(matches!(err, Err(RizinError::IllegalCommand { .. })));
            // A normal command returns its captured output in-process.
            // `malloc://64` is zero-filled, so 4 bytes hex-print as zeros.
            let out = core.exec("p8 4").await.expect("p8");
            assert_eq!(out.output.trim(), "00000000");
            assert!(!out.status.is_failure());
        }
    }

    #[tokio::test]
    async fn sequential_opens_do_not_overlap() {
        // Repeatedly opening must work: each core is fully freed (synchronous
        // Drop) before the next is created.
        for _ in 0..5 {
            let core = RizinCore::open(
                "malloc://16",
                false,
                Duration::from_secs(30),
                Duration::from_secs(30),
            )
            .await;
            if let Ok(core) = core {
                let out = core.exec("p8 1").await.expect("p8");
                assert_eq!(out.output.trim(), "00");
            }
            // `core` dropped here, synchronously freeing it.
        }
    }

    #[tokio::test]
    async fn failure_carries_status_and_log_message() {
        let core = RizinCore::open(
            "malloc://64",
            true,
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .await
        .expect("open malloc://64");
        let out = core.exec("wa \"bogus insn\"").await.expect("exec");
        assert!(out.status.is_failure(), "status: {:?}", out.status);
        assert!(
            out.detail().contains("Cannot assemble"),
            "messages: {:?}",
            out.messages
        );
        // The capture ends with the command: a later success has no messages.
        let ok = core.exec("p8 1").await.expect("exec");
        assert!(!ok.status.is_failure());
        assert!(ok.messages.is_empty(), "messages: {:?}", ok.messages);
    }
}

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Minimal, hand-written FFI to Rizin's C core (`librz_core`).
//!
//! Only the handful of `rz_core_*` entry points needed to open a target and run
//! commands are declared here. Commands are executed through
//! `rz_core_cmd_str_status` (Rizin 0.10+), which returns exactly the same text
//! a `rizin` process would emit for that command together with its status — so
//! every command string used elsewhere in the crate works unchanged, just
//! without the subprocess and pipe. With older Rizin, `rz_core_cmd_str` is used
//! instead; it returns NULL exactly when the command failed.
//!
//! Rizin's log messages (the `ERROR: ...` lines explaining a failure) are
//! routed through `csrc/log_capture.c` and collected per command, so a failure
//! carries its reason; messages logged outside a command go to the server log.
//!
//! The raw pointer is wrapped in [`Core`], a non-`Send` RAII handle: it is
//! created by [`Core::new`], freed on drop, and (being `!Send`) cannot move
//! between threads.
//!
//! ## Thread-safety
//!
//! Rizin keeps process-global state (most importantly the console used to
//! capture command output), so it is never safe to be inside `librz` on two
//! threads at once. Every call below takes [`RZ_LOCK`] first. Combined with the
//! [`crate::rzcore`] design — where a single dedicated worker thread owns each
//! [`Core`] — this guarantees serialized access even across the brief window
//! where one session is being torn down while another starts.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::{Mutex, Once};

use crate::error::RizinError;
use crate::status::{CmdOutput, CmdStatus, clean_messages};

/// Opaque Rizin core type (`RzCore`).
#[repr(C)]
struct RzCore {
    _private: [u8; 0],
}

// Rizin permission bits (from `rz_io.h`).
const RZ_PERM_R: c_int = 4;
const RZ_PERM_W: c_int = 2;

unsafe extern "C" {
    fn rz_core_new() -> *mut RzCore;
    fn rz_core_free(core: *mut RzCore);
    fn rz_core_cmd0(core: *mut RzCore, cmd: *const c_char) -> c_int;
    #[cfg(rz_cmd_status)]
    fn rz_core_cmd_str_status(
        core: *mut RzCore,
        cmd: *const c_char,
        status: *mut c_int,
    ) -> *mut c_char;
    #[cfg(not(rz_cmd_status))]
    fn rz_core_cmd_str(core: *mut RzCore, cmd: *const c_char) -> *mut c_char;
    fn rz_core_file_open_load(
        core: *mut RzCore,
        filepath: *const c_char,
        addr: u64,
        perms: c_int,
        write_mode: bool,
    ) -> bool;
    fn rz_mem_free(p: *mut c_void);
    // csrc/log_capture.c
    fn rizin_mcp_log_set_sink(sink: Option<unsafe extern "C" fn(*const c_char, c_int)>);
}

/// Global guard ensuring only one thread is ever inside `librz`.
static RZ_LOCK: Mutex<()> = Mutex::new(());

/// Log lines of the command being run, or `None` between commands.
static LOG_CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

/// Upper bound on the raw log text kept per command; `clean_messages` keeps
/// far less, this only bounds memory during a noisy command.
const LOG_CAPTURE_LIMIT: usize = 64 * 1024;

/// `RzLogLevel` values (from `rz_log.h`).
const RZ_LOGLVL_WARN: c_int = 3;

static LOG_SINK_INIT: Once = Once::new();

/// Receives every Rizin log message. Rizin calls it with its log lock held, so
/// it must not call back into Rizin.
unsafe extern "C" fn log_sink(output: *const c_char, level: c_int) {
    if output.is_null() {
        return;
    }
    // SAFETY: Rizin passes a NUL-terminated string valid for this call.
    let line = unsafe { CStr::from_ptr(output) }.to_string_lossy();
    let mut capture = LOG_CAPTURE.lock().unwrap_or_else(|e| e.into_inner());
    match capture.as_mut() {
        Some(lines) => {
            let size: usize = lines.iter().map(String::len).sum();
            if size < LOG_CAPTURE_LIMIT {
                lines.push(line.into_owned());
            }
        }
        None if level >= RZ_LOGLVL_WARN => tracing::warn!(target: "rizin", "{}", line.trim_end()),
        None => tracing::debug!(target: "rizin", "{}", line.trim_end()),
    }
}

/// Run `f` (which calls into Rizin) and return what Rizin logged meanwhile.
/// Callers hold [`RZ_LOCK`], so no other command can interleave.
fn with_log_capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    *LOG_CAPTURE.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
    let value = f();
    let lines = LOG_CAPTURE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default();
    for line in &lines {
        tracing::debug!(target: "rizin", "{}", line.trim_end());
    }
    (value, clean_messages(&lines.concat()))
}

/// Acquire the global Rizin lock, recovering from poisoning (a panic while
/// holding it leaves no inconsistent Rust state here, so the data is still
/// usable).
fn lock() -> std::sync::MutexGuard<'static, ()> {
    RZ_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// An owned Rizin core.
///
/// This is intentionally **not** `Send`/`Sync` (it holds a raw pointer): a core
/// must be created, used, and dropped all on the same thread. See the module
/// docs for the global-locking discipline that makes multiple cores safe.
pub struct Core {
    ptr: *mut RzCore,
}

impl Core {
    /// Create a new core, returning `None` if Rizin failed to allocate one.
    pub fn new() -> Option<Core> {
        let _g = lock();
        // SAFETY: the sink is a plain function that never calls into Rizin.
        LOG_SINK_INIT.call_once(|| unsafe { rizin_mcp_log_set_sink(Some(log_sink)) });
        let ptr = unsafe { rz_core_new() };
        if ptr.is_null() {
            None
        } else {
            Some(Core { ptr })
        }
    }

    /// Apply settings that keep command output clean and machine-readable
    /// (no colour, non-interactive, no HTML).
    pub fn configure(&self) {
        for setting in [
            "e scr.color=0",
            "e scr.interactive=false",
            "e scr.html=false",
        ] {
            let _ = self.cmd0(setting);
        }
    }

    /// Run a command for its side effects, ignoring any textual output.
    pub fn cmd0(&self, cmd: &str) -> Result<(), RizinError> {
        let c = CString::new(cmd).map_err(|_| RizinError::IllegalCommand {
            cmd: cmd.to_string(),
        })?;
        let _g = lock();
        unsafe {
            rz_core_cmd0(self.ptr, c.as_ptr());
        }
        Ok(())
    }

    /// Run a command and return its output, status, and diagnostics.
    ///
    /// # Errors
    /// [`RizinError::IllegalCommand`] if the command contains a NUL byte. A
    /// failing command is not an error here; see [`CmdOutput::status`].
    pub fn cmd_status(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
        let c = CString::new(cmd).map_err(|_| RizinError::IllegalCommand {
            cmd: cmd.to_string(),
        })?;
        let _g = lock();
        let ((ptr, status), messages) = with_log_capture(|| self.raw_cmd_str(&c));
        let output = if ptr.is_null() {
            String::new()
        } else {
            // Copy out before freeing the Rizin-allocated buffer.
            let s = unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned();
            unsafe { rz_mem_free(ptr as *mut c_void) };
            s
        };
        Ok(CmdOutput {
            output,
            status,
            messages,
        }
        .with_legacy_status())
    }

    #[cfg(rz_cmd_status)]
    fn raw_cmd_str(&self, cmd: &CStr) -> (*mut c_char, CmdStatus) {
        let mut status: c_int = -1;
        // SAFETY: `self.ptr` is a live core, `cmd` is NUL-terminated, and the
        // caller holds RZ_LOCK. The status is set in any case.
        let ptr = unsafe { rz_core_cmd_str_status(self.ptr, cmd.as_ptr(), &mut status) };
        (ptr, CmdStatus::from_code(status))
    }

    #[cfg(not(rz_cmd_status))]
    fn raw_cmd_str(&self, cmd: &CStr) -> (*mut c_char, CmdStatus) {
        // SAFETY: as above. Before Rizin 0.10, NULL means the command failed.
        let ptr = unsafe { rz_core_cmd_str(self.ptr, cmd.as_ptr()) };
        let status = if ptr.is_null() {
            CmdStatus::Failed
        } else {
            CmdStatus::Ok
        };
        (ptr, status)
    }

    /// Open and load a target (path or Rizin URI) into the core.
    ///
    /// # Errors
    /// [`RizinError::InvalidArgument`] for an interior NUL, and
    /// [`RizinError::OpenFailed`], with what Rizin logged, if Rizin cannot open
    /// the target.
    pub fn file_open_load(&self, path: &str, write: bool) -> Result<(), RizinError> {
        let c = CString::new(path).map_err(|_| RizinError::InvalidArgument {
            arg: path.to_string(),
            reason: "path contains an interior NUL byte".into(),
        })?;
        let perms = if write {
            RZ_PERM_R | RZ_PERM_W
        } else {
            RZ_PERM_R
        };
        let _g = lock();
        let (ok, messages) = with_log_capture(|| unsafe {
            rz_core_file_open_load(self.ptr, c.as_ptr(), 0, perms, write)
        });
        if ok {
            Ok(())
        } else {
            Err(RizinError::OpenFailed {
                target: path.to_string(),
                detail: messages.join("\n"),
            })
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        let _g = lock();
        unsafe { rz_core_free(self.ptr) };
    }
}

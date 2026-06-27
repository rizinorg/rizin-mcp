// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Minimal, hand-written FFI to Rizin's C core (`librz_core`).
//!
//! Only the handful of `rz_core_*` entry points needed to open a target and run
//! commands are declared here. Commands are executed through
//! `rz_core_cmd_str`, which returns exactly the same text a `rizin` process
//! would emit for that command — so every command string used elsewhere in the
//! crate works unchanged, just without the subprocess and pipe.
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
use std::sync::Mutex;

use crate::error::RizinError;

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
    fn rz_core_cmd_str(core: *mut RzCore, cmd: *const c_char) -> *mut c_char;
    fn rz_core_file_open_load(
        core: *mut RzCore,
        filepath: *const c_char,
        addr: u64,
        perms: c_int,
        write_mode: bool,
    ) -> bool;
    fn rz_mem_free(p: *mut c_void);
}

/// Global guard ensuring only one thread is ever inside `librz`.
static RZ_LOCK: Mutex<()> = Mutex::new(());

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

    /// Run a command and return its textual output (the empty string if Rizin
    /// produced none).
    pub fn cmd_str(&self, cmd: &str) -> Result<String, RizinError> {
        let c = CString::new(cmd).map_err(|_| RizinError::IllegalCommand {
            cmd: cmd.to_string(),
        })?;
        let _g = lock();
        let ptr = unsafe { rz_core_cmd_str(self.ptr, c.as_ptr()) };
        if ptr.is_null() {
            return Ok(String::new());
        }
        // Copy out before freeing the Rizin-allocated buffer.
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { rz_mem_free(ptr as *mut c_void) };
        Ok(s)
    }

    /// Open and load a target (path or Rizin URI) into the core.
    ///
    /// Returns whether Rizin reported success.
    pub fn file_open_load(&self, path: &str, write: bool) -> Result<bool, RizinError> {
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
        let ok = unsafe { rz_core_file_open_load(self.ptr, c.as_ptr(), 0, perms, write) };
        Ok(ok)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        let _g = lock();
        unsafe { rz_core_free(self.ptr) };
    }
}

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Runtime configuration for the server.

use std::time::Duration;

/// Which backend the server uses to talk to Rizin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// In-process via Rizin's C library (fast). Requires the `api` feature.
    /// This is the default when compiled in.
    #[cfg_attr(feature = "api", default)]
    Api,
    /// Out-of-process via a spawned `rizin` and its pipe protocol. The default
    /// when the `api` feature is disabled.
    #[cfg_attr(not(feature = "api"), default)]
    Pipe,
}

/// Configuration controlling how the server talks to Rizin and which
/// capabilities are exposed.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Which backend to use (in-process API or a spawned process).
    pub transport: Transport,
    /// Path or name of the `rizin` executable to spawn (pipe backend only).
    pub rizin_binary: String,
    /// Whether files may be opened in write mode and write tools used.
    ///
    /// Writing can modify the in-memory buffer and, for files opened with
    /// write access, the file on disk. Disabled by default.
    pub allow_write: bool,
    /// Whether the raw `command` / `command_json` passthrough tools are exposed.
    ///
    /// These give access to the full Rizin command surface (including shell
    /// escapes via `!` and the debugger), so they can be disabled for
    /// locked-down deployments.
    pub allow_raw: bool,
    /// Whether the debugger tools are permitted. Debugging **executes the target
    /// binary**, so this is off by default and separate from `allow_write`.
    pub allow_debug: bool,
    /// How long to wait for Rizin to become ready after spawning (and for the
    /// optional initial analysis to finish).
    pub startup_timeout: Duration,
    /// How long any single Rizin command may run before it is considered hung;
    /// on timeout the Rizin process is killed and the session is invalidated.
    pub command_timeout: Duration,
    /// Upper bound on the number of bytes a single read/hexdump may return.
    pub max_bytes: u64,
    /// Upper bound on instruction counts for disassembly-style commands.
    pub max_count: u64,
    /// Upper bound on the size of one tool result, in bytes of serialized
    /// output: listings are cut to what fits, text is truncated, and a larger
    /// object is refused.
    pub max_output_bytes: usize,
    /// Number of items a listing returns when the caller gives no `limit`.
    pub default_limit: usize,
    /// An extra FLIRT signature database directory (Rizin's
    /// `flirt.sigdb.path`), e.g. a clone of rizinorg/sigdb.
    pub sigdb_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transport: Transport::default(),
            rizin_binary: "rizin".to_string(),
            allow_write: false,
            allow_raw: true,
            allow_debug: false,
            startup_timeout: Duration::from_secs(60),
            command_timeout: Duration::from_secs(120),
            max_bytes: 1 << 20, // 1 MiB
            max_count: 100_000,
            max_output_bytes: 128 << 10, // 128 KiB, roughly 32k tokens
            default_limit: 100,
            sigdb_path: None,
        }
    }
}

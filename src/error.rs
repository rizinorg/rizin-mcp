// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Error type for the crate and its mapping onto MCP protocol errors.

use rmcp::ErrorData;

/// All errors that can arise while talking to Rizin or validating input.
#[derive(Debug, thiserror::Error)]
pub enum RizinError {
    /// The `rizin` executable could not be spawned.
    #[error("failed to spawn rizin binary '{binary}': {source}")]
    Spawn {
        /// The binary name/path that failed to spawn.
        binary: String,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// Rizin did not complete its startup handshake.
    #[error("rizin startup handshake failed: {0}")]
    Handshake(String),

    /// Rizin took too long to become ready.
    #[error("timed out waiting for rizin to start after {secs}s")]
    StartupTimeout {
        /// The configured startup timeout, in seconds.
        secs: u64,
    },

    /// A command exceeded the configured command timeout.
    #[error("rizin command timed out after {secs}s: {cmd}")]
    CommandTimeout {
        /// The command that timed out.
        cmd: String,
        /// The configured command timeout, in seconds.
        secs: u64,
    },

    /// The background worker thread driving Rizin is gone.
    #[error("rizin worker is gone (the session ended unexpectedly)")]
    WorkerGone,

    /// The session was closed or invalidated and must be reopened.
    #[error("the rizin session is closed or no longer usable; open a file first")]
    SessionClosed,

    /// No file is currently open.
    #[error("no file is open; call `open_file` first")]
    NoFileOpen,

    /// A low-level I/O error occurred while communicating with Rizin.
    #[error("i/o error talking to rizin: {0}")]
    Io(String),

    /// A command contained characters that would corrupt the pipe framing.
    #[error("command contains illegal characters (embedded newline or NUL): {cmd:?}")]
    IllegalCommand {
        /// The offending command.
        cmd: String,
    },

    /// An argument failed validation.
    #[error("invalid argument '{arg}': {reason}")]
    InvalidArgument {
        /// The offending argument value.
        arg: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A JSON command returned no output.
    #[error("rizin returned no output for a command expecting JSON: {cmd}")]
    EmptyJson {
        /// The command that produced no JSON.
        cmd: String,
    },

    /// A JSON command returned output that could not be parsed.
    #[error("failed to parse JSON from rizin command '{cmd}': {source}; raw (truncated): {raw}")]
    Json {
        /// The command whose output failed to parse.
        cmd: String,
        /// The parse error.
        #[source]
        source: serde_json::Error,
        /// A truncated copy of the raw output for debugging.
        raw: String,
    },

    /// The requested operation is disabled by configuration.
    #[error("operation not permitted: {0}")]
    NotPermitted(String),

    /// A path that should exist was not found.
    #[error("file not found: {0}")]
    FileNotFound(String),
}

impl RizinError {
    /// Convert into an MCP [`ErrorData`], choosing a sensible JSON-RPC error
    /// class: user/input problems map to `invalid_params`, everything else to
    /// `internal_error`.
    pub fn to_error_data(&self) -> ErrorData {
        use RizinError::*;
        match self {
            NoFileOpen
            | SessionClosed
            | InvalidArgument { .. }
            | IllegalCommand { .. }
            | EmptyJson { .. }
            | FileNotFound(_)
            | NotPermitted(_) => ErrorData::invalid_params(self.to_string(), None),
            _ => ErrorData::internal_error(self.to_string(), None),
        }
    }
}

/// Convenience extension to turn a [`Result<T, RizinError>`] into the MCP
/// result type expected by tool handlers.
pub trait IntoMcp<T> {
    /// Map the error arm into an [`ErrorData`].
    fn mcp(self) -> Result<T, ErrorData>;
}

impl<T> IntoMcp<T> for Result<T, RizinError> {
    fn mcp(self) -> Result<T, ErrorData> {
        self.map_err(|e| e.to_error_data())
    }
}

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Transport abstraction over the two Rizin backends.
//!
//! [`Backend`] dispatches `cmd`/`cmdj` to either the in-process C library
//! ([`crate::rzcore::RizinCore`], the fast default) or a spawned `rizin`
//! process ([`crate::pipe::RizinPipe`]). JSON parsing is shared here so both
//! backends behave identically.

use serde_json::Value;

use crate::error::RizinError;
use crate::pipe::RizinPipe;
use crate::util::truncate;

/// A live Rizin command channel: either in-process or over a pipe.
pub enum Backend {
    /// In-process via Rizin's C library (requires the `api` feature).
    #[cfg(feature = "api")]
    Api(crate::rzcore::RizinCore),
    /// Out-of-process via a spawned `rizin` and its pipe protocol.
    Pipe(RizinPipe),
}

impl Backend {
    /// Run a command and return its text output.
    pub async fn cmd(&self, cmd: &str) -> Result<String, RizinError> {
        match self {
            #[cfg(feature = "api")]
            Backend::Api(c) => c.cmd(cmd).await,
            Backend::Pipe(p) => p.cmd(cmd).await,
        }
    }

    /// Run a JSON command and parse its output.
    ///
    /// # Errors
    /// [`RizinError::EmptyJson`] if there was no output, or [`RizinError::Json`]
    /// if the output did not parse, in addition to any command error.
    pub async fn cmdj(&self, cmd: &str) -> Result<Value, RizinError> {
        let out = self.cmd(cmd).await?;
        if out.trim().is_empty() {
            return Err(RizinError::EmptyJson {
                cmd: cmd.to_string(),
            });
        }
        serde_json::from_str(&out).map_err(|source| RizinError::Json {
            cmd: cmd.to_string(),
            source,
            raw: truncate(out.trim(), 400),
        })
    }

    /// Whether the underlying session is still usable.
    pub fn is_alive(&self) -> bool {
        match self {
            #[cfg(feature = "api")]
            Backend::Api(c) => c.is_alive(),
            Backend::Pipe(p) => p.is_alive(),
        }
    }
}

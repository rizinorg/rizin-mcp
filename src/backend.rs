// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Transport abstraction over the two Rizin backends.
//!
//! [`Backend`] dispatches commands to either the in-process C library
//! ([`crate::rzcore::RizinCore`], the fast default) or a spawned `rizin`
//! process ([`crate::pipe::RizinPipe`]). Status handling and JSON parsing are
//! shared here so both backends behave identically.

use serde_json::Value;

use crate::error::RizinError;
use crate::pipe::RizinPipe;
use crate::status::CmdOutput;
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
    /// Run a command and return its output, status, and diagnostics. A
    /// command Rizin reports as failed is not an error here.
    pub async fn exec(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
        match self {
            #[cfg(feature = "api")]
            Backend::Api(c) => c.exec(cmd).await,
            Backend::Pipe(p) => p.exec(cmd).await,
        }
    }

    /// Run a command and return its text output.
    ///
    /// # Errors
    /// [`RizinError::CommandFailed`] if Rizin reports a failure, in addition to
    /// any transport error.
    pub async fn cmd(&self, cmd: &str) -> Result<String, RizinError> {
        Ok(check(cmd, self.exec(cmd).await?)?.output)
    }

    /// Run a JSON command and parse its output.
    ///
    /// # Errors
    /// [`RizinError::CommandFailed`] if Rizin reports a failure,
    /// [`RizinError::EmptyJson`] if it succeeded without output, or
    /// [`RizinError::Json`] if the output did not parse, in addition to any
    /// transport error.
    pub async fn cmdj(&self, cmd: &str) -> Result<Value, RizinError> {
        let out = check(cmd, self.exec(cmd).await?)?;
        parse_json(cmd, &out)
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

/// Turn a failure status into [`RizinError::CommandFailed`].
pub fn check(cmd: &str, out: CmdOutput) -> Result<CmdOutput, RizinError> {
    if out.status.is_failure() {
        return Err(RizinError::CommandFailed {
            cmd: cmd.to_string(),
            status: out.status,
            detail: out.detail(),
        });
    }
    Ok(out)
}

/// Parse the output of a successful JSON command.
pub fn parse_json(cmd: &str, out: &CmdOutput) -> Result<Value, RizinError> {
    if out.output.trim().is_empty() {
        return Err(RizinError::EmptyJson {
            cmd: cmd.to_string(),
            detail: out.detail(),
        });
    }
    serde_json::from_str(&out.output).map_err(|source| RizinError::Json {
        cmd: cmd.to_string(),
        source,
        raw: truncate(out.output.trim(), 400),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::CmdStatus;

    fn out(output: &str, status: CmdStatus, messages: &[&str]) -> CmdOutput {
        CmdOutput {
            output: output.into(),
            status,
            messages: messages.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[test]
    fn failure_status_is_an_error_even_with_output() {
        // `/Rj pop rdi; ret`: the first statement printed JSON, `ret` failed.
        let res = check(
            "/Rj pop rdi; ret",
            out(
                "[]",
                CmdStatus::NonExistingCmd,
                &["ERROR: Command 'ret' does not exist."],
            ),
        );
        match res {
            Err(RizinError::CommandFailed { status, detail, .. }) => {
                assert_eq!(status, CmdStatus::NonExistingCmd);
                assert!(detail.contains("'ret'"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_status_is_judged_by_output() {
        assert!(check("p8 1", out("00\n", CmdStatus::Unknown, &[])).is_ok());
        let e = parse_json("ij", &out("", CmdStatus::Unknown, &["ERROR: oops"])).unwrap_err();
        assert!(matches!(e, RizinError::EmptyJson { ref detail, .. } if detail == "ERROR: oops"));
    }

    #[test]
    fn parses_successful_json() {
        let v = parse_json("ij", &out("{\"a\":1}\n", CmdStatus::Ok, &[])).unwrap();
        assert_eq!(v["a"], 1);
        assert!(matches!(
            parse_json("ij", &out("{nope", CmdStatus::Ok, &[])),
            Err(RizinError::Json { .. })
        ));
    }
}

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Command outcome as reported by Rizin: its output, its status, and the
//! diagnostics it emitted while running.
//!
//! Rizin 0.10 reports the status of every command line: in-process through
//! `rz_core_cmd_str_status()`, and to `rizin -q0` consumers through the `_sj`
//! command. Diagnostics never reach the output; they are collected from Rizin's
//! log (in-process) or from the `rizin` process's stderr (pipe).

use serde::Serialize;

/// Maximum number of diagnostic lines kept per command.
const MAX_MESSAGE_LINES: usize = 24;
/// Maximum total size of the diagnostic lines kept per command.
const MAX_MESSAGE_BYTES: usize = 2048;

/// Status of a Rizin command line (`RzCmdStatus`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CmdStatus {
    /// The command succeeded.
    #[serde(rename = "OK")]
    Ok,
    /// The command could not handle the arguments passed to it.
    #[serde(rename = "WRONG_ARGS")]
    WrongArgs,
    /// The command failed while running.
    #[serde(rename = "ERROR")]
    Error,
    /// The line could not be executed (parse error, bad expression, ...).
    #[serde(rename = "INVALID")]
    Invalid,
    /// The command does not exist (e.g. a plugin command whose plugin is not
    /// loaded).
    #[serde(rename = "NONEXISTINGCMD")]
    NonExistingCmd,
    /// The command asked to leave the prompt loop.
    #[serde(rename = "EXIT")]
    Exit,
    /// The command failed, but this Rizin (before 0.10, in-process) does not
    /// say how.
    #[serde(rename = "FAILED")]
    Failed,
    /// This Rizin cannot report command status (before 0.10, pipe).
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl CmdStatus {
    /// Map an `RzCmdStatus` value.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => CmdStatus::Ok,
            1 => CmdStatus::WrongArgs,
            2 => CmdStatus::Error,
            3 => CmdStatus::Invalid,
            4 => CmdStatus::NonExistingCmd,
            5 => CmdStatus::Exit,
            _ => CmdStatus::Unknown,
        }
    }

    /// Map a name printed by `rz_cmd_status_tostring()`.
    pub fn from_name(name: &str) -> Self {
        match name {
            "OK" => CmdStatus::Ok,
            "WRONG_ARGS" => CmdStatus::WrongArgs,
            "ERROR" => CmdStatus::Error,
            "INVALID" => CmdStatus::Invalid,
            "NONEXISTINGCMD" => CmdStatus::NonExistingCmd,
            "EXIT" => CmdStatus::Exit,
            "FAILED" => CmdStatus::Failed,
            _ => CmdStatus::Unknown,
        }
    }

    /// The name Rizin uses for this status.
    pub fn as_str(self) -> &'static str {
        match self {
            CmdStatus::Ok => "OK",
            CmdStatus::WrongArgs => "WRONG_ARGS",
            CmdStatus::Error => "ERROR",
            CmdStatus::Invalid => "INVALID",
            CmdStatus::NonExistingCmd => "NONEXISTINGCMD",
            CmdStatus::Exit => "EXIT",
            CmdStatus::Failed => "FAILED",
            CmdStatus::Unknown => "UNKNOWN",
        }
    }

    /// Whether Rizin reported a failure. `Unknown` is not one: without status
    /// reporting, a command is judged by its output as before.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            CmdStatus::WrongArgs
                | CmdStatus::Error
                | CmdStatus::Invalid
                | CmdStatus::NonExistingCmd
                | CmdStatus::Failed
        )
    }

    /// Parse the output of `_sj`: `{"error":null}` on success, otherwise
    /// `{"error":{"code":"<STATUS>","message":"..."}}`. `None` when the output
    /// is not that object, e.g. because `_sj` does not exist.
    pub fn from_status_json(out: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(out.trim()).ok()?;
        let err = v.as_object()?.get("error")?;
        if err.is_null() {
            return Some(CmdStatus::Ok);
        }
        let code = err.get("code")?.as_str()?;
        Some(CmdStatus::from_name(code))
    }
}

impl std::fmt::Display for CmdStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of running one command line.
#[derive(Clone, Debug)]
pub struct CmdOutput {
    /// What the command printed, also when it failed.
    pub output: String,
    /// The status Rizin reported.
    pub status: CmdStatus,
    /// Diagnostics Rizin emitted while running the command, cleaned up.
    pub messages: Vec<String>,
}

impl CmdOutput {
    /// The diagnostics joined into one line-separated string.
    pub fn detail(&self) -> String {
        self.messages.join("\n")
    }

    /// Recognize a missing command when Rizin (before 0.10) cannot report
    /// the status: its "Command '...' does not exist." message still says so.
    pub fn with_legacy_status(mut self) -> Self {
        if matches!(self.status, CmdStatus::Failed | CmdStatus::Unknown)
            && self
                .messages
                .iter()
                .any(|m| m.contains("Command '") && m.contains("' does not exist."))
        {
            self.status = CmdStatus::NonExistingCmd;
        }
        self
    }
}

/// Strip ANSI escape sequences (colors, the `\x1b[2K` of progress bars).
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            // CSI: parameters and intermediates, then one final byte.
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            chars.next();
        }
    }
    out
}

/// Turn raw diagnostic text into bounded, readable lines: drop escape
/// sequences, progress-bar redraws and blank lines, and cap the amount kept
/// (an unknown command dumps the whole help of its parent).
pub fn clean_messages(raw: &str) -> Vec<String> {
    let text = strip_ansi(raw);
    let mut lines = Vec::new();
    let mut bytes = 0;
    let mut dropped = 0;
    for line in text.split('\n') {
        // A progress bar redraws its line after `\r`; keep the final state.
        let line = line.rsplit('\r').next().unwrap_or("").trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if lines.len() >= MAX_MESSAGE_LINES || bytes + line.len() > MAX_MESSAGE_BYTES {
            dropped += 1;
            continue;
        }
        bytes += line.len();
        lines.push(line.to_string());
    }
    if dropped > 0 {
        lines.push(format!("[{dropped} more line(s) omitted]"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn status_codes_and_names_round_trip() {
        for code in 0..6 {
            let s = CmdStatus::from_code(code);
            assert_ne!(s, CmdStatus::Unknown);
            assert_eq!(CmdStatus::from_name(s.as_str()), s);
        }
        assert_eq!(CmdStatus::from_code(42), CmdStatus::Unknown);
        assert_eq!(CmdStatus::from_name("FAILED"), CmdStatus::Failed);
        assert_eq!(CmdStatus::from_name("nope"), CmdStatus::Unknown);
    }

    #[test]
    fn failures() {
        assert!(!CmdStatus::Ok.is_failure());
        assert!(!CmdStatus::Exit.is_failure());
        assert!(!CmdStatus::Unknown.is_failure());
        for s in [
            CmdStatus::WrongArgs,
            CmdStatus::Error,
            CmdStatus::Invalid,
            CmdStatus::NonExistingCmd,
            CmdStatus::Failed,
        ] {
            assert!(s.is_failure());
        }
    }

    #[test]
    fn legacy_status_recognizes_missing_commands() {
        let out = |status, msg: &str| CmdOutput {
            output: String::new(),
            status,
            messages: vec![msg.to_string()],
        };
        let missing = "ERROR: Command 'pdg' does not exist.";
        for s in [CmdStatus::Failed, CmdStatus::Unknown] {
            assert_eq!(
                out(s, missing).with_legacy_status().status,
                CmdStatus::NonExistingCmd
            );
            assert_eq!(out(s, "ERROR: other").with_legacy_status().status, s);
        }
        // An exact status is never second-guessed.
        assert_eq!(
            out(CmdStatus::Error, missing).with_legacy_status().status,
            CmdStatus::Error
        );
    }

    #[test]
    fn parses_status_json() {
        assert_eq!(
            CmdStatus::from_status_json("{\"error\":null}\n"),
            Some(CmdStatus::Ok)
        );
        assert_eq!(
            CmdStatus::from_status_json(
                r#"{"error":{"code":"NONEXISTINGCMD","message":"Command does not exist"}}"#
            ),
            Some(CmdStatus::NonExistingCmd)
        );
        assert_eq!(CmdStatus::from_status_json(""), None);
        assert_eq!(CmdStatus::from_status_json("[]"), None);
        assert_eq!(CmdStatus::from_status_json("{\"x\":1}"), None);
    }

    #[test]
    fn cleans_progress_bars_and_colors() {
        let raw =
            "\x1b[2K\r[x] Analyze all flags (aa)\n\x1b[31mERROR:\x1b[0m Cannot assemble 'mov'\n\n";
        assert_eq!(
            clean_messages(raw),
            vec!["[x] Analyze all flags (aa)", "ERROR: Cannot assemble 'mov'"]
        );
    }

    #[test]
    fn caps_long_help_dumps() {
        let raw = (0..100)
            .map(|i| format!("ERROR: line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let lines = clean_messages(&raw);
        assert_eq!(lines.len(), MAX_MESSAGE_LINES + 1);
        assert!(lines.last().unwrap().contains("omitted"));
    }

    proptest! {
        // Whatever Rizin prints, the kept text is bounded and escape-free.
        #[test]
        fn cleaned_messages_are_bounded(raw in "(\\PC|\x1b|\r|\n){0,4000}") {
            let lines = clean_messages(&raw);
            prop_assert!(lines.len() <= MAX_MESSAGE_LINES + 1);
            let kept: usize = lines.iter().take(MAX_MESSAGE_LINES).map(|l| l.len()).sum();
            prop_assert!(kept <= MAX_MESSAGE_BYTES);
            for l in &lines {
                prop_assert!(!l.contains('\x1b'));
                prop_assert!(!l.contains('\n'));
                prop_assert!(!l.contains('\r'));
            }
        }
    }
}

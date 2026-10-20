// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Session lifecycle: opening files, tracking the active Rizin process, and
//! serialising command access through it.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::backend::Backend;
use crate::config::{ServerConfig, Transport};
use crate::error::RizinError;
use crate::pipe::RizinPipe;
#[cfg(feature = "api")]
use crate::rzcore::RizinCore;
use crate::status::CmdOutput;

/// How much automatic analysis to run when opening a file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisLevel {
    /// Do not analyse; just load the file (fastest).
    None,
    /// `aa` — analyse symbol/flagged functions (the default).
    #[default]
    Basic,
    /// `aaa` — functions, cross-references, strings, and more.
    Full,
    /// `aaaa` — experimental, deeper (and slower) analysis.
    Experimental,
}

impl AnalysisLevel {
    /// The Rizin command implementing this level, if any.
    pub fn command(self) -> Option<&'static str> {
        match self {
            AnalysisLevel::None => None,
            AnalysisLevel::Basic => Some("aa"),
            AnalysisLevel::Full => Some("aaa"),
            AnalysisLevel::Experimental => Some("aaaa"),
        }
    }
}

/// A single open Rizin session.
struct Session {
    backend: Backend,
    file: String,
    write: bool,
    analysis: AnalysisLevel,
}

/// Owns the (at most one) active Rizin session and brokers access to it.
///
/// Commands are serialised by holding the session lock for the duration of each
/// command, so multiple concurrent tool calls queue rather than race. This is
/// also what keeps the in-process API backend safe, since Rizin's global state
/// must never be touched from two threads at once.
pub struct SessionManager {
    config: ServerConfig,
    inner: Mutex<Option<Session>>,
}

/// Information returned after successfully opening a file.
#[derive(Debug, Clone, Serialize)]
pub struct OpenInfo {
    /// The opened path or URI.
    pub file: String,
    /// Whether write mode is enabled.
    pub write: bool,
    /// The analysis level that was applied.
    pub analysis: AnalysisLevel,
    /// The parsed output of `ij` (binary info), or `null` if unavailable.
    pub info: Value,
    /// Why the requested analysis failed, if Rizin reported a failure. The
    /// file is open either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_error: Option<String>,
}

/// A snapshot of the current session state.
#[derive(Debug, Clone, Serialize)]
pub struct SessionState {
    /// Whether a file is currently open.
    pub open: bool,
    /// The open path/URI, if any.
    pub file: Option<String>,
    /// Whether write mode is enabled.
    pub write: bool,
    /// The applied analysis level, if a file is open.
    pub analysis: Option<AnalysisLevel>,
}

impl SessionManager {
    /// Create a manager with no open session.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(None),
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Open `path` (a filesystem path or Rizin URI), optionally enabling write
    /// mode, and run the requested analysis level. Replaces any current
    /// session (closing the previous backend).
    ///
    /// # Errors
    /// Returns an error if write mode is requested but disabled, a plain path
    /// does not exist, the backend cannot be created, or analysis fails.
    pub async fn open(
        &self,
        path: &str,
        analysis: AnalysisLevel,
        write: bool,
    ) -> Result<OpenInfo, RizinError> {
        if write && !self.config.allow_write {
            return Err(RizinError::NotPermitted(
                "write mode is disabled; start the server with --allow-write".into(),
            ));
        }
        if !is_rizin_uri(path) && path != "-" && !Path::new(path).exists() {
            return Err(RizinError::FileNotFound(path.to_string()));
        }

        // Tear down any existing session first, so at most one backend is ever
        // live at a time. This matters for the in-process API backend, where
        // Rizin's global state does not tolerate two cores at once; the
        // synchronous `Drop` ensures the old core is fully freed before the new
        // one is created. (A consequence is that a failed open leaves nothing
        // open, rather than preserving the previous session.)
        self.close().await;

        let backend = self.spawn_backend(path, write).await?;

        let mut analysis_error = None;
        if let Some(cmd) = analysis.command() {
            // A hard failure (backend died/timeout) fails the open; a failure
            // reported by Rizin leaves a usable, partly analyzed file.
            let out = backend.exec(cmd).await?;
            if let Err(e) = crate::backend::check(cmd, out) {
                analysis_error = Some(e.to_string());
            }
        }
        let info = backend.cmdj("ij").await.unwrap_or(Value::Null);

        let session = Session {
            backend,
            file: path.to_string(),
            write,
            analysis,
        };

        *self.inner.lock().await = Some(session);

        Ok(OpenInfo {
            file: path.to_string(),
            write,
            analysis,
            info,
            analysis_error,
        })
    }

    /// Construct the configured backend for `path`.
    async fn spawn_backend(&self, path: &str, write: bool) -> Result<Backend, RizinError> {
        match self.config.transport {
            #[cfg(feature = "api")]
            Transport::Api => Ok(Backend::Api(
                RizinCore::open(
                    path,
                    write,
                    self.config.startup_timeout,
                    self.config.command_timeout,
                )
                .await?,
            )),
            #[cfg(not(feature = "api"))]
            Transport::Api => Err(RizinError::NotPermitted(
                "this build has no in-process API backend (compiled with \
                 --no-default-features); use --transport pipe"
                    .into(),
            )),
            Transport::Pipe => {
                let mut extra: Vec<String> = Vec::new();
                if write {
                    extra.push("-w".to_string());
                }
                Ok(Backend::Pipe(
                    RizinPipe::spawn(
                        &self.config.rizin_binary,
                        path,
                        &extra,
                        self.config.startup_timeout,
                        self.config.command_timeout,
                    )
                    .await?,
                ))
            }
        }
    }

    /// Close the current session, if any. Returns whether one was open.
    pub async fn close(&self) -> bool {
        self.inner.lock().await.take().is_some()
    }

    /// A snapshot of the current session state.
    pub async fn state(&self) -> SessionState {
        let guard = self.inner.lock().await;
        match guard.as_ref() {
            Some(s) => SessionState {
                open: true,
                file: Some(s.file.clone()),
                write: s.write,
                analysis: Some(s.analysis),
            },
            None => SessionState {
                open: false,
                file: None,
                write: false,
                analysis: None,
            },
        }
    }

    /// Run a command against the current session and return its output,
    /// status, and diagnostics; a failure reported by Rizin is not an error.
    ///
    /// # Errors
    /// [`RizinError::NoFileOpen`] if nothing is open, [`RizinError::SessionClosed`]
    /// if the backend has died, plus any transport error.
    pub async fn exec(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
        let mut guard = self.inner.lock().await;
        match guard.as_ref() {
            Some(s) if s.backend.is_alive() => s.backend.exec(cmd).await,
            Some(_) => {
                *guard = None;
                Err(RizinError::SessionClosed)
            }
            None => Err(RizinError::NoFileOpen),
        }
    }

    /// Run a command against the current session and return its text output.
    ///
    /// The session lock is held for the duration of the command, which
    /// serialises access (and keeps the in-process backend safe). A session
    /// found dead is cleared.
    ///
    /// # Errors
    /// [`RizinError::NoFileOpen`] if nothing is open, [`RizinError::SessionClosed`]
    /// if the backend has died, [`RizinError::CommandFailed`] if Rizin reports
    /// a failure, plus any transport error.
    pub async fn cmd(&self, cmd: &str) -> Result<String, RizinError> {
        let mut guard = self.inner.lock().await;
        match guard.as_ref() {
            Some(s) if s.backend.is_alive() => s.backend.cmd(cmd).await,
            Some(_) => {
                *guard = None;
                Err(RizinError::SessionClosed)
            }
            None => Err(RizinError::NoFileOpen),
        }
    }

    /// Run a JSON command against the current session and parse its output.
    ///
    /// # Errors
    /// [`RizinError::NoFileOpen`] if nothing is open, [`RizinError::SessionClosed`]
    /// if the backend has died, plus any command/JSON error.
    pub async fn cmdj(&self, cmd: &str) -> Result<Value, RizinError> {
        let mut guard = self.inner.lock().await;
        match guard.as_ref() {
            Some(s) if s.backend.is_alive() => s.backend.cmdj(cmd).await,
            Some(_) => {
                *guard = None;
                Err(RizinError::SessionClosed)
            }
            None => Err(RizinError::NoFileOpen),
        }
    }
}

/// Heuristically detect a Rizin URI of the form `scheme://...`.
fn is_rizin_uri(path: &str) -> bool {
    match path.find("://") {
        Some(idx) if idx > 0 => path[..idx]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_level_commands() {
        assert_eq!(AnalysisLevel::None.command(), None);
        assert_eq!(AnalysisLevel::Basic.command(), Some("aa"));
        assert_eq!(AnalysisLevel::Full.command(), Some("aaa"));
        assert_eq!(AnalysisLevel::Experimental.command(), Some("aaaa"));
        assert_eq!(AnalysisLevel::default(), AnalysisLevel::Basic);
    }

    #[test]
    fn analysis_level_serde() {
        assert_eq!(
            serde_json::from_str::<AnalysisLevel>("\"full\"").unwrap(),
            AnalysisLevel::Full
        );
        assert_eq!(
            serde_json::to_string(&AnalysisLevel::Experimental).unwrap(),
            "\"experimental\""
        );
    }

    #[test]
    fn uri_detection() {
        assert!(is_rizin_uri("malloc://512"));
        assert!(is_rizin_uri("hex://90909090"));
        assert!(is_rizin_uri("rzhttp://host"));
        assert!(!is_rizin_uri("/bin/ls"));
        assert!(!is_rizin_uri("./relative/path"));
        assert!(!is_rizin_uri("C:/win/path"));
        assert!(!is_rizin_uri("://nope"));
    }

    #[tokio::test]
    async fn commands_without_open_file_error() {
        let mgr = SessionManager::new(ServerConfig::default());
        assert!(matches!(mgr.cmd("px").await, Err(RizinError::NoFileOpen)));
        assert!(matches!(mgr.cmdj("ij").await, Err(RizinError::NoFileOpen)));
        assert!(!mgr.close().await);
        let st = mgr.state().await;
        assert!(!st.open);
        assert!(st.file.is_none());
    }

    #[tokio::test]
    async fn write_open_rejected_when_disabled() {
        let mgr = SessionManager::new(ServerConfig {
            allow_write: false,
            ..Default::default()
        });
        let err = mgr.open("/bin/ls", AnalysisLevel::None, true).await;
        assert!(matches!(err, Err(RizinError::NotPermitted(_))));
    }

    #[tokio::test]
    async fn open_missing_file_reports_not_found() {
        let mgr = SessionManager::new(ServerConfig::default());
        let err = mgr
            .open("/definitely/not/here/xyzzy.bin", AnalysisLevel::None, false)
            .await;
        assert!(matches!(err, Err(RizinError::FileNotFound(_))));
    }
}

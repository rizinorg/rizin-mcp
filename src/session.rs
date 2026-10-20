// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Session lifecycle: opening files, tracking the active Rizin process, and
//! serialising command access through it.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::backend::{Backend, check, parse_json};
use crate::config::{ServerConfig, Transport};
use crate::error::RizinError;
use crate::pipe::RizinPipe;
#[cfg(feature = "api")]
use crate::rzcore::RizinCore;
use crate::status::CmdOutput;

/// The `open_file` path that opens a session without a file.
pub const EMPTY_SESSION: &str = "-";

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
    /// The file holding bytes opened with [`SessionManager::open_bytes`];
    /// declared after `backend` so Rizin closes it before it is deleted.
    _data: Option<TempFile>,
}

/// Largest sample [`SessionManager::open_bytes`] accepts.
pub const MAX_DATA_BYTES: usize = 64 << 20;

/// A file created for the session and deleted with it.
struct TempFile(PathBuf);

impl TempFile {
    /// Write `bytes` to a new private file named after `name`.
    fn create(name: &str, bytes: &[u8]) -> Result<Self, RizinError> {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let dir = std::env::temp_dir().join(format!("rizin-mcp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| RizinError::Io(e.to_string()))?;
        // Keep a recognizable but harmless file name.
        let safe: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(64)
            .collect();
        let safe = safe.trim_start_matches('.');
        let safe = if safe.is_empty() { "sample.bin" } else { safe };
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{n}-{safe}"));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|e| RizinError::Io(format!("cannot create {}: {e}", path.display())))?;
        let file_guard = TempFile(path);
        file.write_all(bytes)
            .map_err(|e| RizinError::Io(e.to_string()))?;
        Ok(file_guard)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Owns the (at most one) active Rizin session and brokers access to it.
///
/// Commands are serialised by holding the session lock for the duration of each
/// command, so multiple concurrent tool calls queue rather than race. This is
/// also what keeps the in-process API backend safe, since Rizin's global state
/// must never be touched from two threads at once.
pub struct SessionManager {
    config: ServerConfig,
    inner: Mutex<Slot>,
}

/// The session, if any, and why the last one ended on its own.
#[derive(Default)]
struct Slot {
    session: Option<Session>,
    ended: Option<String>,
    /// The file the journal belongs to.
    journal_file: Option<String>,
    /// The state-changing commands run through the tools since the file was
    /// opened. Kept past a close, so the work can still be exported.
    journal: Vec<String>,
}

impl Slot {
    /// Drop a session that is no longer usable, remembering why.
    fn end(&mut self, reason: String) {
        self.session = None;
        self.ended = Some(reason);
    }
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
    /// Why the previous session ended on its own (e.g. a command timed out
    /// and the session was killed), until another file is opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
}

impl SessionManager {
    /// Create a manager with no open session.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Slot::default()),
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Open `path` (a filesystem path or Rizin URI, or `-` for an empty
    /// session), optionally enabling write mode, and run the requested analysis
    /// level. Replaces any current session (closing the previous backend).
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
        self.open_with(path, analysis, write, None).await
    }

    /// Open `bytes` (e.g. a sample sent by the client) as a file named after
    /// `name`, which lives as long as the session.
    ///
    /// # Errors
    /// [`RizinError::InvalidArgument`] for empty or oversized data, plus the
    /// errors of [`Self::open`].
    pub async fn open_bytes(
        &self,
        bytes: &[u8],
        name: &str,
        analysis: AnalysisLevel,
        write: bool,
    ) -> Result<OpenInfo, RizinError> {
        if bytes.is_empty() || bytes.len() > MAX_DATA_BYTES {
            return Err(RizinError::InvalidArgument {
                arg: format!("{} bytes", bytes.len()),
                reason: format!("data must hold 1 to {MAX_DATA_BYTES} bytes"),
            });
        }
        if write && !self.config.allow_write {
            return Err(RizinError::NotPermitted(
                "write mode is disabled; start the server with --allow-write".into(),
            ));
        }
        let data = TempFile::create(name, bytes)?;
        let path = data.0.to_string_lossy().into_owned();
        self.open_with(&path, analysis, write, Some(data)).await
    }

    async fn open_with(
        &self,
        path: &str,
        analysis: AnalysisLevel,
        write: bool,
        data: Option<TempFile>,
    ) -> Result<OpenInfo, RizinError> {
        if write && !self.config.allow_write {
            return Err(RizinError::NotPermitted(
                "write mode is disabled; start the server with --allow-write".into(),
            ));
        }
        if !is_rizin_uri(path) && path != EMPTY_SESSION {
            if !Path::new(path).exists() {
                return Err(RizinError::FileNotFound(path.to_string()));
            }
            // The `rizin` CLI refuses directories, but the library opens one as
            // an endless file.
            if Path::new(path).is_dir() {
                return Err(RizinError::InvalidArgument {
                    arg: path.to_string(),
                    reason: "is a directory, not a file".into(),
                });
            }
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
            if let Err(e) = check(cmd, out) {
                analysis_error = Some(e.to_string());
            }
        }
        let info = backend.cmdj("ij").await.unwrap_or(Value::Null);

        let session = Session {
            backend,
            file: path.to_string(),
            write,
            analysis,
            _data: data,
        };

        *self.inner.lock().await = Slot {
            session: Some(session),
            ended: None,
            journal_file: Some(path.to_string()),
            journal: Vec::new(),
        };

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
        let target = (path != EMPTY_SESSION).then_some(path);
        match self.config.transport {
            #[cfg(feature = "api")]
            Transport::Api => Ok(Backend::Api(
                RizinCore::open(
                    target,
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
                        target,
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
        let mut slot = self.inner.lock().await;
        slot.ended = None;
        slot.session.take().is_some()
    }

    /// Record a command that changed the analysis or the bytes, for
    /// [`Self::journal`].
    pub async fn record(&self, cmd: String) {
        self.inner.lock().await.journal.push(cmd);
    }

    /// The file of the last opened session and the state-changing commands
    /// recorded for it, in order.
    pub async fn journal(&self) -> (Option<String>, Vec<String>) {
        let slot = self.inner.lock().await;
        (slot.journal_file.clone(), slot.journal.clone())
    }

    /// A snapshot of the current session state. A session that died (e.g.
    /// killed after a command timeout) is reported closed, with the reason.
    pub async fn state(&self) -> SessionState {
        let mut slot = self.inner.lock().await;
        if slot.session.as_ref().is_some_and(|s| !s.backend.is_alive()) {
            slot.end(RizinError::SessionClosed.to_string());
        }
        match slot.session.as_ref() {
            Some(s) => SessionState {
                open: true,
                file: Some(s.file.clone()),
                write: s.write,
                analysis: Some(s.analysis),
                ended: None,
            },
            None => SessionState {
                open: false,
                file: None,
                write: false,
                analysis: None,
                ended: slot.ended.clone(),
            },
        }
    }

    /// Run a command against the current session and return its output,
    /// status, and diagnostics; a failure reported by Rizin is not an error.
    ///
    /// The session lock is held for the duration of the command, which
    /// serialises access (and keeps the in-process backend safe). A session
    /// that dies meanwhile (timeout, broken pipe) is cleared, and the reason
    /// kept for [`Self::state`].
    ///
    /// # Errors
    /// [`RizinError::NoFileOpen`] if nothing is open, [`RizinError::SessionClosed`]
    /// if the backend has died, plus any transport error.
    pub async fn exec(&self, cmd: &str) -> Result<CmdOutput, RizinError> {
        let mut slot = self.inner.lock().await;
        let Some(session) = slot.session.as_ref() else {
            return Err(RizinError::NoFileOpen);
        };
        if !session.backend.is_alive() {
            slot.end(RizinError::SessionClosed.to_string());
            return Err(RizinError::SessionClosed);
        }
        let result = session.backend.exec(cmd).await;
        if !session.backend.is_alive() {
            let reason = match &result {
                Err(e) => e.to_string(),
                Ok(_) => RizinError::SessionClosed.to_string(),
            };
            slot.end(reason);
        }
        result
    }

    /// Run a command against the current session and return its text output.
    ///
    /// # Errors
    /// As [`Self::exec`], plus [`RizinError::CommandFailed`] if Rizin reports a
    /// failure.
    pub async fn cmd(&self, cmd: &str) -> Result<String, RizinError> {
        Ok(check(cmd, self.exec(cmd).await?)?.output)
    }

    /// Run a JSON command against the current session and parse its output.
    ///
    /// # Errors
    /// As [`Self::cmd`], plus [`RizinError::EmptyJson`] or
    /// [`RizinError::Json`] if there is no JSON to parse.
    pub async fn cmdj(&self, cmd: &str) -> Result<Value, RizinError> {
        let out = check(cmd, self.exec(cmd).await?)?;
        parse_json(cmd, &out)
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
        assert!(st.ended.is_none());
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

    #[test]
    fn temp_files_are_private_and_removed() {
        let t = TempFile::create("../../etc/passwd x", b"abc").expect("create");
        let path = t.0.clone();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.ends_with("-etcpasswdx"), "{name}");
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        drop(t);
        assert!(!path.exists());
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

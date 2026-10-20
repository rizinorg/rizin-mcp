// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! End-to-end tests against real Rizin, exercised over **both** backends.
//!
//! These drive the full stack — [`SessionManager`] → [`Backend`] → Rizin —
//! including startup, command framing/marshalling, and the exact Rizin command
//! names used by the server's tools.
//!
//! Each test runs once per available transport:
//!
//! * `Transport::Api` (in-process C library) is available whenever the crate
//!   was built with the default `api` feature, so it needs nothing external.
//! * `Transport::Pipe` spawns a `rizin` process; it is skipped automatically
//!   when one cannot be launched. Point `RIZIN_MCP_TEST_BINARY` at a `rizin`
//!   executable (or put one on `PATH`) to enable it.

use rizin_mcp::RizinError;
use rizin_mcp::config::{ServerConfig, Transport};
use rizin_mcp::session::{AnalysisLevel, SessionManager};
use rizin_mcp::status::CmdStatus;

/// The transports to exercise: the in-process API (when compiled in) and the
/// spawned-process pipe.
fn transports() -> Vec<Transport> {
    #[cfg(feature = "api")]
    {
        vec![Transport::Api, Transport::Pipe]
    }
    #[cfg(not(feature = "api"))]
    {
        vec![Transport::Pipe]
    }
}

fn config(transport: Transport) -> ServerConfig {
    ServerConfig {
        transport,
        rizin_binary: std::env::var("RIZIN_MCP_TEST_BINARY")
            .unwrap_or_else(|_| "rizin".to_string()),
        ..Default::default()
    }
}

/// A real ELF to analyze: prefer a system binary, fall back to the test exe.
fn target() -> String {
    for p in ["/bin/ls", "/usr/bin/ls", "/bin/cat"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    std::env::current_exe()
        .expect("current exe")
        .to_string_lossy()
        .into_owned()
}

/// Held while an in-process session is open: Rizin before 0.10 keeps its
/// console in globals, so two in-process cores must never overlap, as tests
/// running in parallel would make them.
#[cfg(feature = "api")]
static API_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An open session, holding [`API_LOCK`] when in process.
struct Opened {
    mgr: SessionManager,
    _guard: Option<tokio::sync::MutexGuard<'static, ()>>,
}

impl std::ops::Deref for Opened {
    type Target = SessionManager;
    fn deref(&self) -> &SessionManager {
        &self.mgr
    }
}

/// Open the target on `transport`, or return `None` (with a notice) if that
/// backend is unavailable.
async fn open_or_skip(transport: Transport, level: AnalysisLevel) -> Option<Opened> {
    let guard = match transport {
        #[cfg(feature = "api")]
        Transport::Api => Some(API_LOCK.lock().await),
        _ => None,
    };
    let mgr = SessionManager::new(config(transport));
    match mgr.open(&target(), level, false).await {
        Ok(_) => Some(Opened { mgr, _guard: guard }),
        Err(e) => {
            eprintln!("skipping {transport:?} integration test (backend unavailable): {e}");
            None
        }
    }
}

async fn binary_info_and_printing(mgr: &SessionManager) {
    // `ij` returns structured binary info.
    let info = mgr.cmdj("ij").await.expect("ij should return JSON");
    assert!(
        info.get("bin").is_some() || info.get("core").is_some(),
        "ij JSON should contain bin/core: {info}"
    );

    // Entry points and sections are arrays.
    assert!(mgr.cmdj("iej").await.expect("iej").is_array());
    assert!(mgr.cmdj("iSj").await.expect("iSj").is_array());

    // Disassemble a few instructions (JSON) at the entry, falling back to the
    // current seek if the `entry0` flag is not present.
    let dis = match mgr.cmdj("pdj 4 @ entry0").await {
        Ok(v) => v,
        Err(_) => mgr.cmdj("pdj 4").await.expect("pdj should return JSON"),
    };
    assert!(dis.is_array(), "pdj should be a JSON array");

    // Hexdump (JSON).
    let hx = match mgr.cmdj("pxj 16 @ entry0").await {
        Ok(v) => v,
        Err(_) => mgr.cmdj("pxj 16").await.expect("pxj should return JSON"),
    };
    assert!(hx.is_array(), "pxj should be a JSON array");

    // Raw byte read used by `read_bytes`.
    let raw = mgr.cmd("p8 8 @ entry0").await.or(mgr.cmd("p8 8").await);
    assert!(raw.is_ok(), "p8 should succeed");

    // Whole-file string scan.
    let strings = mgr.cmdj("izzj").await.expect("izzj should return JSON");
    assert!(strings.is_array() || strings.is_object());

    // Session state reflects the open file.
    let state = mgr.state().await;
    assert!(state.open);
    assert!(!state.write);
    assert_eq!(state.analysis, Some(AnalysisLevel::None));

    assert!(mgr.close().await, "closing an open session returns true");
    // After close, commands must report no open file.
    assert!(mgr.cmd("ij").await.is_err());
}

async fn analysis_and_search(mgr: &SessionManager) {
    // After `aa`, the function list is a JSON array (non-empty for real ELFs,
    // but we only require valid JSON to stay robust across targets).
    let funcs = mgr.cmdj("aflj").await.expect("aflj should return JSON");
    assert!(funcs.is_array(), "aflj should be an array");

    // Byte search (as used by `search_bytes`/`search_string`): search for the
    // target's own magic — the leading bytes of the loaded image — which must
    // therefore be found at least once. Reading the magic from what Rizin
    // actually mapped (rather than hard-coding ELF's `7f454c46`) keeps this
    // correct across object formats: ELF on Linux, Mach-O on macOS, and either
    // slice of a universal binary (whose unmapped fat header is never searched,
    // while the selected slice's Mach-O magic sits at the image base).
    let baddr = mgr
        .cmdj("ij")
        .await
        .expect("ij should return JSON")
        .get("bin")
        .and_then(|b| b.get("baddr"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let magic = mgr
        .cmd(&format!("p8 4 @ 0x{baddr:x}"))
        .await
        .expect("p8 should read the image magic")
        .trim()
        .to_string();
    assert!(
        !magic.is_empty(),
        "could not read magic bytes at image base 0x{baddr:x}"
    );
    let hits = mgr
        .cmdj(&format!("/xj {magic}"))
        .await
        .expect("/xj should return JSON");
    assert!(hits.is_array(), "/xj should be a JSON array");
    assert!(
        hits.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "the image's own magic ({magic}) should be found at least once"
    );

    // Flags and flag spaces (regression cover for the exact command names used
    // by `list_flags`/`flag_spaces`: `flj` and `fslj`).
    assert!(mgr.cmdj("flj").await.expect("flj").is_array());
    assert!(mgr.cmdj("fslj").await.expect("fslj").is_array());

    // If there is a real (non-import) function, exercise the function-detail
    // commands used by the tools against its address: `afij`, `afvlj`,
    // `agf j`, and `axfj`.
    let real = funcs.as_array().and_then(|a| {
        a.iter().find(|f| {
            f.get("size").and_then(|s| s.as_u64()).unwrap_or(0) > 64
                && !f
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .starts_with("sym.imp")
        })
    });
    if let Some(func) = real {
        let off = func.get("offset").and_then(|o| o.as_u64()).expect("offset");
        let addr = format!("0x{off:x}");

        assert!(
            mgr.cmdj(&format!("afij @ {addr}"))
                .await
                .expect("afij")
                .is_array()
        );
        let vars = mgr.cmdj(&format!("afvlj @ {addr}")).await.expect("afvlj");
        assert!(vars.is_object() || vars.is_array(), "afvlj should be JSON");
        let graph = mgr.cmdj(&format!("agf j @ {addr}")).await.expect("agf j");
        assert!(graph.get("nodes").is_some(), "agf j should have nodes");
        assert!(
            mgr.cmdj(&format!("axfj @ {addr}"))
                .await
                .expect("axfj")
                .is_array()
        );
    }
}

#[tokio::test]
async fn end_to_end_binary_info_and_printing() {
    for t in transports() {
        if let Some(mgr) = open_or_skip(t, AnalysisLevel::None).await {
            eprintln!("running binary_info_and_printing on {t:?}");
            binary_info_and_printing(&mgr).await;
        }
    }
}

#[tokio::test]
async fn end_to_end_analysis_and_search() {
    for t in transports() {
        if let Some(mgr) = open_or_skip(t, AnalysisLevel::Basic).await {
            eprintln!("running analysis_and_search on {t:?}");
            analysis_and_search(&mgr).await;
        }
    }
}

async fn status_and_messages(mgr: &SessionManager, transport: Transport) {
    // A successful command reports OK (or Unknown before Rizin 0.10) and no
    // diagnostics.
    let ok = mgr.exec("p8 4 @ 0").await.expect("p8");
    assert!(!ok.status.is_failure(), "{transport:?}: {:?}", ok.status);
    assert!(ok.messages.is_empty(), "{transport:?}: {:?}", ok.messages);

    // A plugin command that is not installed fails with its reason, instead
    // of looking like an empty success.
    let missing = mgr
        .exec("pdzzz")
        .await
        .expect("a failing command is not a transport error");
    // Before Rizin 0.10 the pipe cannot tell and the in-process API only
    // knows that the command failed.
    match missing.status {
        CmdStatus::Unknown | CmdStatus::Failed => {}
        s => assert_eq!(s, CmdStatus::NonExistingCmd, "{transport:?}"),
    }
    assert!(
        missing.detail().contains("does not exist"),
        "{transport:?}: {:?}",
        missing.messages
    );
    match mgr.cmd("pdzzz").await {
        Err(RizinError::CommandFailed { status, detail, .. }) => {
            assert!(status.is_failure());
            assert!(detail.contains("does not exist"), "{transport:?}: {detail}");
        }
        other if missing.status == CmdStatus::Unknown => {
            eprintln!("{transport:?}: no status reporting, got {other:?}")
        }
        other => panic!("{transport:?}: expected CommandFailed, got {other:?}"),
    }

    // A chained line keeps what was printed before the failing statement, but
    // the line as a whole failed.
    let chained = mgr.exec("p8 1 @ 0; pdzzz").await.expect("exec");
    // `rz_core_cmd_str()` of Rizin before 0.10 drops the output of a failed
    // line, so the output is checked only where the status is reported.
    let reports_status = mgr
        .exec("_s?")
        .await
        .is_ok_and(|o| o.status == CmdStatus::Ok);
    if reports_status {
        assert!(
            chained.output.trim().len() == 2,
            "{transport:?}: {:?}",
            chained.output
        );
    }
    if chained.status != CmdStatus::Unknown {
        assert!(chained.status.is_failure(), "{transport:?}");
        assert!(matches!(
            mgr.cmdj("ij; pdzzz").await,
            Err(RizinError::CommandFailed { .. })
        ));
    }
}

#[tokio::test]
async fn end_to_end_status_and_messages() {
    for t in transports() {
        if let Some(mgr) = open_or_skip(t, AnalysisLevel::None).await {
            eprintln!("running status_and_messages on {t:?}");
            status_and_messages(&mgr, t).await;
        }
    }
}

async fn quoting_is_verbatim(mgr: &SessionManager, transport: Transport) {
    // Whatever text is quoted reaches the command unchanged.
    for text in [
        "plain",
        "semi;colon | pipe > gt @ at ~tilde #hash",
        r#"quote " and backslash \ and \" both"#,
        "dollar $sp $(echo sub) and `echo bt` backticks",
        "trailing backslash \\",
        "",
    ] {
        let q = rizin_mcp::util::quote_arg(text).expect("quote");
        let out = mgr.cmd(&format!("echo {q}")).await.expect("echo");
        assert_eq!(
            out.strip_suffix('\n').unwrap_or(&out),
            text,
            "{transport:?}"
        );
    }
}

#[tokio::test]
async fn end_to_end_quoting_is_verbatim() {
    for t in transports() {
        if let Some(mgr) = open_or_skip(t, AnalysisLevel::None).await {
            eprintln!("running quoting_is_verbatim on {t:?}");
            quoting_is_verbatim(&mgr, t).await;
        }
    }
}

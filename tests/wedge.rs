// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! What happens after a command times out. Kept in its own test binary: a
//! timed-out in-process command keeps holding the global Rizin lock, which
//! would stall the in-process tests running next to it.

use std::time::Duration;

use rizin_mcp::RizinError;
use rizin_mcp::config::{ServerConfig, Transport};
use rizin_mcp::session::{AnalysisLevel, SessionManager};

fn config(transport: Transport) -> ServerConfig {
    ServerConfig {
        transport,
        rizin_binary: std::env::var("RIZIN_MCP_TEST_BINARY")
            .unwrap_or_else(|_| "rizin".to_string()),
        command_timeout: Duration::from_secs(1),
        startup_timeout: Duration::from_secs(1),
        ..Default::default()
    }
}

/// Run a command that outlives the timeout and check the session reports it.
async fn time_out(mgr: &SessionManager, transport: Transport, secs: u64) {
    mgr.open("malloc://16", AnalysisLevel::None, false)
        .await
        .expect("open");
    let err = mgr.cmd(&format!("!sleep {secs}")).await.unwrap_err();
    assert!(
        matches!(err, RizinError::CommandTimeout { .. }),
        "{transport:?}: {err:?}"
    );
    let state = mgr.state().await;
    assert!(!state.open, "{transport:?}: a dead session is not open");
    let ended = state.ended.expect("the reason is kept");
    assert!(ended.contains("timed out"), "{transport:?}: {ended}");
    assert!(matches!(mgr.cmd("p8 1").await, Err(RizinError::NoFileOpen)));
}

#[tokio::test]
async fn sessions_after_a_timeout() {
    // The pipe backend kills rizin, so a new session opens at once.
    if std::process::Command::new(config(Transport::Pipe).rizin_binary)
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let mgr = SessionManager::new(config(Transport::Pipe));
        time_out(&mgr, Transport::Pipe, 5).await;
        mgr.open("malloc://16", AnalysisLevel::None, false)
            .await
            .expect("pipe: reopen right away");
        assert!(mgr.state().await.ended.is_none());
    }

    // In process, the call cannot be interrupted: until it returns, it holds
    // the global lock and no new core can be created.
    #[cfg(feature = "api")]
    {
        let mgr = SessionManager::new(config(Transport::Api));
        let started = std::time::Instant::now();
        time_out(&mgr, Transport::Api, 6).await;
        let err = mgr
            .open("malloc://16", AnalysisLevel::None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RizinError::StartupTimeout { .. }),
            "api: {err:?}"
        );
        // Once `sleep` has returned, sessions work again.
        let done = Duration::from_secs(7).saturating_sub(started.elapsed());
        tokio::time::sleep(done).await;
        let mut opened = false;
        for _ in 0..10 {
            if mgr
                .open("malloc://16", AnalysisLevel::None, false)
                .await
                .is_ok()
            {
                opened = true;
                break;
            }
        }
        assert!(opened, "api: no session after the wedged call returned");
        assert_eq!(mgr.cmd("p8 1").await.expect("p8").trim(), "00");
    }
}

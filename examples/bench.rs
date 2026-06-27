// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Micro-benchmark comparing the two backends.
//!
//! Measures (1) the cost of opening a target and (2) the per-command round-trip
//! latency, for the in-process `api` backend and the spawned-process `pipe`
//! backend. Run with:
//!
//! ```text
//! RIZIN_MCP_BENCH_RIZIN=/path/to/rizin cargo run --release --example bench
//! ```
//!
//! The `pipe` portion is skipped if a `rizin` binary cannot be launched.

use std::time::{Duration, Instant};

use rizin_mcp::config::{ServerConfig, Transport};
use rizin_mcp::session::{AnalysisLevel, SessionManager};

fn target() -> String {
    for p in ["/bin/ls", "/usr/bin/ls", "/bin/cat"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    std::env::current_exe()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn rizin_binary() -> String {
    std::env::var("RIZIN_MCP_BENCH_RIZIN").unwrap_or_else(|_| "rizin".to_string())
}

fn config(transport: Transport) -> ServerConfig {
    ServerConfig {
        transport,
        rizin_binary: rizin_binary(),
        ..Default::default()
    }
}

/// Time `iters` open+close cycles; returns the average.
async fn bench_open(transport: Transport, iters: u32) -> Option<Duration> {
    let path = target();
    // Probe once (in its own scope, fully closed) to check this backend works.
    {
        let probe = SessionManager::new(config(transport));
        if probe.open(&path, AnalysisLevel::None, false).await.is_err() {
            return None;
        }
        probe.close().await;
    }
    let start = Instant::now();
    for _ in 0..iters {
        let mgr = SessionManager::new(config(transport));
        mgr.open(&path, AnalysisLevel::None, false).await.unwrap();
        mgr.close().await;
    }
    Some(start.elapsed() / iters)
}

/// Time `iters` commands against one open session; returns the average.
async fn bench_cmd(transport: Transport, iters: u32) -> Option<Duration> {
    let mgr = SessionManager::new(config(transport));
    if mgr
        .open(&target(), AnalysisLevel::None, false)
        .await
        .is_err()
    {
        return None;
    }
    // Warm up.
    for _ in 0..20 {
        let _ = mgr.cmd("p8 4 @ entry0").await;
    }
    let start = Instant::now();
    for _ in 0..iters {
        mgr.cmd("p8 4 @ entry0").await.unwrap();
    }
    let avg = start.elapsed() / iters;
    mgr.close().await;
    Some(avg)
}

fn row(label: &str, api: Option<Duration>, pipe: Option<Duration>) {
    let fmt = |d: Option<Duration>| match d {
        Some(d) => format!("{:>10.3?}", d),
        None => format!("{:>10}", "n/a"),
    };
    let speedup = match (api, pipe) {
        (Some(a), Some(p)) if a.as_nanos() > 0 => {
            format!("{:.1}x", p.as_secs_f64() / a.as_secs_f64())
        }
        _ => "-".to_string(),
    };
    println!("{label:<22} {}  {}   {speedup:>6}", fmt(api), fmt(pipe));
}

#[tokio::main]
async fn main() {
    let transports: &[Transport] = &[Transport::Api, Transport::Pipe];
    let mut open = [None, None];
    let mut cmd = [None, None];
    for (i, &t) in transports.iter().enumerate() {
        open[i] = bench_open(t, 25).await;
        cmd[i] = bench_cmd(t, 1000).await;
    }

    println!("\nRizin MCP backend benchmark (target: {})", target());
    println!(
        "{:<22} {:>10}  {:>10}   {:>6}",
        "", "api", "pipe", "api adv"
    );
    println!("{}", "-".repeat(54));
    row("open + close (avg)", open[0], open[1]);
    row("command (avg)", cmd[0], cmd[1]);
    println!(
        "\n  api  = in-process via librz_core\n  pipe = spawned `rizin -q0` ({})",
        rizin_binary()
    );
}

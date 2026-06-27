// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! `rizin-mcp` binary: a Model Context Protocol server (over stdio) exposing
//! the Rizin reverse-engineering framework.

use std::time::Duration;

use clap::{Parser, ValueEnum};
use rmcp::{ServiceExt, transport::stdio};

use rizin_mcp::config::{ServerConfig, Transport};
use rizin_mcp::server::RizinServer;
use rizin_mcp::session::AnalysisLevel;

/// Command-line options.
#[derive(Debug, Parser)]
#[command(
    name = "rizin-mcp",
    version,
    about = "MCP server exposing the Rizin reverse-engineering framework over stdio"
)]
struct Cli {
    /// Optional binary/file (or Rizin URI) to open at startup.
    file: Option<String>,

    /// Backend to use: `api` (in-process, fast) or `pipe` (spawns `rizin`).
    /// Defaults to `api` when compiled in, otherwise `pipe`.
    #[arg(long, value_enum)]
    transport: Option<TransportArg>,

    /// Path or name of the `rizin` executable (pipe backend only).
    #[arg(long, default_value = "rizin")]
    rizin: String,

    /// Analysis level applied to the startup file.
    #[arg(long, value_enum, default_value_t = AnalysisArg::Basic)]
    analysis: AnalysisArg,

    /// Allow opening files in write mode and using the write tools.
    #[arg(long)]
    allow_write: bool,

    /// Disable the raw `command` / `command_json` passthrough tools.
    #[arg(long)]
    no_raw: bool,

    /// Enable the debugger tools. WARNING: debugging executes the target binary.
    #[arg(long)]
    allow_debug: bool,

    /// Per-command timeout in seconds (a hung command kills the session).
    #[arg(long, default_value_t = 120)]
    command_timeout: u64,

    /// Startup/analysis timeout in seconds.
    #[arg(long, default_value_t = 60)]
    startup_timeout: u64,
}

/// Clap-facing mirror of [`AnalysisLevel`].
#[derive(Debug, Clone, Copy, ValueEnum)]
enum AnalysisArg {
    None,
    Basic,
    Full,
    Experimental,
}

impl From<AnalysisArg> for AnalysisLevel {
    fn from(a: AnalysisArg) -> Self {
        match a {
            AnalysisArg::None => AnalysisLevel::None,
            AnalysisArg::Basic => AnalysisLevel::Basic,
            AnalysisArg::Full => AnalysisLevel::Full,
            AnalysisArg::Experimental => AnalysisLevel::Experimental,
        }
    }
}

/// Clap-facing mirror of [`Transport`].
#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportArg {
    /// In-process via Rizin's C library (requires the `api` feature).
    Api,
    /// Out-of-process via a spawned `rizin` process.
    Pipe,
}

impl From<TransportArg> for Transport {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::Api => Transport::Api,
            TransportArg::Pipe => Transport::Pipe,
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter =
        EnvFilter::try_from_env("RIZIN_MCP_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Logs MUST go to stderr; stdout is the MCP protocol channel.
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let config = ServerConfig {
        transport: cli.transport.map(Into::into).unwrap_or_default(),
        rizin_binary: cli.rizin.clone(),
        allow_write: cli.allow_write,
        allow_raw: !cli.no_raw,
        allow_debug: cli.allow_debug,
        startup_timeout: Duration::from_secs(cli.startup_timeout),
        command_timeout: Duration::from_secs(cli.command_timeout),
        ..Default::default()
    };

    let server = RizinServer::new(config);

    if let Some(file) = cli.file.as_deref() {
        match server
            .manager()
            .open(file, cli.analysis.into(), cli.allow_write)
            .await
        {
            Ok(info) => tracing::info!(file = %info.file, "opened startup file"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to open startup file; continuing without it")
            }
        }
    }

    tracing::info!("starting rizin-mcp on stdio");
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

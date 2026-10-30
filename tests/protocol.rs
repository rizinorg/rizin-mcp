// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! The server speaks to clients of every MCP revision, written as raw JSON-RPC
//! lines: no SDK client would send what a client of another revision sends.

use rizin_mcp::RizinServer;
use rizin_mcp::config::ServerConfig;
use rmcp::ServiceExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf};

/// A client end of an in-memory stdio transport to a running server.
struct Wire {
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
    next_id: u64,
}

impl Wire {
    fn start() -> Self {
        let (server_io, client_io) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            if let Ok(running) = RizinServer::new(ServerConfig::default())
                .serve(server_io)
                .await
            {
                let _ = running.waiting().await;
            }
        });
        let (reader, writer) = tokio::io::split(client_io);
        Self {
            lines: BufReader::new(reader).lines(),
            writer,
            next_id: 0,
        }
    }

    async fn send(&mut self, message: Value) {
        let line = format!("{message}\n");
        self.writer.write_all(line.as_bytes()).await.expect("write");
    }

    /// Send a request and return its response; panics if the server closes
    /// the connection instead.
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        loop {
            let line =
                tokio::time::timeout(std::time::Duration::from_secs(30), self.lines.next_line())
                    .await
                    .expect("response in time")
                    .expect("read")
                    .unwrap_or_else(|| panic!("the server closed the connection on {method}"));
            let message: Value = serde_json::from_str(&line).expect("JSON-RPC");
            if message["id"] == id {
                return message;
            }
        }
    }
}

/// The `_meta` a client of MCP 2026-07-28 sends with every request.
fn meta_2026() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

#[tokio::test]
async fn discovery_falls_back_to_initialize() {
    let mut wire = Wire::start();
    // A client of MCP 2026-07-28 probes with `server/discover` and falls back
    // to `initialize` on an error: the server must answer, not hang up (as
    // rmcp 1.x did, so FastMCP could not connect).
    let probe = wire.request("server/discover", json!({})).await;
    assert!(probe.get("error").is_some(), "{probe}");
    let init = wire
        .request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" },
            }),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "rizin-mcp", "{init}");
    wire.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .await;
    let tools = wire.request("tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()),
        "{tools}"
    );
    let unknown = wire.request("no/such/method", json!({})).await;
    assert_eq!(unknown["error"]["code"], -32601, "{unknown}");
}

#[tokio::test]
async fn clients_of_2026_07_28_need_no_initialize() {
    let mut wire = Wire::start();
    let ping = wire.request("ping", json!({})).await;
    assert!(ping.get("result").is_some(), "{ping}");
    let discovered = wire
        .request("server/discover", json!({ "_meta": meta_2026() }))
        .await;
    let versions = &discovered["result"]["supportedVersions"];
    for version in ["2025-06-18", "2026-07-28"] {
        assert!(
            versions
                .as_array()
                .is_some_and(|v| v.contains(&json!(version))),
            "{discovered}"
        );
    }
    let tools = wire
        .request("tools/list", json!({ "_meta": meta_2026() }))
        .await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()),
        "{tools}"
    );
    // A tool call without a session fails as a tool, not as the protocol.
    let call = wire
        .request(
            "tools/call",
            json!({ "name": "seek", "arguments": { "address": "0x0" }, "_meta": meta_2026() }),
        )
        .await;
    assert!(
        call["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no file is open")),
        "{call}"
    );
}

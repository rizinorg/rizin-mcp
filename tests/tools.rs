// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! MCP-level tests: a real rmcp client talks to [`RizinServer`] over an
//! in-memory duplex stream and calls its tools, on every available backend,
//! the way an MCP client would.

use rizin_mcp::RizinServer;
use rizin_mcp::config::{ServerConfig, Transport};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::{RoleClient, RunningService, ServiceError};
use rmcp::{ErrorData, ServiceExt};
use serde_json::{Value, json};

fn transports() -> Vec<Transport> {
    let mut t = Vec::new();
    #[cfg(feature = "api")]
    t.push(Transport::Api);
    if pipe_available() {
        t.push(Transport::Pipe);
    } else {
        eprintln!("skipping the pipe backend: no runnable rizin");
    }
    t
}

fn rizin_binary() -> String {
    std::env::var("RIZIN_MCP_TEST_BINARY").unwrap_or_else(|_| "rizin".to_string())
}

fn pipe_available() -> bool {
    std::process::Command::new(rizin_binary())
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A real ELF to analyze.
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

/// Held by an in-process server for its whole life: Rizin before 0.10 keeps
/// its console in globals, so two in-process cores must never overlap, as
/// tests running in parallel would make them.
static API_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A connected client; the server runs on a background task.
struct Session {
    client: RunningService<RoleClient, ()>,
    transport: Transport,
}

impl Session {
    async fn start(transport: Transport, tweak: impl FnOnce(&mut ServerConfig)) -> Self {
        let mut config = ServerConfig {
            transport,
            rizin_binary: rizin_binary(),
            ..Default::default()
        };
        tweak(&mut config);
        let (server_io, client_io) = tokio::io::duplex(1 << 16);
        let server = RizinServer::new(config);
        let guard = match transport {
            Transport::Api => Some(API_LOCK.lock().await),
            Transport::Pipe => None,
        };
        tokio::spawn(async move {
            // Released only after the server, and its core, are gone.
            let _guard = guard;
            if let Ok(running) = server.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        let client = ().serve(client_io).await.expect("client handshake");
        Self { client, transport }
    }

    async fn call(&self, name: &str, args: Value) -> Result<CallToolResult, ErrorData> {
        let mut params = CallToolRequestParams::new(name.to_string());
        if let Value::Object(map) = args {
            params = params.with_arguments(map);
        }
        match self.client.call_tool(params).await {
            Ok(r) => Ok(r),
            Err(ServiceError::McpError(e)) => Err(e),
            Err(e) => panic!(
                "{:?}: transport failure calling {name}: {e}",
                self.transport
            ),
        }
    }

    /// Call a tool that must succeed and return its structured content.
    async fn ok(&self, name: &str, args: Value) -> Value {
        let r = self
            .call(name, args)
            .await
            .unwrap_or_else(|e| panic!("{:?}: {name} failed: {e:?}", self.transport));
        assert_ne!(
            r.is_error,
            Some(true),
            "{:?}: {name}: {r:?}",
            self.transport
        );
        r.structured_content.unwrap_or(Value::Null)
    }
}

/// The gadget addresses of a `search_rop` result.
fn gadget_starts(v: &Value) -> Vec<u64> {
    v.as_array()
        .expect("gadget array")
        .iter()
        .map(|g| g["opcodes"][0]["offset"].as_u64().expect("offset"))
        .collect()
}

#[tokio::test]
async fn search_rop_matches_instruction_chains() {
    for t in transports() {
        let s = Session::start(t, |_| {}).await;
        s.ok("open_file", json!({ "path": target(), "analysis": "none" }))
            .await;

        // The chain is matched in order, so every hit has `pop` then `ret`;
        // spaces around `;` do not matter.
        let spaced = s.ok("search_rop", json!({ "query": "pop rbp; ret" })).await;
        let tight = s.ok("search_rop", json!({ "query": "pop rbp;ret" })).await;
        assert_eq!(spaced, tight, "{t:?}");
        assert!(!gadget_starts(&spaced).is_empty(), "{t:?}: no gadgets");
        for g in spaced.as_array().unwrap() {
            let ops: Vec<&str> = g["opcodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["opcode"].as_str().unwrap())
                .collect();
            let pop = ops.iter().position(|o| o.contains("pop rbp"));
            let ret = ops.iter().rposition(|o| o.contains("ret"));
            assert!(
                matches!((pop, ret), (Some(p), Some(r)) if p < r),
                "{t:?}: {ops:?}"
            );
        }

        // A chain is narrower than its first instruction alone.
        let first = s.ok("search_rop", json!({ "query": "pop rbp" })).await;
        assert!(
            gadget_starts(&first).len() >= gadget_starts(&spaced).len(),
            "{t:?}"
        );

        // Exact gadgets are exactly `pop rbp; ret`, a subset of the chain hits.
        let exact = s
            .ok(
                "search_rop",
                json!({ "query": "pop rbp; ret", "exact": true }),
            )
            .await;
        let starts = gadget_starts(&spaced);
        assert!(
            gadget_starts(&exact).iter().all(|a| starts.contains(a)),
            "{t:?}"
        );
        for g in exact.as_array().unwrap() {
            let ops = g["opcodes"].as_array().unwrap();
            assert_eq!(ops.len(), 2, "{t:?}: {g}");
            assert_eq!(ops[0]["opcode"], "pop rbp");
            assert_eq!(ops[1]["opcode"], "ret");
        }

        // Shell metacharacters stay inside the quoted filter: no gadget
        // contains this text, and no `px` output leaks in.
        let quoted = s
            .ok(
                "search_rop",
                json!({ "query": "ret\"; px 4 $(px 4) `px 4`" }),
            )
            .await;
        assert_eq!(quoted, json!([]), "{t:?}");
        let err = s
            .call("search_rop", json!({ "query": "pop rdi\nret" }))
            .await
            .expect_err("a newline must be rejected");
        assert_eq!(err.code.0, -32602, "{t:?}");
    }
}

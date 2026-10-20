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
        let sc = r.structured_content.unwrap_or(Value::Null);
        assert!(
            sc.is_object() || sc.is_null(),
            "{:?}: {name}: structuredContent must be an object: {sc}",
            self.transport
        );
        sc
    }

    /// Call a listing tool that must succeed and return its items.
    async fn items(&self, name: &str, args: Value) -> Vec<Value> {
        let sc = self.ok(name, args).await;
        sc["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{:?}: {name}: no items in {sc}", self.transport))
            .clone()
    }
}

/// The gadget addresses of a `search_rop` result.
fn gadget_starts(gadgets: &[Value]) -> Vec<u64> {
    gadgets
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
        let spaced = s
            .items("search_rop", json!({ "query": "pop rbp; ret" }))
            .await;
        let tight = s
            .items("search_rop", json!({ "query": "pop rbp;ret" }))
            .await;
        assert_eq!(spaced, tight, "{t:?}");
        assert!(!gadget_starts(&spaced).is_empty(), "{t:?}: no gadgets");
        for g in &spaced {
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
        let first = s.items("search_rop", json!({ "query": "pop rbp" })).await;
        assert!(
            gadget_starts(&first).len() >= gadget_starts(&spaced).len(),
            "{t:?}"
        );

        // Exact gadgets are exactly `pop rbp; ret`, a subset of the chain hits.
        let exact = s
            .items(
                "search_rop",
                json!({ "query": "pop rbp; ret", "exact": true }),
            )
            .await;
        let starts = gadget_starts(&spaced);
        assert!(
            gadget_starts(&exact).iter().all(|a| starts.contains(a)),
            "{t:?}"
        );
        for g in &exact {
            let ops = g["opcodes"].as_array().unwrap();
            assert_eq!(ops.len(), 2, "{t:?}: {g}");
            assert_eq!(ops[0]["opcode"], "pop rbp");
            assert_eq!(ops[1]["opcode"], "ret");
        }

        // Shell metacharacters stay inside the quoted filter: no gadget
        // contains this text, and no `px` output leaks in.
        let quoted = s
            .items(
                "search_rop",
                json!({ "query": "ret\"; px 4 $(px 4) `px 4`" }),
            )
            .await;
        assert!(quoted.is_empty(), "{t:?}");
        let err = s
            .call("search_rop", json!({ "query": "pop rdi\nret" }))
            .await
            .expect_err("a newline must be rejected");
        assert_eq!(err.code.0, -32602, "{t:?}");
    }
}

#[tokio::test]
async fn writes_are_verified() {
    for t in transports() {
        let s = Session::start(t, |c| c.allow_write = true).await;
        s.ok(
            "open_file",
            json!({ "path": "malloc://256", "analysis": "none", "write": true }),
        )
        .await;
        let read = |at: &str, n: u64| {
            let at = at.to_string();
            let s = &s;
            async move {
                s.ok("read_bytes", json!({ "at": at, "count": n })).await["data"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
        };

        // Multi-token instructions are assembled whole.
        let w = s
            .ok(
                "write_assembly",
                json!({ "address": "0x20", "assembly": "mov eax, 1" }),
            )
            .await;
        assert_eq!(w["bytes"], "b801000000", "{t:?}");
        assert_eq!(read("0x20", 5).await, "b801000000", "{t:?}");

        // Several instructions, and a branch encoded for its address.
        let w = s
            .ok(
                "write_assembly",
                json!({ "address": "0x30", "assembly": "mov ecx, 3; ret\njmp 0x30" }),
            )
            .await;
        assert_eq!(w["bytes"], "b903000000c3ebf8", "{t:?}");
        assert_eq!(read("0x30", 8).await, "b903000000c3ebf8", "{t:?}");

        // Unassemblable input fails with Rizin's reason and writes nothing.
        let err = s
            .call(
                "write_assembly",
                json!({ "address": "0x50", "assembly": "bogus insn" }),
            )
            .await
            .expect_err("bogus assembly");
        assert_eq!(err.code.0, -32001, "{t:?}");
        assert!(
            err.message.contains("Cannot assemble"),
            "{t:?}: {}",
            err.message
        );
        assert_eq!(read("0x50", 4).await, "00000000", "{t:?}");

        // `wx` says OK when it cannot write; the tools do not.
        for (tool, args) in [
            ("write_hex", json!({ "address": "0xdeadbeef", "hex": "90" })),
            (
                "write_string",
                json!({ "address": "0xdeadbeef", "text": "A" }),
            ),
            (
                "write_assembly",
                json!({ "address": "0xdeadbeef", "assembly": "nop" }),
            ),
        ] {
            let err = s.call(tool, args).await.expect_err(tool);
            assert_eq!(err.code.0, -32001, "{t:?} {tool}: {err:?}");
        }
        let w = s
            .ok(
                "write_hex",
                json!({ "address": "0x60", "hex": "dead beef" }),
            )
            .await;
        assert_eq!(w["wrote"], 4);
        assert_eq!(read("0x60", 4).await, "deadbeef", "{t:?}");
    }
}

#[tokio::test]
async fn empty_session_and_open_failures() {
    for t in transports() {
        let s = Session::start(t, |_| {}).await;
        // `-` opens a session without a file on both backends.
        let info = s
            .ok("open_file", json!({ "path": "-", "analysis": "none" }))
            .await;
        assert_eq!(info["file"], "-", "{t:?}");
        let r = s
            .call("command", json!({ "command": "echo ready" }))
            .await
            .expect("command");
        assert_eq!(r.is_error, Some(false), "{t:?}");

        // A target Rizin cannot open fails the same way on both backends,
        // with Rizin's reason.
        for target in ["nosuchscheme://x", "file:///nonexistent", "malloc://0"] {
            let err = s
                .call("open_file", json!({ "path": target, "analysis": "none" }))
                .await
                .expect_err(target);
            assert_eq!(err.code.0, -32602, "{t:?}: {err:?}");
            assert!(
                err.message
                    .starts_with(&format!("rizin cannot open '{target}'")),
                "{t:?}: {}",
                err.message
            );
            assert!(
                err.message.contains("Cannot open"),
                "{t:?}: {}",
                err.message
            );
        }
        let err = s
            .call("open_file", json!({ "path": "/", "analysis": "none" }))
            .await
            .expect_err("a directory");
        assert!(err.message.contains("directory"), "{t:?}: {}", err.message);
    }
}

#[tokio::test]
async fn every_listing_returns_an_object() {
    // The argument-free read-only tools, plus a few taking a location.
    let calls = [
        ("binary_info", json!({})),
        ("entrypoints", json!({})),
        ("sections", json!({})),
        ("segments", json!({})),
        ("relocations", json!({})),
        ("imports", json!({})),
        ("exports", json!({})),
        ("symbols", json!({})),
        ("libraries", json!({})),
        ("classes", json!({})),
        ("list_strings", json!({ "all": false })),
        ("list_flags", json!({})),
        ("flag_spaces", json!({})),
        ("list_functions", json!({})),
        ("function_info", json!({ "at": "entry0" })),
        ("disassemble", json!({ "at": "entry0", "count": 4 })),
        ("hexdump", json!({ "at": "entry0", "count": 16 })),
        ("instruction_analysis", json!({ "at": "entry0" })),
        ("xrefs_to", json!({ "address": "entry0" })),
        ("xrefs_from", json!({ "address": "entry0" })),
        ("headers", json!({})),
        ("header_fields", json!({})),
        ("signature_info", json!({})),
        ("version_info", json!({})),
        ("resources", json!({})),
        ("hash_algorithms", json!({})),
        ("decompilers", json!({})),
        ("search_bytes", json!({ "hex": "7f454c46" })),
        ("search_value", json!({ "value": "0x464c457f", "size": 4 })),
    ];
    for t in transports() {
        let s = Session::start(t, |_| {}).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;
        for (name, args) in &calls {
            // `ok` asserts that the structured content is an object.
            s.ok(name, args.clone()).await;
        }
    }
}

/// Size of a result as a client receives it (its text content).
fn text_len(r: &CallToolResult) -> usize {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.len()))
        .sum()
}

#[tokio::test]
async fn listings_are_paged_and_bounded() {
    for t in transports() {
        let s = Session::start(t, |_| {}).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;

        // A default page holds at most 100 items and says what is left.
        let first = s.ok("list_strings", json!({})).await;
        let total = first["total"].as_u64().unwrap();
        assert!(first["returned"].as_u64().unwrap() <= 100, "{t:?}");
        if total > 100 {
            assert_eq!(first["truncated"], true, "{t:?}");
            assert_eq!(first["next_offset"], 100, "{t:?}");
        }

        // Following next_offset visits every item once.
        let mut seen = 0;
        let mut offset = 0;
        loop {
            let page = s
                .ok("list_strings", json!({ "offset": offset, "limit": 250 }))
                .await;
            assert_eq!(page["offset"], offset, "{t:?}");
            seen += page["returned"].as_u64().unwrap();
            match page.get("next_offset").and_then(Value::as_u64) {
                Some(next) => offset = next,
                None => break,
            }
        }
        assert_eq!(seen, total, "{t:?}");

        // The gadget listing that used to be ~1 MB stays bounded.
        let r = s
            .call("search_rop", json!({ "query": "ret" }))
            .await
            .expect("search_rop");
        assert!(text_len(&r) <= 128 << 10, "{t:?}: {} bytes", text_len(&r));

        // A function's instructions are paged too.
        let f = s
            .ok("disassemble_function", json!({ "at": "main", "limit": 5 }))
            .await;
        assert_eq!(f["ops"].as_array().map(Vec::len), Some(5), "{t:?}");
        assert_eq!(f["ops_page"]["returned"], 5, "{t:?}");
        assert!(f["ops_page"]["total"].as_u64().unwrap() > 5, "{t:?}");
    }
}

#[tokio::test]
async fn output_ceiling_applies_to_every_result() {
    for t in transports() {
        let s = Session::start(t, |c| c.max_output_bytes = 4096).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;

        // A listing is cut to what fits, even below the requested limit.
        let r = s
            .call("list_functions", json!({ "limit": 1000 }))
            .await
            .expect("list_functions");
        assert!(text_len(&r) <= 4096 + 256, "{t:?}: {}", text_len(&r));
        let sc = r.structured_content.unwrap();
        assert_eq!(sc["truncated"], true, "{t:?}");

        // Raw text is truncated with a notice.
        let r = s
            .call("command", json!({ "command": "pd 2000 @ entry0" }))
            .await
            .expect("command");
        let text = r.content[0].as_text().unwrap().text.clone();
        assert!(text.len() <= 4096 + 256, "{t:?}: {}", text.len());
        assert!(text.contains("[output truncated"), "{t:?}");

        // An object over the ceiling is refused with a hint, not cut.
        let r = s
            .call("function_graph", json!({ "at": "main" }))
            .await
            .expect("function_graph");
        assert_eq!(r.is_error, Some(true), "{t:?}");
        let text = r.content[0].as_text().unwrap().text.clone();
        assert!(text.contains("output limit"), "{t:?}: {text}");
    }
}

#[tokio::test]
async fn disabled_tools_are_not_offered() {
    #[cfg(feature = "api")]
    let transport = Transport::Api;
    #[cfg(not(feature = "api"))]
    let transport = Transport::Pipe;
    let s = Session::start(transport, |c| {
        c.allow_raw = false;
        c.allow_write = false;
        c.allow_debug = false;
    })
    .await;
    let names: Vec<String> = s
        .client
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for hidden in [
        "command",
        "command_json",
        "write_hex",
        "flirt_create",
        "debug_start",
    ] {
        assert!(!names.iter().any(|n| n == hidden), "{hidden} is offered");
    }
    assert!(names.iter().any(|n| n == "list_functions"));
    // Calling one anyway is refused.
    let err = s
        .call("command", json!({ "command": "echo hi" }))
        .await
        .expect_err("command must not run");
    assert_eq!(err.code.0, -32602, "{err:?}");
    assert!(err.message.contains("not found"), "{err:?}");
}

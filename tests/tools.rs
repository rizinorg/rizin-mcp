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

#[tokio::test]
async fn errors_say_what_went_wrong() {
    let pat = std::env::temp_dir().join(format!("rizin-mcp-test-{}.pat", std::process::id()));
    let pat = pat.to_string_lossy().into_owned();
    for t in transports() {
        let s = Session::start(t, |c| c.allow_write = true).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;

        // An unmapped address fails with Rizin's reason, not just "no
        // output" (which a pipe to Rizin before 0.10 still says, but with the
        // reason attached).
        let err = s
            .call("disassemble", json!({ "at": "0xdeadbeef" }))
            .await
            .expect_err("unmapped");
        assert!(matches!(err.code.0, -32001 | -32602), "{t:?}: {err:?}");
        assert!(
            err.message.contains("Failed to read") && err.message.contains("0xdeadbeef"),
            "{t:?}: {}",
            err.message
        );

        // `plf` fails silently where there is no function; the tool says so.
        let err = s
            .call("il_function", json!({ "at": "0x0" }))
            .await
            .expect_err("no function");
        assert!(
            err.message.contains("no function"),
            "{t:?}: {}",
            err.message
        );

        // A missing signature file is not "Found 0 FLIRT signatures".
        let err = s
            .call("flirt_apply", json!({ "path": "/nonexistent.sig" }))
            .await
            .expect_err("missing file");
        assert!(
            err.message.contains("file not found"),
            "{t:?}: {}",
            err.message
        );

        // Signatures made from this binary match it again.
        s.ok("flirt_create", json!({ "path": pat })).await;
        let applied = s.ok("flirt_apply", json!({ "path": pat })).await;
        assert!(
            applied["matched_functions"].as_u64().unwrap() > 0,
            "{t:?}: {applied}"
        );

        // A sigdb filter may contain `@` and other shell characters.
        let r = s
            .ok("flirt_apply_sigdb", json!({ "filter": "x86@64;px" }))
            .await;
        assert_eq!(r["matched_functions"], 0, "{t:?}: {r}");

        // A missing engine is skipped; one that fails is reported, not
        // retried with the next engine under a misleading "install" hint.
        let d = s
            .call("decompile", json!({ "at": "main" }))
            .await
            .expect("decompile");
        let meta = d.structured_content.unwrap();
        assert_eq!(meta["decompiler"], "pseudo", "{t:?}: {meta}");
        let err = s
            .call("decompile", json!({ "at": "0x0", "decompiler": "pseudo" }))
            .await
            .expect_err("no function");
        assert_eq!(err.code.0, -32001, "{t:?}: {err:?}");
        assert!(err.message.contains("function"), "{t:?}: {}", err.message);
    }
    let _ = std::fs::remove_file(&pat);
}

#[tokio::test]
async fn pseudo_decompile_is_the_same_on_both_backends() {
    let backends = transports();
    if backends.len() < 2 {
        eprintln!("skipping: needs both backends");
        return;
    }
    let mut texts: Vec<Vec<String>> = Vec::new();
    for t in &backends {
        let s = Session::start(*t, |_| {}).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;
        // `main`, `entry0`, and a few more of the larger functions.
        let funcs = s.items("list_functions", json!({ "limit": 1000 })).await;
        let mut sized: Vec<(u64, u64)> = funcs
            .iter()
            .filter_map(|f| Some((f["size"].as_u64()?, f["offset"].as_u64()?)))
            .collect();
        sized.sort_unstable_by(|a, b| b.cmp(a));
        let mut at: Vec<String> = vec!["main".into(), "entry0".into()];
        at.extend(sized.iter().take(3).map(|(_, o)| format!("0x{o:x}")));
        let mut out = Vec::new();
        for a in &at {
            let started = std::time::Instant::now();
            let r = s
                .call("decompile", json!({ "at": a, "decompiler": "pseudo" }))
                .await
                .unwrap_or_else(|e| panic!("{t:?} {a}: {e:?}"));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "{t:?} {a}: took {:?}",
                started.elapsed()
            );
            out.push(r.content[0].as_text().unwrap().text.clone());
        }
        texts.push(out);
    }
    for (i, (a, b)) in texts[0].iter().zip(&texts[1]).enumerate() {
        assert!(!a.trim().is_empty());
        assert_eq!(a, b, "function #{i} differs between backends");
    }
}

#[tokio::test]
async fn listing_one_flag_space_leaves_the_others_visible() {
    for t in transports() {
        let s = Session::start(t, |_| {}).await;
        s.ok("open_file", json!({ "path": target(), "analysis": "none" }))
            .await;
        let all = s.ok("list_flags", json!({})).await["total"]
            .as_u64()
            .unwrap();
        let strings = s.ok("list_flags", json!({ "space": "strings" })).await["total"]
            .as_u64()
            .unwrap();
        assert!(strings > 0 && strings < all, "{t:?}: {strings} of {all}");
        // Before the fix, every later listing was stuck in `strings`.
        let again = s.ok("list_flags", json!({})).await["total"]
            .as_u64()
            .unwrap();
        assert_eq!(again, all, "{t:?}");

        // An unknown space is empty and is not created.
        let none = s.ok("list_flags", json!({ "space": "nosuchspace" })).await;
        assert_eq!(none["total"], 0, "{t:?}");
        let spaces = s.items("flag_spaces", json!({})).await;
        assert!(
            !spaces.iter().any(|sp| sp["name"] == "nosuchspace"),
            "{t:?}: {spaces:?}"
        );
    }
}

#[tokio::test]
async fn annotations_change_the_analysis() {
    for t in transports() {
        let s = Session::start(t, |c| c.allow_write = true).await;
        // Annotating needs no write-mode file.
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;

        let r = s
            .ok(
                "rename_function",
                json!({ "at": "main", "name": "parse_args" }),
            )
            .await;
        assert_eq!(r["previous_name"], "main", "{t:?}: {r}");
        assert_eq!(r["name"], "parse_args", "{t:?}: {r}");
        let info = s
            .items("function_info", json!({ "at": "parse_args" }))
            .await;
        assert_eq!(info[0]["name"], "parse_args", "{t:?}");

        let r = s
            .ok(
                "rename_variable",
                json!({ "at": "parse_args", "old_name": "argc", "new_name": "nargs" }),
            )
            .await;
        assert_eq!(r["new_name"], "nargs", "{t:?}");
        let vars = s
            .ok("function_variables", json!({ "at": "parse_args" }))
            .await;
        assert!(vars.to_string().contains("\"nargs\""), "{t:?}: {vars}");
        let err = s
            .call(
                "rename_variable",
                json!({ "at": "parse_args", "old_name": "nosuchvar", "new_name": "x" }),
            )
            .await
            .expect_err("unknown variable");
        // `afvn` reports success here, only logging the error.
        assert!(err.message.contains("nosuchvar"), "{t:?}: {}", err.message);

        // Comments keep shell metacharacters verbatim.
        let text = "checks argv; see @0x10 | \"quoted\" $(x)";
        let r = s
            .ok(
                "set_comment",
                json!({ "address": "parse_args", "text": text }),
            )
            .await;
        assert_eq!(r["comment"], text, "{t:?}");
        let r = s
            .ok(
                "set_comment",
                json!({ "address": "parse_args", "text": "more", "append": true }),
            )
            .await;
        assert_eq!(r["comment"], format!("{text} more"), "{t:?}");
        let r = s
            .ok(
                "set_comment",
                json!({ "address": "parse_args", "text": "fresh" }),
            )
            .await;
        assert_eq!(r["comment"], "fresh", "{t:?}");
        s.ok("remove_comment", json!({ "address": "parse_args" }))
            .await;

        // A flag becomes a usable location, and is gone once removed.
        let r = s
            .ok(
                "set_flag",
                json!({ "name": "mcp.marker", "address": "parse_args", "size": 16 }),
            )
            .await;
        assert_eq!(
            r["at"],
            s.ok("seek", json!({ "address": "parse_args" })).await["offset"]
        );
        s.ok("read_bytes", json!({ "at": "mcp.marker", "count": 4 }))
            .await;
        s.ok("remove_flag", json!({ "name": "mcp.marker" })).await;
        assert!(
            s.call("remove_flag", json!({ "name": "mcp.marker" }))
                .await
                .is_err(),
            "{t:?}: removing an unknown flag must fail"
        );

        let sig = s
            .ok(
                "set_function_signature",
                json!({ "at": "parse_args", "signature": "int parse_args(int nargs, char **args)" }),
            )
            .await;
        assert_eq!(sig["ret"], "int", "{t:?}: {sig}");
        assert_eq!(sig["args"][1]["name"], "args", "{t:?}: {sig}");
    }
}

#[tokio::test]
async fn work_can_be_exported_and_saved() {
    let tmp = std::env::temp_dir();
    let id = std::process::id();
    for t in transports() {
        let script = tmp.join(format!("rizin-mcp-{id}-{t:?}.rz"));
        let project = tmp.join(format!("rizin-mcp-{id}-{t:?}.rzdb"));
        let s = Session::start(t, |c| c.allow_write = true).await;
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;
        s.ok(
            "rename_function",
            json!({ "at": "main", "name": "entry_logic" }),
        )
        .await;
        s.ok(
            "set_comment",
            json!({ "address": "entry_logic", "text": "parses; argv @ start" }),
        )
        .await;
        s.ok(
            "set_flag",
            json!({ "name": "mcp.mark", "address": "entry0" }),
        )
        .await;
        let saved = s
            .ok("save_project", json!({ "path": project.to_string_lossy() }))
            .await;
        assert!(saved["bytes"].as_u64().unwrap() > 0, "{t:?}");

        // The journal survives closing the file.
        s.ok("close_file", json!({})).await;
        let export = s.ok("export_annotations", json!({})).await;
        assert_eq!(export["commands"], 4, "{t:?}: {export}"); // afn, CC-, CC, f+
        std::fs::write(&script, export["script"].as_str().unwrap()).unwrap();

        // Replaying the script on a fresh analysis restores the work.
        s.ok(
            "open_file",
            json!({ "path": target(), "analysis": "basic" }),
        )
        .await;
        assert_eq!(s.ok("export_annotations", json!({})).await["commands"], 0);
        let r = s
            .call(
                "command",
                json!({ "command": format!(". {}", script.to_string_lossy()) }),
            )
            .await
            .expect("replay");
        assert_ne!(r.is_error, Some(true), "{t:?}: {r:?}");
        let info = s
            .items("function_info", json!({ "at": "entry_logic" }))
            .await;
        assert_eq!(info[0]["name"], "entry_logic", "{t:?}");
        let c = s
            .call("command", json!({ "command": "CC. @ entry_logic" }))
            .await
            .expect("CC.");
        assert_eq!(
            c.content[0].as_text().unwrap().text.trim(),
            "parses; argv @ start",
            "{t:?}"
        );
        s.ok("seek", json!({ "address": "mcp.mark" })).await;

        // The project reopens in rizin with the renamed function.
        if pipe_available() {
            let out = std::process::Command::new(rizin_binary())
                .args(["-q", "-p"])
                .arg(&project)
                .args(["-c", "afl~entry_logic"])
                .output()
                .expect("rizin -p");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("entry_logic"), "{t:?}: {stdout:?}");
        }
        let _ = std::fs::remove_file(&script);
        let _ = std::fs::remove_file(&project);
    }
}

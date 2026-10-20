// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! The contract between the tools and Rizin: the commands they run exist, and
//! the JSON fields they read are there with the expected types.
//!
//! Rizin publishes no JSON schemas yet (rizinorg/rizin#6543, B2), so these
//! tests pin what the server relies on. Run nightly against Rizin's `dev`
//! branch, they turn a renamed command or field into a CI failure instead of
//! an empty or wrong result in a user's session.

use rizin_mcp::config::{ServerConfig, Transport};
use rizin_mcp::session::{AnalysisLevel, SessionManager};
use rizin_mcp::status::CmdStatus;
use serde_json::Value;

/// Every Rizin command the tools, resources and backends run, by name.
const COMMANDS: &[&str] = &[
    // session, status and settings
    "aa", "aaa", "aaaa", "e", "s", // binary information
    "ij", "iej", "iSj", "iSSj", "irj", "iij", "iEj", "isj", "ilj", "icj", "izj", "izzj", "iHj",
    "ihj", "iCj", "iVj", "iRj", // flags
    "flj", "fslj", "fss+", "fss-", "f+", "f-", "fd", // functions and references
    "aflj", "afij", "afvlj", "af", "afn", "afvn", "afs", "afsj", "afsbj", "axtj", "axfj", "agf",
    // printing
    "pdj", "pdfj", "pdr", "pxj", "p8", "pa", "aoj", "ph", "phlj", "plf", "Lcj",
    // comments, projects, writing
    "CC", "CC-", "CC.", "Ps", "wx", // searching and diffing
    "/xj", "/v1j", "/v2j", "/v4j", "/v8j", "/Rj", "/mj", "/cmj", "cxj", "cfj",
    // FLIRT and RzIL
    "Fl", "Fa", "Fs", "Fd", "Fc", "aezi", "aezsej", // debugger
    "ood", "doc", "dc", "ds", "drj", "db", "db-", "dblj", "dbtj", "dmj", "dij",
];

/// Commands that appeared in Rizin 0.10 and are used only when present.
const SINCE_0_10: &[&str] = &["_s", "Flj"];

/// Commands of optional plugins, which may be missing.
const PLUGIN_COMMANDS: &[&str] = &["pdg", "pdd", "sil"];

/// Held while an in-process session is open: Rizin before 0.10 keeps its
/// console in globals, so two in-process cores must never overlap.
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

async fn open(transport: Transport, target: &str, level: AnalysisLevel) -> Option<Opened> {
    let guard = match transport {
        #[cfg(feature = "api")]
        Transport::Api => Some(API_LOCK.lock().await),
        _ => None,
    };
    let mgr = SessionManager::new(ServerConfig {
        transport,
        rizin_binary: std::env::var("RIZIN_MCP_TEST_BINARY")
            .unwrap_or_else(|_| "rizin".to_string()),
        ..Default::default()
    });
    match mgr.open(target, level, false).await {
        Ok(_) => Some(Opened { mgr, _guard: guard }),
        Err(e) => {
            eprintln!("skipping {transport:?}: {e}");
            None
        }
    }
}

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

#[tokio::test]
async fn commands_used_by_the_tools_exist() {
    for t in transports() {
        let Some(mgr) = open(t, "-", AnalysisLevel::None).await else {
            continue;
        };
        // Rizin 0.10 reports command status, and has `_s` for it.
        let modern = mgr
            .exec("_s?")
            .await
            .is_ok_and(|o| o.status == CmdStatus::Ok);
        let expected = COMMANDS.iter().chain(if modern { SINCE_0_10 } else { &[] });
        let mut missing = Vec::new();
        for cmd in expected {
            // The help of a command exists exactly when the command does.
            let out = mgr.exec(&format!("{cmd}?")).await.expect("exec");
            let exists = match out.status {
                CmdStatus::Unknown => !out.output.trim().is_empty(),
                status => !status.is_failure(),
            };
            if !exists {
                missing.push(*cmd);
            }
        }
        assert!(missing.is_empty(), "{t:?}: Rizin lacks {missing:?}");
    }
}

/// The command names in the string literals passed to the command helpers
/// in `src/server.rs` (placeholders such as `{suffix}` dropped).
fn commands_in_server_source() -> Vec<String> {
    let src = include_str!("../src/server.rs");
    let src = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    let mut found = Vec::new();
    for call in [".cmd(", ".cmdj(", ".exec(", "cmd_strict(", "cmdj_optional("] {
        for (pos, _) in src.match_indices(call) {
            let rest = src[pos + call.len()..].trim_start();
            let rest = rest.strip_prefix("&format!(").unwrap_or(rest).trim_start();
            let Some(lit) = rest.strip_prefix('"') else {
                continue;
            };
            let lit = &lit[..lit.find('"').unwrap_or(0)];
            for stmt in lit.split(';') {
                let mut name = String::new();
                let mut depth = 0;
                for c in stmt.trim().chars() {
                    match c {
                        '{' => depth += 1,
                        '}' => depth -= 1,
                        ' ' if depth == 0 => break,
                        c if depth == 0 => name.push(c),
                        _ => {}
                    }
                }
                if !name.is_empty() {
                    found.push(name);
                }
            }
        }
    }
    found
}

#[test]
fn command_list_covers_the_server() {
    let found = commands_in_server_source();
    assert!(found.len() > 50, "the scan found only {found:?}");
    for name in &found {
        // `/v{size}j` becomes `/vj`.
        let known = COMMANDS.contains(&name.as_str())
            || SINCE_0_10.contains(&name.as_str())
            || PLUGIN_COMMANDS.contains(&name.as_str())
            || (name == "/vj");
        assert!(known, "`{name}` is run by a tool but not in COMMANDS");
    }
}

/// Assert that `v` has `path` (dot-separated; `0` indexes arrays) with a
/// value of kind `kind`.
fn require(v: &Value, what: &str, path: &str, kind: &str) {
    let mut cur = v;
    for key in path.split('.') {
        cur = match key.parse::<usize>() {
            Ok(i) => &cur[i],
            Err(_) => &cur[key],
        };
    }
    let ok = match kind {
        "u64" => cur.is_u64(),
        "str" => cur.is_string(),
        "bool" => cur.is_boolean(),
        "array" => cur.is_array(),
        "object" => cur.is_object(),
        _ => unreachable!(),
    };
    assert!(ok, "{what}: `{path}` should be {kind}, got {cur}");
}

#[tokio::test]
async fn json_fields_the_tools_read() {
    for t in transports() {
        let Some(mgr) = open(t, &target(), AnalysisLevel::Basic).await else {
            continue;
        };
        let j = |cmd: &'static str| {
            let mgr = &mgr;
            async move {
                mgr.cmdj(cmd)
                    .await
                    .unwrap_or_else(|e| panic!("{t:?} {cmd}: {e}"))
            }
        };

        let info = j("ij").await;
        require(&info, "ij", "core.size", "u64");
        require(&info, "ij", "bin.baddr", "u64");

        let funcs = j("aflj").await;
        for f in ["offset", "name", "size"] {
            require(
                &funcs,
                "aflj",
                &format!("0.{f}"),
                if f == "name" { "str" } else { "u64" },
            );
        }

        // function_summary and the annotation tools
        let afi = j("afij @ main").await;
        for f in ["offset", "size", "nbbs", "cc", "nargs", "nlocals"] {
            require(&afi, "afij", &format!("0.{f}"), "u64");
        }
        require(&afi, "afij", "0.name", "str");
        require(&afi, "afij", "0.signature", "str");
        require(&afi, "afij", "0.noreturn", "bool");
        for refs in ["callrefs", "datarefs"] {
            require(&afi, "afij", &format!("0.{refs}.0.to"), "u64");
            require(&afi, "afij", &format!("0.{refs}.0.type"), "str");
        }
        let callers = j("axtj @ main").await;
        require(&callers, "axtj", "0.from", "u64");
        require(&callers, "axtj", "0.type", "str");
        let vars = j("afvlj @ main").await;
        assert!(vars.is_object(), "{t:?} afvlj: {vars}");
        let sig = j("afsj @ main").await;
        require(&sig, "afsj", "ret", "str");
        require(&sig, "afsj", "args.0.name", "str");
        let strings = j("izj").await;
        for (f, k) in [
            ("vaddr", "u64"),
            ("size", "u64"),
            ("string", "str"),
            ("type", "str"),
        ] {
            require(&strings, "izj", &format!("0.{f}"), k);
        }

        // disassemble_function pages `ops`
        let pdf = j("pdfj @ main").await;
        require(&pdf, "pdfj", "ops", "array");

        // search_rop and the exact filter
        let gadgets = j("/Rj \"ret\"").await;
        require(&gadgets, "/Rj", "0.opcodes.0.offset", "u64");
        require(&gadgets, "/Rj", "0.opcodes.0.opcode", "str");

        // list_flags and the FLIRT counts
        let spaces = j("fslj").await;
        require(&spaces, "fslj", "0.name", "str");
        require(&spaces, "fslj", "0.count", "u64");

        // decompilers
        let plugins = j("Lcj").await;
        assert!(plugins.is_array(), "{t:?} Lcj: {plugins}");
        if let Some(p) = plugins.as_array().and_then(|a| a.first()) {
            require(p, "Lcj", "name", "str");
        }

        // flirt_list (a text table before Rizin 0.10)
        let sigdb = mgr.cmdj("Flj").await.unwrap_or(Value::Array(Vec::new()));
        assert!(sigdb.is_array(), "{t:?} Flj: {sigdb}");
        if let Some(s) = sigdb.as_array().and_then(|a| a.first()) {
            for f in ["bin", "arch", "name", "details"] {
                require(s, "Flj", f, "str");
            }
            require(s, "Flj", "modules", "u64");
        }

        // function_graph
        let graph = j("agf j @ main").await;
        require(&graph, "agf j", "nodes", "array");
    }
}

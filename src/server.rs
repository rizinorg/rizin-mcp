// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! The MCP server: every Rizin-backed tool, resource, and prompt.
//!
//! [`RizinServer`] is cheap to clone (it holds an `Arc<SessionManager>`), as
//! required by the rmcp handler model. Tools are grouped roughly as: session
//! lifecycle, binary information, analysis/functions, disassembly/printing,
//! searching, and (optionally) writing.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use rmcp::{prompt, prompt_handler, prompt_router, tool, tool_handler, tool_router};
use serde_json::{Value, json};

use crate::config::ServerConfig;
use crate::error::{IntoMcp, RizinError};
use crate::params::*;
use crate::session::{AnalysisLevel, SessionManager};
use crate::status::CmdStatus;
use crate::util::{
    at_suffix, clamp_count, parse_hex_bytes, to_hex, validate_algo, validate_location,
    validate_number, validate_path,
};

/// Resources exposed by the server: `(uri, display name, rizin JSON command)`.
const RESOURCES: &[(&str, &str, &str)] = &[
    ("rizin://info", "binary information (ij)", "ij"),
    ("rizin://functions", "analyzed functions (aflj)", "aflj"),
    ("rizin://strings", "strings (izzj)", "izzj"),
    ("rizin://sections", "sections (iSj)", "iSj"),
    ("rizin://imports", "imports (iij)", "iij"),
    ("rizin://exports", "exports (iEj)", "iEj"),
    ("rizin://symbols", "symbols (isj)", "isj"),
    ("rizin://entrypoints", "entry points (iej)", "iej"),
    ("rizin://headers", "structured header fields (iHj)", "iHj"),
];

/// Human-readable usage instructions advertised to clients.
const INSTRUCTIONS: &str = "\
Drive the Rizin reverse-engineering framework. Start by calling `open_file` with \
a path (analysis defaults to `basic`/`aa`; use `analyze` for deeper passes). Then \
explore with `list_functions`, `disassemble_function`, `decompile`, `binary_info`, \
`headers`, `list_strings`, `imports`/`exports`/`symbols`, `xrefs_to`/`xrefs_from`, \
and the search tools (`search_string`, `search_bytes`, `search_value`, `search_rop`, \
`search_magic`, `search_crypto`). Inspect function signatures with \
`function_signature`/`function_signature_bytes`, hash regions with `hash`, lift to \
RzIL with `il_function`/`emulate_il`, and diff bytes with `compare_bytes`/`compare_file`. \
`decompile` uses rz-ghidra or jsdec when installed (see `decompilers`), else built-in \
pseudo-disassembly. Name library functions with the `flirt_*` tools (FLIRT signatures) \
and, when the rz-silhouette plugin is configured, with `silhouette`. \
Dynamic analysis is available via the `debug_*` tools when the server is started with \
--allow-debug. Addresses may be hex (e.g. 0x401000) or flag/symbol names (e.g. main, \
sym.imp.printf). For anything not covered by a dedicated tool, use `command` (text) or \
`command_json` (parsed JSON) to run a raw Rizin command.";

/// A Model Context Protocol server backed by a Rizin session.
#[derive(Clone)]
pub struct RizinServer {
    manager: Arc<SessionManager>,
}

impl RizinServer {
    /// Create a server with the given configuration and no open file.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            manager: Arc::new(SessionManager::new(config)),
        }
    }

    /// Access the shared session manager (used by the binary to open a startup
    /// file before serving).
    pub fn manager(&self) -> Arc<SessionManager> {
        self.manager.clone()
    }

    /// Guard used by the write tools.
    async fn ensure_write(&self) -> Result<(), ErrorData> {
        if !self.manager.config().allow_write {
            return Err(RizinError::NotPermitted(
                "write tools are disabled; start the server with --allow-write".into(),
            )
            .to_error_data());
        }
        let state = self.manager.state().await;
        if !state.open {
            return Err(RizinError::NoFileOpen.to_error_data());
        }
        if !state.write {
            return Err(RizinError::NotPermitted(
                "the current file was opened read-only; reopen with write=true".into(),
            )
            .to_error_data());
        }
        Ok(())
    }

    /// Guard used by the raw command tools.
    fn ensure_raw(&self) -> Result<(), ErrorData> {
        if !self.manager.config().allow_raw {
            return Err(RizinError::NotPermitted(
                "raw command tools are disabled (server started with --no-raw)".into(),
            )
            .to_error_data());
        }
        Ok(())
    }

    /// Guard used by the debugger tools.
    async fn ensure_debug(&self) -> Result<(), ErrorData> {
        if !self.manager.config().allow_debug {
            return Err(RizinError::NotPermitted(
                "debugger tools are disabled; start the server with --allow-debug \
                 (note: debugging executes the target binary)"
                    .into(),
            )
            .to_error_data());
        }
        if !self.manager.state().await.open {
            return Err(RizinError::NoFileOpen.to_error_data());
        }
        Ok(())
    }

    /// Run a JSON command, returning `default` when the command produced no
    /// output or failed while running. Used for optional metadata (absent on
    /// some formats; `iCj` fails on an unsigned ELF) and for scans whose
    /// database may be unavailable, so "no data" is not an error. A command
    /// that does not exist or was called wrongly is still an error.
    async fn cmdj_optional(&self, cmd: &str, default: Value) -> Result<Value, ErrorData> {
        match self.manager.cmdj(cmd).await {
            Ok(value) => Ok(value),
            Err(RizinError::EmptyJson { .. })
            | Err(RizinError::CommandFailed {
                status: CmdStatus::Error | CmdStatus::Failed,
                ..
            }) => Ok(default),
            Err(e) => Err(e.to_error_data()),
        }
    }

    /// Map a missing plugin command to a hint naming the plugin.
    fn plugin_hint(e: RizinError, hint: &str) -> ErrorData {
        match e {
            RizinError::CommandFailed {
                status: CmdStatus::NonExistingCmd | CmdStatus::Failed,
                ..
            } => RizinError::NotPermitted(hint.into()).to_error_data(),
            e => e.to_error_data(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl RizinServer {
    // --- Session lifecycle ------------------------------------------------

    /// Open a binary/file (or Rizin URI) and run initial analysis. Replaces any
    /// currently open file.
    #[tool(
        description = "Open a binary file (or Rizin URI like malloc://512) and run \
        initial analysis. Returns binary info. Replaces any currently open file."
    )]
    async fn open_file(
        &self,
        Parameters(p): Parameters<OpenFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let analysis = p.analysis.unwrap_or_default();
        let write = p.write.unwrap_or(false);
        let info = self.manager.open(&p.path, analysis, write).await.mcp()?;
        Ok(json_result(
            serde_json::to_value(info).unwrap_or(Value::Null),
        ))
    }

    /// Close the current session.
    #[tool(description = "Close the currently open file and tear down the Rizin session.")]
    async fn close_file(&self) -> Result<CallToolResult, ErrorData> {
        let closed = self.manager.close().await;
        Ok(text_result(if closed {
            "Closed the open file."
        } else {
            "No file was open."
        }))
    }

    /// Report current session state and binary info.
    #[tool(description = "Report whether a file is open, its path/mode, and binary info (ij).")]
    async fn session_info(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.manager.state().await;
        let info = self.manager.cmdj("ij").await.unwrap_or(Value::Null);
        Ok(json_result(json!({ "session": state, "info": info })))
    }

    /// Run analysis at a chosen depth.
    #[tool(
        description = "Run Rizin analysis at the given level (none/basic/full/experimental; \
        default full = aaa). Returns the resulting function count."
    )]
    async fn analyze(
        &self,
        Parameters(p): Parameters<AnalyzeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let level = p.level.unwrap_or(AnalysisLevel::Full);
        if let Some(cmd) = level.command() {
            self.manager.cmd(cmd).await.mcp()?;
        }
        let functions = self
            .manager
            .cmdj("aflj")
            .await
            .ok()
            .and_then(|v| v.as_array().map(|a| a.len()))
            .unwrap_or(0);
        Ok(json_result(
            json!({ "level": level, "functions": functions }),
        ))
    }

    /// Seek to an address/flag and report the new offset.
    #[tool(description = "Seek to an address or flag/symbol, returning the new current offset.")]
    async fn seek(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = validate_location(&p.address).mcp()?;
        self.manager.cmd(&format!("s {loc}")).await.mcp()?;
        let offset = self.manager.cmd("s").await.mcp()?;
        Ok(json_result(json!({ "offset": offset.trim() })))
    }

    /// Run a raw Rizin command and return its text output.
    #[tool(
        description = "Run a raw Rizin command line and return its text output. Chain \
        multiple commands with ';'. When Rizin reports a failure (e.g. an unknown \
        command), the result is an error carrying the status, Rizin's messages, and \
        whatever was printed before the failure. This exposes the full Rizin surface \
        (including the debugger and shell escapes), so use with care."
    )]
    async fn command(
        &self,
        Parameters(p): Parameters<CommandParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_raw()?;
        let out = self.manager.exec(&p.command).await.mcp()?;
        if !out.status.is_failure() {
            return Ok(text_result(out.output));
        }
        // A chained line may have printed useful output before failing.
        let mut content = Vec::new();
        if !out.output.is_empty() {
            content.push(Content::text(out.output.clone()));
        }
        let mut summary = format!("rizin command failed ({})", out.status);
        if !out.messages.is_empty() {
            summary.push('\n');
            summary.push_str(&out.detail());
        }
        content.push(Content::text(summary));
        let mut result = CallToolResult::error(content);
        result.structured_content = Some(json!({
            "status": out.status,
            "messages": out.messages,
        }));
        Ok(result)
    }

    /// Run a raw Rizin command expecting JSON and return parsed output.
    #[tool(
        description = "Run a raw Rizin command that produces JSON (usually with a 'j' \
        suffix, e.g. 'pdfj', 'aflj') and return the parsed JSON."
    )]
    async fn command_json(
        &self,
        Parameters(p): Parameters<CommandParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_raw()?;
        let value = self.manager.cmdj(&p.command).await.mcp()?;
        Ok(json_result(value))
    }

    // --- Binary information ----------------------------------------------

    /// Binary metadata (`ij`).
    #[tool(
        description = "Binary information: format, architecture, bits, endianness, entry, etc. (ij)."
    )]
    async fn binary_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("ij").await.mcp()?))
    }

    /// Entry points (`iej`).
    #[tool(description = "List program entry points (iej).")]
    async fn entrypoints(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iej").await.mcp()?))
    }

    /// Sections (`iSj`).
    #[tool(description = "List binary sections with addresses, sizes and permissions (iSj).")]
    async fn sections(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iSj").await.mcp()?))
    }

    /// Segments (`iSSj`).
    #[tool(description = "List binary segments (iSSj).")]
    async fn segments(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iSSj").await.mcp()?))
    }

    /// Relocations (`irj`).
    #[tool(description = "List relocations (irj).")]
    async fn relocations(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("irj").await.mcp()?))
    }

    /// Imports (`iij`).
    #[tool(description = "List imported symbols (iij).")]
    async fn imports(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iij").await.mcp()?))
    }

    /// Exports (`iEj`).
    #[tool(description = "List exported symbols (iEj).")]
    async fn exports(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iEj").await.mcp()?))
    }

    /// Symbols (`isj`).
    #[tool(description = "List all symbols (isj).")]
    async fn symbols(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("isj").await.mcp()?))
    }

    /// Linked libraries (`ilj`).
    #[tool(description = "List linked/required libraries (ilj).")]
    async fn libraries(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("ilj").await.mcp()?))
    }

    /// Classes (`icj`).
    #[tool(description = "List classes/methods recovered from the binary (icj).")]
    async fn classes(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("icj").await.mcp()?))
    }

    /// Strings (`izzj`/`izj`).
    #[tool(
        description = "List strings. By default scans the whole file (izz); set all=false \
        to scan only data sections (iz)."
    )]
    async fn list_strings(
        &self,
        Parameters(p): Parameters<StringsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = if p.all.unwrap_or(true) { "izzj" } else { "izj" };
        Ok(json_result(self.manager.cmdj(cmd).await.mcp()?))
    }

    /// Flags (`fj`), optionally restricted to one flag space.
    #[tool(
        description = "List flags (named addresses). Optionally restrict to a single flag \
        space (e.g. symbols, strings, imports)."
    )]
    async fn list_flags(
        &self,
        Parameters(p): Parameters<FlagsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = match &p.space {
            Some(space) => format!("fs {};flj", validate_location(space).mcp()?),
            None => "flj".to_string(),
        };
        Ok(json_result(self.manager.cmdj(&cmd).await.mcp()?))
    }

    /// Flag spaces (`fslj`).
    #[tool(description = "List flag spaces and their flag counts (fslj).")]
    async fn flag_spaces(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("fslj").await.mcp()?))
    }

    // --- Analysis / functions --------------------------------------------

    /// Function list (`aflj`).
    #[tool(description = "List analyzed functions with addresses, sizes and names (aflj).")]
    async fn list_functions(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("aflj").await.mcp()?))
    }

    /// Function info (`afij`).
    #[tool(
        description = "Detailed info for the function at a location: bounds, stack frame, \
        calling convention, callers/callees, etc. (afij)."
    )]
    async fn function_info(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("afij{suffix}")).await.mcp()?,
        ))
    }

    /// Function variables (`afvlj`).
    #[tool(
        description = "List local variables and arguments of the function at a location (afvlj)."
    )]
    async fn function_variables(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("afvlj{suffix}")).await.mcp()?,
        ))
    }

    /// Analyze a single function (`af`) and return its info.
    #[tool(
        description = "Analyze (or re-analyze) the function at a location, then return its \
        info (af; afij)."
    )]
    async fn analyze_function(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        self.manager.cmd(&format!("af{suffix}")).await.mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("afij{suffix}")).await.mcp()?,
        ))
    }

    /// Cross-references to an address (`axtj`).
    #[tool(
        description = "List cross-references TO an address or flag/symbol (who references it) (axtj)."
    )]
    async fn xrefs_to(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = validate_location(&p.address).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("axtj @ {loc}")).await.mcp()?,
        ))
    }

    /// Cross-references from an address (`axfj`).
    #[tool(
        description = "List cross-references FROM an address or flag/symbol (what it references) (axfj)."
    )]
    async fn xrefs_from(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = validate_location(&p.address).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("axfj @ {loc}")).await.mcp()?,
        ))
    }

    /// Function control-flow graph (`agf j`).
    #[tool(
        description = "Control-flow graph of the function at a location, as JSON nodes/edges (agf j)."
    )]
    async fn function_graph(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("agf j{suffix}")).await.mcp()?,
        ))
    }

    // --- Disassembly / printing ------------------------------------------

    /// Disassemble N instructions (`pdj`).
    #[tool(
        description = "Disassemble a number of instructions at a location (default 32) as \
        structured JSON (pdj)."
    )]
    async fn disassemble(
        &self,
        Parameters(p): Parameters<DisasmParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let count = clamp_count(p.count, 32, self.manager.config().max_count);
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager
                .cmdj(&format!("pdj {count}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    /// Disassemble a whole function (`pdfj`).
    #[tool(
        description = "Disassemble the entire function at a location as structured JSON (pdfj)."
    )]
    async fn disassemble_function(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("pdfj{suffix}")).await.mcp()?,
        ))
    }

    /// Decompile (`pdg`/`pdd`/pseudo).
    #[tool(
        description = "Decompile the function at a location to pseudo-C. `decompiler` selects \
        the engine: `auto` (default) tries rz-ghidra (pdg), then jsdec (pdd), then built-in \
        pseudo-disassembly; or force `ghidra`, `jsdec`, or `pseudo`. rz-ghidra and jsdec are \
        optional plugins; see `decompilers` for what is installed. The engine actually used is \
        reported in structuredContent."
    )]
    async fn decompile(
        &self,
        Parameters(p): Parameters<DecompileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        let which = p.decompiler.as_deref().unwrap_or("auto").to_lowercase();

        // (engine name, command) candidates for each selection.
        let ghidra = ("ghidra", format!("pdg{suffix}"));
        let jsdec = ("jsdec", format!("pdd{suffix}"));
        // Pseudo-disassembly of the whole function, via a temporary eval so the
        // global `asm.pseudo` setting is left untouched.
        let pseudo = (
            "pseudo",
            format!("pdf @e:asm.pseudo=true{}", at_suffix(&p.at).mcp()?),
        );

        let candidates: Vec<(&str, String)> = match which.as_str() {
            "auto" => vec![ghidra, jsdec, pseudo],
            "ghidra" => vec![ghidra],
            "jsdec" => vec![jsdec],
            "pseudo" => vec![pseudo],
            other => {
                return Err(RizinError::InvalidArgument {
                    arg: other.to_string(),
                    reason: "decompiler must be auto, ghidra, jsdec, or pseudo".into(),
                }
                .to_error_data());
            }
        };

        for (engine, cmd) in &candidates {
            match self.manager.cmd(cmd).await {
                Ok(out) if !out.trim().is_empty() => {
                    return Ok(text_result_meta(out, json!({ "decompiler": engine })));
                }
                Ok(_) => {} // empty: plugin missing or nothing to show, try next
                Err(e @ (RizinError::NoFileOpen | RizinError::SessionClosed)) => {
                    return Err(e.to_error_data());
                }
                Err(_) => {}
            }
        }

        let hint = if which == "auto" || which == "ghidra" || which == "jsdec" {
            "no decompiler output. Install the rz-ghidra (pdg) or jsdec (pdd) plugin, or use \
             decompiler=\"pseudo\"."
        } else {
            "no decompiler output for the function at this location."
        };
        Err(RizinError::NotPermitted(hint.into()).to_error_data())
    }

    /// Report which decompiler engines are available (`Lcj`).
    #[tool(
        description = "Report which decompiler engines are installed: `ghidra` (rz-ghidra), \
        `jsdec`, and `pseudo` (built-in, always true). Detected from the loaded core plugins."
    )]
    async fn decompilers(&self) -> Result<CallToolResult, ErrorData> {
        let plugins = self.cmdj_optional("Lcj", json!([])).await?;
        let has = |needle: &str| {
            plugins.as_array().is_some_and(|arr| {
                arr.iter().any(|p| {
                    p.get("name")
                        .and_then(|n| n.as_str())
                        .is_some_and(|n| n.to_lowercase().contains(needle))
                })
            })
        };
        Ok(json_result(json!({
            "ghidra": has("ghidra"),
            "jsdec": has("jsdec"),
            "pseudo": true,
        })))
    }

    /// Hexdump (`pxj`).
    #[tool(
        description = "Hexdump bytes at a location (default 64 bytes) as structured JSON (pxj)."
    )]
    async fn hexdump(
        &self,
        Parameters(p): Parameters<HexdumpParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let count = clamp_count(p.count, 64, self.manager.config().max_bytes);
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager
                .cmdj(&format!("pxj {count}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    /// Read raw bytes (`p8`).
    #[tool(
        description = "Read raw bytes at a location (default 64) and return them encoded as \
        hex (default) or base64."
    )]
    async fn read_bytes(
        &self,
        Parameters(p): Parameters<ReadBytesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let count = clamp_count(p.count, 64, self.manager.config().max_bytes);
        let suffix = at_suffix(&p.at).mcp()?;
        let hex = self
            .manager
            .cmd(&format!("p8 {count}{suffix}"))
            .await
            .mcp()?;
        let bytes = parse_hex_bytes(hex.trim()).mcp()?;
        let encoding = p.encoding.as_deref().unwrap_or("hex").to_lowercase();
        let data = match encoding.as_str() {
            "hex" => to_hex(&bytes),
            "base64" => BASE64.encode(&bytes),
            other => {
                return Err(RizinError::InvalidArgument {
                    arg: other.to_string(),
                    reason: "encoding must be 'hex' or 'base64'".into(),
                }
                .to_error_data());
            }
        };
        Ok(json_result(json!({
            "length": bytes.len(),
            "encoding": encoding,
            "data": data,
        })))
    }

    /// Per-instruction analysis (`aoj`).
    #[tool(
        description = "Analyze instructions at a location (default 1): opcode type, ESIL, \
        operands, jump/fail targets, etc. (aoj)."
    )]
    async fn instruction_analysis(
        &self,
        Parameters(p): Parameters<InstructionAnalysisParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let count = clamp_count(p.count, 1, self.manager.config().max_count);
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager
                .cmdj(&format!("aoj {count}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    // --- Searching --------------------------------------------------------

    /// Search for a string (`/xj` of its bytes).
    #[tool(
        description = "Search the whole address space for a string (matched as raw bytes). \
        Returns match addresses (/xj)."
    )]
    async fn search_string(
        &self,
        Parameters(p): Parameters<SearchStringParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.query.is_empty() {
            return Err(RizinError::InvalidArgument {
                arg: p.query.clone(),
                reason: "query must not be empty".into(),
            }
            .to_error_data());
        }
        let hex = to_hex(p.query.as_bytes());
        Ok(json_result(
            self.manager.cmdj(&format!("/xj {hex}")).await.mcp()?,
        ))
    }

    /// Search for a byte pattern (`/xj`).
    #[tool(
        description = "Search the whole address space for a hex byte pattern (e.g. '90 90' \
        or 'deadbeef'). Returns match addresses (/xj)."
    )]
    async fn search_bytes(
        &self,
        Parameters(p): Parameters<SearchBytesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let bytes = parse_hex_bytes(&p.hex).mcp()?;
        let hex = to_hex(&bytes);
        Ok(json_result(
            self.manager.cmdj(&format!("/xj {hex}")).await.mcp()?,
        ))
    }

    // --- Writing (guarded) ------------------------------------------------

    /// Write hex bytes (`wx`).
    #[tool(
        description = "Write raw hex bytes at an address (requires --allow-write and a file \
        opened with write=true)."
    )]
    async fn write_hex(
        &self,
        Parameters(p): Parameters<WriteHexParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_write().await?;
        let loc = validate_location(&p.address).mcp()?;
        let bytes = parse_hex_bytes(&p.hex).mcp()?;
        let hex = to_hex(&bytes);
        self.manager.cmd(&format!("wx {hex} @ {loc}")).await.mcp()?;
        Ok(json_result(json!({ "wrote": bytes.len(), "at": loc })))
    }

    /// Write a string (`wx` of its bytes).
    #[tool(
        description = "Write a UTF-8 string (as raw bytes) at an address (requires \
        --allow-write and a file opened with write=true)."
    )]
    async fn write_string(
        &self,
        Parameters(p): Parameters<WriteStringParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_write().await?;
        let loc = validate_location(&p.address).mcp()?;
        let hex = to_hex(p.text.as_bytes());
        self.manager.cmd(&format!("wx {hex} @ {loc}")).await.mcp()?;
        Ok(json_result(json!({ "wrote": p.text.len(), "at": loc })))
    }

    /// Assemble and write (`wa`).
    #[tool(
        description = "Assemble an instruction (or ';'-separated instructions) and write the \
        bytes at an address (requires --allow-write and a file opened with write=true)."
    )]
    async fn write_assembly(
        &self,
        Parameters(p): Parameters<WriteAssemblyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_write().await?;
        let loc = validate_location(&p.address).mcp()?;
        let out = self
            .manager
            .cmd(&format!("wa {} @ {loc}", p.assembly))
            .await
            .mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            format!("Assembled and wrote at {loc}.")
        } else {
            out
        }))
    }

    // --- Hashing ----------------------------------------------------------

    /// Compute a digest/checksum/entropy over a region (`ph`).
    #[tool(
        description = "Compute a hash/checksum/entropy (e.g. md5, sha256, crc32, entropy) over \
        a region at a location. `size` defaults to the current block size (ph)."
    )]
    async fn hash(
        &self,
        Parameters(p): Parameters<HashParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let algo = validate_algo(&p.algo).mcp()?;
        let suffix = at_suffix(&p.at).mcp()?;
        // Temporary block size via `@!<size>` so we hash exactly `size` bytes.
        let bs = match p.size {
            Some(n) => format!(
                " @!{}",
                clamp_count(Some(n), 1, self.manager.config().max_bytes)
            ),
            None => String::new(),
        };
        let out = self
            .manager
            .cmd(&format!("ph {algo}{suffix}{bs}"))
            .await
            .mcp()?;
        let digest = out.trim();
        if digest.is_empty() {
            return Err(RizinError::InvalidArgument {
                arg: p.algo,
                reason: "no output (unknown algorithm? see hash_algorithms)".into(),
            }
            .to_error_data());
        }
        Ok(json_result(json!({ "algorithm": algo, "digest": digest })))
    }

    /// List supported hash algorithms (`phlj`).
    #[tool(description = "List all supported hash/checksum algorithms with descriptions (phlj).")]
    async fn hash_algorithms(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("phlj").await.mcp()?))
    }

    // --- Binary parsing / headers ----------------------------------------

    /// Structured header fields (`iHj`).
    #[tool(
        description = "Show the binary's structured header fields (ELF/PE/Mach-O header), as \
        JSON (iHj)."
    )]
    async fn headers(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.manager.cmdj("iHj").await.mcp()?))
    }

    /// Header field summary (`ihj`).
    #[tool(description = "Show a summary of binary header fields as JSON (ihj).")]
    async fn header_fields(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("ihj", json!(null)).await?))
    }

    /// Code-signing / entitlements (`iCj`).
    #[tool(
        description = "Show code-signing / signature info such as entitlements. Null when the \
        binary is unsigned or the format has no such data (iCj)."
    )]
    async fn signature_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("iCj", json!(null)).await?))
    }

    /// File version info (`iVj`).
    #[tool(description = "Show file version information. Null when not present (iVj).")]
    async fn version_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("iVj", json!(null)).await?))
    }

    /// Embedded resources (`iRj`).
    #[tool(description = "List embedded resources. Empty when not present (iRj).")]
    async fn resources(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("iRj", json!([])).await?))
    }

    // --- Function signatures (FLIRT-style) -------------------------------

    /// Function C signature (`afsj`).
    #[tool(
        description = "Get the function's C signature at a location: return type, calling \
        convention, and typed arguments (afsj)."
    )]
    async fn function_signature(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("afsj{suffix}")).await.mcp()?,
        ))
    }

    /// Function signature bytes + mask (`afsbj`).
    #[tool(
        description = "Get the function's signature bytes, byte mask, and search mask at a \
        location — the masked byte pattern that identifies the function regardless of relocated \
        operands. (For actual FLIRT signature creation/application, see the flirt_* tools.) \
        (afsbj)."
    )]
    async fn function_signature_bytes(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("afsbj{suffix}")).await.mcp()?,
        ))
    }

    // --- FLIRT signatures -------------------------------------------------

    /// List signatures in the sigdb (`Fl`).
    #[tool(
        description = "List the FLIRT signatures available in Rizin's signature database \
        (sigdb), with their architecture, module count, and description (Fl)."
    )]
    async fn flirt_list(&self) -> Result<CallToolResult, ErrorData> {
        let out = self.manager.cmd("Fl").await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            "No FLIRT signatures found in the sigdb.".to_string()
        } else {
            out
        }))
    }

    /// Apply signatures from the sigdb (`Fa`).
    #[tool(
        description = "Apply FLIRT signatures from Rizin's signature database (sigdb) to the \
        loaded binary, naming matched library functions. An optional filter narrows which \
        signatures are tried (Fa)."
    )]
    async fn flirt_apply_sigdb(
        &self,
        Parameters(p): Parameters<FlirtSigdbParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = match &p.filter {
            Some(f) => format!("Fa {}", validate_path(f).mcp()?),
            None => "Fa".to_string(),
        };
        let out = self.manager.cmd(&cmd).await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            "Applied sigdb signatures (no new matches reported).".to_string()
        } else {
            out
        }))
    }

    /// Apply a FLIRT signature file (`Fs`).
    #[tool(
        description = "Open a FLIRT signature file (.sig or .pat) and apply its signatures to \
        the loaded binary, naming matched functions (Fs)."
    )]
    async fn flirt_apply(
        &self,
        Parameters(p): Parameters<FlirtFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = validate_path(&p.path).mcp()?;
        let out = self.manager.cmd(&format!("Fs {path}")).await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            format!("Applied FLIRT signatures from {path}.")
        } else {
            out
        }))
    }

    /// Dump a FLIRT signature file (`Fd`).
    #[tool(
        description = "Open a FLIRT signature file (.sig or .pat) and dump its contents \
        (format, version, architecture, and the per-module byte patterns) (Fd)."
    )]
    async fn flirt_dump(
        &self,
        Parameters(p): Parameters<FlirtFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = validate_path(&p.path).mcp()?;
        let out = self.manager.cmd(&format!("Fd {path}")).await.mcp()?;
        if out.trim().is_empty() {
            return Err(RizinError::InvalidArgument {
                arg: p.path,
                reason: "no FLIRT data (missing or not a .sig/.pat file?)".into(),
            }
            .to_error_data());
        }
        Ok(text_result(out))
    }

    /// Create a FLIRT signature file (`Fc`, write).
    #[tool(
        description = "Create a FLIRT signature file (.sig or .pat) from the current analysis, \
        writing it to the given path. Requires --allow-write (it writes a file to disk) (Fc)."
    )]
    async fn flirt_create(
        &self,
        Parameters(p): Parameters<FlirtFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // Writing a file to disk is a filesystem mutation: gate behind --allow-write.
        if !self.manager.config().allow_write {
            return Err(RizinError::NotPermitted(
                "flirt_create writes a file to disk; start the server with --allow-write".into(),
            )
            .to_error_data());
        }
        if !self.manager.state().await.open {
            return Err(RizinError::NoFileOpen.to_error_data());
        }
        let path = validate_path(&p.path).mcp()?;
        let out = self.manager.cmd(&format!("Fc {path}")).await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            format!("Created FLIRT signature file at {path}.")
        } else {
            out
        }))
    }

    // --- Silhouette (rz-silhouette plugin) --------------------------------

    /// Fetch & apply symbols from a Silhouette server (`sil`).
    #[tool(
        description = "Fetch symbols and hints from a configured Rizin Silhouette server and \
        apply them to the open binary. Requires the rz-silhouette plugin and `silhouette.*` \
        configuration (host/port/psk), e.g. set via the `command` tool or a .rizinrc (sil)."
    )]
    async fn silhouette(&self) -> Result<CallToolResult, ErrorData> {
        const HINT: &str = "no output from `sil`. Ensure the rz-silhouette plugin is \
             installed and silhouette.{host,port,psk} are configured.";
        let out = self
            .manager
            .cmd("sil")
            .await
            .map_err(|e| Self::plugin_hint(e, HINT))?;
        if out.trim().is_empty() {
            return Err(RizinError::NotPermitted(HINT.into()).to_error_data());
        }
        Ok(text_result(out))
    }

    /// Test the Silhouette server connection (`sil test`).
    #[tool(
        description = "Test connectivity and credentials against the configured Rizin \
        Silhouette server. Requires the rz-silhouette plugin and `silhouette.*` configuration \
        (sil test)."
    )]
    async fn silhouette_test(&self) -> Result<CallToolResult, ErrorData> {
        const HINT: &str = "no output from `sil test`. Ensure the rz-silhouette plugin is \
             installed and silhouette.{host,port,psk} are configured.";
        let out = self
            .manager
            .cmd("sil test")
            .await
            .map_err(|e| Self::plugin_hint(e, HINT))?;
        if out.trim().is_empty() {
            return Err(RizinError::NotPermitted(HINT.into()).to_error_data());
        }
        Ok(text_result(out))
    }

    // --- RzIL -------------------------------------------------------------

    /// RzIL listing of a function (`plf`).
    #[tool(
        description = "Print the RzIL (Rizin Intermediate Language) lifting of the function at \
        a location, instruction by instruction (plf)."
    )]
    async fn il_function(
        &self,
        Parameters(p): Parameters<AtParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        let out = self.manager.cmd(&format!("plf{suffix}")).await.mcp()?;
        if out.trim().is_empty() {
            return Err(RizinError::EmptyJson {
                cmd: "plf".into(),
                detail: String::new(),
            }
            .to_error_data());
        }
        Ok(text_result(out))
    }

    /// Emulate instructions in the RzIL VM (`aezi` + `aezsej`).
    #[tool(
        description = "Emulate instructions in the RzIL virtual machine starting at a location, \
        stepping `steps` instructions (default 1). Returns the VM read/write changes per step \
        (register/PC/memory writes) as JSON (aezi; aezsej)."
    )]
    async fn emulate_il(
        &self,
        Parameters(p): Parameters<EmulateIlParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = match &p.at {
            Some(a) => validate_location(a).mcp()?,
            None => self.manager.cmd("s").await.mcp()?.trim().to_string(),
        };
        let steps = clamp_count(p.steps, 1, self.manager.config().max_count);
        // Initialise the VM at the location, then step and capture the changes.
        self.manager.cmd(&format!("aezi @ {loc}")).await.mcp()?;
        Ok(json_result(
            self.manager.cmdj(&format!("aezsej {steps}")).await.mcp()?,
        ))
    }

    // --- Diffing ----------------------------------------------------------

    /// Compare bytes at a location with a hex pattern (`cxj`).
    #[tool(
        description = "Compare the bytes at a location against a hex pattern; returns the \
        differing offsets and values (cxj)."
    )]
    async fn compare_bytes(
        &self,
        Parameters(p): Parameters<CompareBytesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let bytes = parse_hex_bytes(&p.hex).mcp()?;
        let hex = to_hex(&bytes);
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager
                .cmdj(&format!("cxj {hex}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    /// Compare bytes at a location with another file's contents (`cfj`).
    #[tool(
        description = "Compare the bytes at a location against the contents of another file on \
        disk; returns the differing offsets and values (cfj). Useful for byte-level diffing of \
        two binaries."
    )]
    async fn compare_file(
        &self,
        Parameters(p): Parameters<CompareFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = validate_path(&p.path).mcp()?;
        let suffix = at_suffix(&p.at).mcp()?;
        Ok(json_result(
            self.manager
                .cmdj(&format!("cfj {path}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    // --- Extended search --------------------------------------------------

    /// Search for an integer value (`/v<size>j`).
    #[tool(
        description = "Search the whole address space for an integer value of a given width \
        (1/2/4/8 bytes, default 4). Value may be decimal or 0x-hex. Returns match addresses \
        (/vNj)."
    )]
    async fn search_value(
        &self,
        Parameters(p): Parameters<SearchValueParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let value = validate_number(&p.value).mcp()?;
        let size = match p.size.unwrap_or(4) {
            1 | 2 | 4 | 8 => p.size.unwrap_or(4),
            other => {
                return Err(RizinError::InvalidArgument {
                    arg: other.to_string(),
                    reason: "size must be 1, 2, 4, or 8".into(),
                }
                .to_error_data());
            }
        };
        Ok(json_result(
            self.manager
                .cmdj(&format!("/v{size}j {value}"))
                .await
                .mcp()?,
        ))
    }

    /// Search for ROP gadgets (`/Rj`).
    #[tool(
        description = "Search for ROP gadgets matching one or more `;`-separated instructions \
        (e.g. 'pop rdi; ret'). Returns matching gadget chains with addresses (/Rj)."
    )]
    async fn search_rop(
        &self,
        Parameters(p): Parameters<SearchRopParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.query.trim().is_empty() {
            return Err(RizinError::InvalidArgument {
                arg: p.query.clone(),
                reason: "query must not be empty".into(),
            }
            .to_error_data());
        }
        // The gadget query legitimately uses `;`; reject only framing-breakers.
        if p.query.contains(['\n', '\0', '|', '`', '>']) {
            return Err(RizinError::InvalidArgument {
                arg: p.query.clone(),
                reason: "query contains a disallowed character".into(),
            }
            .to_error_data());
        }
        Ok(json_result(
            self.manager
                .cmdj(&format!("/Rj {}", p.query.trim()))
                .await
                .mcp()?,
        ))
    }

    /// Search for magic/file-format constants (`/mj`).
    #[tool(
        description = "Scan the address space for magic/file-format signatures (embedded files, \
        headers, known constants) and return their locations. Requires Rizin's magic database \
        in its data dir; empty when unavailable (/mj)."
    )]
    async fn search_magic(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("/mj", json!([])).await?))
    }

    /// Search for cryptographic material (`/cmj`).
    #[tool(
        description = "Scan for cryptographic material (e.g. AES key schedules, known crypto \
        constants) and return their locations. Empty when none found (/cmj)."
    )]
    async fn search_crypto(&self) -> Result<CallToolResult, ErrorData> {
        Ok(json_result(self.cmdj_optional("/cmj", json!([])).await?))
    }

    // --- Debugging (guarded by --allow-debug) ----------------------------

    /// Start debugging the open file (`ood`).
    #[tool(
        description = "Start a debug session by (re)launching the currently open file under the \
        debugger, stopped at its entry point. Requires --allow-debug. WARNING: this executes \
        the target binary (ood)."
    )]
    async fn debug_start(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let out = self.manager.cmd("ood").await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            "Debug session started.".to_string()
        } else {
            out
        }))
    }

    /// Stop the debug session (`doc`).
    #[tool(description = "Close the current debug session, killing the debuggee (doc).")]
    async fn debug_stop(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let out = self.manager.cmd("doc").await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            "Debug session closed.".to_string()
        } else {
            out
        }))
    }

    /// Continue execution (`dc`).
    #[tool(
        description = "Continue execution of the debuggee until it stops (breakpoint, signal, or \
        exit). Requires an active debug session (dc)."
    )]
    async fn debug_continue(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let out = self.manager.cmd("dc").await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            "Continued.".to_string()
        } else {
            out
        }))
    }

    /// Step instructions (`ds`).
    #[tool(
        description = "Single-step the debuggee `count` instructions (default 1). Requires an \
        active debug session (ds)."
    )]
    async fn debug_step(
        &self,
        Parameters(p): Parameters<DebugStepParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let count = clamp_count(p.count, 1, self.manager.config().max_count);
        let out = self.manager.cmd(&format!("ds {count}")).await.mcp()?;
        Ok(text_result(if out.trim().is_empty() {
            format!("Stepped {count} instruction(s).")
        } else {
            out
        }))
    }

    /// Read debug registers (`drj`).
    #[tool(
        description = "Read the debuggee's CPU register values as JSON. Requires an active \
        debug session (drj)."
    )]
    async fn debug_registers(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(json_result(self.manager.cmdj("drj").await.mcp()?))
    }

    /// Set a breakpoint (`db @ addr`).
    #[tool(
        description = "Set a breakpoint at an address or flag/symbol. Requires an active debug \
        session (db)."
    )]
    async fn debug_breakpoint(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let loc = validate_location(&p.address).mcp()?;
        self.manager.cmd(&format!("db @ {loc}")).await.mcp()?;
        Ok(json_result(json!({ "breakpoint_set": loc })))
    }

    /// Remove a breakpoint (`db- @ addr`).
    #[tool(
        description = "Remove the breakpoint at an address or flag/symbol. Requires an active \
        debug session (db-)."
    )]
    async fn debug_breakpoint_remove(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        let loc = validate_location(&p.address).mcp()?;
        self.manager.cmd(&format!("db- @ {loc}")).await.mcp()?;
        Ok(json_result(json!({ "breakpoint_removed": loc })))
    }

    /// List breakpoints (`dblj`).
    #[tool(description = "List all breakpoints as JSON. Requires an active debug session (dblj).")]
    async fn debug_breakpoints(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(json_result(self.manager.cmdj("dblj").await.mcp()?))
    }

    /// Backtrace (`dbtj`).
    #[tool(
        description = "Show the call-stack backtrace of the debuggee as JSON. Requires an active \
        debug session (dbtj)."
    )]
    async fn debug_backtrace(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(json_result(self.manager.cmdj("dbtj").await.mcp()?))
    }

    /// Memory maps (`dmj`).
    #[tool(
        description = "List the debuggee's memory maps (regions, permissions, names) as JSON. \
        Requires an active debug session (dmj)."
    )]
    async fn debug_maps(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(json_result(self.manager.cmdj("dmj").await.mcp()?))
    }

    /// Debuggee status (`dij`).
    #[tool(
        description = "Report the debuggee's status as JSON (PID, stop reason, signal, current \
        PC, etc.). Requires an active debug session (dij)."
    )]
    async fn debug_status(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(json_result(self.manager.cmdj("dij").await.mcp()?))
    }
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

#[prompt_router]
impl RizinServer {
    /// First-pass triage workflow.
    #[prompt(
        name = "triage_binary",
        description = "Guided first-pass triage of the currently open binary"
    )]
    async fn prompt_triage(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::User,
            "Perform a first-pass triage of the binary that is currently open in Rizin. \
             Use `binary_info` for format/arch/entry, `entrypoints`, `sections`, \
             `imports`/`exports`, and `list_strings` to characterize it. Then run \
             `list_functions` and inspect the entry function and `main` with \
             `disassemble_function` or `decompile`. Summarize: what the binary is, its \
             likely purpose, notable imports/strings, and anything that warrants deeper \
             analysis.",
        )]
    }

    /// Deep dive on one function.
    #[prompt(
        name = "analyze_function",
        description = "Analyze a specific function in depth"
    )]
    async fn prompt_analyze_function(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> GetPromptResult {
        let mut result = GetPromptResult::default();
        result.description = Some(format!(
            "In-depth analysis of the function at {}",
            p.address
        ));
        result.messages = vec![PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Analyze the function at {addr} in depth. Start with \
                 `function_info {{\"at\": \"{addr}\"}}` for its bounds and signature, then \
                 `disassemble_function` and `decompile`. Use `function_variables` for locals \
                 and arguments, `xrefs_to` to see callers and `xrefs_from`/`function_graph` to \
                 understand its behavior. Explain what the function does, its inputs and \
                 outputs, and flag any suspicious or unsafe patterns.",
                addr = p.address
            ),
        )];
        result
    }

    /// Vulnerability hunting workflow.
    #[prompt(
        name = "find_vulnerabilities",
        description = "Hunt for common vulnerability patterns in the open binary"
    )]
    async fn prompt_find_vulnerabilities(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::User,
            "Look for common vulnerability patterns in the open binary. Use `imports` to find \
             risky calls (e.g. strcpy, gets, sprintf, system, memcpy, malloc/free) and \
             `xrefs_to` each to locate call sites. Inspect those sites with \
             `disassemble_function` and `decompile`, and review `function_variables` for \
             stack buffers. Report any potential buffer overflows, format-string bugs, \
             command injection, integer overflows, or use-after-free, with the address and \
             reasoning for each.",
        )]
    }
}

// ---------------------------------------------------------------------------
// Server handler: capabilities, resources, prompts wiring
// ---------------------------------------------------------------------------

#[tool_handler]
#[prompt_handler]
impl ServerHandler for RizinServer {
    fn get_info(&self) -> ServerInfo {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_prompts()
            .build();
        let mut server_info = Implementation::new("rizin-mcp", env!("CARGO_PKG_VERSION"));
        server_info.title = Some("Rizin MCP".to_string());
        server_info.description = Some("Reverse engineering with the Rizin framework".to_string());
        server_info.website_url = Some("https://rizin.re".to_string());
        InitializeResult::new(capabilities)
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(server_info)
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = RESOURCES
            .iter()
            .map(|(uri, name, _)| RawResource::new(*uri, *name).no_annotation())
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let template = RawResourceTemplate::new(
            "rizin://disasm/{address}",
            "disassemble the function at {address}",
        )
        .no_annotation();
        Ok(ListResourceTemplatesResult::with_all_items(vec![template]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = request.uri.as_str();
        let value = if let Some((_, _, cmd)) = RESOURCES.iter().find(|(u, _, _)| *u == uri) {
            self.manager.cmdj(cmd).await.mcp()?
        } else if let Some(loc) = uri.strip_prefix("rizin://disasm/") {
            let loc = validate_location(loc).mcp()?;
            self.manager.cmdj(&format!("pdfj @ {loc}")).await.mcp()?
        } else {
            return Err(ErrorData::resource_not_found(
                "unknown resource uri",
                Some(json!({ "uri": uri })),
            ));
        };
        let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            pretty, uri,
        )]))
    }
}

// ---------------------------------------------------------------------------
// Result helpers
// ---------------------------------------------------------------------------

/// Build a tool result carrying a JSON value both as pretty text (for clients
/// that show text) and as structured content (for clients that parse it).
fn json_result(value: Value) -> CallToolResult {
    let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut result = CallToolResult::success(vec![Content::text(pretty)]);
    result.structured_content = Some(value);
    result
}

/// Build a plain-text tool result.
fn text_result(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text.into())])
}

/// Build a tool result whose body is plain text (e.g. decompiled code, kept
/// pristine for reading) but which also carries structured metadata.
fn text_result_meta(text: impl Into<String>, meta: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![Content::text(text.into())]);
    result.structured_content = Some(meta);
    result
}

/// Build a server with default configuration (handy for tests/embedding).
impl Default for RizinServer {
    fn default() -> Self {
        Self::new(ServerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_advertises_capabilities() {
        let server = RizinServer::default();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "rizin-mcp");
        assert!(info.capabilities.tools.is_some());
        assert!(info.capabilities.resources.is_some());
        assert!(info.capabilities.prompts.is_some());
        assert!(info.instructions.is_some());
        assert_eq!(info.protocol_version, ProtocolVersion::LATEST);
    }

    #[test]
    fn tool_router_exposes_expected_tools() {
        let router = RizinServer::tool_router();
        let names: Vec<String> = router
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        for expected in [
            "open_file",
            "close_file",
            "session_info",
            "analyze",
            "seek",
            "command",
            "command_json",
            "binary_info",
            "list_functions",
            "disassemble",
            "disassemble_function",
            "decompile",
            "decompilers",
            "flirt_list",
            "flirt_apply",
            "flirt_apply_sigdb",
            "flirt_dump",
            "flirt_create",
            "silhouette",
            "silhouette_test",
            "hexdump",
            "read_bytes",
            "xrefs_to",
            "xrefs_from",
            "list_strings",
            "imports",
            "exports",
            "symbols",
            "search_string",
            "search_bytes",
            "search_value",
            "search_rop",
            "search_magic",
            "search_crypto",
            "hash",
            "hash_algorithms",
            "headers",
            "header_fields",
            "signature_info",
            "version_info",
            "resources",
            "function_signature",
            "function_signature_bytes",
            "il_function",
            "emulate_il",
            "compare_bytes",
            "compare_file",
            "debug_start",
            "debug_stop",
            "debug_continue",
            "debug_step",
            "debug_registers",
            "debug_breakpoint",
            "debug_breakpoint_remove",
            "debug_breakpoints",
            "debug_backtrace",
            "debug_maps",
            "debug_status",
            "write_hex",
            "write_string",
            "write_assembly",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing tool: {expected}"
            );
        }
        assert!(
            names.len() >= 70,
            "expected many tools, got {}",
            names.len()
        );
        assert!(router.has_route("open_file"));
    }

    #[test]
    fn prompt_router_exposes_prompts() {
        let router = RizinServer::prompt_router();
        let names: Vec<String> = router
            .list_all()
            .iter()
            .map(|p| p.name.to_string())
            .collect();
        for expected in ["triage_binary", "analyze_function", "find_vulnerabilities"] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing prompt: {expected}"
            );
        }
    }

    #[test]
    fn json_result_sets_text_and_structured() {
        let r = json_result(json!({"a": 1, "b": [2, 3]}));
        assert_eq!(r.structured_content, Some(json!({"a": 1, "b": [2, 3]})));
        assert_eq!(r.content.len(), 1);
        assert!(r.is_error.is_none() || r.is_error == Some(false));
    }

    #[tokio::test]
    async fn raw_disabled_blocks_command_tool() {
        let server = RizinServer::new(ServerConfig {
            allow_raw: false,
            ..Default::default()
        });
        let res = server.ensure_raw();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn write_guard_requires_allow_write() {
        let server = RizinServer::new(ServerConfig {
            allow_write: false,
            ..Default::default()
        });
        assert!(server.ensure_write().await.is_err());
    }

    #[tokio::test]
    async fn debug_guard_requires_allow_debug() {
        let server = RizinServer::new(ServerConfig {
            allow_debug: false,
            ..Default::default()
        });
        assert!(server.ensure_debug().await.is_err());
    }
}

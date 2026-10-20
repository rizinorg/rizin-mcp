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
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use rmcp::{prompt, prompt_handler, prompt_router, tool, tool_handler, tool_router};
use serde_json::{Value, json};

use crate::config::ServerConfig;
use crate::error::{IntoMcp, RizinError};
use crate::output::{Page, paginate, truncate_text};
use crate::params::*;
use crate::session::{AnalysisLevel, SessionManager};
use crate::status::CmdStatus;
use crate::util::{
    at_suffix, clamp_count, gadget_matches_exactly, parse_hex_bytes, parse_instructions,
    parse_rop_query, quote_arg, to_hex, validate_algo, validate_flag_name, validate_location,
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
Listings are paged: they return `items` with `total` and, when more remain, \
`truncated: true` and `next_offset` to pass as `offset` (use `limit` to change the \
page size). `decompile` uses rz-ghidra or jsdec when installed (see `decompilers`), else built-in \
pseudo-disassembly. Name library functions with the `flirt_*` tools (FLIRT signatures) \
and, when the rz-silhouette plugin is configured, with `silhouette`. \
With --allow-write, record findings with `rename_function`, `rename_variable`, \
`set_comment`, `set_flag`, and `set_function_signature`. \
Dynamic analysis is available via the `debug_*` tools when the server is started with \
--allow-debug. Addresses may be hex (e.g. 0x401000) or flag/symbol names (e.g. main, \
sym.imp.printf). For anything not covered by a dedicated tool, use `command` (text) or \
`command_json` (parsed JSON) to run a raw Rizin command.";

/// The raw passthrough tools, offered only without `--no-raw`.
pub const RAW_TOOLS: &[&str] = &["command", "command_json"];

/// The tools that modify the file or write to disk, offered only with
/// `--allow-write`.
pub const WRITE_TOOLS: &[&str] = &[
    "write_hex",
    "write_string",
    "write_assembly",
    "flirt_create",
];

/// The tools that change the analysis (names, comments, flags, types),
/// offered only with `--allow-write`. They do not modify the file.
pub const ANNOTATION_TOOLS: &[&str] = &[
    "rename_function",
    "rename_variable",
    "set_comment",
    "remove_comment",
    "set_flag",
    "remove_flag",
    "set_function_signature",
];

/// The debugger tools, offered only with `--allow-debug`.
pub const DEBUG_TOOLS: &[&str] = &[
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
];

/// A Model Context Protocol server backed by a Rizin session.
#[derive(Clone)]
pub struct RizinServer {
    manager: Arc<SessionManager>,
    /// The tools this configuration offers.
    tool_router: Arc<ToolRouter<Self>>,
}

impl RizinServer {
    /// Create a server with the given configuration and no open file.
    ///
    /// Tools whose capability is disabled are left out of the catalog, so
    /// clients neither see nor try them; their guards stay as a second line.
    pub fn new(config: ServerConfig) -> Self {
        let mut router = Self::tool_router();
        for (enabled, tools) in [
            (config.allow_raw, RAW_TOOLS),
            (config.allow_write, WRITE_TOOLS),
            (config.allow_write, ANNOTATION_TOOLS),
            (config.allow_debug, DEBUG_TOOLS),
        ] {
            if !enabled {
                for name in tools {
                    router.remove_route(name);
                }
            }
        }
        Self {
            manager: Arc::new(SessionManager::new(config)),
            tool_router: Arc::new(router),
        }
    }

    /// Access the shared session manager (used by the binary to open a startup
    /// file before serving).
    pub fn manager(&self) -> Arc<SessionManager> {
        self.manager.clone()
    }

    /// Build a JSON tool result within the output ceiling: an array is cut to
    /// what fits (see [`Self::listing`]); an object over the ceiling becomes an
    /// error result asking for a narrower request.
    fn json_result(&self, value: Value) -> CallToolResult {
        if value.is_array() {
            return self.page_result(value, Page::ALL);
        }
        let value = as_structured(value);
        let size = serde_json::to_string(&value).map_or(0, |s| s.len());
        let max = self.manager.config().max_output_bytes;
        if size > max {
            return CallToolResult::error(vec![Content::text(format!(
                "the result is {size} bytes, over the {max}-byte output limit; \
                 narrow the request (e.g. a smaller count or a smaller function), \
                 or raise the server's --max-output-bytes"
            ))]);
        }
        structured_result(value)
    }

    /// Return one page of a listing (`offset`, `limit`, at most
    /// `default_limit` items unless asked otherwise) as `{"items", "total",
    /// "offset", "returned", "truncated"[, "next_offset"]}`.
    fn listing(&self, value: Value, p: &PageParams) -> CallToolResult {
        if value.is_array() {
            self.page_result(value, self.page(p))
        } else {
            self.json_result(value)
        }
    }

    /// The page requested by `p`, with the configured default limit.
    fn page(&self, p: &PageParams) -> Page {
        let to_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        Page {
            offset: p.offset.map_or(0, to_usize),
            limit: Some(
                p.limit
                    .map_or(self.manager.config().default_limit, to_usize)
                    .max(1),
            ),
        }
    }

    fn page_result(&self, value: Value, page: Page) -> CallToolResult {
        let items = match value {
            Value::Array(items) => items,
            other => vec![other],
        };
        structured_result(paginate(
            items,
            page,
            self.manager.config().max_output_bytes,
        ))
    }

    /// Build a plain-text tool result within the output ceiling.
    fn text_result(&self, text: impl Into<String>) -> CallToolResult {
        let (text, _) = truncate_text(text.into(), self.manager.config().max_output_bytes);
        CallToolResult::success(vec![Content::text(text)])
    }

    /// Build a tool result whose body is plain text (e.g. decompiled code, kept
    /// pristine for reading) but which also carries structured metadata.
    fn text_result_meta(&self, text: impl Into<String>, meta: Value) -> CallToolResult {
        let (text, truncated) = truncate_text(text.into(), self.manager.config().max_output_bytes);
        let mut meta = as_structured(meta);
        if truncated {
            meta["truncated"] = json!(true);
        }
        let mut result = CallToolResult::success(vec![Content::text(text)]);
        result.structured_content = Some(meta);
        result
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

    /// Guard used by the annotation tools: they change the analysis, not the
    /// file, so a read-only file is fine.
    async fn ensure_annotate(&self) -> Result<(), ErrorData> {
        if !self.manager.config().allow_write {
            return Err(RizinError::NotPermitted(
                "annotation tools are disabled; start the server with --allow-write".into(),
            )
            .to_error_data());
        }
        if !self.manager.state().await.open {
            return Err(RizinError::NoFileOpen.to_error_data());
        }
        Ok(())
    }

    /// Run a command that changes state, failing also when Rizin logs an
    /// error but reports success, as `f`, `wx` and `Fs` do.
    async fn cmd_strict(&self, cmd: &str) -> Result<String, ErrorData> {
        let out = self.manager.exec(cmd).await.mcp()?;
        let out = crate::backend::check(cmd, out).mcp()?;
        let errors: Vec<&str> = out
            .messages
            .iter()
            .map(String::as_str)
            .filter(|m| m.starts_with("ERROR"))
            .collect();
        if !errors.is_empty() {
            return Err(RizinError::CommandFailed {
                cmd: cmd.to_string(),
                status: CmdStatus::Error,
                detail: errors.join("\n"),
            }
            .to_error_data());
        }
        Ok(out.output)
    }

    /// The address `loc` (a hex address or flag) stands for, as `0x...`.
    async fn resolve(&self, loc: &str) -> Result<String, ErrorData> {
        let loc = validate_location(loc).mcp()?;
        let addr = self.manager.cmd(&format!("s @ {loc}")).await.mcp()?;
        let addr = addr.trim();
        // A pipe to Rizin before 0.10 prints nothing for an unknown flag.
        if !addr.starts_with("0x") {
            return Err(RizinError::InvalidArgument {
                arg: loc,
                reason: "not a known address or flag".into(),
            }
            .to_error_data());
        }
        Ok(addr.to_string())
    }

    /// The start address and `afij` entry of the function covering `loc`.
    async fn function_at(&self, loc: &str) -> Result<(String, Value), ErrorData> {
        let addr = self.resolve(loc).await?;
        let info = self.manager.cmdj(&format!("afij @ {addr}")).await.mcp()?;
        let Some(func) = info.as_array().and_then(|a| a.first()).cloned() else {
            return Err(RizinError::InvalidArgument {
                arg: loc.to_string(),
                reason: "no function there (analyze it first, e.g. with analyze_function)".into(),
            }
            .to_error_data());
        };
        let start = func
            .get("offset")
            .and_then(Value::as_u64)
            .map_or(addr, |o| format!("0x{o:x}"));
        Ok((start, func))
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

    /// Write `bytes` at `loc` and read them back. `wx` reports success even
    /// when it could not write (an unmapped address, a read-only map), saying
    /// so only in an error message.
    async fn write_verified(&self, loc: &str, bytes: &[u8]) -> Result<(), ErrorData> {
        let cmd = format!("wx {} @ {loc}", to_hex(bytes));
        let out = self.manager.exec(&cmd).await.mcp()?;
        let out = crate::backend::check(&cmd, out).mcp()?;
        let failed = |detail: String| {
            RizinError::WriteFailed {
                at: loc.to_string(),
                len: bytes.len(),
                detail,
            }
            .to_error_data()
        };
        let errors: Vec<&str> = out
            .messages
            .iter()
            .map(String::as_str)
            .filter(|m| m.starts_with("ERROR"))
            .collect();
        if !errors.is_empty() {
            return Err(failed(errors.join("\n")));
        }
        let back = self
            .manager
            .cmd(&format!("p8 {} @ {loc}", bytes.len()))
            .await
            .mcp()?;
        if parse_hex_bytes(back.trim()).ok().as_deref() != Some(bytes) {
            return Err(failed(format!(
                "read back {} instead of {}",
                back.trim(),
                to_hex(bytes)
            )));
        }
        Ok(())
    }

    /// Whether a function covers the location of `suffix` (an `at_suffix`).
    async fn has_function(&self, suffix: &str) -> bool {
        self.manager
            .cmdj(&format!("afij{suffix}"))
            .await
            .is_ok_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
    }

    /// The number of flags in the `flirt` flag space, which FLIRT matches
    /// create.
    async fn flirt_flag_count(&self) -> Result<u64, ErrorData> {
        let spaces = self.cmdj_optional("fslj", json!([])).await?;
        Ok(spaces
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s.get("name").and_then(Value::as_str) == Some("flirt"))
            .and_then(|s| s.get("count").and_then(Value::as_u64))
            .unwrap_or(0))
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
        Ok(self.json_result(serde_json::to_value(info).unwrap_or(Value::Null)))
    }

    /// Close the current session.
    #[tool(description = "Close the currently open file and tear down the Rizin session.")]
    async fn close_file(&self) -> Result<CallToolResult, ErrorData> {
        let closed = self.manager.close().await;
        Ok(self.text_result(if closed {
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
        Ok(self.json_result(json!({ "session": state, "info": info })))
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
        Ok(self.json_result(json!({ "level": level, "functions": functions })))
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
        Ok(self.json_result(json!({ "offset": offset.trim() })))
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
            return Ok(self.text_result(out.output));
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
        Ok(self.json_result(value))
    }

    // --- Binary information ----------------------------------------------

    /// Binary metadata (`ij`).
    #[tool(
        description = "Binary information: format, architecture, bits, endianness, entry, etc. (ij)."
    )]
    async fn binary_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.json_result(self.manager.cmdj("ij").await.mcp()?))
    }

    /// Entry points (`iej`).
    #[tool(description = "List program entry points (iej).")]
    async fn entrypoints(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("iej").await.mcp()?, &p))
    }

    /// Sections (`iSj`).
    #[tool(description = "List binary sections with addresses, sizes and permissions (iSj).")]
    async fn sections(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("iSj").await.mcp()?, &p))
    }

    /// Segments (`iSSj`).
    #[tool(description = "List binary segments (iSSj).")]
    async fn segments(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("iSSj").await.mcp()?, &p))
    }

    /// Relocations (`irj`).
    #[tool(description = "List relocations (irj).")]
    async fn relocations(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("irj").await.mcp()?, &p))
    }

    /// Imports (`iij`).
    #[tool(description = "List imported symbols (iij).")]
    async fn imports(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("iij").await.mcp()?, &p))
    }

    /// Exports (`iEj`).
    #[tool(description = "List exported symbols (iEj).")]
    async fn exports(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("iEj").await.mcp()?, &p))
    }

    /// Symbols (`isj`).
    #[tool(description = "List all symbols (isj).")]
    async fn symbols(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("isj").await.mcp()?, &p))
    }

    /// Linked libraries (`ilj`).
    #[tool(description = "List linked/required libraries (ilj).")]
    async fn libraries(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("ilj").await.mcp()?, &p))
    }

    /// Classes (`icj`).
    #[tool(description = "List classes/methods recovered from the binary (icj).")]
    async fn classes(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("icj").await.mcp()?, &p))
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
        Ok(self.listing(self.manager.cmdj(cmd).await.mcp()?, &p.page))
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
        let flags = match &p.space {
            Some(space) => {
                let space = validate_location(space).mcp()?;
                // `fs <space>` would select the space for every later `flj`,
                // and `fss+` creates a space that does not exist.
                let spaces = self.cmdj_optional("fslj", json!([])).await?;
                let exists = spaces
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|s| s.get("name").and_then(Value::as_str) == Some(space.as_str()));
                if exists {
                    self.manager
                        .cmdj(&format!("fss+ {space};flj;fss-"))
                        .await
                        .mcp()?
                } else {
                    json!([])
                }
            }
            None => self.manager.cmdj("flj").await.mcp()?,
        };
        Ok(self.listing(flags, &p.page))
    }

    /// Flag spaces (`fslj`).
    #[tool(description = "List flag spaces and their flag counts (fslj).")]
    async fn flag_spaces(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("fslj").await.mcp()?, &p))
    }

    // --- Analysis / functions --------------------------------------------

    /// Function list (`aflj`).
    #[tool(description = "List analyzed functions with addresses, sizes and names (aflj).")]
    async fn list_functions(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("aflj").await.mcp()?, &p))
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
        Ok(self.json_result(self.manager.cmdj(&format!("afij{suffix}")).await.mcp()?))
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
        Ok(self.json_result(self.manager.cmdj(&format!("afvlj{suffix}")).await.mcp()?))
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
        Ok(self.json_result(self.manager.cmdj(&format!("afij{suffix}")).await.mcp()?))
    }

    /// Cross-references to an address (`axtj`).
    #[tool(
        description = "List cross-references TO an address or flag/symbol (who references it) (axtj)."
    )]
    async fn xrefs_to(
        &self,
        Parameters(p): Parameters<XrefParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = validate_location(&p.address).mcp()?;
        Ok(self.listing(
            self.manager.cmdj(&format!("axtj @ {loc}")).await.mcp()?,
            &p.page,
        ))
    }

    /// Cross-references from an address (`axfj`).
    #[tool(
        description = "List cross-references FROM an address or flag/symbol (what it references) (axfj)."
    )]
    async fn xrefs_from(
        &self,
        Parameters(p): Parameters<XrefParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let loc = validate_location(&p.address).mcp()?;
        Ok(self.listing(
            self.manager.cmdj(&format!("axfj @ {loc}")).await.mcp()?,
            &p.page,
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
        Ok(self.json_result(self.manager.cmdj(&format!("agf j{suffix}")).await.mcp()?))
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
        Ok(self.json_result(
            self.manager
                .cmdj(&format!("pdj {count}{suffix}"))
                .await
                .mcp()?,
        ))
    }

    /// Disassemble a whole function (`pdfj`), its instructions paged.
    #[tool(
        description = "Disassemble the function at a location as structured JSON (pdfj). \
        Its instructions (`ops`) are paged with offset/limit like a listing; the page \
        details are in `ops_page`."
    )]
    async fn disassemble_function(
        &self,
        Parameters(p): Parameters<FunctionPageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let suffix = at_suffix(&p.at).mcp()?;
        let mut func = self.manager.cmdj(&format!("pdfj{suffix}")).await.mcp()?;
        if let Some(Value::Array(ops)) = func.get_mut("ops").map(Value::take) {
            // Leave room for the rest of the function object and the page info.
            let rest = serde_json::to_string(&func).map_or(0, |s| s.len()) + 256;
            let budget = self.manager.config().max_output_bytes.saturating_sub(rest);
            let mut page = paginate(ops, self.page(&p.page), budget);
            func["ops"] = page["items"].take();
            if let Some(obj) = page.as_object_mut() {
                obj.remove("items");
            }
            func["ops_page"] = page;
        }
        Ok(self.json_result(func))
    }

    /// Decompile (`pdg`/`pdd`/pseudo).
    #[tool(
        description = "Decompile the function at a location to pseudo-C. `decompiler` selects \
        the engine: `auto` (default) tries rz-ghidra (pdg), then jsdec (pdd), then built-in \
        pseudo-disassembly of the function's basic blocks (pdr); or force `ghidra`, `jsdec`, \
        or `pseudo`. rz-ghidra and jsdec are \
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
        // Pseudo-disassembly of the whole function, with temporary evals so the
        // global settings are left untouched. Without the jump arrows
        // (`asm.lines`), which Rizin omits from captured in-process output, the
        // text is the same on both backends. `pdr` walks the basic blocks:
        // `pdf` spends seconds per pointer operand in a large function.
        let pseudo = (
            "pseudo",
            format!("pdr @e:asm.pseudo=true @e:asm.lines=false{suffix}"),
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

        // Only a missing plugin (or an empty result) moves on to the next
        // engine: an engine that ran and failed (e.g. no function there) would
        // fail the same way in the next one, and a timeout or dead session
        // must not be retried.
        let mut skipped = serde_json::Map::new();
        for (engine, cmd) in &candidates {
            let out = self.manager.exec(cmd).await.mcp()?;
            match crate::backend::check(cmd, out) {
                Ok(out) if !out.output.trim().is_empty() => {
                    return Ok(self.text_result_meta(
                        out.output,
                        json!({ "decompiler": engine, "skipped": skipped }),
                    ));
                }
                // A pipe to Rizin before 0.10 sees a failure only as no output
                // and an error message.
                Ok(out) if out.messages.iter().any(|m| m.starts_with("ERROR")) => {
                    return Err(RizinError::CommandFailed {
                        cmd: cmd.clone(),
                        status: out.status,
                        detail: out.detail(),
                    }
                    .to_error_data());
                }
                Ok(_) => {
                    skipped.insert(engine.to_string(), json!("no output"));
                }
                Err(RizinError::CommandFailed {
                    status: CmdStatus::NonExistingCmd,
                    ..
                }) => {
                    skipped.insert(engine.to_string(), json!("not installed"));
                }
                Err(e) => return Err(e.to_error_data()),
            }
        }

        let missing = skipped.values().any(|v| v == "not installed");
        let hint = if missing {
            "no decompiler output: the requested engine is not installed. Install the \
             rz-ghidra (pdg) or jsdec (pdd) plugin, or use decompiler=\"pseudo\"."
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
        Ok(self.json_result(json!({
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
        Ok(self.json_result(
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
        Ok(self.json_result(json!({
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
        Ok(self.json_result(
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
        Ok(self.listing(
            self.manager.cmdj(&format!("/xj {hex}")).await.mcp()?,
            &p.page,
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
        Ok(self.listing(
            self.manager.cmdj(&format!("/xj {hex}")).await.mcp()?,
            &p.page,
        ))
    }

    // --- Annotation (guarded by --allow-write) ----------------------------

    /// Rename a function (`afn`).
    #[tool(
        description = "Rename the function containing a location; returns the name Rizin \
        stored. Changes the analysis only, not the file. Requires --allow-write (afn)."
    )]
    async fn rename_function(
        &self,
        Parameters(p): Parameters<RenameFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let (addr, before) = self.function_at(&p.at).await?;
        let name = quote_arg(&p.name).mcp()?;
        self.cmd_strict(&format!("afn {name} @ {addr}")).await?;
        let (_, after) = self.function_at(&addr).await?;
        Ok(self.json_result(json!({
            "function": addr,
            "previous_name": before["name"],
            "name": after["name"],
        })))
    }

    /// Rename a function argument or local variable (`afvn`).
    #[tool(
        description = "Rename an argument or local variable of the function containing a \
        location (see function_variables for the names). Requires --allow-write (afvn)."
    )]
    async fn rename_variable(
        &self,
        Parameters(p): Parameters<RenameVariableParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let (addr, _) = self.function_at(&p.at).await?;
        let new = quote_arg(&p.new_name).mcp()?;
        let old = quote_arg(&p.old_name).mcp()?;
        self.cmd_strict(&format!("afvn {new} {old} @ {addr}"))
            .await?;
        let vars = self.manager.cmdj(&format!("afvlj @ {addr}")).await.mcp()?;
        let names: Vec<&str> = vars
            .as_object()
            .into_iter()
            .flat_map(|o| o.values())
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(|v| v.get("name").and_then(Value::as_str))
            .collect();
        if !names.contains(&p.new_name.as_str()) {
            return Err(RizinError::InvalidArgument {
                arg: p.old_name,
                reason: format!("no such variable in the function at {addr}"),
            }
            .to_error_data());
        }
        Ok(self.json_result(json!({
            "function": addr,
            "old_name": p.old_name,
            "new_name": p.new_name,
        })))
    }

    /// Set or append a comment (`CC`).
    #[tool(
        description = "Set the comment at an address (replacing any comment there, or \
        appending with append=true); returns the resulting comment. Requires --allow-write \
        (CC)."
    )]
    async fn set_comment(
        &self,
        Parameters(p): Parameters<SetCommentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let addr = self.resolve(&p.address).await?;
        let text = quote_arg(&p.text).mcp()?;
        if !p.append.unwrap_or(false) {
            self.cmd_strict(&format!("CC- @ {addr}")).await?;
        }
        self.cmd_strict(&format!("CC {text} @ {addr}")).await?;
        let comment = self.manager.cmd(&format!("CC. @ {addr}")).await.mcp()?;
        Ok(self.json_result(json!({
            "at": addr,
            "comment": comment.trim_end_matches('\n'),
        })))
    }

    /// Remove a comment (`CC-`).
    #[tool(description = "Remove the comment at an address. Requires --allow-write (CC-).")]
    async fn remove_comment(
        &self,
        Parameters(p): Parameters<AddressParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let addr = self.resolve(&p.address).await?;
        self.cmd_strict(&format!("CC- @ {addr}")).await?;
        Ok(self.json_result(json!({ "at": addr, "removed": true })))
    }

    /// Create or move a flag (`f+`).
    #[tool(
        description = "Name an address with a flag (creating it, or moving an existing flag of \
        that name), usable as a location afterwards. Requires --allow-write (f+)."
    )]
    async fn set_flag(
        &self,
        Parameters(p): Parameters<SetFlagParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let name = validate_flag_name(&p.name).mcp()?;
        let addr = self.resolve(&p.address).await?;
        let size = clamp_count(p.size, 1, u64::MAX);
        // `f` refuses an address that already has a flag; `f+` adds one in
        // any case, and moves a flag of the same name.
        self.cmd_strict(&format!("f+ {name} {size} @ {addr}"))
            .await?;
        let at = self.resolve(&name).await?;
        Ok(self.json_result(json!({ "name": name, "at": at, "size": size })))
    }

    /// Remove a flag (`f-`).
    #[tool(description = "Remove a flag by name. Requires --allow-write (f-).")]
    async fn remove_flag(
        &self,
        Parameters(p): Parameters<FlagNameParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let name = validate_flag_name(&p.name).mcp()?;
        // `f-` of an unknown name succeeds silently.
        self.resolve(&name).await?;
        self.cmd_strict(&format!("f- {name}")).await?;
        Ok(self.json_result(json!({ "name": name, "removed": true })))
    }

    /// Set a function's C signature (`afs`).
    #[tool(
        description = "Set the C prototype of the function containing a location, typing its \
        arguments and return value (e.g. 'int parse_args(int argc, char **argv)'); returns \
        the resulting signature. Requires --allow-write (afs)."
    )]
    async fn set_function_signature(
        &self,
        Parameters(p): Parameters<SetSignatureParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_annotate().await?;
        let (addr, _) = self.function_at(&p.at).await?;
        let sig = quote_arg(&p.signature).mcp()?;
        self.cmd_strict(&format!("afs {sig} @ {addr}")).await?;
        Ok(self.json_result(self.manager.cmdj(&format!("afsj @ {addr}")).await.mcp()?))
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
        self.write_verified(&loc, &bytes).await?;
        Ok(self.json_result(json!({ "wrote": bytes.len(), "at": loc })))
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
        if p.text.is_empty() {
            return Err(RizinError::InvalidArgument {
                arg: p.text,
                reason: "text must not be empty".into(),
            }
            .to_error_data());
        }
        self.write_verified(&loc, p.text.as_bytes()).await?;
        Ok(self.json_result(json!({ "wrote": p.text.len(), "at": loc })))
    }

    /// Assemble and write (`pa`, then `wx`).
    #[tool(
        description = "Assemble one or more instructions (separated by ';' or newlines) for \
        the destination address and write the bytes there; returns the bytes written. \
        Requires --allow-write and a file opened with write=true (pa; wx)."
    )]
    async fn write_assembly(
        &self,
        Parameters(p): Parameters<WriteAssemblyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_write().await?;
        let loc = validate_location(&p.address).mcp()?;
        let insns = parse_instructions(&p.assembly).mcp()?;
        // `wa mov eax, 1` assembles each space-separated word as its own
        // instruction; one quoted, `;`-joined argument keeps them whole.
        let asm = quote_arg(&insns.join(";")).mcp()?;
        let cmd = format!("pa {asm} @ {loc}");
        let out = self.manager.exec(&cmd).await.mcp()?;
        let out = crate::backend::check(&cmd, out).mcp()?;
        let bytes = parse_hex_bytes(out.output.trim()).map_err(|_| {
            // A pipe to Rizin before 0.10 cannot report the failure, but its
            // message (e.g. "Cannot assemble") says what went wrong.
            if out.messages.is_empty() {
                RizinError::InvalidArgument {
                    arg: p.assembly.clone(),
                    reason: format!("assembled to no bytes ({:?})", out.output.trim()),
                }
            } else {
                RizinError::CommandFailed {
                    cmd: cmd.clone(),
                    status: out.status,
                    detail: out.detail(),
                }
            }
            .to_error_data()
        })?;
        self.write_verified(&loc, &bytes).await?;
        Ok(self.json_result(json!({
            "wrote": bytes.len(),
            "at": loc,
            "bytes": to_hex(&bytes),
        })))
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
        Ok(self.json_result(json!({ "algorithm": algo, "digest": digest })))
    }

    /// List supported hash algorithms (`phlj`).
    #[tool(description = "List all supported hash/checksum algorithms with descriptions (phlj).")]
    async fn hash_algorithms(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.manager.cmdj("phlj").await.mcp()?, &p))
    }

    // --- Binary parsing / headers ----------------------------------------

    /// Structured header fields (`iHj`).
    #[tool(
        description = "Show the binary's structured header fields (ELF/PE/Mach-O header), as \
        JSON (iHj)."
    )]
    async fn headers(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.json_result(self.manager.cmdj("iHj").await.mcp()?))
    }

    /// Header field summary (`ihj`).
    #[tool(description = "Show a summary of binary header fields as JSON (ihj).")]
    async fn header_fields(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.json_result(self.cmdj_optional("ihj", json!(null)).await?))
    }

    /// Code-signing / entitlements (`iCj`).
    #[tool(
        description = "Show code-signing / signature info such as entitlements. Null when the \
        binary is unsigned or the format has no such data (iCj)."
    )]
    async fn signature_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.json_result(self.cmdj_optional("iCj", json!(null)).await?))
    }

    /// File version info (`iVj`).
    #[tool(description = "Show file version information. Null when not present (iVj).")]
    async fn version_info(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.json_result(self.cmdj_optional("iVj", json!(null)).await?))
    }

    /// Embedded resources (`iRj`).
    #[tool(description = "List embedded resources. Empty when not present (iRj).")]
    async fn resources(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.cmdj_optional("iRj", json!([])).await?, &p))
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
        Ok(self.json_result(self.manager.cmdj(&format!("afsj{suffix}")).await.mcp()?))
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
        Ok(self.json_result(self.manager.cmdj(&format!("afsbj{suffix}")).await.mcp()?))
    }

    // --- FLIRT signatures -------------------------------------------------

    /// List signatures in the sigdb (`Fl`).
    #[tool(
        description = "List the FLIRT signatures available in Rizin's signature database \
        (sigdb), with their architecture, module count, and description (Fl)."
    )]
    async fn flirt_list(&self) -> Result<CallToolResult, ErrorData> {
        let out = self.manager.cmd("Fl").await.mcp()?;
        Ok(self.text_result(if out.trim().is_empty() {
            "No FLIRT signatures found in the sigdb.".to_string()
        } else {
            out
        }))
    }

    /// Apply signatures from the sigdb (`Fa`).
    #[tool(
        description = "Apply FLIRT signatures from Rizin's signature database (sigdb) to the \
        loaded binary, naming matched library functions. An optional filter narrows which \
        signature files are tried. Returns the number of matched functions and the files \
        applied (Fa)."
    )]
    async fn flirt_apply_sigdb(
        &self,
        Parameters(p): Parameters<FlirtSigdbParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // The filter is a substring of the signature files' sigdb paths
        // (e.g. `elf/x86/64`), so it is quoted rather than path-checked.
        let cmd = match &p.filter {
            Some(f) => format!("Fa {}", quote_arg(f).mcp()?),
            None => "Fa".to_string(),
        };
        let before = self.flirt_flag_count().await?;
        let out = self.manager.cmd(&cmd).await.mcp()?;
        let applied = self.flirt_flag_count().await?.saturating_sub(before);
        let files: Vec<&str> = out
            .lines()
            .filter_map(|l| l.strip_prefix("Applying "))
            .collect();
        Ok(self.json_result(json!({
            "matched_functions": applied,
            "signature_files": files,
        })))
    }

    /// Apply a FLIRT signature file (`Fs`).
    #[tool(
        description = "Open a FLIRT signature file (.sig or .pat; a glob is accepted) and apply \
        its signatures to the loaded binary, naming matched functions. Returns the number of \
        matched functions (Fs)."
    )]
    async fn flirt_apply(
        &self,
        Parameters(p): Parameters<FlirtFileParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let path = validate_path(&p.path).mcp()?;
        // `Fs` takes a glob; a plain path must exist.
        if !path.contains(['*', '?', '[']) && !std::path::Path::new(&path).is_file() {
            return Err(RizinError::FileNotFound(path).to_error_data());
        }
        let cmd = format!("Fs {path}");
        let out = self.manager.exec(&cmd).await.mcp()?;
        let out = crate::backend::check(&cmd, out).mcp()?;
        // `Fs` reports success even when it cannot read a file, saying so only
        // in an error message.
        let errors: Vec<&str> = out
            .messages
            .iter()
            .map(String::as_str)
            .filter(|m| m.starts_with("ERROR"))
            .collect();
        if !errors.is_empty() {
            return Err(RizinError::CommandFailed {
                cmd,
                status: CmdStatus::Error,
                detail: errors.join("\n"),
            }
            .to_error_data());
        }
        let matched = out
            .output
            .split_whitespace()
            .nth(1)
            .and_then(|n| n.parse::<u64>().ok());
        Ok(self.json_result(json!({
            "path": path,
            "matched_functions": matched,
            "output": out.output.trim(),
        })))
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
        Ok(self.text_result(out))
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
        Ok(self.text_result(if out.trim().is_empty() {
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
        Ok(self.text_result(out))
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
        Ok(self.text_result(out))
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
        let cmd = format!("plf{suffix}");
        // `plf` fails without saying why (and before Rizin 0.10, a pipe only
        // sees no output); the usual reason is that there is no function.
        let no_function = || {
            RizinError::InvalidArgument {
                arg: p.at.clone().unwrap_or_else(|| "the current seek".into()),
                reason: "no function there (analyze it first, e.g. with analyze_function)".into(),
            }
            .to_error_data()
        };
        let out = match self.manager.cmd(&cmd).await {
            Ok(out) => out,
            Err(RizinError::CommandFailed { detail, .. })
                if detail.is_empty() && !self.has_function(&suffix).await =>
            {
                return Err(no_function());
            }
            Err(e) => return Err(e.to_error_data()),
        };
        if out.trim().is_empty() {
            if !self.has_function(&suffix).await {
                return Err(no_function());
            }
            return Err(RizinError::EmptyOutput { cmd }.to_error_data());
        }
        Ok(self.text_result(out))
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
        Ok(self.json_result(self.manager.cmdj(&format!("aezsej {steps}")).await.mcp()?))
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
        Ok(self.listing(
            self.manager
                .cmdj(&format!("cxj {hex}{suffix}"))
                .await
                .mcp()?,
            &p.page,
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
        Ok(self.listing(
            self.manager
                .cmdj(&format!("cfj {path}{suffix}"))
                .await
                .mcp()?,
            &p.page,
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
        Ok(self.listing(
            self.manager
                .cmdj(&format!("/v{size}j {value}"))
                .await
                .mcp()?,
            &p.page,
        ))
    }

    /// Search for ROP gadgets (`/Rj`).
    #[tool(
        description = "Search for ROP gadgets containing one or more `;`-separated \
        instructions (e.g. 'pop rdi; ret'), matched in order, each as a substring of an \
        instruction; other instructions may sit in between. Set exact=true to only get \
        gadgets made of exactly those instructions. Returns the gadgets with their \
        instructions and addresses (/Rj)."
    )]
    async fn search_rop(
        &self,
        Parameters(p): Parameters<SearchRopParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let fields = parse_rop_query(&p.query).mcp()?;
        let filter = quote_arg(&fields.join(";")).mcp()?;
        let gadgets = self.manager.cmdj(&format!("/Rj {filter}")).await.mcp()?;
        if !p.exact.unwrap_or(false) {
            return Ok(self.listing(gadgets, &p.page));
        }
        let exact: Vec<Value> = gadgets
            .as_array()
            .into_iter()
            .flatten()
            .filter(|g| gadget_matches_exactly(g, &fields))
            .cloned()
            .collect();
        Ok(self.listing(Value::Array(exact), &p.page))
    }

    /// Search for magic/file-format constants (`/mj`).
    #[tool(
        description = "Scan the address space for magic/file-format signatures (embedded files, \
        headers, known constants) and return their locations. Requires Rizin's magic database \
        in its data dir; empty when unavailable (/mj)."
    )]
    async fn search_magic(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.cmdj_optional("/mj", json!([])).await?, &p))
    }

    /// Search for cryptographic material (`/cmj`).
    #[tool(
        description = "Scan for cryptographic material (e.g. AES key schedules, known crypto \
        constants) and return their locations. Empty when none found (/cmj)."
    )]
    async fn search_crypto(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self.listing(self.cmdj_optional("/cmj", json!([])).await?, &p))
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
        Ok(self.text_result(if out.trim().is_empty() {
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
        Ok(self.text_result(if out.trim().is_empty() {
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
        Ok(self.text_result(if out.trim().is_empty() {
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
        Ok(self.text_result(if out.trim().is_empty() {
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
        Ok(self.json_result(self.manager.cmdj("drj").await.mcp()?))
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
        Ok(self.json_result(json!({ "breakpoint_set": loc })))
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
        Ok(self.json_result(json!({ "breakpoint_removed": loc })))
    }

    /// List breakpoints (`dblj`).
    #[tool(description = "List all breakpoints as JSON. Requires an active debug session (dblj).")]
    async fn debug_breakpoints(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(self.listing(self.manager.cmdj("dblj").await.mcp()?, &p))
    }

    /// Backtrace (`dbtj`).
    #[tool(
        description = "Show the call-stack backtrace of the debuggee as JSON. Requires an active \
        debug session (dbtj)."
    )]
    async fn debug_backtrace(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(self.listing(self.manager.cmdj("dbtj").await.mcp()?, &p))
    }

    /// Memory maps (`dmj`).
    #[tool(
        description = "List the debuggee's memory maps (regions, permissions, names) as JSON. \
        Requires an active debug session (dmj)."
    )]
    async fn debug_maps(
        &self,
        Parameters(p): Parameters<PageParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(self.listing(self.manager.cmdj("dmj").await.mcp()?, &p))
    }

    /// Debuggee status (`dij`).
    #[tool(
        description = "Report the debuggee's status as JSON (PID, stop reason, signal, current \
        PC, etc.). Requires an active debug session (dij)."
    )]
    async fn debug_status(&self) -> Result<CallToolResult, ErrorData> {
        self.ensure_debug().await?;
        Ok(self.json_result(self.manager.cmdj("dij").await.mcp()?))
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

#[tool_handler(router = self.tool_router)]
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

/// Make `value` a valid `structuredContent`, which MCP requires to be a JSON
/// object: arrays become `{"items": [...]}`, other non-objects
/// `{"result": ...}`.
fn as_structured(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        Value::Array(_) => json!({ "items": value }),
        other => json!({ "result": other }),
    }
}

/// Build a tool result carrying a JSON object both as compact text (for
/// clients that show text; MCP recommends the serialized structured content)
/// and as structured content (for clients that parse it).
fn structured_result(value: Value) -> CallToolResult {
    let text = serde_json::to_string(&value).unwrap_or_default();
    let mut result = CallToolResult::success(vec![Content::text(text)]);
    result.structured_content = Some(value);
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
        let r = RizinServer::default().json_result(json!({"a": 1, "b": [2, 3]}));
        assert_eq!(r.structured_content, Some(json!({"a": 1, "b": [2, 3]})));
        assert_eq!(r.content.len(), 1);
        assert!(r.is_error.is_none() || r.is_error == Some(false));
    }

    #[test]
    fn oversized_results_are_bounded() {
        let server = RizinServer::new(ServerConfig {
            max_output_bytes: 64,
            ..Default::default()
        });
        let big = json!({ "blob": "x".repeat(100) });
        assert_eq!(server.json_result(big).is_error, Some(true));
        let list = server.json_result(json!(["a".repeat(30), "b".repeat(30), "c"]));
        let sc = list.structured_content.unwrap();
        assert_eq!(sc["returned"], 1);
        assert_eq!(sc["truncated"], true);
        let text = server.text_result("line\n".repeat(50));
        let text = text.content[0].as_text().unwrap().text.clone();
        assert!(text.contains("[output truncated"), "{text}");
    }

    #[test]
    fn structured_content_is_always_an_object() {
        // The TypeScript and Python MCP SDKs reject a call result whose
        // structuredContent is not an object.
        let listing = RizinServer::default()
            .json_result(json!([1, 2]))
            .structured_content
            .unwrap();
        assert_eq!(listing["items"], json!([1, 2]));
        assert_eq!(listing["total"], 2);
        assert_eq!(
            RizinServer::default()
                .json_result(Value::Null)
                .structured_content,
            Some(json!({"result": null}))
        );
        assert_eq!(
            RizinServer::default()
                .json_result(json!("x"))
                .structured_content,
            Some(json!({"result": "x"}))
        );
        let r = RizinServer::default().json_result(json!([]));
        let text = r.content[0].as_text().expect("text").text.clone();
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap(),
            r.structured_content.unwrap()
        );
    }

    fn listed(config: ServerConfig) -> Vec<String> {
        RizinServer::new(config)
            .tool_router
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    #[test]
    fn disabled_capabilities_hide_their_tools() {
        let all = listed(ServerConfig {
            allow_raw: true,
            allow_write: true,
            allow_debug: true,
            ..Default::default()
        });
        let locked = listed(ServerConfig {
            allow_raw: false,
            allow_write: false,
            allow_debug: false,
            ..Default::default()
        });
        for name in RAW_TOOLS
            .iter()
            .chain(WRITE_TOOLS)
            .chain(ANNOTATION_TOOLS)
            .chain(DEBUG_TOOLS)
        {
            assert!(all.iter().any(|n| n == name), "{name} missing");
            assert!(!locked.iter().any(|n| n == name), "{name} offered");
        }
        assert_eq!(
            all.len() - locked.len(),
            RAW_TOOLS.len() + WRITE_TOOLS.len() + ANNOTATION_TOOLS.len() + DEBUG_TOOLS.len()
        );
        // The defaults offer raw commands, but neither writing nor debugging.
        let default = listed(ServerConfig::default());
        assert!(default.iter().any(|n| n == "command"));
        assert!(
            !default
                .iter()
                .any(|n| n == "write_hex" || n == "debug_start")
        );
    }

    #[test]
    fn gated_tool_lists_cover_every_gated_tool() {
        // A new write_*/debug_* tool must be added to its list.
        for t in RizinServer::tool_router().list_all() {
            let name = t.name.as_ref();
            if name.starts_with("debug_") {
                assert!(DEBUG_TOOLS.contains(&name), "{name} not in DEBUG_TOOLS");
            }
            if name.starts_with("write_") {
                assert!(WRITE_TOOLS.contains(&name), "{name} not in WRITE_TOOLS");
            }
        }
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

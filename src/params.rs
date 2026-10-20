// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Typed parameter structs for the MCP tools.
//!
//! Each struct derives [`serde::Deserialize`] and [`schemars::JsonSchema`] so
//! the `#[tool]` macro can both deserialize incoming arguments and publish a
//! JSON Schema for them. Optional fields use `Option<T>` with defaults applied
//! in the tool body, which keeps every field optional in the schema unless it
//! is genuinely required.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::session::AnalysisLevel;

/// Parameters for `open_file`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenFileParams {
    /// Path to the binary/file to open, or a Rizin URI (e.g. `malloc://512`,
    /// `hex://9090`). Use `-` for an empty session with no file open.
    pub path: String,
    /// Analysis depth to run immediately after opening. Defaults to `basic`.
    #[serde(default)]
    pub analysis: Option<AnalysisLevel>,
    /// Open in write mode. Requires the server to be started with
    /// `--allow-write`.
    #[serde(default)]
    pub write: Option<bool>,
}

/// Paging of a listing.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct PageParams {
    /// Index of the first item to return (default 0). Pass the
    /// `next_offset` of the previous page to continue.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum number of items to return (default 100). The server's output
    /// limit may return fewer; `truncated` then says more remain.
    #[serde(default)]
    pub limit: Option<u64>,
}

/// Parameters for `open_data`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenDataParams {
    /// The file's bytes, encoded as `encoding` says.
    pub data: String,
    /// `base64` (default) or `hex`.
    #[serde(default)]
    pub encoding: Option<String>,
    /// A file name to show for it, e.g. `sample.exe`. Defaults to
    /// `sample.bin`.
    #[serde(default)]
    pub name: Option<String>,
    /// Analysis depth to run immediately after opening. Defaults to `basic`.
    #[serde(default)]
    pub analysis: Option<AnalysisLevel>,
    /// Open in write mode (changes stay in the temporary copy). Requires the
    /// server to be started with `--allow-write`.
    #[serde(default)]
    pub write: Option<bool>,
}

/// Parameters for tools that operate at an optional location.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct AtParams {
    /// Optional location: a hex address (e.g. `0x401000`) or a flag/symbol name
    /// (e.g. `main`, `sym.main`, `entry0`). Defaults to the current seek.
    #[serde(default)]
    pub at: Option<String>,
}

/// Parameters for instruction-count disassembly.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DisasmParams {
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of instructions to disassemble (default 32).
    #[serde(default)]
    pub count: Option<u64>,
}

/// Parameters for hexdumps.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HexdumpParams {
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of bytes to dump (default 64).
    #[serde(default)]
    pub count: Option<u64>,
}

/// Parameters for raw byte reads.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ReadBytesParams {
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of bytes to read (default 64).
    #[serde(default)]
    pub count: Option<u64>,
    /// Output encoding: `hex` (default) or `base64`.
    #[serde(default)]
    pub encoding: Option<String>,
}

/// Parameters for instruction-level analysis.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct InstructionAnalysisParams {
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of instructions to analyse (default 1).
    #[serde(default)]
    pub count: Option<u64>,
}

/// Parameters for tools requiring an explicit target address.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressParams {
    /// Target address (hex like `0x401000`) or a flag/symbol name.
    pub address: String,
}

/// Parameters for the cross-reference listings.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefParams {
    /// Target address (hex like `0x401000`) or a flag/symbol name.
    pub address: String,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `disassemble_function`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FunctionPageParams {
    /// Optional location: a hex address (e.g. `0x401000`) or a flag/symbol name
    /// (e.g. `main`, `sym.main`, `entry0`). Defaults to the current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Paging of the function's instructions.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `function_summary`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionSummaryParams {
    /// A location inside the function (hex address or flag/symbol name).
    pub at: String,
    /// Maximum number of callers, callees and strings listed (default 20,
    /// at most 100).
    #[serde(default)]
    pub max_items: Option<u64>,
    /// Number of decompiled lines included (default 30, at most 500).
    #[serde(default)]
    pub snippet_lines: Option<u64>,
}

/// Parameters for `analyze`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct AnalyzeParams {
    /// Analysis depth to run. Defaults to `full` (`aaa`).
    #[serde(default)]
    pub level: Option<AnalysisLevel>,
}

/// Parameters for the raw command tools.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommandParams {
    /// A single Rizin command line. Chain multiple commands with `;`
    /// (embedded newlines are rejected).
    pub command: String,
}

/// Parameters for `list_strings`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct StringsParams {
    /// Scan the whole file (`izz`) rather than only data sections (`iz`).
    /// Defaults to `true`.
    #[serde(default)]
    pub all: Option<bool>,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `list_flags`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FlagsParams {
    /// Restrict to a single flag space (e.g. `symbols`, `strings`, `imports`).
    #[serde(default)]
    pub space: Option<String>,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `search_string`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchStringParams {
    /// String to search for. Matched as its raw UTF-8 bytes, so any characters
    /// are safe.
    pub query: String,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `search_bytes`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchBytesParams {
    /// Hex byte pattern, e.g. `90 90`, `9090`, or `0xdeadbeef`.
    pub hex: String,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `rename_function`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFunctionParams {
    /// A location inside the function (hex address or flag/symbol name).
    pub at: String,
    /// The new name, e.g. `parse_args`.
    pub name: String,
}

/// Parameters for `rename_variable`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameVariableParams {
    /// A location inside the function (hex address or flag/symbol name).
    pub at: String,
    /// The current name of the argument or local variable (see
    /// `function_variables`).
    pub old_name: String,
    /// The new name.
    pub new_name: String,
}

/// Parameters for `set_comment`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetCommentParams {
    /// Address (hex) or flag/symbol name.
    pub address: String,
    /// The comment text (one line).
    pub text: String,
    /// Append to an existing comment instead of replacing it. Defaults to
    /// `false`.
    #[serde(default)]
    pub append: Option<bool>,
}

/// Parameters for `set_flag`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetFlagParams {
    /// Flag name, made of `[A-Za-z0-9_.:]`, e.g. `crypto.key_schedule`.
    pub name: String,
    /// Address (hex) or flag/symbol name the flag marks.
    pub address: String,
    /// Size in bytes of the flagged item. Defaults to 1.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Parameters for `remove_flag`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlagNameParams {
    /// Flag name.
    pub name: String,
}

/// Parameters for `set_function_signature`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetSignatureParams {
    /// A location inside the function (hex address or flag/symbol name).
    pub at: String,
    /// C prototype, e.g. `int parse_args(int argc, char **argv)`.
    pub signature: String,
}

/// Parameters for `save_project`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SaveProjectParams {
    /// Where to write the Rizin project (`.rzdb`), e.g. `/tmp/sample.rzdb`.
    pub path: String,
}

/// Parameters for `write_hex` (write mode only).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteHexParams {
    /// Destination address (hex) or flag/symbol name.
    pub address: String,
    /// Hex bytes to write, e.g. `90 90` or `9090`.
    pub hex: String,
}

/// Parameters for `write_string` (write mode only).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteStringParams {
    /// Destination address (hex) or flag/symbol name.
    pub address: String,
    /// Text to write; written as its raw UTF-8 bytes.
    pub text: String,
}

/// Parameters for `write_assembly` (write mode only).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteAssemblyParams {
    /// Destination address (hex) or flag/symbol name.
    pub address: String,
    /// Assembly to assemble and write, e.g. `mov eax, 1`. Separate several
    /// instructions with `;` or newlines. Assembled for the destination
    /// address, so relative branches are encoded for it.
    pub assembly: String,
}

// --- Hashing ---------------------------------------------------------------

/// Parameters for `hash`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HashParams {
    /// Digest/checksum/entropy algorithm, e.g. `md5`, `sha256`, `crc32`,
    /// `entropy`. See `hash_algorithms` for the full list.
    pub algo: String,
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of bytes to hash. Defaults to the current block size (256).
    #[serde(default)]
    pub size: Option<u64>,
}

// --- Function signatures ---------------------------------------------------

/// Parameters for value search.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchValueParams {
    /// Integer value to search for, in decimal (`1234`) or hex (`0x401000`).
    pub value: String,
    /// Width in bytes: 1, 2, 4 (default) or 8.
    #[serde(default)]
    pub size: Option<u64>,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for ROP gadget search.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchRopParams {
    /// Gadget to look for, as one or more `;`-separated instructions, e.g.
    /// `pop rdi; ret` or `pop rdi`. Each instruction matches as a substring
    /// (`pop r` matches `pop rdi`), in order; other instructions may come in
    /// between unless `exact` is set.
    pub query: String,
    /// Only return gadgets made of exactly these instructions, in this order,
    /// each matching in full (ignoring case and spacing). Defaults to `false`.
    #[serde(default)]
    pub exact: Option<bool>,
    /// Paging.
    #[serde(flatten)]
    pub page: PageParams,
}

// --- Diffing ---------------------------------------------------------------

/// Parameters for `compare_bytes`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareBytesParams {
    /// Hex byte pattern to compare against, e.g. `90 90` or `9090`.
    pub hex: String,
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Paging of the differences.
    #[serde(flatten)]
    pub page: PageParams,
}

/// Parameters for `compare_file`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareFileParams {
    /// Path to the other file whose contents are compared against the bytes at
    /// the location.
    pub path: String,
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Paging of the differences.
    #[serde(flatten)]
    pub page: PageParams,
}

// --- RzIL ------------------------------------------------------------------

/// Parameters for `emulate_il`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EmulateIlParams {
    /// Optional location to start emulation (hex address or flag/symbol).
    /// Defaults to the current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Number of instructions to step (default 1).
    #[serde(default)]
    pub steps: Option<u64>,
}

// --- Debugging -------------------------------------------------------------

/// Parameters for `debug_step`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DebugStepParams {
    /// Number of instructions to step (default 1).
    #[serde(default)]
    pub count: Option<u64>,
}

// --- Decompilation & plugins -----------------------------------------------

/// Parameters for `decompile`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct DecompileParams {
    /// Optional location (hex address or flag/symbol). Defaults to current seek.
    #[serde(default)]
    pub at: Option<String>,
    /// Which decompiler to use: `auto` (default; tries ghidra, then jsdec, then
    /// pseudo-disassembly), `ghidra` (rz-ghidra `pdg`), `jsdec` (`pdd`), or
    /// `pseudo` (built-in pseudo-disassembly, always available).
    #[serde(default)]
    pub decompiler: Option<String>,
}

/// Parameters for FLIRT tools that take a signature file path.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlirtFileParams {
    /// Path to a FLIRT signature file (`.sig` or `.pat`).
    pub path: String,
}

/// Parameters for `flirt_apply_sigdb`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FlirtSigdbParams {
    /// Optional filter selecting the signature files whose sigdb path contains
    /// it (e.g. `elf/x86/64` or `libc`); without one, the files matching the
    /// binary's format, architecture, and bits are applied.
    #[serde(default)]
    pub filter: Option<String>,
}

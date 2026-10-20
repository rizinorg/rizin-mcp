# rizin-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server, written
in pure Rust, that exposes the [Rizin](https://rizin.re) reverse-engineering
framework to MCP-capable clients (Claude Desktop, IDE assistants, etc.).

It runs Rizin **in-process** through its C library by default — or, optionally,
by driving a `rizin` subprocess over the pipe interface — and surfaces ~74
focused tools (binary info & headers, disassembly, decompilation via rz-ghidra
or jsdec, cross-references, strings, hashing, search, byte diffing, function
signatures & FLIRT, RzIL emulation, optional patching, and optional debugging),
9 resources, and 3 guided prompts.

Built on the official [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk)
(`rmcp`). Tested end-to-end against Rizin 0.9.0.

## Backends

The server can talk to Rizin two ways, selected with `--transport`:

| | `api` (default) | `pipe` |
|---|---|---|
| How | Links Rizin's C libraries (`librz_core` …) and runs commands against an in-process `RzCore` | Spawns `rizin -q0` and talks over stdin/stdout |
| Speed | Fast — no process spawn, no IPC | Slower |
| Build needs | Rizin **dev libraries** (via `pkg-config`) | nothing Rizin at build time |
| Run needs | nothing external | a `rizin` **binary** |
| Hard-cancel a stuck command | No (in-process C call can't be force-killed) | Yes (the process is killed on timeout) |

Both run the exact same Rizin commands and return identical JSON. On this
machine, opening `/bin/ls` and issuing commands measured roughly:

```
                          api        pipe    api advantage
open + close (avg)    10.8 ms     60.7 ms        ~5.6x
command   (avg)       24.7 µs     79.3 µs        ~3.2x
```

(Reproduce with `cargo run --release --example bench`.)

Use `pipe` if you cannot link Rizin, or if you enable the raw `command` tool /
debugger and want a hard timeout that can kill a wedged command.

## Features

All tools return structured JSON (via Rizin's `j`-suffixed commands) in addition
to a text rendering, so clients can parse results directly.

**Session**
- `open_file` — open a binary/file or Rizin URI (`malloc://`, `hex://`, …) and run analysis
- `close_file`, `session_info`, `analyze` (none/basic/full/experimental), `seek`
- `command`, `command_json` — raw Rizin passthrough (see *Security* below)

**Binary information**
- `binary_info`, `entrypoints`, `sections`, `segments`, `relocations`
- `imports`, `exports`, `symbols`, `libraries`, `classes`
- `list_strings`, `list_flags`, `flag_spaces`
- `headers` (structured `iH`), `header_fields` (`ih`), `signature_info`
  (code-signing/entitlements), `version_info`, `resources`

**Analysis & functions**
- `list_functions`, `function_info`, `function_variables`, `analyze_function`
- `xrefs_to`, `xrefs_from`, `function_graph`

**Disassembly & decompilation**
- `disassemble`, `disassemble_function`
- `decompile` — pseudo-C via rz-ghidra (`pdg`) or jsdec (`pdd`) when installed,
  else built-in pseudo-disassembly; the engine used is reported in
  `structuredContent`. `decompilers` reports which engines are available.
- `hexdump`, `read_bytes` (hex or base64), `instruction_analysis`

**Function signatures & FLIRT**
- `function_signature` (C prototype), `function_signature_bytes` (signature
  bytes + mask)
- `flirt_list` (signatures in the sigdb), `flirt_apply_sigdb` (apply from the
  sigdb), `flirt_apply` (apply a `.sig`/`.pat` file), `flirt_dump` (inspect a
  signature file), `flirt_create` (write a signature file — needs
  `--allow-write`)
- `silhouette`, `silhouette_test` — fetch & apply symbols from a Rizin
  Silhouette server (needs the rz-silhouette plugin and configuration)

**Hashing**
- `hash` (md5/sha256/crc32/entropy/… over a region), `hash_algorithms`

**RzIL** (Rizin's intermediate language)
- `il_function` (lift a function to RzIL), `emulate_il` (step the RzIL VM and
  report register/PC/memory changes)

**Searching**
- `search_string`, `search_bytes`, `search_value` (1/2/4/8-byte integers),
  `search_rop` (ROP gadgets), `search_magic`, `search_crypto`

**Diffing**
- `compare_bytes` (against a hex pattern), `compare_file` (against another file)

**Debugging** (disabled by default — see *Security*)
- `debug_start`/`debug_stop`, `debug_continue`, `debug_step`,
  `debug_registers`, `debug_breakpoint`/`debug_breakpoint_remove`,
  `debug_breakpoints`, `debug_backtrace`, `debug_maps`, `debug_status`

**Writing** (disabled by default — see *Security*)
- `write_hex`, `write_string`, `write_assembly`

**Resources:** `rizin://info`, `rizin://functions`, `rizin://strings`,
`rizin://sections`, `rizin://imports`, `rizin://exports`, `rizin://symbols`,
`rizin://entrypoints`, `rizin://headers`, plus the template
`rizin://disasm/{address}`.

**Prompts:** `triage_binary`, `analyze_function`, `find_vulnerabilities`.

### Notes on a few tools

- **Decompilation.** Rizin 0.9 has no bundled C decompiler. `decompile` uses
  whichever decompiler plugin is installed — rz-ghidra (`pdg`) or jsdec (`pdd`) —
  and otherwise falls back to built-in pseudo-disassembly (an `asm.pseudo`
  rendering of the function, applied via a temporary eval so no global state
  changes). `decompiler` can force `ghidra`, `jsdec`, or `pseudo`; `decompilers`
  reports what is available. See *External plugins* below.
- **FLIRT.** The `flirt_*` tools wrap Rizin's built-in `F` command family:
  `flirt_list`/`flirt_apply_sigdb` work against the signature database (sigdb)
  shipped with Rizin, while `flirt_apply`/`flirt_dump`/`flirt_create` work with
  individual `.sig`/`.pat` files. (`function_signature_bytes` is unrelated to
  FLIRT — it just returns a function's masked byte pattern.)
- **Silhouette.** `silhouette`/`silhouette_test` drive the
  [rz-silhouette](https://github.com/rizinorg/rz-silhouette) plugin's `sil`
  command, which fetches symbols/hints from a Rizin Silhouette server. It needs
  the plugin installed and `silhouette.{enable,host,port,psk}` configured (set
  them via the `command` tool or a `.rizinrc`).
- **`search_magic`** needs Rizin's magic database from its data dir. With a
  normally-installed `rizin` (pipe backend, or the `api` backend when the data
  dir is found) it works; on a bare embedded core it returns an empty list.
- **`signature_info`/`version_info`/`resources`** return `null`/`[]` for formats
  that don't carry that data (e.g. a plain ELF is unsigned), rather than erroring.

## Errors

Every tool checks the status Rizin reports for its commands, so a command
that failed is never mistaken for one that succeeded with no output:

- A failure reported by Rizin becomes a JSON-RPC error with code `-32001`
  (`rizin command failed`), whose message carries Rizin's own diagnostics
  (e.g. `Cannot assemble 'mov'`) and whose `data` holds `command`, `status`
  (`ERROR`, `WRONG_ARGS`, `INVALID`, `NONEXISTINGCMD`) and `detail`.
- The raw `command` tool returns a tool result with `isError: true` instead,
  keeping whatever the line printed before it failed.
- Invalid tool arguments stay `-32602` (`invalid params`).

The diagnostics come from Rizin's log in-process, and from the `rizin`
process's stderr with the `pipe` backend (on Unix). Exact statuses need
Rizin 0.10 (`rz_core_cmd_str_status()` and the `_s` command): with older
Rizin the `api` backend only knows that a command failed (`FAILED`), and the
`pipe` backend cannot tell (`UNKNOWN`), so it judges commands by their output
as before.

## External plugins

Rizin loads core plugins from its plugin directories automatically, so once a
plugin is installed both backends pick it up — the `api` backend (it links the
same `librz`) and the `pipe` backend (the spawned `rizin`) alike. These optional
plugins light up the tools above:

- [rz-ghidra](https://github.com/rizinorg/rz-ghidra/) — Ghidra-based decompiler
  (`pdg`), the highest-quality engine for `decompile`.
- [jsdec](https://github.com/rizinorg/jsdec/) — JavaScript-based pseudo-C
  decompiler (`pdd`).
- [rz-silhouette](https://github.com/rizinorg/rz-silhouette) — client for a
  Rizin Silhouette symbol server (`sil`), powering the `silhouette` tools.

Install them with Rizin's package manager (`rz-pm install rz-ghidra jsdec
rz-silhouette`) or from source; nothing in this server needs rebuilding. Run
`decompilers` to confirm which decompiler engines are visible.

## Requirements

- Rust 1.87+ (2024 edition) to build, and a C compiler for the `api`
  backend (a few lines of C route Rizin's log messages to the server).
- **For the default `api` backend:** Rizin's development libraries discoverable
  via `pkg-config` (i.e. `pkg-config --exists rz_core` succeeds). Install Rizin
  with your package manager's `-dev`/`-devel` package, `meson install` from
  source, or point `PKG_CONFIG_PATH` at a Rizin build's `lib/pkgconfig`.
- **For the `pipe` backend:** a `rizin` executable (0.9.0 recommended) on your
  `PATH`, or pass `--rizin /path/to/rizin`. The `api` backend needs no binary.
- Decompilation via `decompile` is best with the
  [rz-ghidra](https://github.com/rizinorg/rz-ghidra/) (`pdg`) or
  [jsdec](https://github.com/rizinorg/jsdec/) (`pdd`) plugin installed; without
  either, `decompile` falls back to built-in pseudo-disassembly. See *External
  plugins*.

## Build

Default build (in-process `api` backend; locates Rizin via `pkg-config`):

```sh
cargo build --release
# binary at target/release/rizin-mcp
```

If Rizin lives somewhere non-standard, or you want to **static-link** it (e.g.
against a portable build that ships `librz_*.a`):

```sh
export PKG_CONFIG_PATH=/path/to/rizin/lib/pkgconfig
export RIZIN_STATIC=1            # link the static archives instead of .so
cargo build --release
```

On Debian/Ubuntu-style hosts Meson installs into a multiarch library
directory even for a custom prefix, so the `.pc` files of a
`meson setup --prefix=$HOME/.local/rizin` install live in
`$HOME/.local/rizin/lib/x86_64-linux-gnu/pkgconfig`. The build script trusts
only a library directory that really contains `librz_core`, and fails with the
directories it tried otherwise.

A dynamically linked build records Rizin's library directory as an rpath
(`RUNPATH`), so the binary starts without `LD_LIBRARY_PATH` — which an MCP
client launching a bare `"command"` cannot set. No rpath is added for the
loader's default directories (`/usr/lib`, `/usr/lib/<triplet>`, …); set
`RIZIN_RPATH=0` to never add one, e.g. for distribution packages, and make
the libraries findable through `ldconfig` or `LD_LIBRARY_PATH` instead.

To build **without** the C library at all (pipe-only; needs no Rizin to
compile, only a `rizin` binary at run time):

```sh
cargo build --release --no-default-features
```

## Usage

The server speaks JSON-RPC over **stdio**; an MCP client launches it as a
subprocess. You can also run it directly for a smoke test:

```sh
# Optionally open a file at startup:
rizin-mcp /bin/ls --analysis basic
```

### Claude Desktop

Add to your `claude_desktop_config.json` (the default `api` backend needs no
`rizin` binary):

```json
{
  "mcpServers": {
    "rizin": {
      "command": "/absolute/path/to/target/release/rizin-mcp"
    }
  }
}
```

To use the pipe backend instead, set `"args": ["--transport", "pipe", "--rizin", "/usr/bin/rizin"]`.
Then ask the assistant to open a binary and explore it. To allow patching, add
`"--allow-write"` to `args` (and open files with `write: true`).

### CLI options

```
rizin-mcp [FILE] [OPTIONS]

  FILE                        Optional binary/file (or Rizin URI) to open at startup
  --transport <BACKEND>       api | pipe (default: api when compiled in, else pipe)
  --rizin <PATH>              Path/name of the rizin executable (pipe backend only)
  --analysis <LEVEL>          none | basic | full | experimental (default: basic)
  --allow-write               Permit write mode and the write_* tools
  --allow-debug               Permit the debug_* tools (executes the target!)
  --no-raw                    Disable the raw `command` / `command_json` tools
  --command-timeout <SECS>    Per-command timeout (default: 120)
  --startup-timeout <SECS>    Startup/analysis timeout (default: 60)
```

Logging goes to **stderr** (stdout is the protocol channel). Control verbosity
with `RIZIN_MCP_LOG`, e.g. `RIZIN_MCP_LOG=debug`.

## Security

This server can run a powerful binary-analysis engine on attacker-supplied input.
Two capabilities are gated:

- **Raw commands** (`command`, `command_json`) expose the *entire* Rizin command
  surface — including the debugger and shell escapes (`!`) — which is effectively
  arbitrary code execution. They are **on by default** (to maximize usefulness);
  disable them with `--no-raw` for untrusted contexts.
- **Writing** (`write_hex`, `write_string`, `write_assembly`, and opening with
  `write: true`) can modify the in-memory buffer and, for files opened writable,
  the file on disk. This is **off by default**; enable with `--allow-write`.
- **Debugging** (`debug_*`) **runs the target binary** under a debugger, which is
  by definition arbitrary code execution. It is **off by default**; enable with
  `--allow-debug`, and only on binaries you trust or in a sandbox. Prefer
  `--transport pipe` for debugging: the debuggee then runs under the isolated
  `rizin` subprocess (whose stdout can't corrupt the protocol stream, and which
  can be force-killed if it hangs), whereas the in-process `api` backend shares
  the server's file descriptors and cannot hard-cancel a wedged debuggee.

Addresses and flag names passed to tools are validated against a strict
character set, and every command is checked for the NUL byte (and, for the pipe
backend, the newline) that would corrupt command framing, to avoid command
injection through arguments.

Run the server with the least privilege necessary, and prefer analyzing untrusted
samples in a sandbox or container.

## Development

```sh
# Default (api) build — needs Rizin dev libs on PKG_CONFIG_PATH:
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test                       # unit + property tests, and integration tests
                                 # (the api backend is exercised in-process)

# Integration tests also cover the pipe backend when a rizin binary is given:
RIZIN_MCP_TEST_BINARY=/path/to/rizin cargo test --test integration

# Pipe-only build (no Rizin libraries required to compile):
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --no-default-features

# Compare backend latency:
RIZIN_MCP_BENCH_RIZIN=/path/to/rizin cargo run --release --example bench
```

CI (`.github/workflows/ci.yml`) builds Rizin `dev` and the latest release
into a user prefix — the multiarch layout of the documented install path —
and builds, lints, starts (without `LD_LIBRARY_PATH`), and tests the server
against each; it also runs nightly to catch drift on Rizin's `dev` branch.

The end-to-end tests run against **both** backends: the in-process `api` backend
(always available when compiled in) and the `pipe` backend (skipped if a `rizin`
process can't be launched).

The codebase is split into small modules: `backend` (transport dispatch),
`rzcore`/`ffi` (the in-process C backend), `pipe` (async Rizin pipe + framing),
`session` (lifecycle), `params` (tool schemas), `server` (tools/resources/prompts),
`util` (validation/hex), `config`, and `error`. Pure helpers and the pipe framing
are covered by property tests; the end-to-end tests cover both backends.

## License

GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later). See
[`LICENSE`](LICENSE) (and [`COPYING`](COPYING) for the GPLv3 text it builds on).

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! # rizin-mcp
//!
//! A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the
//! [Rizin](https://rizin.re) reverse-engineering framework as a set of MCP tools,
//! resources, and prompts.
//!
//! The server can talk to Rizin two ways:
//!
//! * **In-process API** (default, requires the `api` feature): Rizin's C
//!   libraries are linked in and commands run against an `RzCore` in the same
//!   process. This avoids the cost of spawning a process and shuffling bytes
//!   over a pipe.
//! * **Pipe**: it spawns `rizin -q0` and talks to it over stdin/stdout exactly
//!   like the official `rz-pipe` bindings — writing a command and reading the
//!   result up to a terminating `NUL`. This needs no Rizin libraries at build
//!   time and supports hard cancellation of a stuck command.
//!
//! Either way, most tools use Rizin's JSON command variants (the `j` suffix,
//! e.g. `aflj`, `pdfj`, `izzj`) so results come back as structured data.
//!
//! ## Module layout
//!
//! * [`config`] — runtime configuration ([`config::ServerConfig`],
//!   [`config::Transport`]).
//! * [`error`] — the crate error type and conversion into MCP errors.
//! * [`backend`] — transport dispatch ([`backend::Backend`]).
//! * [`pipe`] — the low-level async Rizin pipe ([`pipe::RizinPipe`]).
//! * `ffi`/`rzcore` — the in-process C backend (only with the `api` feature).
//! * [`session`] — session/lifecycle management ([`session::SessionManager`]).
//! * [`status`] — command status and diagnostics reported by Rizin.
//! * [`params`] — typed tool-parameter structs (with JSON schemas).
//! * [`server`] — the MCP server and all tools/resources/prompts
//!   ([`server::RizinServer`]).
//! * [`util`] — small pure helpers (argument validation, hex encoding).
//!
//! This crate is licensed under the GNU Lesser General Public License v3.0 or later.

pub mod backend;
pub mod config;
pub mod error;
#[cfg(feature = "api")]
pub mod ffi;
pub mod params;
pub mod pipe;
#[cfg(feature = "api")]
pub mod rzcore;
pub mod server;
pub mod session;
pub mod status;
pub mod util;

pub use config::ServerConfig;
pub use error::RizinError;
pub use server::RizinServer;

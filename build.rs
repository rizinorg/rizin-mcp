// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Build script: locate and link the Rizin C libraries for the `api` backend.
//!
//! Rizin is discovered through `pkg-config` (honouring `PKG_CONFIG_PATH`), so
//! this works against a system install or a relocated/portable build. Two
//! linking modes are supported:
//!
//! * **Dynamic** (default): link the shared `librz_core` (and any sibling
//!   `librz_*` shared objects present), letting the dynamic loader resolve the
//!   rest. This is the normal case for a packaged Rizin install.
//! * **Static** (`RIZIN_STATIC=1`): link every `librz_*.a` found in the
//!   library directory, wrapped in a `--start-group`/`--end-group` so the
//!   circular dependencies among the Rizin archives resolve.
//!
//! A dynamically linked binary gets an rpath to Rizin's library directory, so
//! it starts without `LD_LIBRARY_PATH` when Rizin lives in a custom prefix.
//! Directories the dynamic loader searches anyway get none; set
//! `RIZIN_RPATH=0` to never embed one (e.g. for distribution packages).
//!
//! When the `api` feature is disabled, this script does nothing (the server is
//! built pipe-only and needs no Rizin libraries to compile).

use std::path::{Path, PathBuf};
use std::process::Command;

fn pkg_config(args: &[&str]) -> Option<String> {
    let out = Command::new("pkg-config").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The `librz_core` file in `libdir` matching the wanted link mode, if any.
fn core_library(libdir: &Path, shared_suffix: &str) -> Option<PathBuf> {
    [format!("librz_core{shared_suffix}"), "librz_core.a".into()]
        .into_iter()
        .map(|name| libdir.join(name))
        .find(|p| p.exists())
}

/// Resolve Rizin's library directory, trusting only a directory that really
/// holds `librz_core`.
///
/// The plain `libdir` variable comes first: it is what Meson wrote at install
/// time. `--define-prefix` is only a fallback for relocated builds, since it
/// rebuilds the prefix assuming a `<prefix>/lib/pkgconfig` layout and yields
/// `<prefix>/lib/lib/<triplet>` for a multiarch `lib/<triplet>/pkgconfig` one.
fn rizin_libdir(shared_suffix: &str) -> PathBuf {
    let candidates = [
        pkg_config(&["--variable=libdir", "rz_core"]),
        pkg_config(&["--define-prefix", "--variable=libdir", "rz_core"]),
    ];
    if candidates.iter().all(Option::is_none) {
        panic!(
            "could not locate Rizin via pkg-config (looked for `rz_core`).\n\
             Install the Rizin development libraries, or point PKG_CONFIG_PATH \
             at the pkgconfig directory of a Rizin install (e.g. \
             <prefix>/lib/pkgconfig or <prefix>/lib/<triplet>/pkgconfig).\n\
             To build without the C library, use --no-default-features."
        );
    }
    let mut tried = Vec::new();
    for dir in candidates.into_iter().flatten() {
        let dir = PathBuf::from(dir);
        if core_library(&dir, shared_suffix).is_some() {
            return dir;
        }
        if !tried.contains(&dir) {
            tried.push(dir);
        }
    }
    panic!(
        "pkg-config found `rz_core`, but no librz_core{shared_suffix} or librz_core.a \
         exists in the library directory it reports ({}). Is the Rizin install \
         complete, and does PKG_CONFIG_PATH point at the right install?",
        tried
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Whether `libdir` is one the dynamic loader searches without an rpath:
/// `/lib`, `/usr/lib`, their `64` variants, and multiarch subdirectories such
/// as `/usr/lib/x86_64-linux-gnu`.
fn is_default_libdir(libdir: &Path) -> bool {
    let top = |p: &Path| {
        ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .iter()
            .any(|d| p == Path::new(d))
    };
    top(libdir)
        || (libdir.parent().is_some_and(top)
            && libdir
                .file_name()
                .is_some_and(|n| n.to_string_lossy().contains("-linux-")))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for var in [
        "RIZIN_STATIC",
        "RIZIN_RPATH",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // Nothing to link for a pipe-only build.
    if std::env::var_os("CARGO_FEATURE_API").is_none() {
        return;
    }

    // Shared libraries use a platform-specific suffix: `.dylib` on macOS, `.so`
    // on other Unix targets. A build script must consult the *target* through
    // `CARGO_CFG_TARGET_OS` (not the host's `cfg!`), so this stays correct when
    // cross-compiling.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let shared_suffix = if target_os == "macos" {
        ".dylib"
    } else {
        ".so"
    };

    let libdir = rizin_libdir(shared_suffix);
    println!("cargo:rustc-link-search=native={}", libdir.display());
    // A Rizin (re)install must refresh the link setup computed here.
    if let Some(core) = core_library(&libdir, shared_suffix) {
        println!("cargo:rerun-if-changed={}", core.display());
    }
    if let Some(pcdir) = pkg_config(&["--variable=pcfiledir", "rz_core"]) {
        println!("cargo:rerun-if-changed={pcdir}/rz_core.pc");
    }

    let want_static = std::env::var("RIZIN_STATIC").map(|v| v == "1").unwrap_or(false)
        // If only static archives are available, link statically.
        || (!libdir.join(format!("librz_core{shared_suffix}")).exists()
            && libdir.join("librz_core.a").exists());

    // Discover all Rizin component libraries in the library directory.
    //
    // Static archives are always `.a`; shared objects use `shared_suffix`. On
    // macOS the installed shared object may also be versioned
    // (`librz_util.1.0.dylib`), so an exact `strip_suffix` would miss it. Match
    // any file ending in the suffix and take the stem up to the first dot, which
    // collapses the unversioned symlink and any versioned siblings onto the same
    // `rz_<component>` name (deduplicated below).
    let suffix = if want_static { ".a" } else { shared_suffix };
    let entries = std::fs::read_dir(&libdir).unwrap_or_else(|e| {
        panic!(
            "cannot list the Rizin library directory {}: {e}",
            libdir.display()
        )
    });
    let mut libs: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix("lib") else {
            continue;
        };
        if !rest.ends_with(suffix) {
            continue;
        }
        // e.g. `rz_util.1.0.dylib` -> `rz_util`, `rz_core.so` -> `rz_core`.
        let stem = rest.split('.').next().unwrap_or(rest);
        if stem.starts_with("rz_") {
            libs.push(stem.to_string());
        }
    }
    libs.sort();
    libs.dedup();
    // Linking `rz_core` alone leaves symbols such as `rz_mem_free` (in
    // `rz_util`) unresolved, so a partial set is an error, not a fallback.
    if !libs.iter().any(|l| l == "rz_core") || !libs.iter().any(|l| l == "rz_util") {
        panic!(
            "no complete set of Rizin libraries (*{suffix}) in {}: found [{}], \
             need at least rz_core and rz_util",
            libdir.display(),
            libs.join(", ")
        );
    }

    if want_static {
        // Circular dependencies among the static archives require a group.
        println!("cargo:rustc-link-arg=-Wl,--start-group");
        for l in &libs {
            println!("cargo:rustc-link-arg=-l{l}");
        }
        println!("cargo:rustc-link-arg=-Wl,--end-group");
        // System libraries the archives depend on.
        for sys in ["m", "dl", "pthread", "rt"] {
            println!("cargo:rustc-link-lib=dylib={sys}");
        }
    } else {
        for l in &libs {
            println!("cargo:rustc-link-lib=dylib={l}");
        }
        // MCP clients start the server from a bare command line, where no
        // LD_LIBRARY_PATH can be set.
        let rpath_wanted = std::env::var("RIZIN_RPATH").map_or(true, |v| v != "0");
        if rpath_wanted && !is_default_libdir(&libdir) {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", libdir.display());
        }
    }
}

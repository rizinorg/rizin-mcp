// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Small, pure helpers for validating arguments and encoding bytes.
//!
//! These functions are deliberately free of I/O so they can be unit- and
//! property-tested in isolation.

use crate::error::RizinError;

/// Characters permitted inside an address/flag expression passed to a Rizin
/// `@` seek modifier. This intentionally excludes whitespace and shell-like
/// metacharacters so that a location can be concatenated into a command line
/// without changing its parse.
fn is_location_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '$' | '+' | '-')
}

/// Validate a location (address or flag/symbol name) and return it trimmed.
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] if the location is empty, too long,
/// or contains characters outside `[A-Za-z0-9_.:$+-]`.
pub fn validate_location(at: &str) -> Result<String, RizinError> {
    let trimmed = at.trim();
    if trimmed.is_empty() {
        return Err(RizinError::InvalidArgument {
            arg: at.to_string(),
            reason: "location is empty".into(),
        });
    }
    if trimmed.len() > 256 {
        return Err(RizinError::InvalidArgument {
            arg: at.to_string(),
            reason: "location is too long (max 256 chars)".into(),
        });
    }
    if !trimmed.chars().all(is_location_char) {
        return Err(RizinError::InvalidArgument {
            arg: at.to_string(),
            reason: "only [A-Za-z0-9_.:$+-] are allowed in addresses/flags".into(),
        });
    }
    Ok(trimmed.to_string())
}

/// Build a ` @ <location>` suffix for an optional location, or an empty string
/// when no location is given.
///
/// # Errors
/// Propagates [`validate_location`] failures.
pub fn at_suffix(at: &Option<String>) -> Result<String, RizinError> {
    match at {
        None => Ok(String::new()),
        Some(a) => Ok(format!(" @ {}", validate_location(a)?)),
    }
}

/// Validate a hash/checksum algorithm name (e.g. `md5`, `sha256`, `crc32`).
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] if it is empty or contains anything
/// outside `[A-Za-z0-9_-]`.
pub fn validate_algo(algo: &str) -> Result<String, RizinError> {
    let trimmed = algo.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        return Err(RizinError::InvalidArgument {
            arg: algo.to_string(),
            reason: "algorithm name is empty or too long".into(),
        });
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(RizinError::InvalidArgument {
            arg: algo.to_string(),
            reason: "only [A-Za-z0-9_-] are allowed in an algorithm name".into(),
        });
    }
    Ok(trimmed.to_string())
}

/// Validate an integer literal in decimal or `0x` hexadecimal form.
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] if it is not a plain decimal or
/// `0x`-prefixed hexadecimal number.
pub fn validate_number(value: &str) -> Result<String, RizinError> {
    let trimmed = value.trim();
    let valid = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit())
    };
    if !valid {
        return Err(RizinError::InvalidArgument {
            arg: value.to_string(),
            reason: "value must be decimal or 0x-hexadecimal".into(),
        });
    }
    Ok(trimmed.to_string())
}

/// Validate a filesystem path used as a command argument.
///
/// Spaces are allowed (the path is the remainder of the command line), but
/// control characters and Rizin command metacharacters (`; | > < ! `` ` ``) are
/// rejected so the path cannot break out of its command.
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] for an empty path or one containing a
/// disallowed character.
pub fn validate_path(path: &str) -> Result<String, RizinError> {
    if path.is_empty() || path.len() > 4096 {
        return Err(RizinError::InvalidArgument {
            arg: path.to_string(),
            reason: "path is empty or too long".into(),
        });
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, ';' | '|' | '>' | '<' | '!' | '`' | '@'))
    {
        return Err(RizinError::InvalidArgument {
            arg: path.to_string(),
            reason: "path contains a control or command metacharacter".into(),
        });
    }
    Ok(path.to_string())
}

/// Collapse runs of whitespace into single spaces and trim.
fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Quote `arg` as one double-quoted Rizin shell argument.
///
/// Inside double quotes Rizin still expands `$(...)` and backticks and treats
/// `\` and `"` specially; all four are backslash-escaped, so any other text,
/// including `;`, `@`, `|`, `>` and `~`, reaches the command verbatim.
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] for control characters, which the
/// shell drops or treats as line ends.
pub fn quote_arg(arg: &str) -> Result<String, RizinError> {
    if arg.chars().any(char::is_control) {
        return Err(RizinError::InvalidArgument {
            arg: arg.to_string(),
            reason: "control characters are not allowed".into(),
        });
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for c in arg.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Ok(quoted)
}

/// Split a ROP gadget query into its `;`-separated instructions, trimmed and
/// with whitespace collapsed; empty fields (e.g. a trailing `;`) are dropped.
///
/// Rizin's `/R` filter matches the fields in order against the gadget's
/// instructions, but neither trims them (so `pop rdi; ret` looks for " ret")
/// nor survives an unquoted `;`, which its shell splits into a second command.
/// Callers re-join the fields without spaces and pass them through
/// [`quote_arg`].
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] for a query with no instruction or
/// with a control character.
pub fn parse_rop_query(query: &str) -> Result<Vec<String>, RizinError> {
    if query.chars().any(char::is_control) {
        return Err(RizinError::InvalidArgument {
            arg: query.to_string(),
            reason: "query contains a control character".into(),
        });
    }
    let fields: Vec<String> = query
        .split(';')
        .map(collapse_whitespace)
        .filter(|f| !f.is_empty())
        .collect();
    if fields.is_empty() {
        return Err(RizinError::InvalidArgument {
            arg: query.to_string(),
            reason: "query must contain at least one instruction".into(),
        });
    }
    Ok(fields)
}

/// Whether a `/Rj` gadget consists of exactly `fields`, in order: one
/// instruction per field, each equal to it up to case and whitespace.
pub fn gadget_matches_exactly(gadget: &serde_json::Value, fields: &[String]) -> bool {
    let Some(ops) = gadget.get("opcodes").and_then(|o| o.as_array()) else {
        return false;
    };
    ops.len() == fields.len()
        && ops.iter().zip(fields).all(|(op, field)| {
            op.get("opcode")
                .and_then(|o| o.as_str())
                .is_some_and(|o| collapse_whitespace(o).eq_ignore_ascii_case(field))
        })
}

/// Parse a flexible hex byte string into raw bytes.
///
/// Accepts optional surrounding whitespace, interior whitespace between bytes,
/// and an optional `0x`/`0X` prefix. The number of hex digits must be even.
///
/// # Errors
/// Returns [`RizinError::InvalidArgument`] for empty input, an odd digit count,
/// or any non-hex digit.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, RizinError> {
    let mut cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(rest) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        cleaned = rest.to_string();
    }
    if cleaned.is_empty() {
        return Err(RizinError::InvalidArgument {
            arg: s.to_string(),
            reason: "no hex digits found".into(),
        });
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(RizinError::InvalidArgument {
            arg: s.to_string(),
            reason: "odd number of hex digits".into(),
        });
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or_else(|| RizinError::InvalidArgument {
            arg: s.to_string(),
            reason: "invalid hex digit".into(),
        })?;
        let lo = hex_val(bytes[i + 1]).ok_or_else(|| RizinError::InvalidArgument {
            arg: s.to_string(),
            reason: "invalid hex digit".into(),
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode bytes as a lowercase, unspaced hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Clamp a requested count into `[1, max]`, applying `default` when absent.
pub fn clamp_count(requested: Option<u64>, default: u64, max: u64) -> u64 {
    requested.unwrap_or(default).clamp(1, max)
}

/// Truncate a string to at most `max` characters, appending an ellipsis when
/// it was shortened. Used to keep error messages bounded.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn validate_location_accepts_addresses_and_flags() {
        for ok in [
            "0x401000",
            "main",
            "sym.imp.printf",
            "entry0",
            "rip+0x10",
            "0xdead-1",
        ] {
            assert!(validate_location(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn validate_location_rejects_injection() {
        for bad in [
            "",
            "  ",
            "0x10; px",
            "a|b",
            "sym main",
            "x\npd",
            "back`tick",
        ] {
            assert!(validate_location(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn at_suffix_formats_or_empties() {
        assert_eq!(at_suffix(&None).unwrap(), "");
        assert_eq!(at_suffix(&Some("0x10".into())).unwrap(), " @ 0x10");
        assert!(at_suffix(&Some("bad addr".into())).is_err());
    }

    #[test]
    fn parse_hex_variants() {
        assert_eq!(parse_hex_bytes("90 90").unwrap(), vec![0x90, 0x90]);
        assert_eq!(parse_hex_bytes("9090").unwrap(), vec![0x90, 0x90]);
        assert_eq!(
            parse_hex_bytes("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_hex_bytes("  de ad  ").unwrap(), vec![0xde, 0xad]);
        assert!(parse_hex_bytes("").is_err());
        assert!(parse_hex_bytes("abc").is_err()); // odd
        assert!(parse_hex_bytes("zz").is_err()); // non-hex
    }

    #[test]
    fn clamp_count_bounds() {
        assert_eq!(clamp_count(None, 10, 100), 10);
        assert_eq!(clamp_count(Some(0), 10, 100), 1);
        assert_eq!(clamp_count(Some(5000), 10, 100), 100);
        assert_eq!(clamp_count(Some(50), 10, 100), 50);
    }

    proptest! {
        // Hex encode/decode round-trips for arbitrary byte vectors.
        #[test]
        fn hex_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let hex = to_hex(&bytes);
            prop_assert_eq!(hex.len(), bytes.len() * 2);
            if bytes.is_empty() {
                // An empty hex string is rejected by design.
                prop_assert!(parse_hex_bytes(&hex).is_err());
            } else {
                prop_assert_eq!(parse_hex_bytes(&hex).unwrap(), bytes);
            }
        }

        // Interior whitespace never changes the decoded bytes.
        #[test]
        fn hex_ignores_spaces(bytes in proptest::collection::vec(any::<u8>(), 1..64)) {
            let spaced = bytes.iter().map(|b| format!("{b:02x} ")).collect::<String>();
            prop_assert_eq!(parse_hex_bytes(&spaced).unwrap(), bytes);
        }

        // clamp_count always lands in range.
        #[test]
        fn clamp_in_range(req in any::<u64>(), default in 1u64..1000, max in 1u64..1000) {
            let c = clamp_count(Some(req), default, max.max(1));
            prop_assert!(c >= 1);
            prop_assert!(c <= max.max(1));
        }

        // A valid query never yields a field that is empty, padded, or holds
        // the `;` that separates fields.
        #[test]
        fn rop_fields_are_trimmed(q in "[ -~]{0,64}") {
            if let Ok(fields) = parse_rop_query(&q) {
                prop_assert!(!fields.is_empty());
                for f in &fields {
                    prop_assert!(!f.is_empty());
                    prop_assert_eq!(f.trim(), f.as_str());
                    prop_assert!(!f.contains(';'));
                    prop_assert!(!f.contains("  "));
                }
            }
        }

        // A quoted argument is one double-quoted token: every special inside
        // it is escaped, and removing the escapes gives the input back.
        #[test]
        fn quote_arg_round_trips(arg in "\\PC{0,64}") {
            let q = quote_arg(&arg).unwrap();
            prop_assert!(q.len() >= 2 && q.starts_with('"') && q.ends_with('"'));
            let inner = &q[1..q.len() - 1];
            let mut out = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        let next = chars.next();
                        prop_assert!(matches!(next, Some('\\' | '"' | '$' | '`')));
                        out.extend(next);
                    }
                    '"' | '$' | '`' => prop_assert!(false, "unescaped {:?} in {}", c, q),
                    c => out.push(c),
                }
            }
            prop_assert_eq!(out, arg);
        }

        // Any string built only from legal location chars validates and is
        // returned unchanged; appending a metacharacter makes it invalid.
        #[test]
        fn location_charset(s in "[A-Za-z0-9_.:$+-]{1,64}") {
            prop_assert_eq!(validate_location(&s).unwrap(), s.clone());
            let injected = format!("{s};px");
            prop_assert!(validate_location(&injected).is_err());
        }
    }

    #[test]
    fn validate_algo_accepts_names_rejects_meta() {
        assert_eq!(validate_algo("sha256").unwrap(), "sha256");
        assert_eq!(validate_algo(" crc32 ").unwrap(), "crc32");
        assert!(validate_algo("md5; px").is_err());
        assert!(validate_algo("").is_err());
    }

    #[test]
    fn validate_number_accepts_dec_and_hex() {
        assert_eq!(validate_number("1234").unwrap(), "1234");
        assert_eq!(validate_number("0xDEAD").unwrap(), "0xDEAD");
        assert!(validate_number("12; px").is_err());
        assert!(validate_number("0x").is_err());
        assert!(validate_number("nope").is_err());
    }

    #[test]
    fn rop_query_is_trimmed_and_split() {
        assert_eq!(
            parse_rop_query("pop rdi; ret").unwrap(),
            vec!["pop rdi", "ret"]
        );
        assert_eq!(
            parse_rop_query("  pop   rdi ;ret;  ").unwrap(),
            vec!["pop rdi", "ret"]
        );
        assert_eq!(parse_rop_query("ret").unwrap(), vec!["ret"]);
        for bad in ["", " ; ", "pop\nrdi", "pop\trdi"] {
            assert!(parse_rop_query(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn quote_arg_escapes_shell_specials() {
        assert_eq!(quote_arg("pop rdi;ret").unwrap(), "\"pop rdi;ret\"");
        assert_eq!(
            quote_arg(r#"a"b\c$(d)`e`"#).unwrap(),
            r#""a\"b\\c\$(d)\`e\`""#
        );
        assert_eq!(quote_arg("").unwrap(), "\"\"");
        assert!(quote_arg("a\nb").is_err());
        assert!(quote_arg("a\tb").is_err());
    }

    #[test]
    fn exact_gadget_match() {
        let g = serde_json::json!({"opcodes": [
            {"opcode": "pop rdi"}, {"opcode": "pop  rbp"}, {"opcode": "ret"}
        ]});
        let f = |q: &str| parse_rop_query(q).unwrap();
        assert!(gadget_matches_exactly(&g, &f("pop rdi; POP RBP; ret")));
        assert!(!gadget_matches_exactly(&g, &f("pop rdi; ret")));
        assert!(!gadget_matches_exactly(&g, &f("pop rdi; pop rbp")));
        assert!(!gadget_matches_exactly(&serde_json::json!({}), &f("ret")));
    }

    #[test]
    fn validate_path_allows_spaces_rejects_meta() {
        assert_eq!(
            validate_path("/tmp/my file.bin").unwrap(),
            "/tmp/my file.bin"
        );
        assert!(validate_path("/tmp/x; !sh").is_err());
        assert!(validate_path("/tmp/a`b`").is_err());
        assert!(validate_path("/tmp/a@b").is_err());
        assert!(validate_path("").is_err());
    }
}

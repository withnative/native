//! The frozen `native.defn/6` text-format table (design a328c07 §4).
//!
//! Hand-written byte checkers, no regex. The table, the grammars and the
//! blank set [`BLANK_SET`] are fixed for `/6`; changing any of them needs a
//! new language marker. Formats only validate: a value is never rewritten.

/// One entry of the closed format table.
pub struct TextFormat {
    pub name: &'static str,
    /// ABNF (RFC 5234) over the exact string, using the core rules in
    /// [`CORE_RULES`]. Rule names are hyphenated; format names are not.
    pub abnf: &'static str,
    pub description: &'static str,
    check: fn(&str) -> bool,
}

/// Shared ABNF rules. RFC 5234 quoted strings are case-insensitive, so every
/// letter that must be lowercase is written as `%x` values.
pub const CORE_RULES: &str =
    "LOWER = %x61-7A\nDIGIT = %x30-39\nHEXLOW = DIGIT / %x61-66\nHEXANY = HEXLOW / %x41-46";

/// W: Unicode `White_Space` (Unicode 15.1, what `str::trim` uses) plus
/// U+FEFF (ECMA-262 WhiteSpace). Listed, not looked up at runtime.
pub const BLANK_SET: [char; 26] = [
    '\u{0009}', '\u{000A}', '\u{000B}', '\u{000C}', '\u{000D}', '\u{0020}', '\u{0085}', '\u{00A0}',
    '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
    '\u{2007}', '\u{2008}', '\u{2009}', '\u{200A}', '\u{2028}', '\u{2029}', '\u{202F}', '\u{205F}',
    '\u{3000}', '\u{FEFF}',
];

pub const TEXT_FORMATS: [TextFormat; 7] = [
    TextFormat {
        name: "uuid_v4v7",
        abnf: "uuid-v4v7 = 8HEXLOW \"-\" 4HEXLOW \"-\" (\"4\" / \"7\") 3HEXLOW \"-\" 4HEXLOW \"-\" 12HEXLOW",
        description: "Canonical lowercase UUID with version nibble 4 or 7",
        check: uuid_v4v7,
    },
    TextFormat {
        name: "record_locator",
        abnf: "record-locator = uuid-v4v7 / native-token\nnative-token = %x6E.61.74.69.76.65.3A LOWER *(LOWER / DIGIT / \"-\")",
        description: "A lowercase v4/v7 UUID, or a lowercase \"native:\" token; the prefix is case-sensitive",
        check: record_locator,
    },
    TextFormat {
        name: "hex_colour",
        abnf: "hex-colour = \"#\" 6HEXANY",
        description: "A # followed by six hex digits of either case; case is not normalised",
        check: hex_colour,
    },
    TextFormat {
        name: "dotted_id",
        abnf: "dotted-id = segment 1*(\".\" segment)\nsegment = LOWER *(LOWER / DIGIT / \"-\")",
        description: "Two or more dot-separated lowercase segments of letters, digits and hyphens",
        check: dotted_id,
    },
    TextFormat {
        name: "versioned_token",
        abnf: "versioned-token = LOWER *(LOWER / DIGIT / \"-\") \"/\" %x31-39 *DIGIT",
        description: "A lowercase token, a slash and a positive version number without leading zeros",
        check: versioned_token,
    },
    TextFormat {
        name: "snake_field",
        abnf: "snake-field = LOWER *(LOWER / DIGIT / \"_\")",
        description: "A lowercase letter followed by lowercase letters, digits and underscores",
        check: snake_field,
    },
    TextFormat {
        name: "nonblank",
        abnf: "nonblank = <a string containing at least one Unicode scalar value outside W>",
        description: "Any text containing at least one code point that is not in W",
        check: nonblank,
    },
];

pub fn find(name: &str) -> Option<&'static TextFormat> {
    TEXT_FORMATS.iter().find(|format| format.name == name)
}

impl TextFormat {
    pub fn matches(&self, value: &str) -> bool {
        (self.check)(value)
    }
}

/// Whether the text counts as blank under `/6`: every code point is in W.
/// The empty string is blank.
pub fn is_blank(value: &str) -> bool {
    value.chars().all(|c| BLANK_SET.contains(&c))
}

fn lower(b: u8) -> bool {
    b.is_ascii_lowercase()
}
fn digit(b: u8) -> bool {
    b.is_ascii_digit()
}
fn hex_low(b: u8) -> bool {
    digit(b) || (b'a'..=b'f').contains(&b)
}
fn hex_any(b: u8) -> bool {
    b.is_ascii_hexdigit()
}
/// `LOWER *(LOWER / DIGIT / extra)`
fn lower_led(bytes: &[u8], extra: u8) -> bool {
    match bytes.split_first() {
        Some((&first, rest)) => {
            lower(first) && rest.iter().all(|&b| lower(b) || digit(b) || b == extra)
        }
        None => false,
    }
}

fn uuid_v4v7(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            14 => c == b'4' || c == b'7',
            _ => hex_low(c),
        })
}

fn record_locator(value: &str) -> bool {
    match value.as_bytes().strip_prefix(b"native:") {
        Some(rest) => lower_led(rest, b'-'),
        None => uuid_v4v7(value),
    }
}

fn hex_colour(value: &str) -> bool {
    match value.as_bytes() {
        [b'#', rest @ ..] => rest.len() == 6 && rest.iter().all(|&b| hex_any(b)),
        _ => false,
    }
}

fn dotted_id(value: &str) -> bool {
    let mut segments = 0;
    for segment in value.split('.') {
        if !lower_led(segment.as_bytes(), b'-') {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

fn versioned_token(value: &str) -> bool {
    let Some((token, version)) = value.split_once('/') else {
        return false;
    };
    let version = version.as_bytes();
    lower_led(token.as_bytes(), b'-')
        && matches!(version.first(), Some(b'1'..=b'9'))
        && version.iter().all(|&b| digit(b))
}

fn snake_field(value: &str) -> bool {
    lower_led(value.as_bytes(), b'_')
}

fn nonblank(value: &str) -> bool {
    !is_blank(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(name: &str, values: &[&str]) {
        let format = find(name).unwrap();
        for value in values {
            assert!(format.matches(value), "{name} should accept {value:?}");
        }
    }
    fn refuses(name: &str, values: &[&str]) {
        let format = find(name).unwrap();
        for value in values {
            assert!(!format.matches(value), "{name} should refuse {value:?}");
        }
    }

    const V4: &str = "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a";
    const V7: &str = "01939d6f-8a3c-7c1e-9b2a-3f4e5d6c7b8a";

    #[test]
    fn uuid_v4v7_corpus() {
        accepts(
            "uuid_v4v7",
            &[V4, V7, "00000000-0000-4000-0000-000000000000"],
        );
        refuses(
            "uuid_v4v7",
            &[
                "",
                &V4.to_uppercase(),
                "0b9c6c0e-5d2b-1a40-8e0f-1f2e3d4c5b6a",
                "0b9c6c0e-5d2b-5a40-8e0f-1f2e3d4c5b6a",
                "0b9c6c0e-5d2b-8a40-8e0f-1f2e3d4c5b6a",
                "0b9c6c0e5d2b4a408e0f1f2e3d4c5b6a",
                "{0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a}",
                "urn:uuid:0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a",
                "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6g",
                "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a\n",
                " 0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a",
                "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6aa",
                "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6",
                "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b６a",
            ],
        );
    }

    /// The hand-written check must give the same answers as the engine's
    /// canonical-uuid test on a fixed corpus, including variant nibbles the
    /// grammar leaves unconstrained.
    #[test]
    fn uuid_v4v7_agrees_with_canonical_uuid_check() {
        let mut corpus: Vec<String> = vec![
            V4.into(),
            V7.into(),
            V4.to_uppercase(),
            V7.to_uppercase(),
            "native:root".into(),
            "".into(),
            "order-one".into(),
            "0b9c6c0e5d2b4a408e0f1f2e3d4c5b6a".into(),
            "{0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a}".into(),
            "urn:uuid:0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a".into(),
            "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a\n".into(),
            "0B9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a".into(),
            "00000000-0000-0000-0000-000000000000".into(),
            "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
        ];
        for version in '0'..='9' {
            for variant in ['0', '7', '8', '9', 'a', 'b', 'c', 'f'] {
                corpus.push(format!(
                    "0b9c6c0e-5d2b-{version}a40-{variant}e0f-1f2e3d4c5b6a"
                ));
            }
        }
        for version in ['a', 'b', 'c', 'd', 'e', 'f'] {
            corpus.push(format!("0b9c6c0e-5d2b-{version}a40-8e0f-1f2e3d4c5b6a"));
        }
        for value in &corpus {
            assert_eq!(
                find("uuid_v4v7").unwrap().matches(value),
                crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(value),
                "disagreement on {value:?}"
            );
        }
    }

    #[test]
    fn record_locator_corpus() {
        accepts(
            "record_locator",
            &[
                V4,
                V7,
                "native:root",
                "native:a",
                "native:a1-b2-c3",
                "native:unfiled",
                "native:a-",
                "native:z--9",
            ],
        );
        refuses(
            "record_locator",
            &[
                "",
                "native:",
                "NATIVE:root",
                "Native:root",
                "nativE:root",
                "native:Root",
                "native:1",
                "native:-a",
                "native:a_b",
                "native:a b",
                "native:root\n",
                "native:root ",
                " native:root",
                "native::root",
                "natives:root",
                &V4.to_uppercase(),
                "native:ünï",
            ],
        );
    }

    #[test]
    fn hex_colour_corpus() {
        accepts(
            "hex_colour",
            &["#000000", "#ffffff", "#FFFFFF", "#a1B2c3", "#0A9fAa"],
        );
        refuses(
            "hex_colour",
            &[
                "",
                "#",
                "#fff",
                "#fffff",
                "#fffffff",
                "ffffff",
                "#gggggg",
                "#ffffff\n",
                " #ffffff",
                "#ffff ff",
                "##ffffff",
                "#ｆｆｆｆｆｆ",
            ],
        );
    }

    #[test]
    fn dotted_id_corpus() {
        accepts(
            "dotted_id",
            &[
                "a.b",
                "native.foci",
                "a1.b2.c3",
                "a-b.c-d",
                "a--.b",
                "native.query-view.v2x",
            ],
        );
        refuses(
            "dotted_id",
            &[
                "", "a", "a.", ".a", "a..b", "A.b", "a.B", "1a.b", "a.1b", "-a.b", "a.-b", "a_b.c",
                "a.b\n", "a.b ", " a.b", "a.b/1", "ä.b",
            ],
        );
    }

    #[test]
    fn versioned_token_corpus() {
        accepts(
            "versioned_token",
            &[
                "a/1",
                "query-view/12",
                "a1-b2/9",
                "native-ids/1000000",
                "a--/5",
            ],
        );
        refuses(
            "versioned_token",
            &[
                "", "a", "a/", "/1", "a/0", "a/01", "a/1.0", "a/1a", "A/1", "1a/1", "-a/1",
                "a_b/1", "a/b/1", "a/1/", "a/1\n", "a /1", "a/ 1", "a/１",
            ],
        );
    }

    #[test]
    fn snake_field_corpus() {
        accepts(
            "snake_field",
            &["a", "field", "sort_key", "a1", "a_1_b", "a__", "x9_y"],
        );
        refuses(
            "snake_field",
            &[
                "", "_a", "1a", "A", "aB", "a-b", "a b", "a.b", "a\n", " a", "ä", "a__é",
            ],
        );
    }

    #[test]
    fn nonblank_corpus() {
        accepts(
            "nonblank",
            &[
                "a",
                " a ",
                "\u{3000}x",
                "\u{FEFF}\u{3000}z",
                "·",
                "\u{200B}",
                "\u{180E}",
                "\u{2800}",
            ],
        );
        refuses(
            "nonblank",
            &[
                "",
                " ",
                "\t\n\r",
                "\u{3000}",
                "\u{FEFF}",
                "\u{0085}",
                "\u{2028}\u{2029}",
                "\u{FEFF}\u{3000}",
                "\u{00A0}\u{202F}\u{205F}",
            ],
        );
    }

    #[test]
    fn blank_set_membership() {
        assert_eq!(BLANK_SET.len(), 26);
        let mut sorted = BLANK_SET;
        sorted.sort();
        assert!(sorted.windows(2).all(|w| w[0] != w[1]), "duplicates in W");
        // Contains Unicode White_Space exactly as str::trim sees it, plus U+FEFF.
        for code in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            let expected = c.is_whitespace() || c == '\u{FEFF}';
            assert_eq!(BLANK_SET.contains(&c), expected, "U+{code:04X}");
        }
        // v1's translated `\S` class is contained in W.
        for c in [
            ' ', '\t', '\n', '\r', '\u{0B}', '\u{0C}', '\u{00A0}', '\u{FEFF}', '\u{2028}',
            '\u{2029}',
        ] {
            assert!(BLANK_SET.contains(&c));
        }
    }

    /// The four §4.7 examples: values v1 accepted that `/6` refuses.
    #[test]
    fn blank_rule_examples() {
        for value in ["\u{3000}", "\u{2003}", "\u{0085}", "\u{FEFF}\u{3000}"] {
            assert!(is_blank(value), "{value:?}");
            assert!(!find("nonblank").unwrap().matches(value));
        }
        assert!(is_blank(""));
        assert!(!is_blank("a"));
        assert!(!is_blank(" \u{200B} "));
    }
}

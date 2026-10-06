//! Optional transport encoding for whole-body writes that carry HTML app
//! source (`create_record.body`, `update_record.body_set` / `body`).
//!
//! A raw source string travels inside a JSON tool call, where escaping can
//! inflate it several-fold against the hosted request limit. `body_encoding`
//! lets a caller send the same bytes as base64, or gzip then base64. The
//! decode runs at the tool boundary, before anything else reads the body, and
//! rewrites the arguments in place: everything downstream (validation,
//! `BODY_LIMIT`, storage, `body_digest`, source events, idempotency digests)
//! sees only the decoded text, so an encoded and a raw submission of the same
//! body are indistinguishable.

use std::io::Read;

use base64::Engine as _;
use flate2::bufread::GzDecoder;
use serde_json::Value;

use crate::artifact_html::BODY_LIMIT;
use crate::error::{Error, Result};

pub(crate) const FIELD: &str = "body_encoding";
const ACCEPTED: &str = "utf8, base64, gzip+base64";
/// Slack over `BODY_LIMIT` for gzip framing on incompressible input, so the
/// pre-decode length check never refuses a stream a real compressor produced
/// from a body at the limit.
const GZIP_OVERHEAD: usize = 1024;

/// The `body_encoding` property advertised on the two whole-body write
/// operations (`create_record`, `update_record`). Deliberately description-free:
/// the hosted descriptor profiles are within a few hundred bytes of their
/// budgets, and the enum names say what each value is (`gzip+base64` is gzip,
/// then standard base64). Refusals name the accepted values.
pub(crate) fn schema() -> Value {
    serde_json::json!({
        "type": "string",
        "enum": ["utf8", "base64", "gzip+base64"],
        "default": "utf8"
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8,
    Base64,
    GzipBase64,
}

fn refuse(tool: &str, code: &str, message: impl std::fmt::Display) -> Error {
    Error::engine(format!("{tool}: {message} [{code}]"))
}

/// The tool-level entry point: only the two whole-body write tools take the
/// field; every other tool's arguments pass through untouched (and still hit
/// their own strict argument parsing if they carry it).
pub(crate) fn decode_for_tool(tool: &str, arguments: &mut Value) -> Result<()> {
    match tool {
        "create_record" => decode_arguments(tool, arguments, &["body"]),
        "update_record" => decode_arguments(tool, arguments, &["body", "body_set"]),
        _ => Ok(()),
    }
}

/// Decode `body_encoding` (when present) into the body field named by
/// `body_keys`, leaving arguments without the field untouched. The field is
/// removed from `arguments` so the strict argument parser downstream never
/// sees it. `utf8` is accepted and changes nothing.
pub(crate) fn decode_arguments(
    tool: &str,
    arguments: &mut Value,
    body_keys: &[&str],
) -> Result<()> {
    let Some(object) = arguments.as_object_mut() else {
        return Ok(());
    };
    let Some(declared) = object.remove(FIELD) else {
        return Ok(());
    };
    let encoding = match declared.as_str() {
        Some("utf8") => Encoding::Utf8,
        Some("base64") => Encoding::Base64,
        Some("gzip+base64") => Encoding::GzipBase64,
        _ => {
            return Err(refuse(
                tool,
                "body_encoding_unknown",
                format!("'{FIELD}' must be one of {ACCEPTED}, got {declared}"),
            ))
        }
    };
    // `utf8` is the default spelled out: an unconditional no-op once the field
    // itself is dropped, whatever else the call carries.
    if encoding == Encoding::Utf8 {
        return Ok(());
    }
    let Some(key) = body_keys
        .iter()
        .copied()
        .find(|key| object.get(*key).is_some_and(Value::is_string))
    else {
        return Err(refuse(
            tool,
            "body_encoding_without_body",
            format!(
                "'{FIELD}' describes a whole-body string ({}); it cannot accompany body_append, body_replace or a null body",
                body_keys.join(" or "),
            ),
        ));
    };
    let encoded = object[key]
        .as_str()
        .expect("body key was checked as a string");
    let decoded = decode(tool, key, encoding, encoded)?;
    object.insert(key.into(), Value::String(decoded));
    Ok(())
}

fn decode(tool: &str, key: &str, encoding: Encoding, encoded: &str) -> Result<String> {
    let name = if encoding == Encoding::GzipBase64 {
        "gzip+base64"
    } else {
        "base64"
    };
    // Refuse an obviously oversized string before spending any work on it.
    let max_raw = BODY_LIMIT
        + if encoding == Encoding::GzipBase64 {
            GZIP_OVERHEAD
        } else {
            0
        };
    let max_encoded = max_raw.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        return Err(refuse(
            tool,
            "body_encoding_too_large",
            format!(
                "'{key}' is {} characters of {name}, over the {max_encoded}-character maximum for a {BODY_LIMIT}-byte body; shrink the source",
                encoded.len(),
            ),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| {
            refuse(
                tool,
                "body_encoding_invalid_base64",
                format!("'{key}' is not valid standard base64 (padded, no whitespace): {error}"),
            )
        })?;
    let bytes = if encoding == Encoding::GzipBase64 {
        // Hard output cap: read at most one byte past the limit, so a bomb is
        // refused as soon as it crosses the line and is never fully inflated.
        let mut inflated = Vec::new();
        let mut input = bytes.as_slice();
        let mut member = GzDecoder::new(&mut input);
        (&mut member)
            .take(BODY_LIMIT as u64 + 1)
            .read_to_end(&mut inflated)
            .map_err(|error| {
                refuse(
                    tool,
                    "body_encoding_invalid_gzip",
                    format!("'{key}' is not a valid gzip stream after base64 decoding: {error}"),
                )
            })?;
        drop(member);
        // A bufread decoder consumes exactly one member. Anything left is a
        // second member or trailing bytes, which would otherwise be dropped
        // silently, so a concatenated stream cannot be quietly truncated.
        if inflated.len() <= BODY_LIMIT && !input.is_empty() {
            return Err(refuse(
                tool,
                "body_encoding_invalid_gzip",
                format!(
                    "'{key}' has {} bytes after its first gzip member; send exactly one gzip stream with no trailing data",
                    input.len()
                ),
            ));
        }
        if inflated.len() > BODY_LIMIT {
            return Err(refuse(
                tool,
                "body_encoding_too_large",
                format!(
                    "'{key}' decompresses to more than the {BODY_LIMIT}-byte body limit (decompression stopped at the limit); shrink the source"
                ),
            ));
        }
        inflated
    } else {
        bytes
    };
    if bytes.len() > BODY_LIMIT {
        return Err(refuse(
            tool,
            "body_encoding_too_large",
            format!(
                "'{key}' decodes to {} bytes, over the {BODY_LIMIT}-byte body limit; shrink the source",
                bytes.len(),
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        refuse(
            tool,
            "body_encoding_invalid_utf8",
            format!(
                "'{key}' decodes to bytes that are not valid UTF-8 (invalid at byte {}); encode the UTF-8 text of the source",
                error.utf8_error().valid_up_to(),
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{write::GzEncoder, Compression};
    use serde_json::json;

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn gzip_b64(bytes: &[u8]) -> String {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(bytes).unwrap();
        b64(&encoder.finish().unwrap())
    }

    fn run(encoding: &str, body: &str) -> Result<Value> {
        let mut arguments = json!({"body": body, "body_encoding": encoding, "reason": "r"});
        decode_arguments("create_record", &mut arguments, &["body"])?;
        Ok(arguments)
    }

    fn message(result: Result<Value>) -> String {
        result.expect_err("expected a refusal").to_string()
    }

    #[test]
    fn absent_field_leaves_arguments_untouched() {
        let mut arguments = json!({"body": "AAAA", "reason": "r"});
        decode_arguments("create_record", &mut arguments, &["body"]).unwrap();
        assert_eq!(arguments, json!({"body": "AAAA", "reason": "r"}));
    }

    #[test]
    fn utf8_is_a_noop_that_drops_the_field() {
        let out = run("utf8", "héllo").unwrap();
        assert_eq!(out, json!({"body": "héllo", "reason": "r"}));
    }

    #[test]
    fn base64_and_gzip_round_trip() {
        let source = "<!doctype html>\n<p>héllo \"quoted\" 🎉</p>".repeat(50);
        assert_eq!(
            run("base64", &b64(source.as_bytes())).unwrap()["body"],
            source
        );
        assert_eq!(
            run("gzip+base64", &gzip_b64(source.as_bytes())).unwrap()["body"],
            source
        );
        assert!(run("base64", &b64(source.as_bytes()))
            .unwrap()
            .get(FIELD)
            .is_none());
    }

    #[test]
    fn unknown_encoding_is_refused() {
        let text = message(run("hex", "abcd"));
        assert!(
            text.contains("body_encoding_unknown") && text.contains("gzip+base64"),
            "{text}"
        );
        let text = message(run("", "abcd"));
        assert!(text.contains("body_encoding_unknown"), "{text}");
    }

    #[test]
    fn invalid_base64_and_gzip_are_refused() {
        assert!(message(run("base64", "not base64!!")).contains("body_encoding_invalid_base64"));
        assert!(message(run("base64", "QUJD\nREVG")).contains("body_encoding_invalid_base64"));
        assert!(message(run("gzip+base64", &b64(b"plain, not gzip")))
            .contains("body_encoding_invalid_gzip"));
        let truncated = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
            encoder.write_all("x".repeat(10_000).as_bytes()).unwrap();
            let bytes = encoder.finish().unwrap();
            b64(&bytes[..bytes.len() / 2])
        };
        assert!(message(run("gzip+base64", &truncated)).contains("body_encoding_invalid_gzip"));
    }

    #[test]
    fn utf8_is_a_noop_even_without_a_body() {
        let mut arguments = json!({"body_set": null, "body_encoding": "utf8"});
        decode_arguments("update_record", &mut arguments, &["body", "body_set"]).unwrap();
        assert_eq!(arguments, json!({"body_set": null}));
        let mut arguments = json!({"body_append": "x", "body_encoding": "utf8"});
        decode_arguments("update_record", &mut arguments, &["body", "body_set"]).unwrap();
        assert_eq!(arguments, json!({"body_append": "x"}));
    }

    #[test]
    fn multi_member_and_trailing_gzip_are_refused() {
        let gz = |text: &str| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(text.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let mut two = gz("<p>first</p>");
        two.extend(gz("<p>second</p>"));
        let text = message(run("gzip+base64", &b64(&two)));
        assert!(
            text.contains("body_encoding_invalid_gzip")
                && text.contains("after its first gzip member"),
            "{text}"
        );
        let mut trailing = gz("<p>only</p>");
        trailing.extend(b"garbage");
        let text = message(run("gzip+base64", &b64(&trailing)));
        assert!(
            text.contains("body_encoding_invalid_gzip") && text.contains("7 bytes"),
            "{text}"
        );
        assert_eq!(
            run("gzip+base64", &b64(&gz("<p>only</p>"))).unwrap()["body"],
            "<p>only</p>"
        );
    }

    #[test]
    fn decoded_bytes_must_be_utf8() {
        let text = message(run("base64", &b64(&[b'o', b'k', 0xff, 0xfe])));
        assert!(
            text.contains("body_encoding_invalid_utf8") && text.contains("byte 2"),
            "{text}"
        );
        assert!(message(run("gzip+base64", &gzip_b64(&[0xc3, 0x28])))
            .contains("body_encoding_invalid_utf8"));
    }

    #[test]
    fn decoded_limit_is_exact() {
        let at_limit = "a".repeat(BODY_LIMIT);
        assert_eq!(
            run("base64", &b64(at_limit.as_bytes())).unwrap()["body"],
            at_limit
        );
        assert_eq!(
            run("gzip+base64", &gzip_b64(at_limit.as_bytes())).unwrap()["body"],
            at_limit
        );
        let over = "a".repeat(BODY_LIMIT + 1);
        let text = message(run("base64", &b64(over.as_bytes())));
        assert!(
            text.contains("body_encoding_too_large") && text.contains("524288"),
            "{text}"
        );
        let text = message(run("gzip+base64", &gzip_b64(over.as_bytes())));
        assert!(
            text.contains("body_encoding_too_large") && text.contains("524288"),
            "{text}"
        );
    }

    #[test]
    fn gzip_bomb_is_refused_without_full_inflation() {
        // 64 MiB of zeros compresses to ~64 KiB: well under the encoded cap,
        // far over the decoded one. The bounded reader stops at BODY_LIMIT + 1.
        let bomb = gzip_b64(&vec![0u8; 64 * 1024 * 1024]);
        assert!(
            bomb.len() < 200_000,
            "fixture must be small, was {}",
            bomb.len()
        );
        let text = message(run("gzip+base64", &bomb));
        assert!(
            text.contains("body_encoding_too_large") && text.contains("decompression stopped"),
            "{text}"
        );
    }

    #[test]
    fn oversized_encoded_string_is_refused_before_decoding() {
        let text = message(run("base64", &"A".repeat(BODY_LIMIT * 2)));
        assert!(
            text.contains("body_encoding_too_large") && text.contains("characters"),
            "{text}"
        );
    }

    #[test]
    fn update_accepts_body_set_and_body_but_not_other_operations() {
        let mut arguments =
            json!({"id": "x", "body_set": b64(b"hi"), "body_encoding": "base64", "reason": "r"});
        decode_arguments("update_record", &mut arguments, &["body", "body_set"]).unwrap();
        assert_eq!(arguments["body_set"], "hi");
        let mut arguments =
            json!({"id": "x", "body": b64(b"hi"), "body_encoding": "base64", "reason": "r"});
        decode_arguments("update_record", &mut arguments, &["body", "body_set"]).unwrap();
        assert_eq!(arguments["body"], "hi");
        for other in [
            json!({"body_append": "aGk="}),
            json!({"body_set": null}),
            json!({"name": "n"}),
        ] {
            let mut arguments = other;
            arguments["body_encoding"] = json!("base64");
            let text = decode_arguments("update_record", &mut arguments, &["body", "body_set"])
                .unwrap_err()
                .to_string();
            assert!(text.contains("body_encoding_without_body"), "{text}");
        }
    }
}

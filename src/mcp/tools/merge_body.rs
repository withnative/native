//! `merge_body`: the home operation behind the node's `body.merge` intent
//! (design `docs/design/body-merge-home.md`, section 2 and section 7).
//!
//! This file is the engine-independent half: the descriptor, the input
//! contract, the single evaluator, the refusal shapes and the receipt
//! rendering. The caller holds *base version, base text, my text*; the home
//! does the three-way merge of [`crate::coedit::body_merge`] against the text
//! it holds now. A stale base is not an error: non-overlapping edits are
//! placed, overlapping ones are returned as clashes and not applied.
//!
//! The only engine that implements the operation is KernelV2
//! (`mcp::kernel_v2::merge_body`). The SQLite engine registers a refusing
//! handler, the same arrangement as publication management.
//!
//! # One evaluator
//!
//! `evaluate` is the only place the merge outcome is decided. There are no
//! fast paths: "current equals base" is just the ordinary output of the same
//! code, so a first call and a replay cannot disagree.
use super::*;
use crate::mcp::ToolKind;
use serde_json::json;

#[cfg(any(test, feature = "v2-kernel-probe"))]
use crate::coedit::body_merge::{self, Hunk, MergedClash};

#[cfg(feature = "v2-kernel-probe")]
pub(crate) const TOOL: &str = "merge_body";

/// Largest `base_text`, `my_text` or merged result, in bytes. It applies to
/// every outcome: a body above it could not be the next call's `base_text`.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Largest `theirs` text echoed per clash passage.
#[cfg(feature = "v2-kernel-probe")]
const CLASH_THEIRS_CAP_BYTES: usize = 64 * 1024;

#[cfg(any(test, feature = "v2-kernel-probe"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Merged,
    MergedWithClashes,
}

#[cfg(feature = "v2-kernel-probe")]
impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Merged => "merged",
            Outcome::MergedWithClashes => "merged_with_clashes",
        }
    }
}

/// The merge of `mine` (made against `base`) onto `theirs`. Pure and
/// deterministic.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) struct Evaluation {
    pub(crate) outcome: Outcome,
    /// `merged != theirs`: whether applying the placed hunks changes the text.
    pub(crate) changed: bool,
    pub(crate) merged: String,
    pub(crate) placed: Vec<Hunk>,
    pub(crate) clashes: Vec<MergedClash>,
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) fn evaluate(base: &str, mine: &str, theirs: &str) -> Evaluation {
    let merge = body_merge::merge_bodies(base, mine, theirs);
    Evaluation {
        outcome: if merge.clashes.is_empty() {
            Outcome::Merged
        } else {
            Outcome::MergedWithClashes
        },
        changed: merge.merged != theirs,
        merged: merge.merged,
        placed: merge.placed,
        clashes: merge.clashes,
    }
}

/// `rec:N` with N a positive integer, nothing else.
pub(crate) fn parse_base_version(token: &str) -> Option<i64> {
    let digits = token.strip_prefix("rec:")?;
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok().filter(|seq| *seq > 0)
}

/// Prefix of `text` of at most `cap` bytes, ending on a character boundary.
#[cfg(any(test, feature = "v2-kernel-probe"))]
fn bounded_prefix(text: &str, cap: usize) -> (&str, bool) {
    if text.len() <= cap {
        return (text, false);
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) struct Refusal {
    pub(crate) reason: &'static str,
    retryable: bool,
    error_code: Option<&'static str>,
    message: &'static str,
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const FEATURE_NOT_ENABLED: Refusal = Refusal {
    reason: "feature_not_enabled",
    retryable: true,
    error_code: Some("BODY_MERGE_NOT_ENABLED"),
    message: "Merging held edits is not turned on for this account yet. Nothing was changed; the edit is still held on your device.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const HOME_BUSY: Refusal = Refusal {
    reason: "home_busy",
    retryable: true,
    error_code: None,
    message: "A live session is open on this record. Nothing was changed; try again shortly.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const NOT_PERMITTED: Refusal = Refusal {
    reason: "not_permitted",
    retryable: false,
    error_code: None,
    message: "You can no longer edit this record. Nothing was changed.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const RECORD_MISSING: Refusal = Refusal {
    reason: "record_missing",
    retryable: false,
    error_code: None,
    message: "This record does not exist or is not visible to you. Nothing was changed.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const RECORD_NOT_TEXT: Refusal = Refusal {
    reason: "record_not_text",
    retryable: false,
    error_code: None,
    message: "This record has no text body that can be merged. Nothing was changed.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const BASE_UNVERIFIED: Refusal = Refusal {
    reason: "base_unverified",
    retryable: false,
    error_code: None,
    message: "The version this edit was made against could not be confirmed as this record's own history. Nothing was changed; the edit is kept on your device.",
};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) const BAD_INTENT: Refusal = Refusal {
    reason: "bad_intent",
    retryable: false,
    error_code: None,
    message:
        "The edit, or the text it would merge into, is too large to merge. Nothing was changed.",
};

/// A refusal result. Nothing is written and nothing is stored under the key.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) fn refused(record_id: &str, key: &str, refusal: &Refusal) -> Value {
    let mut result = json!({
        "outcome": "refused",
        "reason": refusal.reason,
        "retryable": refusal.retryable,
        "applied": false,
        "record_id": record_id,
        "idempotency_key": key,
        "unit": "unicode_scalars",
        "message": refusal.message,
    });
    if let Some(code) = refusal.error_code {
        result["error_code"] = json!(code);
    }
    result
}

/// What a success-shaped receipt is built from.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct Rendered<'a> {
    pub(crate) record_id: &'a str,
    pub(crate) key: &'a str,
    pub(crate) base_version: &'a str,
    /// A real merge happened: the text the merge ran against differs from the
    /// base. Informational on KernelV2: no version marker is written (design
    /// section 7).
    pub(crate) merged_offline: bool,
    pub(crate) evaluation: &'a Evaluation,
    /// `result.version`: the new event's version for a write, else the horizon
    /// the merge observed.
    pub(crate) version: i64,
    /// `result.body`: the committed text after this call, exactly the body at
    /// `version`. Always echoed in full.
    pub(crate) body: &'a str,
    /// The act of the event this call appended, when it appended one.
    pub(crate) act: Option<i64>,
    /// The appended event, in the v2 write-receipt shape; `None` when the call
    /// appended nothing.
    pub(crate) write_receipt: Option<Value>,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn render(input: Rendered<'_>) -> Value {
    let Rendered {
        record_id,
        key,
        base_version,
        merged_offline,
        evaluation,
        version,
        body,
        act,
        write_receipt,
    } = input;
    // The full body is always echoed (it is bounded by MAX_TEXT_BYTES on every
    // outcome). A receipt that omitted it could not be recovered on KernelV2:
    // `get_record` takes no `as_of` there, and version diffs refuse some
    // positions an unchanged or clash-only receipt can return as its horizon.
    let result = json!({
        "version": format!("rec:{version}"),
        "body_digest": super::lifecycle::body_digest(Some(body)),
        "body": body,
    });
    let mut receipt = json!({
        "outcome": evaluation.outcome.as_str(),
        "applied": true,
        "record_id": record_id,
        "idempotency_key": key,
        "unit": "unicode_scalars",
        "merged_offline": merged_offline,
        "base": { "version": base_version, "verified": true },
        "result": result,
    });
    if let Some(write_receipt) = write_receipt {
        // Present only when an event was appended: the interaction extractor
        // reads it as "this call touched the record".
        receipt["write_receipt"] = write_receipt;
    }
    if let Some(act) = act {
        receipt["act"] = json!(act);
    }
    match evaluation.outcome {
        Outcome::Merged => {
            receipt["changed"] = json!(evaluation.changed);
        }
        Outcome::MergedWithClashes => {
            receipt["applied_hunks"] = json!(evaluation.placed.len());
            receipt["unmerged"] = Value::Array(
                evaluation
                    .clashes
                    .iter()
                    .enumerate()
                    .map(|(index, merged)| {
                        let clash = &merged.clash;
                        let (theirs, truncated) =
                            bounded_prefix(&clash.theirs, CLASH_THEIRS_CAP_BYTES);
                        let mut item = json!({
                            "id": format!("u{}", index + 1),
                            "base": clash.base,
                            "mine": clash.mine,
                            "theirs": theirs,
                            "base_start": clash.base_start,
                            "base_end": clash.base_end,
                            "at_start": merged.at_start,
                            "at_end": merged.at_end,
                        });
                        if truncated {
                            item["theirs_truncated"] = json!(true);
                        }
                        item
                    })
                    .collect(),
            );
        }
    }
    receipt
}

pub(crate) fn input_schema() -> Value {
    // Deliberately minimal: the complete descriptor profile has a byte budget.
    // Required fields and unknown arguments are enforced by the handler's own
    // strict parse (an absent field or an unknown one is refused by name);
    // semantics live in the design note (sections 2.2 and 7).
    json!({
        "type": "object",
        "properties": {
            "record_id": { "type": "string" },
            "base_version": { "type": "string" },
            "base_text": { "type": "string" },
            "my_text": { "type": "string" },
            "reason": { "type": "string" },
            "idempotency_key": { "type": "string" }
        }
    })
}

pub(crate) const DESCRIPTION: &str =
    "Three-way merge a held body edit into the current body. Keyed. KernelV2 only.";

/// Register the descriptor. The SQLite engine refuses: the operation exists
/// only on KernelV2, where Native HQ is moving.
pub(crate) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::MergeBody,
        DESCRIPTION,
        input_schema(),
        |_db, _caller, _args| async {
            Err::<Value, _>(Error::engine(
                "merge_body_unsupported: merge_body requires the KernelV2 engine",
            ))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_version_tokens_are_strictly_rec_n() {
        assert_eq!(parse_base_version("rec:7"), Some(7));
        assert_eq!(parse_base_version("rec:1234567"), Some(1_234_567));
        for bad in [
            "",
            "rec:",
            "rec:0",
            "rec:-1",
            "rec:+1",
            "rec:1x",
            "7",
            "REC:7",
            " rec:7",
            "rec:99999999999999999999",
        ] {
            assert_eq!(parse_base_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_evaluator_decides_clean_clashing_and_unchanged_merges() {
        let clean = evaluate("a\n\nb\n", "a\n\nB\n", "A\n\nb\n");
        assert_eq!(clean.outcome, Outcome::Merged);
        assert!(clean.changed);
        assert_eq!(clean.merged, "A\n\nB\n");
        assert_eq!(clean.placed.len(), 1, "the clean edit places one hunk");

        let clash = evaluate("abc", "axc", "ayc");
        assert_eq!(clash.outcome, Outcome::MergedWithClashes);
        assert!(!clash.changed, "a clash-only merge applies nothing");
        assert_eq!(clash.merged, "ayc");
        assert!(clash.placed.is_empty(), "clash-only edits place no hunks");

        // Nothing to carry over: the person changed nothing.
        let same = evaluate("abc", "abc", "abcd");
        assert_eq!(same.outcome, Outcome::Merged);
        assert!(!same.changed);
        // Deterministic.
        let again = evaluate("abc", "axc", "ayc");
        assert_eq!(again.merged, clash.merged);
        assert_eq!(again.clashes, clash.clashes);
    }

    #[test]
    fn a_clash_stays_inside_the_merged_text_it_was_located_in() {
        let evaluation = evaluate("a m z\n", "A x Z\n", "a M z\n");
        assert_eq!(evaluation.merged, "A M Z\n");
        for located in &evaluation.clashes {
            let chars: Vec<char> = evaluation.merged.chars().collect();
            let slice: String = chars[located.at_start..located.at_end].iter().collect();
            assert_eq!(slice, located.clash.theirs);
        }
    }

    #[test]
    fn bounded_prefix_ends_on_a_character_boundary() {
        assert_eq!(bounded_prefix("hello", 10), ("hello", false));
        assert_eq!(bounded_prefix("hello", 3), ("hel", true));
        // "é" is two bytes: a cap inside it backs off.
        assert_eq!(bounded_prefix("aé", 2), ("a", true));
    }

    #[test]
    fn refusals_carry_the_shape_the_node_classifies_on() {
        let flag = refused("r", "k", &FEATURE_NOT_ENABLED);
        assert_eq!(flag["outcome"], "refused");
        assert_eq!(flag["reason"], "feature_not_enabled");
        assert_eq!(flag["error_code"], "BODY_MERGE_NOT_ENABLED");
        assert_eq!(flag["retryable"], true);
        assert_eq!(flag["applied"], false);
        let busy = refused("r", "k", &HOME_BUSY);
        assert_eq!(
            (busy["reason"].as_str(), busy["retryable"].as_bool()),
            (Some("home_busy"), Some(true))
        );
        assert!(busy.get("error_code").is_none());
        for terminal in [
            &NOT_PERMITTED,
            &RECORD_MISSING,
            &RECORD_NOT_TEXT,
            &BASE_UNVERIFIED,
            &BAD_INTENT,
        ] {
            let result = refused("r", "k", terminal);
            assert_eq!(result["retryable"], false);
            assert_eq!(result["applied"], false);
        }
    }
}

//! One build-owned product model used by both QuickStart and the deeper guide.

use std::fmt::Write as _;

use serde_json::{json, Value};

pub const CONTRACT: &str = "native.product-model.v1";
pub const VERSION: i64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductPrinciple {
    pub id: &'static str,
    pub summary: &'static str,
    pub explanation: &'static str,
}

pub const PRINCIPLES: [ProductPrinciple; 6] = [
    ProductPrinciple {
        id: "explicit-durable-records",
        summary: "Native keeps explicit, durable records; it does not passively remember everything.",
        explanation: "An agent writes a record deliberately when something should survive. Ordinary conversation and activity are not silently converted into durable memory.",
    },
    ProductPrinciple {
        id: "cross-session-retrieval",
        summary: "Workspace records are the normal durable home and can be rediscovered by later agents and sessions.",
        explanation: "A record's placement, links, type, and facets make it findable without relying on one client or one conversation retaining hidden context.",
    },
    ProductPrinciple {
        id: "solo-to-shared",
        summary: "A workspace can start solo and later support collaboration through the same durable records.",
        explanation: "Most new workspaces are currently single-player. If collaborators are added later, workspace-visible records become shared context without requiring a different storage model.",
    },
    ProductPrinciple {
        id: "intentional-private-context",
        summary: "My agent context is the intentional private alternative to a workspace record.",
        explanation: "Use private agent context when the user wants durable context that should not be workspace-visible. Privacy is a placement choice, not an invisible memory layer.",
    },
    ProductPrinciple {
        id: "human-control",
        summary: "The user controls what is written, where it is placed, and when visibility should be restricted.",
        explanation: "Agents should preview consequential durable writes when appropriate, obtain confirmation, and explain how the result will be found again.",
    },
    ProductPrinciple {
        id: "outcomes-over-storage",
        summary: "Storage is not the outcome; a useful workflow, explanation, or comparison is.",
        explanation: "Records make value durable, but QuickStart should first anchor on what the user wants to accomplish and choose the smallest credible proof of that value.",
    },
];

pub fn compact() -> Value {
    json!({
        "contract": CONTRACT,
        "version": VERSION,
        "principles": PRINCIPLES.iter().map(|principle| json!({
            "id": principle.id,
            "summary": principle.summary,
        })).collect::<Vec<_>>(),
    })
}

pub fn guide_markdown() -> String {
    let mut out = format!(
        "# Native product model\n\nContract: `{CONTRACT}` · version `{VERSION}`\n\nNative is a durable context system for humans and agents. Its value comes from making useful context explicit, findable, controllable, and available beyond one conversation.\n\n"
    );
    for principle in PRINCIPLES {
        let _ = writeln!(
            out,
            "## {}\n\n{}\n\n{}\n",
            principle.id, principle.summary, principle.explanation
        );
    }
    out.push_str(
        r#"## Declared source basis

An ordinary write may name the records it rested on under `sources`: each entry is a `record_id`, a `reason`, an optional `role`, and an optional `revision_event_id`. The engine stores the declaration on the write event itself, beside the write's `reason`, under `native.source-basis.v1`, replacing each omitted revision with the source's current body head. An omitted `sources` means *not declared*; an explicit empty list means *declared as none*, and the two are stored distinguishably.

Declarations serve the agent that made them and whoever arrives next. The read log is disposable and is dropped; a declaration is canonical — recorded on the write event itself, durable, and readable from history — so it is not lost with your context window. A later agent can check whether the basis has moved instead of redoing your reading. The person you act for can see what you looked at before you acted, which is the oversight Native promises. Honesty is symmetrical: declaring none is as useful as declaring some, and not declaring is neither.

A declaration is a claim, not an observation. The engine records what you said you used; it does not verify it, and it does not rank or retrieve anything by it. A false reason discredits the rest.

Adoption is measured, not assumed. This query gives the weekly volume of `record.created` / `record.updated` events, bucketed with portable integer date maths over the `created_at_ms` companion column. Weeks here are Unix-epoch-aligned 7-day buckets starting Thursday 00:00 UTC: calendar weeks have no portable spelling, so say epoch weeks when you report the number.

```sql
SELECT created_at_ms / 604800000 AS week_epoch,
       COUNT(*) AS writes
  FROM content_events
 WHERE type IN ('record.created', 'record.updated')
 GROUP BY created_at_ms / 604800000
 ORDER BY week_epoch DESC;
```

The declared-or-declared-none fraction has no portable SQL form: the logical `content_events` relation exposes no payload or run-key column, so per-write `sources` declarations can be neither filtered nor aggregated in `query_sql`. Sample records and read their history instead, where each write event carries its `sources` declaration. To bound recency, add `WHERE created_at_ms >= ?1` with a client-computed epoch-millis cutoff passed as a parameter: a relative 'now' has no portable spelling (Native e25665c).

"#,
    );
    out.push_str("## Applying the model\n\nStart with the user's desired outcome. Choose a practical workflow, comparison, or conceptual explanation that can create value now. Use workspace records as the normal durable destination, `native:unfiled` when no better workspace home is known, and My agent context when the user intentionally wants the result private. Do not confuse storing something with finishing the user's job.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_and_guide_share_every_principle() {
        let compact = compact();
        let markdown = guide_markdown();
        assert_eq!(compact["contract"], CONTRACT);
        assert_eq!(compact["version"], VERSION);
        assert_eq!(
            compact["principles"].as_array().unwrap().len(),
            PRINCIPLES.len()
        );
        for principle in PRINCIPLES {
            assert!(markdown.contains(principle.summary));
            assert!(markdown.contains(principle.explanation));
        }
    }
}

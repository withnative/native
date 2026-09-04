//! Compile-time embedded, repo-canonical orientation guides.
//!
//! The table in this module is the sole callable-topic truth. Discovery,
//! dispatch and stale-caller diagnostics all derive from it; bootstrap does
//! not carry a second index.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::Db;
use crate::error::{Error, Result};

use super::registry::{Caller, ToolRegistry};
use super::ToolKind;

/// The repo-canonical source class for one compiled guide.
///
/// This lives beside the topic rather than in the generator so extending the
/// callable corpus and choosing how its body is produced is one atomic edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuideSource {
    HandwrittenTemplate,
    ProductModel,
    FrozenSqliteDdl,
    CompleteToolRegistry,
}

/// One callable guide topic, its final Markdown body, and its source class.
#[derive(Clone, Copy, Debug)]
pub struct GuideSpec {
    pub topic: &'static str,
    pub markdown: &'static str,
    pub source: GuideSource,
}

/// The canonical ordered topic table for the shipped guide corpus.
pub const GUIDE_SPECS: [GuideSpec; 24] = [
    GuideSpec {
        topic: "about",
        markdown: include_str!("about.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "entering-a-live-shared-world",
        markdown: include_str!("entering-a-live-shared-world.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "earning-intelligent-independence",
        markdown: include_str!("earning-intelligent-independence.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "turning-intent-into-useful-durable-work",
        markdown: include_str!("turning-intent-into-useful-durable-work.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "working-in-a-shared-world",
        markdown: include_str!("working-in-a-shared-world.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "effective-sessions",
        markdown: include_str!("effective-sessions.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "effective-searching",
        markdown: include_str!("effective-searching.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "effective-writing",
        markdown: include_str!("effective-writing.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "product-model",
        markdown: include_str!("product-model.md"),
        source: GuideSource::ProductModel,
    },
    GuideSpec {
        topic: "placement",
        markdown: include_str!("placement.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "record-types",
        markdown: include_str!("record-types.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "links",
        markdown: include_str!("links.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "facets-and-vocabularies",
        markdown: include_str!("facets-and-vocabularies.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "query-dsl",
        markdown: include_str!("query-dsl.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "query-sql",
        markdown: include_str!("query-sql.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "lifecycle",
        markdown: include_str!("lifecycle.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "coordination",
        markdown: include_str!("coordination.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "messaging",
        markdown: include_str!("messaging.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "attachment",
        markdown: include_str!("attachment.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "compositions",
        markdown: include_str!("compositions.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "change-summaries",
        markdown: include_str!("change-summaries.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "interpretive-claims",
        markdown: include_str!("interpretive-claims.md"),
        source: GuideSource::HandwrittenTemplate,
    },
    GuideSpec {
        topic: "sql-schema",
        markdown: include_str!("sql-schema.md"),
        source: GuideSource::FrozenSqliteDdl,
    },
    GuideSpec {
        topic: "capabilities",
        markdown: include_str!("capabilities.md"),
        source: GuideSource::CompleteToolRegistry,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadGuideArgs {
    topic: String,
}

fn valid_topics() -> Vec<&'static str> {
    GUIDE_SPECS.iter().map(|guide| guide.topic).collect()
}

async fn read_guide(_db: Db, _caller: Caller, arguments: Value) -> Result<Value> {
    let args: ReadGuideArgs = serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("read_guide: invalid arguments: {error}")))?;
    let Some(guide) = GUIDE_SPECS.iter().find(|guide| guide.topic == args.topic) else {
        return Err(Error::engine(format!(
            "read_guide: unknown topic '{}'; valid topics: {}",
            args.topic,
            valid_topics().join(", ")
        )));
    };
    Ok(json!({ "topic": guide.topic, "markdown": guide.markdown }))
}

pub(crate) fn register_guide_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ReadGuide,
        "Read one compiled cross-cutting guide by topic. Use the topic enum for discovery; guide bodies are returned only on demand.",
        json!({
            "type": "object",
            "properties": {
                "topic": {
                    "type": "string",
                    "enum": valid_topics()
                }
            },
            "required": ["topic"],
            "additionalProperties": false
        }),
        read_guide,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn canonical_topics_are_unique_ordered_and_non_empty() {
        let mut unique = HashSet::new();
        for guide in GUIDE_SPECS {
            assert!(
                unique.insert(guide.topic),
                "duplicate topic {}",
                guide.topic
            );
            assert!(
                !guide.markdown.trim().is_empty(),
                "empty guide {}",
                guide.topic
            );
        }
        assert_eq!(valid_topics().len(), unique.len());
        assert_eq!(
            valid_topics(),
            vec![
                "about",
                "entering-a-live-shared-world",
                "earning-intelligent-independence",
                "turning-intent-into-useful-durable-work",
                "working-in-a-shared-world",
                "effective-sessions",
                "effective-searching",
                "effective-writing",
                "product-model",
                "placement",
                "record-types",
                "links",
                "facets-and-vocabularies",
                "query-dsl",
                "query-sql",
                "lifecycle",
                "coordination",
                "messaging",
                "attachment",
                "compositions",
                "change-summaries",
                "interpretive-claims",
                "sql-schema",
                "capabilities",
            ]
        );
        let searching = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "effective-searching")
            .unwrap()
            .markdown;
        for phrase in [
            "full id or short record reference",
            "Pass that address in `ids`",
            "Its `query` is text, not a record address",
            "address-valued `scope`",
        ] {
            assert!(
                searching.contains(phrase),
                "missing {phrase:?}: {searching}"
            );
        }
    }

    #[test]
    fn messaging_guide_covers_the_reply_and_mention_model() {
        let guide = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "messaging")
            .expect("messaging guide");
        for phrase in [
            "communication origin",
            "Filing home",
            "Addressed audience",
            "addressed_to",
            "expectation",
            "reply_to",
            "supersedes",
            "cannot be added after creation",
            "sent flat",
            "unthreaded",
            "half-open",
            "character boundaries",
            "authored_label",
            "principal",
            "record mentions",
            "Héllo recipient",
            "recipient confirmed",
            "Failure modes",
        ] {
            assert!(
                guide.markdown.contains(phrase),
                "messaging guide must cover {phrase:?}"
            );
        }
    }

    #[test]
    fn registration_derives_the_topic_enum_without_descriptions() {
        let mut registry = ToolRegistry::new();
        register_guide_tool(&mut registry).unwrap();
        let spec = registry.get("read_guide").unwrap();
        assert_eq!(
            spec.input_schema["properties"]["topic"]["enum"],
            json!(valid_topics())
        );
        assert!(spec.input_schema["properties"]["topic"]
            .get("description")
            .is_none());
    }

    #[tokio::test]
    async fn handler_returns_exact_payload_and_unknown_lists_every_topic() {
        let db = crate::create_database(":memory:").await.unwrap();
        let expected = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "query-sql")
            .unwrap();
        let value = read_guide(db.clone(), Caller::local(), json!({ "topic": "query-sql" }))
            .await
            .unwrap();
        assert_eq!(
            value,
            json!({ "topic": "query-sql", "markdown": expected.markdown })
        );

        let error = read_guide(
            db.clone(),
            Caller::local(),
            json!({ "topic": "future-topic" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown topic 'future-topic'"), "{error}");
        assert!(error.ends_with(&valid_topics().join(", ")), "{error}");

        for topic in ["interpretive-claims", "sql-schema", "capabilities"] {
            let guide = GUIDE_SPECS
                .iter()
                .find(|guide| guide.topic == topic)
                .unwrap();
            let value = read_guide(db.clone(), Caller::local(), json!({ "topic": topic }))
                .await
                .unwrap();
            assert_eq!(value, json!({ "topic": topic, "markdown": guide.markdown }));
        }
        db.close().await;
    }
}

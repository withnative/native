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
    SuppliedKitRelease,
}

/// One callable guide topic, its final Markdown body, and its source class.
#[derive(Clone, Copy, Debug)]
pub struct GuideSpec {
    pub topic: &'static str,
    pub markdown: &'static str,
    pub source: GuideSource,
}

/// The canonical ordered topic table for the shipped guide corpus.
pub const GUIDE_SPECS: [GuideSpec; 28] = [
    GuideSpec {
        topic: "app-builder-1.0.0",
        markdown: include_str!("app-builder-1.0.0.md"),
        source: GuideSource::HandwrittenTemplate,
    },
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
        topic: "app-skins",
        markdown: include_str!("app-skins.md"),
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
    GuideSpec {
        topic: "app-kit-core-1.0.0",
        markdown: include_str!("app-kit-core-1.0.0.md"),
        source: GuideSource::SuppliedKitRelease,
    },
    GuideSpec {
        topic: "app-kit-core-1.1.0",
        markdown: include_str!("app-kit-core-1.1.0.md"),
        source: GuideSource::SuppliedKitRelease,
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
                "app-builder-1.0.0",
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
                "app-skins",
                "change-summaries",
                "interpretive-claims",
                "sql-schema",
                "capabilities",
                "app-kit-core-1.0.0",
                "app-kit-core-1.1.0",
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

        for topic in [
            "app-builder-1.0.0",
            "app-kit-core-1.0.0",
            "app-kit-core-1.1.0",
            "interpretive-claims",
            "sql-schema",
            "capabilities",
        ] {
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

    #[test]
    fn app_requests_route_to_the_callable_installed_app_builder() {
        let builder = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "app-builder-1.0.0")
            .unwrap();
        for prerequisite in [
            "app-kit-core-1.1.0",
            "artifacts_read.manage_alpha_tabs.prepare_install",
            "Preview",
            "Adopt",
        ] {
            assert!(builder.markdown.contains(prerequisite), "{prerequisite}");
        }
        let prose = builder.markdown.split("```").step_by(2).collect::<String>();
        let prose = prose.to_ascii_lowercase();
        for scenario in ["meeting", "inbox"] {
            assert!(!prose.contains(scenario), "builder prose must stay generic");
        }
        let compositions = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "compositions")
            .unwrap();
        let routing = compositions
            .markdown
            .split_once("\n## ")
            .expect("compositions has recipe sections")
            .0;
        for text in [
            routing,
            crate::instructions::ENGINE_ORIENTATION,
            super::super::tools::quickstart::MARKDOWN,
        ] {
            let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
            for cue in ["app-builder-1.0.0", "installed apps", "Preview/Adopt"] {
                assert!(normalized.contains(cue), "missing {cue}: {normalized}");
            }
        }
        let mut registry = ToolRegistry::new();
        register_guide_tool(&mut registry).unwrap();
        let tool = registry.get("read_guide").unwrap();
        assert!(tool.input_schema["properties"]["topic"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!(builder.topic)));
    }

    #[test]
    fn app_builder_operation_pairs_exist_in_generated_catalogue() {
        let catalogue: Value = serde_json::from_str(include_str!(
            "../executor_prototype/candidate-audit.public.generated.json"
        ))
        .unwrap();
        let pairs: std::collections::BTreeSet<_> = catalogue["audit_rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                format!(
                    "{}.{}",
                    row["candidate_executor"].as_str().unwrap(),
                    row["candidate_operation"].as_str().unwrap()
                )
            })
            .collect();
        let legacy_tools: std::collections::BTreeSet<_> = catalogue["audit_rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["legacy_tool"].as_str().unwrap())
            .collect();
        let executors: std::collections::BTreeSet<_> = catalogue["audit_rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["candidate_executor"].as_str().unwrap())
            .collect();
        let preparation = "artifacts_read.manage_alpha_tabs.prepare_install";
        assert!(
            pairs.contains(preparation),
            "install preparation must exist in the catalogue"
        );
        let guide = GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "app-builder-1.0.0")
            .unwrap();
        let names =
            regex::Regex::new(r"\b([a-z][a-z0-9]*_[a-z0-9_]+)\.([a-z][a-z0-9_.]+)\b").unwrap();
        let mut named: std::collections::BTreeSet<_> = names
            .find_iter(guide.markdown)
            .filter(|name| {
                let prefix = name.as_str().split('.').next().unwrap();
                // `manage_alpha_tabs.prepare_install` alone is an action name,
                // not an executor pair; its separate executor is checked below.
                prefix != "next_call"
                    && (!legacy_tools.contains(prefix) || executors.contains(prefix))
            })
            .map(|name| name.as_str().to_owned())
            .collect();
        let dispatch =
            regex::Regex::new(r"executor `([a-z_]+)`,\s*operation `([a-z0-9_.]+)`").unwrap();
        for capture in dispatch.captures_iter(guide.markdown) {
            named.insert(format!("{}.{}", &capture[1], &capture[2]));
        }
        assert!(
            named.contains(preparation),
            "builder must name the preparation prerequisite"
        );
        for name in named {
            assert!(
                pairs.contains(&name),
                "builder names unknown executor/operation pair: {name}"
            );
        }
    }

    #[test]
    fn core_release_guide_contains_exact_canonical_types_and_hashes() {
        for (topic, manifest_text, types) in [
            (
                "app-kit-core-1.0.0",
                include_str!("../../../crates/artifact-html/kit-releases/1.0.0/manifest.json"),
                include_str!("../../../crates/artifact-html/kit-releases/1.0.0/core.d.ts"),
            ),
            (
                "app-kit-core-1.1.0",
                include_str!("../../../crates/artifact-html/kit-releases/1.1.0/manifest.json"),
                include_str!("../../../crates/artifact-html/kit-releases/1.1.0/core.d.ts"),
            ),
        ] {
            let guide = GUIDE_SPECS
                .iter()
                .find(|guide| guide.topic == topic)
                .unwrap();
            let manifest: Value = serde_json::from_str(manifest_text).unwrap();
            assert!(guide
                .markdown
                .contains(&format!("```typescript\n{types}```")));
            for key in ["js", "types"] {
                assert!(guide
                    .markdown
                    .contains(manifest[key]["sha256"].as_str().unwrap()));
            }
            assert!(guide
                .markdown
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("synchronously before the first author script"));
            assert!(guide.markdown.contains("kit_major_unavailable"));
            assert_eq!(guide.source, GuideSource::SuppliedKitRelease);
        }
    }

    /// E2 I-6: every SQL statement an agent can read in the shipped guides
    /// must pass the SQLite validator, so worked examples can never teach a
    /// statement the engine rejects. Extracts fenced ```sql blocks and
    /// `"sql"` JSON fields whose value is a SELECT/WITH statement from the
    /// exact rendered bodies agents receive. The `sql-schema` topic is
    /// physical DDL documentation, not queryable SQL, and is skipped by
    /// source class.
    #[test]
    fn every_guide_sql_example_passes_the_sqlite_validator() {
        let mut checked = 0;
        for guide in GUIDE_SPECS {
            if guide.source == GuideSource::FrozenSqliteDdl {
                continue;
            }
            // Native 702de73: examples in the ad-hoc SQLite section are
            // validated under the ad-hoc allowance; every other example must
            // still pass the portable validator, so saved-SQL teaching is
            // unchanged.
            let ad_hoc_section = guide
                .markdown
                .split_once("## SQLite functions in ad-hoc SQL")
                .map(|(_, rest)| rest.split("\n## ").next().unwrap_or(rest))
                .unwrap_or("");
            for (origin, statement) in guide_sql_examples(guide.topic, guide.markdown) {
                let validated = if ad_hoc_section.contains(statement.as_str()) {
                    crate::query::sql::validate_ad_hoc(&statement)
                } else {
                    crate::query::sql::validate(&statement)
                };
                validated.unwrap_or_else(|error| {
                    panic!("guide {origin} teaches a rejected statement: {error}\n{statement}")
                });
                checked += 1;
            }
        }
        assert!(
            checked >= 4,
            "guide SQL guard found only {checked} examples; the extractor is stale"
        );
    }

    /// `(topic:location, statement)` pairs an agent could copy into
    /// `query_sql`: fenced sql blocks plus `"sql"` JSON string values that
    /// parse as a SELECT/WITH statement.
    fn guide_sql_examples(topic: &str, markdown: &str) -> Vec<(String, String)> {
        let mut examples = Vec::new();
        let mut rest = markdown;
        while let Some(open) = rest.find("```sql") {
            let after_open = &rest[open + "```sql".len()..];
            let Some(close) = after_open.find("```") else {
                break;
            };
            let statement = after_open[..close].trim().to_string();
            if !statement.is_empty() {
                examples.push((format!("{topic} fenced block"), statement));
            }
            rest = &after_open[close + "```".len()..];
        }
        let bytes = markdown.as_bytes();
        let mut index = 0;
        while let Some(key) = markdown[index..].find("\"sql\"") {
            let mut cursor = index + key + "\"sql\"".len();
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b':') {
                index = cursor;
                continue;
            }
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b'"') {
                index = cursor;
                continue;
            }
            cursor += 1;
            let mut value = String::new();
            let mut closed = false;
            while let Some(byte) = bytes.get(cursor) {
                match byte {
                    b'"' => {
                        closed = true;
                        cursor += 1;
                        break;
                    }
                    b'\\' => {
                        cursor += 1;
                        match bytes.get(cursor) {
                            Some(b'n') => value.push('\n'),
                            Some(b't') => value.push('\t'),
                            Some(b'r') => value.push('\r'),
                            Some(b'u') => {
                                let hex = markdown
                                    .get(cursor + 1..cursor + 5)
                                    .filter(|hex| {
                                        hex.len() == 4
                                            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                                    })
                                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                                    .and_then(char::from_u32)
                                    .unwrap_or_else(|| {
                                        panic!("guide {topic} has an invalid \\u escape")
                                    });
                                value.push(hex);
                                cursor += 4;
                            }
                            Some(other) => value.push(*other as char),
                            None => break,
                        }
                        cursor += 1;
                    }
                    _ => {
                        value.push(*byte as char);
                        cursor += 1;
                    }
                }
            }
            index = cursor;
            if !closed {
                continue;
            }
            let head = value.trim_start().to_ascii_uppercase();
            if head.starts_with("SELECT") || head.starts_with("WITH") {
                examples.push((format!("{topic} \"sql\" field"), value));
            }
        }
        examples
    }
}

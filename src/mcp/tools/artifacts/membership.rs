//! Single-target collection membership for write-path binding checks.
//!
//! [`resolve_collection_in`] builds a bound collection's every member (record
//! rows, facet maps, schema rows, sort) and costs time in proportion to the
//! collection. A write that only needs to know whether one target is inside
//! can ask the same query engine a narrowed question instead, provided the
//! narrowing returns exactly the answer the full resolution would.
//!
//! Each narrowing below leans on the pipeline's semantics
//! (`crate::query::pipeline`): a filter step keeps the ids that satisfy its
//! conjunction of predicates (live, not hidden, not archived unless
//! `include_archived`, plus its own constraints) and that the caller can
//! View, and its result does not depend on which other ids it was given.
//! Hidden-family visibility is decided once per pipeline from the kinds its
//! filters name, so a step that names no kinds leaves it unchanged.

use super::*;

/// Whether `target` is among the members [`resolve_collection_in`] would
/// return for `(id, kind)`, answered without materializing the collection
/// where an exact narrowing exists.
///
/// Errors match too, as far as the target can see them: a collection the
/// full resolver could not resolve (unsupported kind, invalid or governed
/// saved query) falls back to it and fails the same way, and the target's
/// own row is converted exactly as the full resolver converts every member,
/// so a non-canonical declared facet on the target still refuses. The one
/// deliberate difference is that another member's non-canonical facet no
/// longer refuses a write to this target.
pub(crate) async fn collection_contains_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    id: &str,
    kind: &str,
    target: &str,
) -> Result<bool> {
    let Some(values) = target_member_values_in(tx, caller, id, kind, target).await? else {
        let members = resolve_collection_in(tx, caller, id, kind).await?;
        return Ok(members.iter().any(|record| record.id == target));
    };
    if values.is_empty() {
        return Ok(false);
    }
    let records = input_records_from_values_in(tx, values).await?;
    Ok(records.iter().any(|record| record.id == target))
}

/// The collection's member rows narrowed to `target` (so at most the target
/// itself), or `None` when this collection has no exact narrowing and must
/// be resolved whole.
async fn target_member_values_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    id: &str,
    kind: &str,
    target: &str,
) -> Result<Option<Vec<Value>>> {
    // Prepending this seed to a pipeline of filters intersects its result
    // with {target}: every later filter then tests the target alone, against
    // the same predicates it applies when seeding from the whole file.
    // `include_archived` keeps the seed from excluding anything the original
    // filters would admit; naming no kinds leaves hidden visibility alone.
    let seed = json!({"step": "filter", "ids": [target], "include_archived": true});
    match kind {
        // Full: filter{home_id}. Narrowed: [seed, filter{home_id}].
        "folder" => Ok(Some(
            paged_query_in(
                tx,
                caller,
                &json!({"steps": [seed, {"step": "filter", "home_id": id}], "order": "name_asc"}),
            )
            .await?,
        )),
        // Full: [filter{ids:[id]}, traverse member_of in] — every live,
        // visible, viewable source of a member_of link into a live,
        // unarchived, viewable collection. Walking the same link outward
        // from the target and then filtering to the collection tests the
        // same conjunction of predicates on the same two records, so the
        // answer is non-empty exactly when the target is a member. This
        // costs two small queries (the walk, then the target's own row)
        // where the other kinds need one.
        "selection" => {
            let reached = paged_query_in(
                tx,
                caller,
                &json!({
                    "steps": [
                        seed,
                        { "step": "traverse", "target": "links", "relationship": "member_of", "direction": "out" },
                        { "step": "filter", "ids": [id] }
                    ],
                    "order": "name_asc"
                }),
            )
            .await?;
            if reached.is_empty() {
                return Ok(Some(Vec::new()));
            }
            // The target's own row, rendered as any query renders it.
            Ok(Some(
                paged_query_in(tx, caller, &json!({"steps": [seed], "order": "name_asc"})).await?,
            ))
        }
        "query" => {
            let Some(mut query) = all_matching_filter_query_in(tx, id).await? else {
                return Ok(None);
            };
            query["steps"]
                .as_array_mut()
                .expect("checked: steps is an array")
                .insert(0, seed);
            Ok(Some(paged_query_in(tx, caller, &query).await?))
        }
        _ => Ok(None),
    }
}

/// The collection's saved query when its full membership is every match of
/// a pipeline made only of filter steps — the shape a prepended seed
/// narrows exactly. Anything else (a traverse, a page bound, an implicit
/// page scope, extra plan keys, an unreadable query) returns `None`.
async fn all_matching_filter_query_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
) -> Result<Option<Value>> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = 'query'")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let super::super::querying::SavedQueryInspection::Valid { query, .. } =
        super::super::querying::inspect_saved_record_query(raw.as_deref())
    else {
        return Ok(None);
    };
    let all_matching: Option<String> = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'input_membership'",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    if all_matching.as_deref() != Some("all_matching") {
        return Ok(None);
    }
    let Some(plan) = query.as_object() else {
        return Ok(None);
    };
    if plan.keys().any(|key| key != "steps" && key != "order") {
        return Ok(None);
    }
    let filters_only = plan
        .get("steps")
        .and_then(Value::as_array)
        .is_some_and(|steps| {
            !steps.is_empty()
                && steps
                    .iter()
                    .all(|step| step.get("step").and_then(Value::as_str) == Some("filter"))
        });
    Ok(filters_only.then_some(query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::AllowEntry;

    const ACCOUNT: &str = "membership-reader";
    const FOLDER: &str = "c0000000-0000-4000-8000-0000000000f1";
    const SELECTION: &str = "c0000000-0000-4000-8000-0000000000f2";
    const ARCHIVED_SELECTION: &str = "c0000000-0000-4000-8000-0000000000f3";
    const SUBFOLDER: &str = "c0000000-0000-4000-8000-0000000000f4";
    const VISIBLE: &str = "c0000000-0000-4000-8000-0000000000d1";
    const NOTE_TWO: &str = "c0000000-0000-4000-8000-0000000000d2";
    const ARCHIVED: &str = "c0000000-0000-4000-8000-0000000000d3";
    const DELETED: &str = "c0000000-0000-4000-8000-0000000000d4";
    const UNVIEWABLE: &str = "c0000000-0000-4000-8000-0000000000d5";
    const TASK: &str = "c0000000-0000-4000-8000-0000000000d6";
    const OUTSIDE: &str = "c0000000-0000-4000-8000-0000000000d7";
    const NESTED: &str = "c0000000-0000-4000-8000-0000000000d8";
    const PROGRESS: &str = "c0000000-0000-4000-8000-0000000000d9";
    const COMMENT: &str = "c0000000-0000-4000-8000-0000000000da";
    const OWNER: &str = "c0000000-0000-4000-8000-0000000000db";
    const DOCS: &str = "c0000000-0000-4000-8000-0000000000a1";

    /// How a query collection's `query` facet is stored.
    enum Stored {
        /// Written through `create_record` as a v0.2 saved record query.
        Saved(Value),
        /// Written past the tool surface after creation: `Some` replaces the
        /// facet's raw text, `None` removes the facet.
        Raw(Option<String>),
    }

    struct QueryCase {
        id: &'static str,
        stored: Stored,
        all_matching: bool,
        /// Whether `collection_contains_in` narrows it (else full fallback).
        narrowed: bool,
    }

    fn case(id: &'static str, query: Value, narrowed: bool) -> QueryCase {
        QueryCase {
            id,
            stored: Stored::Saved(query),
            all_matching: true,
            narrowed,
        }
    }

    fn raw(id: &'static str, text: Option<String>) -> QueryCase {
        QueryCase {
            id,
            stored: Stored::Raw(text),
            all_matching: true,
            narrowed: false,
        }
    }

    /// A valid saved governed SQL definition (the shape record ports refuse).
    fn governed_sql() -> String {
        use crate::mcp::tools::querying::{
            SavedSqlBounds, SavedSqlColumn, SavedSqlColumnType, SavedSqlDefinition,
            SavedSqlDirection, SavedSqlOrder, SavedSqlOutput, SavedSqlProfile,
            SavedSqlRelationDependency,
        };
        let columns = vec![
            SavedSqlColumn {
                name: "id".into(),
                column_type: SavedSqlColumnType::Identifier,
                nullable: false,
            },
            SavedSqlColumn {
                name: "name".into(),
                column_type: SavedSqlColumnType::Text,
                nullable: false,
            },
        ];
        let schema_sha256 = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!(columns)));
        serde_json::to_string(&SavedSqlDefinition {
            v: "1.1".into(),
            kind: "governed_sql".into(),
            profile: SavedSqlProfile {
                id: "sqlite-local".into(),
                revision: 1,
            },
            catalog_revision: crate::query::sql_contract::LOGICAL_CATALOG_REVISION,
            relations: BTreeMap::from([(
                "records".into(),
                SavedSqlRelationDependency {
                    identity: "native.query-sql.records".into(),
                    semantic_version: 1,
                },
            )]),
            sql: "SELECT id,name FROM records WHERE type=?1".into(),
            parameters: vec![crate::query::sql_contract::QuerySqlParameter::Text {
                value: Some("Document".into()),
            }],
            output: SavedSqlOutput {
                columns,
                schema_sha256,
                row_identity: vec!["id".into()],
                order: vec![
                    SavedSqlOrder {
                        column: "name".into(),
                        direction: SavedSqlDirection::Asc,
                    },
                    SavedSqlOrder {
                        column: "id".into(),
                        direction: SavedSqlDirection::Asc,
                    },
                ],
            },
            bounds: SavedSqlBounds { rows: 10 },
        })
        .unwrap()
    }

    /// Saved query collections. The narrowed ones each exercise one part of
    /// the "filters are per-row conjunctions" argument; the rest must fall
    /// back to the full resolution.
    fn query_collections() -> Vec<QueryCase> {
        let documents =
            json!({"steps": [{"step": "filter", "types": ["Document"]}], "order": "name_asc"});
        vec![
            // Docs' production `pages` binding.
            case(
                DOCS,
                json!({"steps": [{"step": "filter", "types": ["Document"], "include_archived": true}], "order": "name_asc"}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000a2",
                json!({"steps": [{"step": "filter", "home_id": FOLDER}, {"step": "filter", "kinds": ["note"]}], "order": "name_asc"}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000a3",
                json!({"steps": [{"step": "filter", "types": ["WorkItem"], "lifecycle": ["open"]}]}),
                true,
            ),
            // A hidden-family kind opts the whole pipeline into comments.
            case(
                "c0000000-0000-4000-8000-0000000000a7",
                json!({"steps": [{"step": "filter", "kinds": ["comment"], "include_archived": true}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000a8",
                json!({"steps": [{"step": "filter", "facets": [{"key": "priority", "eq": "high"}]}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000a9",
                json!({"steps": [{"step": "filter", "facets": [{"key": "score", "gte": 2}]}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000aa",
                json!({"steps": [{"step": "filter", "ancestor_id": FOLDER}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000ab",
                json!({"steps": [{"step": "filter", "owner_id": OWNER}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000ac",
                json!({"steps": [{"step": "filter", "name_contains": "SEC"}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000ad",
                json!({"steps": [{"step": "filter", "has_query": true}]}),
                true,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000ae",
                json!({"steps": [{"step": "filter", "types": ["Collection"], "bears_shape": false}]}),
                true,
            ),
            // `in_progress` is aliased to `open` in the fixture.
            case(
                "c0000000-0000-4000-8000-0000000000af",
                json!({"steps": [{"step": "filter", "types": ["WorkItem"], "lifecycle": ["in_progress"]}]}),
                true,
            ),
            // An archived-inclusive filter, then a default one that drops them.
            case(
                "c0000000-0000-4000-8000-0000000000b0",
                json!({"steps": [{"step": "filter", "types": ["Document"], "include_archived": true}, {"step": "filter", "home_id": FOLDER}]}),
                true,
            ),
            // Fallbacks: a traverse, an explicit bound, an offset, an
            // implicit page, an extra plan key, a missing, invalid or
            // governed-SQL query facet.
            case(
                "c0000000-0000-4000-8000-0000000000a4",
                json!({"steps": [{"step": "filter", "ids": [SELECTION]}, {"step": "traverse", "target": "links", "relationship": "member_of", "direction": "in"}]}),
                false,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000a5",
                json!({"steps": [{"step": "filter", "types": ["Document"]}], "order": "name_asc", "limit": 2}),
                false,
            ),
            case(
                "c0000000-0000-4000-8000-0000000000b1",
                json!({"steps": [{"step": "filter", "types": ["Document"]}], "order": "name_asc", "offset": 1}),
                false,
            ),
            QueryCase {
                id: "c0000000-0000-4000-8000-0000000000a6",
                stored: Stored::Saved(documents.clone()),
                all_matching: false,
                narrowed: false,
            },
            raw(
                "c0000000-0000-4000-8000-0000000000b2",
                Some(
                    json!({"v": "0.2", "query": {"steps": [{"step": "filter", "types": ["Document"]}], "count_by": "type"}})
                        .to_string(),
                ),
            ),
            raw("c0000000-0000-4000-8000-0000000000b3", None),
            raw("c0000000-0000-4000-8000-0000000000b4", Some("not json".into())),
            raw("c0000000-0000-4000-8000-0000000000b5", Some(governed_sql())),
        ]
    }

    async fn fixture() -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let local = Caller::local();
        let call = |tool: &'static str, args: Value| {
            let (db, registry, local) = (db.clone(), &registry, local.clone());
            async move { registry.call(db, local, tool, args).await.unwrap() }
        };
        for (id, kind, name) in [
            (FOLDER, "folder", "Membership folder"),
            (SELECTION, "selection", "Membership selection"),
            (ARCHIVED_SELECTION, "selection", "Archived selection"),
        ] {
            call(
                "create_record",
                json!({"id": id, "type": "Collection", "kind": kind,
                "name": name, "reason": "Membership fixture."}),
            )
            .await;
        }
        call(
            "create_record",
            json!({"id": SUBFOLDER, "type": "Collection", "kind": "folder", "name": "Subfolder",
                "home_id": FOLDER, "reason": "Membership fixture."}),
        )
        .await;
        call(
            "create_record",
            json!({"id": OWNER, "type": "Entity", "kind": "person", "name": "Owner",
                "reason": "Membership fixture."}),
        )
        .await;
        for (id, type_, kind, name, home) in [
            (VISIBLE, "Document", "note", "visible", Some(FOLDER)),
            (NOTE_TWO, "Document", "note", "second", Some(FOLDER)),
            (ARCHIVED, "Document", "note", "archived", Some(FOLDER)),
            (DELETED, "Document", "note", "deleted", Some(FOLDER)),
            (UNVIEWABLE, "Document", "note", "unviewable", Some(FOLDER)),
            (TASK, "WorkItem", "task", "task", Some(FOLDER)),
            (PROGRESS, "WorkItem", "task", "progress", Some(FOLDER)),
            (OUTSIDE, "Document", "note", "outside", None),
            (NESTED, "Document", "note", "nested", Some(SUBFOLDER)),
        ] {
            let mut args = json!({"id": id, "type": type_, "kind": kind, "name": name,
                "reason": "Membership fixture."});
            if let Some(home) = home {
                args["home_id"] = json!(home);
            }
            match id {
                TASK => args["lifecycle"] = json!("open"),
                PROGRESS => args["lifecycle"] = json!("in_progress"),
                VISIBLE => {
                    args["facets"] = json!({"priority": "high", "score": 3});
                    args["owner_id"] = json!(OWNER);
                }
                NOTE_TWO => args["facets"] = json!({"score": 1}),
                _ => {}
            }
            call("create_record", args).await;
        }
        call(
            "create_record",
            json!({"id": COMMENT, "type": "Annotation", "kind": "comment", "name": "Stored comment",
                "lifecycle": "open", "body": "A concern.", "home_id": FOLDER,
                "links": [{"target_id": VISIBLE, "relationship": "part_of"}],
                "reason": "Membership fixture."}),
        )
        .await;
        for member in [VISIBLE, ARCHIVED, DELETED, UNVIEWABLE, OUTSIDE] {
            call(
                "manage_links",
                json!({"action": "add", "source_id": member,
                "target_id": SELECTION, "relationship": "member_of"}),
            )
            .await;
        }
        call(
            "manage_links",
            json!({"action": "add", "source_id": VISIBLE,
            "target_id": ARCHIVED_SELECTION, "relationship": "member_of"}),
        )
        .await;
        let benign = json!({"steps": [{"step": "filter", "types": ["Document"]}]});
        for query in query_collections() {
            let saved = match &query.stored {
                Stored::Saved(saved) => saved,
                Stored::Raw(_) => &benign,
            };
            let mut facets = json!({"query": json!({"v": "0.2", "query": saved}).to_string()});
            if query.all_matching {
                facets["input_membership"] = json!("all_matching");
            }
            call(
                "create_record",
                json!({"id": query.id, "type": "Collection", "kind": "query",
                "name": format!("query {}", query.id), "facets": facets, "reason": "Membership fixture."}),
            )
            .await;
            if let Stored::Raw(text) = &query.stored {
                let statement = match text {
                    Some(_) => {
                        "UPDATE facet_values SET value=?1 WHERE record_id=?2 AND key='query'"
                    }
                    None => {
                        "DELETE FROM facet_values WHERE ?1 IS NULL AND record_id=?2 AND key='query'"
                    }
                };
                sqlx::query(statement)
                    .bind(text)
                    .bind(query.id)
                    .execute(db.write_pool())
                    .await
                    .unwrap();
            }
        }
        for id in [ARCHIVED, ARCHIVED_SELECTION] {
            call(
                "archive_record",
                json!({"id": id, "reason": "Membership fixture."}),
            )
            .await;
        }
        call(
            "delete_record",
            json!({"id": DELETED, "reason": "Membership fixture."}),
        )
        .await;
        // Alias `in_progress` to `open`, after PROGRESS stored the raw token.
        let value_id = |value: &'static str| {
            let db = db.clone();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT id FROM vocabulary_values WHERE vocabulary_id='voc:lifecycle' AND value=?",
                )
                .bind(value)
                .fetch_one(db.write_pool())
                .await
                .unwrap()
            }
        };
        crate::meta::alias_value(&db, &value_id("in_progress").await, &value_id("open").await)
            .await
            .unwrap();
        // The reader sees the folder's subtree, the selections, the outside
        // note and the query collections — but not UNVIEWABLE or OWNER.
        let mut readable = vec![FOLDER, SELECTION, ARCHIVED_SELECTION, OUTSIDE];
        readable.extend(query_collections().iter().map(|query| query.id));
        for id in readable {
            crate::authorization::replace_explicit_policy(
                &db,
                "test:membership",
                id,
                vec![AllowEntry::account(ACCOUNT, Capability::View)],
            )
            .await
            .unwrap();
        }
        crate::authorization::replace_explicit_policy(&db, "test:membership", UNVIEWABLE, vec![])
            .await
            .unwrap();
        db
    }

    fn collections() -> Vec<(&'static str, &'static str)> {
        let mut all = vec![
            (FOLDER, "folder"),
            (SELECTION, "selection"),
            (ARCHIVED_SELECTION, "selection"),
        ];
        all.extend(query_collections().iter().map(|query| (query.id, "query")));
        all
    }

    fn targets() -> Vec<&'static str> {
        vec![
            VISIBLE,
            NOTE_TWO,
            ARCHIVED,
            DELETED,
            UNVIEWABLE,
            TASK,
            PROGRESS,
            OUTSIDE,
            NESTED,
            COMMENT,
            OWNER,
            FOLDER,
            SUBFOLDER,
            SELECTION,
            DOCS,
            "c0000000-0000-4000-8000-00000000dead",
        ]
    }

    /// The targeted answer, the full resolution's answer, side by side.
    async fn both(
        db: &Db,
        caller: &Caller,
        id: &str,
        kind: &str,
        target: &str,
    ) -> (
        std::result::Result<bool, String>,
        std::result::Result<bool, String>,
    ) {
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let targeted = collection_contains_in(&mut tx, caller, id, kind, target)
            .await
            .map_err(|error| error.to_string());
        let full = resolve_collection_in(&mut tx, caller, id, kind)
            .await
            .map(|members| members.iter().any(|record| record.id == target))
            .map_err(|error| error.to_string());
        tx.rollback().await.unwrap();
        (targeted, full)
    }

    #[tokio::test]
    async fn targeted_membership_agrees_with_full_resolution_for_every_kind_and_target() {
        let db = fixture().await;
        let narrowed: Vec<&str> = query_collections()
            .iter()
            .filter(|query| query.narrowed)
            .map(|query| query.id)
            .collect();
        for caller in [Caller::local(), Caller::authenticated(ACCOUNT)] {
            for (id, kind) in collections() {
                let mut inside = 0;
                for target in targets() {
                    let (targeted, full) = both(&db, &caller, id, kind, target).await;
                    assert_eq!(
                        targeted,
                        full,
                        "{kind} {id} target {target} caller {:?}",
                        caller.credential()
                    );
                    inside += usize::from(full == Ok(true));
                }
                // Guard against vacuous agreement: as the local caller,
                // every narrowed shape admits at least one target.
                if caller.credential() == Caller::local().credential() && narrowed.contains(&id) {
                    assert!(inside > 0, "narrowed query {id} admits no target");
                }
            }
        }
    }

    #[tokio::test]
    async fn targeted_membership_answers_the_cases_that_matter() {
        let db = fixture().await;
        let reader = Caller::authenticated(ACCOUNT);
        let cases = [
            // Folder: live children only; archived, deleted and unviewable out.
            (FOLDER, "folder", VISIBLE, true),
            (FOLDER, "folder", ARCHIVED, false),
            (FOLDER, "folder", DELETED, false),
            (FOLDER, "folder", UNVIEWABLE, false),
            (FOLDER, "folder", OUTSIDE, false),
            (FOLDER, "folder", NESTED, false),
            // Selection: traversal keeps archived members, not deleted or
            // unviewable ones; an archived selection resolves to nothing.
            (SELECTION, "selection", OUTSIDE, true),
            (SELECTION, "selection", ARCHIVED, true),
            (SELECTION, "selection", DELETED, false),
            (SELECTION, "selection", UNVIEWABLE, false),
            (SELECTION, "selection", NOTE_TWO, false),
            (ARCHIVED_SELECTION, "selection", VISIBLE, false),
            // Docs' pages query: every viewable Document, archived included.
            (DOCS, "query", VISIBLE, true),
            (DOCS, "query", ARCHIVED, true),
            (DOCS, "query", OUTSIDE, true),
            (DOCS, "query", NESTED, true),
            (DOCS, "query", DELETED, false),
            (DOCS, "query", UNVIEWABLE, false),
            (DOCS, "query", TASK, false),
            (DOCS, "query", COMMENT, false),
        ];
        for (id, kind, target, expected) in cases {
            let (targeted, full) = both(&db, &reader, id, kind, target).await;
            assert_eq!(full, Ok(expected), "full {kind} {target}");
            assert_eq!(targeted, Ok(expected), "targeted {kind} {target}");
        }
    }

    #[tokio::test]
    async fn only_all_matching_filter_queries_are_narrowed() {
        let db = fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        for query in query_collections() {
            let narrowed = all_matching_filter_query_in(&mut tx, query.id)
                .await
                .unwrap()
                .is_some();
            assert_eq!(narrowed, query.narrowed, "query {}", query.id);
        }
        tx.rollback().await.unwrap();
    }

    /// The one deliberate difference from the full resolution: it converts
    /// every member, so one malformed typed facet anywhere refused every
    /// target. The targeted check converts only the target.
    #[tokio::test]
    async fn only_the_targets_own_malformed_typed_facet_refuses() {
        let db = fixture().await;
        // Declare `score` a number for notes filed in FOLDER, then store a
        // non-canonical value on NOTE_TWO past the tool surface.
        sqlx::query(
            "INSERT INTO schema_config(id,layer,data,applies_to_collection_id) VALUES(?,'user',?,?)",
        )
        .bind("test:membership-score")
        .bind(json!({"shapes": {"Document:note": {"facets": {"score": {"type": "number"}}}}}).to_string())
        .bind(FOLDER)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE facet_values SET value='not a number' WHERE record_id=? AND key='score'",
        )
        .bind(NOTE_TWO)
        .execute(db.write_pool())
        .await
        .unwrap();
        let local = Caller::local();
        let malformed = Err(NON_CANONICAL_TYPED_FACET_ERROR.to_string());
        for (id, kind) in [(FOLDER, "folder"), (DOCS, "query")] {
            // The target itself is malformed: both refuse, identically.
            assert_eq!(
                both(&db, &local, id, kind, NOTE_TWO).await,
                (malformed.clone(), malformed.clone()),
                "{kind} malformed target"
            );
            // A neighbour is malformed: only the full resolution refuses.
            assert_eq!(
                both(&db, &local, id, kind, VISIBLE).await,
                (Ok(true), malformed.clone()),
                "{kind} malformed neighbour"
            );
        }
    }
}

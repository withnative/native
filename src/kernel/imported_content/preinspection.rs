//! Operator-owned v1 observations, never kernel activation authority. Unknown
//! dependency shapes use the whole source snapshot; only legacy standalone
//! board/MDX/HTML may use record partitions. Always rerun target verifiers.
use super::*;
use crate::v1_import::cutover::SnapshotEvidence;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FORMAT: &str = "native.v1-artifact-preinspection.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preinspection {
    schema: String,
    build_sha: String,
    members: BTreeSet<String>,
    entries: BTreeMap<String, Entry>,
    pub summary: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: Option<String>,
    observation: Observation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub outcomes: BTreeMap<String, Option<Value>>,
    pub non_string_failure: bool,
}

impl Observation {
    fn reusable(&self) -> bool {
        self.outcomes.values().flatten().all(|outcome| {
            outcome["status"] == "rendered"
                || matches!(
                    outcome["diagnostic"]["code"].as_str(),
                    Some(
                        "binding_unavailable"
                            | "named_input_missing"
                            | "module_capability_denied"
                            | "invalid_artifact_body"
                            | "missing_runtime"
                            | "unsupported_runtime"
                            | "unsupported_runtime_revision"
                            | "artifact_source_unattested"
                            | "binding_repinned_by_source_edit"
                            | "invalid_artifact_shape"
                            | "named_input_ambiguous"
                            | "named_input_incompatible"
                            | "html_source_too_large"
                            | "html_invalid_document"
                            | "unsupported_on_v2"
                    )
                )
        })
    }
}

// Standalone legacy readers consume their own source/runtime and governed
// schema, with current View authority rechecked for EVERY member. They have no
// collection/module inputs. Their key deliberately excludes unrelated records
// and log bookkeeping. A bound reader must match the complete source digest.
// Changes to the legacy renderer's read contract must update this key as well.
async fn key(
    v1: &Db,
    id: &str,
    runtime: Option<&str>,
    members: &BTreeSet<String>,
    evidence: &SnapshotEvidence,
) -> Result<Option<String>> {
    // Saved queries can use now_ms(), live activity, run/session or other
    // non-replayable relations. Snapshot equality does not freeze those inputs.
    // Until a dependency-aware query receipt exists, always reobserve any
    // artifact with a query input, including module-only named ports.
    let query_bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records r WHERE r.type='Collection' AND r.kind='query' AND (r.id IN (SELECT collection_id FROM artifact_inputs WHERE artifact_id=?) OR r.id IN (SELECT target_id FROM links WHERE source_id=? AND relationship='renders')))")
        .bind(id).bind(id).fetch_one(v1.pool()).await?;
    if query_bound {
        return Ok(None);
    }
    let mut standalone = evidence.records.contains_key(id)
        && matches!(
            runtime,
            Some("native.board.v1" | "native.mdx.v1" | "native.html.v1")
        );
    if standalone {
        // A source attestation makes board/MDX readers non-standalone. For
        // legacy HTML it does not, because of the named-input check below:
        // HTML that declares no named inputs takes the standalone path
        // (`materialize_live_html` returns before any binding read, then
        // `resolve_artifact` finds no renders edge), and nothing on that path
        // reads `artifact_source_attestations`. The renderer reads attestations
        // only for named HTML inputs, bound ports and native.mdx.v2.
        let attestation_binds = runtime != Some("native.html.v1");
        let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND relationship='renders') OR (? AND EXISTS(SELECT 1 FROM artifact_source_attestations WHERE artifact_id=?)) OR EXISTS(SELECT 1 FROM artifact_inputs WHERE artifact_id=?)")
            .bind(id).bind(attestation_binds).bind(id).bind(id).fetch_one(v1.pool()).await?;
        standalone = !bound;
    }
    let mut visibility = BTreeMap::new();
    if standalone {
        for member in members {
            let visible = crate::authorization::effective_capability(
                v1,
                crate::authorization::Principal::bound(member, true),
                id,
            )
            .await?
            .allows(Capability::View);
            visibility.insert(member, visible);
        }
        // Outside every imported member's scope, ordinary inspection never
        // reads the body. Do not make cache-key construction decode a hidden,
        // possibly malformed source that the uncached path would skip.
        if !visibility.values().any(|visible| *visible) {
            return Ok(None);
        }
        if !crate::query::read::ordinary_record_read_eligible(v1, id).await? {
            return Ok(None);
        }
    }
    if standalone && runtime == Some("native.html.v1") {
        let source =
            crate::record_body::live_artifact::latest_present_source_on(v1.pool(), id, None)
                .await?;
        // Never interpret malformed/non-string source as safely standalone.
        standalone = source
            .and_then(|row| row.try_get::<Option<String>, _>("body").ok().flatten())
            .and_then(|body| crate::artifact_html::validate_cached(&body).ok())
            .is_some_and(|manifest| !manifest.named_inputs_declared);
    }
    let value = if standalone {
        json!([
            FORMAT,
            "standalone",
            runtime,
            visibility,
            &evidence.environment,
            evidence.records.get(id)
        ])
    } else {
        json!([FORMAT, "snapshot", runtime, &evidence.digest])
    };
    Ok(Some(native_artifact_runtime::mdx::sha256_hex(
        serde_json::to_string(&value)?.as_bytes(),
    )))
}

impl Preinspection {
    pub(super) async fn observation<'a>(
        &'a self,
        v1: &Db,
        id: &str,
        runtime: Option<&str>,
        members: &BTreeSet<String>,
        evidence: &SnapshotEvidence,
    ) -> Result<Option<&'a Observation>> {
        if self.schema != FORMAT
            || self.build_sha != crate::FULL_GIT_SHA
            || &self.members != members
        {
            return Ok(None);
        }
        let Some(entry) = self.entries.get(id) else {
            return Ok(None);
        };
        if entry.key.is_none() || !entry.observation.reusable() {
            return Ok(None);
        }
        if entry
            .observation
            .outcomes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != *members
            || entry.key != key(v1, id, runtime, members, evidence).await?
        {
            return Ok(None);
        }
        Ok(Some(&entry.observation))
    }
}

/// Observe a stable operator-owned snapshot before the freeze. No target writer,
/// identity provisioning, delivery bearer or activation proof is created.
/// # Safety
/// The caller excludes writes/replacement of the source for the entire call and
/// obtains `evidence` from that same snapshot. `members` are portable accounts
/// resolved from the current hosted roster, never catalog IDs or email guesses.
pub async unsafe fn preinspect(
    source: &std::path::Path,
    members: &BTreeSet<String>,
    evidence: &SnapshotEvidence,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<Preinspection> {
    let v1 = crate::db::open_current_database_read_only_at(source).await?;
    let result = Box::pin(async {
        let sources = crate::mcp::tools::artifacts::frozen_artifact_sources(&v1).await?;
        let total = sources.len();
        let mut entries = BTreeMap::new();
        let mut timings = Vec::new();
        progress("artifacts", 0, total);
        for (index, (id, runtime)) in sources.into_iter().enumerate() {
            let started = std::time::Instant::now();
            let observation = observe(&v1, &id, members).await?;
            // Runtime worker/storage failures and new diagnostic classes must
            // be observed again, rather than making a transient refusal stick.
            let key = if observation.reusable() { key(&v1, &id, runtime.as_deref(), members, evidence).await? } else { None };
            let entry = Entry { key, observation };
            timings.push((started.elapsed().as_secs_f64(), id.clone()));
            entries.insert(id, entry);
            progress("artifacts", index + 1, total);
        }
        timings.sort_by(|a,b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let cacheable = entries.values().filter(|entry| entry.key.is_some()).count();
        Ok(Preinspection {
            schema: FORMAT.into(), build_sha: crate::FULL_GIT_SHA.into(), members: members.clone(), entries,
            summary: json!({"artifacts":total,"members":members.len(),"cacheable":cacheable,"uncacheable":total-cacheable,"slowest_v1_artifacts":timings.into_iter().take(10).map(|(seconds,id)| json!({"artifact_id":id,"seconds":seconds})).collect::<Vec<_>>() }),
        })
    }).await;
    v1.close().await;
    result
}

/// Benchmark probe, not an activation path: classify how many observations in
/// `receipt` a later snapshot would reuse. Reports only runtimes and counts.
#[doc(hidden)]
pub async fn reuse_probe(
    receipt: &Preinspection,
    source: &std::path::Path,
    members: &BTreeSet<String>,
    evidence: &SnapshotEvidence,
) -> Result<Value> {
    let v1 = crate::db::open_current_database_read_only_at(source).await?;
    let result = Box::pin(async {
        let sources = crate::mcp::tools::artifacts::frozen_artifact_sources(&v1).await?;
        let mut counts = BTreeMap::<String, usize>::new();
        for (id, runtime) in sources {
            let reused = receipt
                .observation(&v1, &id, runtime.as_deref(), members, evidence)
                .await?
                .is_some();
            let attested: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM artifact_source_attestations WHERE artifact_id=?)",
            )
            .bind(&id)
            .fetch_one(v1.pool())
            .await?;
            let class = format!(
                "{}|{}|{}",
                runtime.as_deref().unwrap_or("none"),
                if attested { "attested" } else { "unattested" },
                if reused { "reused" } else { "inspected" }
            );
            *counts.entry(class).or_default() += 1;
        }
        let reused = counts.iter().filter(|(class, _)| class.ends_with("|reused")).map(|(_, n)| n).sum::<usize>();
        let total = counts.values().sum::<usize>();
        Ok(json!({"artifacts": total, "reused": reused, "inspected": total - reused, "by_class": counts}))
    })
    .await;
    v1.close().await;
    result
}

pub(super) async fn observe(v1: &Db, id: &str, members: &BTreeSet<String>) -> Result<Observation> {
    let mut outcomes = BTreeMap::new();
    let mut non_string_failure = false;
    for member in members {
        let caller =
            crate::mcp::Caller::authenticated(member).with_suppressed_request_persistence();
        // Permission failures are expected for private artifacts. Other
        // failures must not be silently treated as v1 render refusals.
        let visible = crate::authorization::effective_capability(
            v1,
            crate::authorization::Principal::bound(member, true),
            id,
        )
        .await?
        .allows(Capability::View);
        if !visible {
            outcomes.insert(member.clone(), None);
            continue;
        }
        // Keep the large renderer future off each caller's stack/frame.
        let result = match Box::pin(crate::mcp::tools::artifacts::frozen_render_outcome(
            v1, &caller, id,
        ))
        .await
        {
            Ok(result) => result,
            Err(error) => {
                // v1 preserves SQLx's refusal for numeric body cells, which
                // has no structured diagnostic. Only that known source-cell
                // incompatibility becomes an unsupported exclusion. Storage
                // and unrelated decoder failures still abort.
                let body_decode = matches!(&error, Error::Sqlx(sqlx::Error::ColumnDecode { index, .. }) if index.trim_matches('"') == "body");
                if !body_decode {
                    return Err(error);
                }
                let source = crate::record_body::live_artifact::latest_present_source_on(
                    v1.pool(),
                    id,
                    None,
                )
                .await?
                .ok_or_else(|| refusal("served_source_missing", 1))?;
                let event: String = source.try_get("id")?;
                let kind: Option<String> = sqlx::query_scalar(
                    "SELECT json_type(payload,'$.body') FROM content_events WHERE id=?",
                )
                .bind(event)
                .fetch_one(v1.pool())
                .await?;
                if !matches!(kind.as_deref(), Some("integer" | "real" | "true" | "false")) {
                    return Err(error);
                }
                non_string_failure = true;
                artifact_closures::unsupported_outcome(id)
            }
        };

        // Successful renders need only their status. Refusals retain the exact
        // diagnostic needed by exclusion activation and per-member parity.
        let result = if result["status"] == "rendered" {
            json!({"status":"rendered"})
        } else {
            result
        };
        outcomes.insert(member.clone(), Some(result));
    }
    Ok(Observation {
        outcomes,
        non_string_failure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_HTML: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Plain</title></head><body><main><h1>Plain</h1></main></body></html>"#;

    fn named_html() -> String {
        let declaration = json!({
            "schema": crate::artifact_html::MANIFEST_SCHEMA,
            "inputs": {"counts": {
                "envelope": crate::artifact_html::GROUPED_COUNT_ENVELOPE,
                "required": false,
                "expose_to_root": true,
                "projection": {"kind": "grouped_count", "axis": {"kind": "facet", "key": "status"}}
            }},
            "capability_requests": [{"capability": "input.read", "scope": {"port": "counts"}}],
        });
        PLAIN_HTML.replace(
            "</head>",
            &format!("<script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script></head>"),
        )
    }

    async fn set_source(db: &Db, id: &str, event: &str, body: &str) {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,1,'legacy_unknown')")
            .bind(event).bind(id).bind(json!({"body": body}).to_string())
            .execute(db.write_pool()).await.unwrap();
    }

    async fn attest(db: &Db, id: &str, event: &str) {
        sqlx::query("INSERT INTO artifact_source_attestations(attestation_event_id,artifact_id,source_event_id,source_sha256,descriptor,attestation_sha256,event_seq,created_at) VALUES(?,?,?,?,'{}',?,1,'2026-11-07T00:00:00Z')")
            .bind(format!("attestation:{event}")).bind(id).bind(event)
            .bind("a".repeat(64)).bind("b".repeat(64))
            .execute(db.write_pool()).await.unwrap();
    }

    /// Attested legacy HTML without named inputs renders through the
    /// standalone path, which never reads attestations, so it keeps a
    /// per-record key. Named HTML and attested board/MDX stay snapshot-keyed.
    #[tokio::test]
    async fn attested_plain_html_keeps_a_record_key_and_named_html_does_not() {
        assert!(
            !crate::artifact_html::validate_cached(PLAIN_HTML)
                .unwrap()
                .named_inputs_declared
        );
        assert!(
            crate::artifact_html::validate_cached(&named_html())
                .unwrap()
                .named_inputs_declared
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO records(id,type,kind,home_id,policy_anchor_id) VALUES('parent','Collection','folder','native:root','native:root'),('plain','Document','artifact','parent','native:root'),('named','Document','artifact','parent','native:root'),('board','Document','artifact','parent','native:root'),('unrelated','Document','note','parent','native:root')")
            .execute(db.write_pool()).await.unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:preinspection",
            "parent",
            vec![crate::authorization::AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        set_source(&db, "plain", "plain-1", PLAIN_HTML).await;
        set_source(&db, "named", "named-1", &named_html()).await;
        set_source(&db, "board", "board-1", "{}").await;
        let members = BTreeSet::from(["member".into()]);
        let evidence = || crate::v1_import::cutover::snapshot_evidence(&path, true);
        const HTML: Option<&str> = Some("native.html.v1");
        const BOARD: Option<&str> = Some("native.board.v1");

        let unattested = evidence().await.unwrap();
        let plain_unattested = key(&db, "plain", HTML, &members, &unattested)
            .await
            .unwrap();
        assert!(plain_unattested.is_some());
        attest(&db, "plain", "plain-1").await;
        attest(&db, "named", "named-1").await;
        attest(&db, "board", "board-1").await;
        // A module grant is another binding-side row the standalone path never reads.
        sqlx::query("INSERT INTO artifact_module_grants VALUES('plain','artifact_source','plain','plain-1',?,'attestation:plain-1','plain-1',?,'input.read',?,'{}',1)")
            .bind("c".repeat(64)).bind("a".repeat(64)).bind("d".repeat(64))
            .execute(db.write_pool()).await.unwrap();
        let attested = evidence().await.unwrap();
        assert_ne!(unattested.digest, attested.digest);
        // Neither the attestation nor the grant is an input of the standalone reader.
        let plain = key(&db, "plain", HTML, &members, &attested).await.unwrap();
        assert_eq!(plain, plain_unattested);
        let named = key(&db, "named", HTML, &members, &attested).await.unwrap();
        let board = key(&db, "board", BOARD, &members, &attested).await.unwrap();
        assert!(named.is_some() && board.is_some());

        // An unrelated write keeps the plain key and evicts the bound ones.
        sqlx::query("UPDATE records SET body='unrelated edit' WHERE id='unrelated'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let unrelated = evidence().await.unwrap();
        assert_ne!(attested.digest, unrelated.digest);
        assert_eq!(
            key(&db, "plain", HTML, &members, &unrelated).await.unwrap(),
            plain
        );
        assert_ne!(
            key(&db, "named", HTML, &members, &unrelated).await.unwrap(),
            named
        );
        assert_ne!(
            key(&db, "board", BOARD, &members, &unrelated)
                .await
                .unwrap(),
            board
        );

        // The artifact's own source edit still changes its key, and a source
        // that starts declaring named inputs leaves the record key entirely.
        set_source(
            &db,
            "plain",
            "plain-2",
            &PLAIN_HTML.replace("Plain</h1>", "Edited</h1>"),
        )
        .await;
        let edited = evidence().await.unwrap();
        let plain_edited = key(&db, "plain", HTML, &members, &edited).await.unwrap();
        assert!(plain_edited.is_some());
        assert_ne!(plain_edited, plain);
        set_source(&db, "plain", "plain-3", &named_html()).await;
        let now_named = evidence().await.unwrap();
        let snapshot_keyed = key(&db, "plain", HTML, &members, &now_named).await.unwrap();
        sqlx::query("UPDATE records SET body='another unrelated edit' WHERE id='unrelated'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let later = evidence().await.unwrap();
        assert_ne!(
            key(&db, "plain", HTML, &members, &later).await.unwrap(),
            snapshot_keyed
        );
        db.close().await;
    }

    #[tokio::test]
    async fn query_inputs_are_never_reused_even_for_identical_snapshots() {
        let transient = Observation {
            outcomes: BTreeMap::from([(
                "member".into(),
                Some(json!({"status":"refused","diagnostic":{"code":"mdx_runtime_failed"}})),
            )]),
            non_string_failure: false,
        };
        assert!(!transient.reusable());
        let stable = Observation {
            outcomes: BTreeMap::from([(
                "member".into(),
                Some(json!({"status":"refused","diagnostic":{"code":"binding_unavailable"}})),
            )]),
            non_string_failure: false,
        };
        assert!(stable.reusable());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO records(id,type,kind,home_id,policy_anchor_id) VALUES('parent','Collection','folder','native:root','native:root'),('artifact','Document','artifact','parent','native:root'),('clock-query','Collection','query','native:root','native:root')")
            .execute(db.write_pool()).await.unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:preinspection",
            "parent",
            vec![crate::authorization::AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        let evidence = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        let members = BTreeSet::from(["member".into()]);
        assert!(key(
            &db,
            "artifact",
            Some("native.board.v1"),
            &members,
            &evidence
        )
        .await
        .unwrap()
        .is_some());
        sqlx::query("INSERT INTO links(id,source_id,target_id,relationship) VALUES('input','artifact','clock-query','renders')")
            .execute(db.write_pool()).await.unwrap();
        let evidence = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert!(key(
            &db,
            "artifact",
            Some("native.board.v1"),
            &members,
            &evidence
        )
        .await
        .unwrap()
        .is_none());
        sqlx::query("DELETE FROM links WHERE id='input'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let evidence = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        let receipt = Preinspection {
            schema: FORMAT.into(),
            build_sha: crate::FULL_GIT_SHA.into(),
            members: members.clone(),
            entries: BTreeMap::from([(
                "artifact".into(),
                Entry {
                    key: key(
                        &db,
                        "artifact",
                        Some("native.board.v1"),
                        &members,
                        &evidence,
                    )
                    .await
                    .unwrap(),
                    observation: stable,
                },
            )]),
            summary: json!({}),
        };
        assert!(receipt
            .observation(
                &db,
                "artifact",
                Some("native.board.v1"),
                &members,
                &evidence
            )
            .await
            .unwrap()
            .is_some());
        assert!(receipt
            .observation(
                &db,
                "artifact",
                Some("native.board.v1"),
                &BTreeSet::from(["another-member".into()]),
                &evidence
            )
            .await
            .unwrap()
            .is_none());
        // A real indexed body projection change elsewhere must not evict a
        // standalone renderer whose source and visibility are unchanged.
        sqlx::query("UPDATE records SET body='unrelated edit' WHERE id='clock-query'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let unrelated = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert_ne!(evidence.digest, unrelated.digest);
        assert!(receipt
            .observation(
                &db,
                "artifact",
                Some("native.board.v1"),
                &members,
                &unrelated
            )
            .await
            .unwrap()
            .is_some());
        sqlx::query("UPDATE records SET body='edited source' WHERE id='artifact'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let edited = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert!(receipt
            .observation(&db, "artifact", Some("native.board.v1"), &members, &edited)
            .await
            .unwrap()
            .is_none());
        sqlx::query("UPDATE records SET body=NULL WHERE id='artifact'")
            .execute(db.write_pool())
            .await
            .unwrap();
        let restored = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert!(receipt
            .observation(
                &db,
                "artifact",
                Some("native.board.v1"),
                &members,
                &restored
            )
            .await
            .unwrap()
            .is_some());
        crate::authorization::replace_explicit_policy(&db, "test:preinspection", "parent", vec![])
            .await
            .unwrap();
        let revoked = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert_eq!(restored.records["artifact"], revoked.records["artifact"]);
        assert_eq!(restored.environment, revoked.environment);
        assert!(receipt
            .observation(&db, "artifact", Some("native.board.v1"), &members, &revoked)
            .await
            .unwrap()
            .is_none());
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES('hidden-non-string-source','artifact','record.updated',?,1,'legacy_unknown')").bind(json!({"body":17}).to_string()).execute(db.write_pool()).await.unwrap();
        let hidden = crate::v1_import::cutover::snapshot_evidence(&path, true)
            .await
            .unwrap();
        assert!(observe(&db, "artifact", &members).await.is_ok());
        assert!(
            key(&db, "artifact", Some("native.html.v1"), &members, &hidden)
                .await
                .unwrap()
                .is_none()
        );
        db.close().await;
    }
}

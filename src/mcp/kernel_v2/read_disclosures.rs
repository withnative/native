//! Definition-driven bounded read disclosures (task b788408).
//!
//! Rules come from governed relationship definitions plus the interim
//! same-shape table for not-yet-governed relationships; candidate links come
//! from the already-admitted visible batch the caller holds. No per-name
//! branches: rules are matched by relationship string and their flags —
//! including the `summary_template` wording — drive filtering and rendering
//! generically.
//!
//! Semantics (documented, not inferred authority):
//! - `supersedes` inverse is an authored claim: "superseded by X".
//! - `draws_from` inverse is a fact about links: only sources created after
//!   the anchor's last substantive change are disclosed. Newer never
//!   establishes authority, and no disclosure never establishes that no
//!   newer work exists.
//! - `blocks` inverse names only sources with a governed nonterminal
//!   (`open`) lifecycle. Unknown, absent or unclassified status is never
//!   open. Archived or deleted sources are never named.
//! - `part_of` forward names the anchor's targets: "part of Y".
//! - `relates_to` discloses nothing, by absence from the rule table.
//!
//! Substantive clock (per record, greatest wins): native content writes
//! (`body_set`, record creation/revision, type correction) by an ordinary
//! caller, then the imported source time for the last content change, then
//! source-time-aware record creation. Migration envelopes never move it:
//! UUID imports emit ordinary `record_created` / `record_revised` events, but
//! when the sealed import host authored them they keep their source time, and
//! `import_state_delta` envelopes are excluded outright. Imported source
//! `updated_at` is not substantive by itself: v1 owner, home, facet, archive,
//! maturity and persistence changes bump it without changing content, so only
//! the provenance clock paired with a body or content-field change counts.
//! With no comparable source history the initial snapshot `updated_at` is the
//! best known baseline — old source history that lacks content precision can
//! only bound it. Claims, link changes and native housekeeping (facets,
//! metadata, archive, rehome, messages, provider receipts) never move it.
//!
//! Names resolve through the authorized read path (the same fields an
//! ordinary read shows), never raw field rows. Totals count visible,
//! rule-matching sources; hidden records change neither wording nor counts.

use super::*;
use crate::relationship::{DisclosureDirection, DisclosureKind};

/// One disclosure rule: the relationship name plus its disclosure data.
#[derive(Debug, Clone)]
pub(crate) struct DisclosureRule {
    pub relationship: String,
    pub direction: DisclosureDirection,
    pub kind: DisclosureKind,
    pub newer_than_target: bool,
    pub open_source_only: bool,
    pub max_items: usize,
    pub summary_template: String,
}

/// All disclosure rules: governed definitions that declare one, plus the
/// interim same-shape entries. Interim names must not collide with a
/// governed disclosure.
pub(crate) fn disclosure_rules() -> Result<Vec<DisclosureRule>> {
    let manifest = crate::relationship::core_relationship_type_manifest()?;
    let mut rules = Vec::new();
    for definition in &manifest.relationship_types {
        if let Some(disclosure) = &definition.read_disclosure {
            rules.push(DisclosureRule {
                relationship: definition.relationship_type.clone(),
                direction: disclosure.direction,
                kind: disclosure.kind,
                newer_than_target: disclosure.newer_than_target,
                open_source_only: disclosure.open_source_only,
                max_items: disclosure.max_items as usize,
                summary_template: disclosure.summary_template.clone(),
            });
        }
    }
    for interim in crate::relationship::interim_read_disclosures()? {
        if rules
            .iter()
            .any(|rule| rule.relationship == interim.relationship)
        {
            return Err(Error::engine(
                "interim read disclosure collides with a governed one",
            ));
        }
        rules.push(DisclosureRule {
            relationship: interim.relationship,
            direction: interim.read_disclosure.direction,
            kind: interim.read_disclosure.kind,
            newer_than_target: interim.read_disclosure.newer_than_target,
            open_source_only: interim.read_disclosure.open_source_only,
            max_items: interim.read_disclosure.max_items as usize,
            summary_template: interim.read_disclosure.summary_template,
        });
    }
    Ok(rules)
}

/// Parse the accepted link-clock spellings to epoch millis: RFC 3339 (with
/// offsets), RFC 2822, SQLite UTC datetime spellings (with fractions) and
/// calendar dates. Mirrors the admission-time validation in
/// `kernel::generic_links`, so admitted rows order chronologically rather
/// than lexicographically. Unparseable clocks sort oldest.
fn created_millis(raw: &str) -> Option<i64> {
    let value = raw.trim();
    if let Ok(moment) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(moment.timestamp_millis());
    }
    if let Ok(moment) = chrono::DateTime::parse_from_rfc2822(value) {
        return Some(moment.timestamp_millis());
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc().timestamp_millis());
        }
    }
    if let Ok(day) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Some(day.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis());
    }
    None
}

/// Visible candidate far ends for one anchor under one rule: newest first by
/// parsed clock (unparseable oldest), stable id tiebreak, deduplicated so
/// multiple link representations of one far end count and name once. Pure
/// over the admitted link rows: the visibility gate already ran where the
/// batch was built.
fn select_candidates(
    links: &[Value],
    anchor: &str,
    rule: &DisclosureRule,
) -> Vec<(String, i64, String)> {
    let mut candidates = Vec::new();
    for link in links {
        let source = link.get("source_id").and_then(Value::as_str);
        let target = link.get("target_id").and_then(Value::as_str);
        let relationship = link.get("relationship").and_then(Value::as_str);
        if relationship != Some(rule.relationship.as_str()) {
            continue;
        }
        let far = match rule.direction {
            DisclosureDirection::Inverse => {
                if target != Some(anchor) {
                    continue;
                }
                source
            }
            DisclosureDirection::Forward => {
                if source != Some(anchor) {
                    continue;
                }
                target
            }
        };
        let Some(far) = far.filter(|far| !far.is_empty()) else {
            continue;
        };
        let created = link
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        candidates.push((
            far.to_owned(),
            created_millis(&created).unwrap_or(i64::MIN),
            created,
        ));
    }
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    // Repeats need not be adjacent: B@3, C@2, B@1 is one far end seen twice.
    // The timestamp sort above puts the newest representation first, so a
    // seen set keeps exactly that one.
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(candidates.len());
    for (far, millis, created) in candidates {
        if !seen.insert(far.clone()) {
            continue;
        }
        deduped.push((far, millis, created));
    }
    deduped
}

fn links_json(ids: &[String]) -> Result<String> {
    serde_json::to_string(ids).map_err(crate::Error::from)
}

/// Source-time-aware creation per id: import `snapshot_provenance` first, as
/// the read projection does, so imported work keeps its source creation time
/// rather than its migration time.
async fn creations_on(
    conn: &mut sqlx::SqliteConnection,
    ids: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    use sqlx::Row;
    let mut out = std::collections::HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let rows = sqlx::query(
        "SELECT r.id, coalesce((SELECT m.created_at FROM main.kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='snapshot_provenance' ORDER BY m.seq DESC LIMIT 1), r.created_at) FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?))",
    )
    .bind(links_json(ids)?)
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        out.insert(row.try_get::<String, _>(0)?, row.try_get::<String, _>(1)?);
    }
    Ok(out)
}

/// Native content clocks per id. The set is content only — claims, links,
/// facets, metadata, archive, rehome and messages never move it. Events
/// authored by the sealed import host (including UUID-preserving
/// `record_created`/`record_revised`) and `import_state_delta` envelopes are
/// migration clocks and never count.
async fn native_substantive_on(
    conn: &mut sqlx::SqliteConnection,
    ids: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    use sqlx::Row;
    let mut out = std::collections::HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let rows = sqlx::query(
        "SELECT r.id, (SELECT MAX(e.created_at) FROM main.content_events e WHERE e.record_id=r.id AND e.type IN ('kernel.body_set.v1','kernel.record_created.v1','kernel.record_created.v2','kernel.record_revised.v1','kernel.record_revised.v2','kernel.record_type_corrected.v1') AND NOT EXISTS (SELECT 1 FROM main.kernel_principals p WHERE p.principal_id=e.actor AND p.auth_binding='host:v1-import')) FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?))",
    )
    .bind(links_json(ids)?)
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        if let Some(at) = row.try_get::<Option<String>, _>(1)? {
            out.insert(row.try_get::<String, _>(0)?, at);
        }
    }
    Ok(out)
}

/// Imported source substantive time per id. A v1 source `updated_at` moves for
/// owner, home, facet, archive, maturity and persistence edits that change no
/// content, so the newest provenance clock is not substantive by itself.
/// Compare consecutive imported snapshots on body and content fields, keep the
/// last content change, and pair it with the provenance clock appended for
/// that import. No comparable history means the initial snapshot
/// `updated_at` is the best known baseline: old source history without content
/// precision bounds this clock rather than proving its exact substantive time.
async fn imported_substantive_on(
    conn: &mut sqlx::SqliteConnection,
    ids: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    use sqlx::Row;
    let mut out = std::collections::HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let rows = sqlx::query(
        "WITH states AS (
            SELECT e.record_id, e.seq,
              CASE WHEN e.type='kernel.import_state_delta.v1'
                THEN json_extract(e.payload,'$.snapshot.state')
                ELSE json_extract(e.payload,'$.state') END AS state
            FROM main.content_events e
            WHERE e.record_id IN (SELECT value FROM json_each(?))
              AND e.type IN ('kernel.import_state.v1','kernel.import_state_delta.v1')
         ), marked AS (
            SELECT record_id, seq, state,
              LAG(state) OVER (PARTITION BY record_id ORDER BY seq) AS prior
            FROM states
         ), substantive AS (
            SELECT record_id, seq FROM marked
            WHERE prior IS NULL
               OR json_extract(state,'$.body') IS NOT json_extract(prior,'$.body')
               OR json_extract(state,'$.definition.primary_type') IS NOT json_extract(prior,'$.definition.primary_type')
               OR json_extract(state,'$.definition.kind') IS NOT json_extract(prior,'$.definition.kind')
               OR json_extract(state,'$.definition.fields.title') IS NOT json_extract(prior,'$.definition.fields.title')
               OR json_extract(state,'$.definition.fields.name') IS NOT json_extract(prior,'$.definition.fields.name')
               OR json_extract(state,'$.definition.fields.summary') IS NOT json_extract(prior,'$.definition.fields.summary')
               OR json_extract(state,'$.definition.fields.v1_type') IS NOT json_extract(prior,'$.definition.fields.v1_type')
               OR json_extract(state,'$.definition.fields.v1_kind') IS NOT json_extract(prior,'$.definition.fields.v1_kind')
         ), latest AS (
            SELECT record_id, MAX(seq) AS seq FROM substantive GROUP BY record_id
         )
         SELECT l.record_id,
           coalesce(
             (SELECT json_extract(e.payload,'$.legacy.payload.updated_at')
                FROM main.kernel_legacy_sql_events h
                JOIN main.content_events e ON e.seq=h.seq
                WHERE h.record_id=l.record_id AND h.source_stream='snapshot_provenance'
                  AND h.seq > l.seq
                ORDER BY h.seq LIMIT 1),
             (SELECT json_extract(e.payload,'$.legacy.payload.updated_at')
                FROM main.kernel_legacy_sql_events h
                JOIN main.content_events e ON e.seq=h.seq
                WHERE h.record_id=l.record_id AND h.source_stream='snapshot_provenance'
                ORDER BY h.seq DESC LIMIT 1))
         FROM latest l",
    )
    .bind(links_json(ids)?)
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        if let Some(at) = row.try_get::<Option<String>, _>(1)? {
            out.insert(row.try_get::<String, _>(0)?, at);
        }
    }
    Ok(out)
}

/// Greatest parseable substantive instant per id. Unparseable clocks are
/// ignored; ids with no parseable clock at all sort before every real one.
fn substantive_millis(
    native: Option<&str>,
    source_updated: Option<&str>,
    creation: Option<&str>,
) -> i64 {
    [native, source_updated, creation]
        .into_iter()
        .flatten()
        .filter_map(created_millis)
        .max()
        .unwrap_or(i64::MIN)
}

/// Display name through the authorized metadata read: the same title/name an
/// ordinary read shows the caller, without hydrating the body. `None` when
/// the record is gone for this caller (a visibility race after the admitted
/// batch, never the rule).
async fn display_name_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<String>> {
    let Some(view) = kernel::read_record_metadata_on(conn, actor, id).await? else {
        return Ok(None);
    };
    Ok(Some(
        view.fields
            .get("title")
            .or_else(|| view.fields.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    ))
}

/// True iff the source reports a governed nonterminal (`open`) lifecycle.
/// Unknown, absent or unclassified status is never open, and archived or
/// deleted sources never qualify. The lifecycle raw value honors the facet
/// override exactly as the record projection does. Uses the body-free
/// metadata read: counting never needs the candidate's text.
async fn is_open_blocker(conn: &mut sqlx::SqliteConnection, actor: &str, id: &str) -> Result<bool> {
    let Some(view) = kernel::read_record_metadata_on(conn, actor, id).await? else {
        return Ok(false);
    };
    if view.archived {
        return Ok(false);
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM main.kernel_records WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        view.family.as_deref(),
        view.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        view.kind.as_deref(),
        &view.fields,
    );
    let facet: Option<String> = sqlx::query_scalar(
        "SELECT value FROM main.kernel_facets WHERE record_id=? AND key='lifecycle'",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let raw = facet
        .as_deref()
        .or_else(|| view.fields.get("lifecycle").and_then(Value::as_str));
    let interpretation =
        kernel::v1_state::lifecycle_on(conn, actor, typ.unwrap_or_default(), kind, id, raw).await?;
    Ok(
        interpretation.get("status").and_then(Value::as_str) == Some("governed")
            && interpretation.get("terminality").and_then(Value::as_str) == Some("open"),
    )
}

/// Render one rule's named window from its template data: `Name (ref)`
/// items, bare refs when nameless, with a visible remainder suffix.
fn format_summary(template: &str, items: &[(String, String)], total: usize) -> String {
    let mut parts = Vec::with_capacity(items.len());
    for (name, reference) in items {
        if reference.is_empty() {
            parts.push(name.clone());
        } else if name.is_empty() {
            parts.push(reference.clone());
        } else {
            parts.push(format!("{name} ({reference})"));
        }
    }
    let mut list = parts.join(", ");
    let rest = total.saturating_sub(items.len());
    if rest > 0 {
        if list.is_empty() {
            list = format!("{rest} more");
        } else {
            list.push_str(&format!(" and {rest} more"));
        }
    }
    template.replace("{list}", &list)
}

/// Partition one admitted link batch by anchor, mirroring the Get path:
/// rows touching an anchor on either end ride that anchor exactly once per
/// end (a self-loop lands once). Rows touching no anchor are dropped.
pub(crate) fn partition_links(
    links: Vec<Value>,
    anchors: &std::collections::BTreeSet<String>,
) -> std::collections::HashMap<String, Vec<Value>> {
    let mut by_anchor: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for link in links {
        let source = link.get("source_id").and_then(Value::as_str);
        let target = link.get("target_id").and_then(Value::as_str);
        if let Some(source) = source.filter(|id| anchors.contains(*id)) {
            by_anchor
                .entry(source.to_owned())
                .or_default()
                .push(link.clone());
        }
        if let Some(target) = target.filter(|id| Some(*id) != source && anchors.contains(*id)) {
            by_anchor
                .entry(target.to_owned())
                .or_default()
                .push(link.clone());
        }
    }
    by_anchor
}

/// Bounded visible-only disclosures per anchor, keyed by anchor id.
/// Anchors with nothing to disclose are absent from the map, and rules with
/// no visible candidates emit no entry: there is no disclosure key when
/// empty. Each rule carries its template wording plus items with usable
/// read references.
pub(crate) async fn disclosures_for(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    anchors: &[(&str, &[Value])],
) -> Result<std::collections::HashMap<String, Vec<Value>>> {
    let rules = disclosure_rules()?;
    if rules.is_empty() || anchors.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    // Only newer-work rules need clocks. Ordinary records and parent/blocker
    // disclosures must not parse imported content history as an enrichment tax.
    let mut involved: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut clock_anchors = std::collections::BTreeSet::new();
    let mut staged = Vec::new();
    for (anchor, links) in anchors {
        for rule in &rules {
            let candidates = select_candidates(links, anchor, rule);
            if rule.newer_than_target && !candidates.is_empty() {
                clock_anchors.insert(anchor.to_string());
                for (far, _, _) in &candidates {
                    if seen.insert(far.clone()) {
                        involved.push(far.clone());
                    }
                }
            }
            staged.push((anchor.to_string(), rule, candidates));
        }
    }
    for anchor in &clock_anchors {
        if seen.insert(anchor.clone()) {
            involved.push(anchor.clone());
        }
    }
    involved.sort();
    let creations = creations_on(conn, &involved).await?;
    let clock_anchors: Vec<_> = clock_anchors.into_iter().collect();
    let native = native_substantive_on(conn, &clock_anchors).await?;
    let imported = imported_substantive_on(conn, &clock_anchors).await?;
    let substantive = |id: &str| -> i64 {
        substantive_millis(
            native.get(id).map(String::as_str),
            imported.get(id).map(String::as_str),
            creations.get(id).map(String::as_str),
        )
    };
    // Filter before counting: totals name only what the caller may see, and
    // hidden records never change wording or counts (the input batch is
    // already the admitted one, so filtering here only applies rule flags).
    let mut per_anchor: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for (anchor, rule, candidates) in &staged {
        let anchor_substantive = substantive(anchor);
        let mut kept = Vec::new();
        for (far, _, _) in candidates {
            if rule.newer_than_target {
                let source_created = creations
                    .get(far)
                    .and_then(|created| created_millis(created));
                if source_created.is_none_or(|millis| millis <= anchor_substantive) {
                    continue;
                }
            }
            if rule.open_source_only && !is_open_blocker(conn, actor, far).await? {
                continue;
            }
            kept.push(far.clone());
        }
        if kept.is_empty() {
            continue;
        }
        let direction = match rule.direction {
            DisclosureDirection::Inverse => "inverse",
            DisclosureDirection::Forward => "forward",
        };
        let kind = match rule.kind {
            DisclosureKind::Claim => "claim",
            DisclosureKind::Fact => "fact",
        };
        let mut named = Vec::new();
        for far in kept.iter().take(rule.max_items) {
            // Presentation-only resolution over the already-admitted set; a
            // visibility race resolves to an unnamed item, never a leak.
            let name = display_name_on(conn, actor, far).await?.unwrap_or_default();
            let reference = super::writes::short_reference(conn, far)
                .await?
                .unwrap_or_else(|| far.clone());
            named.push((name, reference));
        }
        let mut items = Vec::new();
        for ((name, reference), far) in named.iter().zip(kept.iter().take(rule.max_items)) {
            let mut item = json!({"id": far, "name": name});
            if reference != far {
                item["display_reference"] = json!(reference);
            }
            items.push(item);
        }
        let summary = format_summary(&rule.summary_template, &named, kept.len());
        per_anchor.entry(anchor.clone()).or_default().push(json!({
            "relationship": rule.relationship,
            "direction": direction,
            "kind": kind,
            "summary": summary,
            "items": items,
            "total_count": kept.len() as i64,
        }));
    }
    Ok(per_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_table_covers_slice_four_with_expected_shapes() {
        let rules = disclosure_rules().unwrap();
        let at = |name: &str| {
            rules
                .iter()
                .find(|rule| rule.relationship == name)
                .unwrap_or_else(|| panic!("missing rule {name}"))
                .clone()
        };
        let supersedes = at("supersedes");
        assert_eq!(supersedes.direction, DisclosureDirection::Inverse);
        assert_eq!(supersedes.kind, DisclosureKind::Claim);
        assert!(!supersedes.newer_than_target && !supersedes.open_source_only);
        assert!(supersedes.summary_template.contains("{list}"));
        let draws_from = at("draws_from");
        assert_eq!(draws_from.direction, DisclosureDirection::Inverse);
        assert_eq!(draws_from.kind, DisclosureKind::Fact);
        assert!(draws_from.newer_than_target && !draws_from.open_source_only);
        let blocks = at("blocks");
        assert_eq!(blocks.direction, DisclosureDirection::Inverse);
        assert!(blocks.open_source_only && !blocks.newer_than_target);
        let part_of = at("part_of");
        assert_eq!(part_of.direction, DisclosureDirection::Forward);
        assert!(!part_of.newer_than_target && !part_of.open_source_only);
        assert!(rules.iter().all(|rule| (1..=3).contains(&rule.max_items)));
        assert!(rules.iter().all(|rule| rule.relationship != "relates_to"));
        assert!(rules
            .iter()
            .all(|rule| rule.summary_template.contains("{list}")));
    }

    #[test]
    fn selection_matches_direction_orders_chronologically_and_dedupes() {
        let rule = DisclosureRule {
            relationship: "draws_from".into(),
            direction: DisclosureDirection::Inverse,
            kind: DisclosureKind::Fact,
            newer_than_target: true,
            open_source_only: false,
            max_items: 3,
            summary_template: "newer work builds on this: {list}".into(),
        };
        let links = vec![
            json!({"source_id":"b","target_id":"a","relationship":"draws_from","created_at":"2026-01-02T00:00:00+02:00"}),
            json!({"source_id":"b","target_id":"a","relationship":"draws_from","created_at":"2026-01-01T00:00:00Z"}),
            json!({"source_id":"c","target_id":"a","relationship":"draws_from","created_at":"2026-01-01"}),
            json!({"source_id":"a","target_id":"x","relationship":"draws_from","created_at":"2026-02-01T00:00:00Z"}),
            json!({"source_id":"b","target_id":"a","relationship":"blocks","created_at":"2026-03-01T00:00:00Z"}),
        ];
        let selected = select_candidates(&links, "a", &rule);
        // Offsets order chronologically (b@+02:00 precedes the UTC twin),
        // the duplicate representation keeps its newest clock only once,
        // and the forward row plus other relationships never match.
        assert_eq!(
            selected
                .iter()
                .map(|(far, _, _)| far.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
        assert!(selected[0].1 > selected[1].1);
    }

    #[test]
    fn selection_dedupes_non_adjacent_repeats_after_timestamp_sort() {
        let rule = DisclosureRule {
            relationship: "draws_from".into(),
            direction: DisclosureDirection::Inverse,
            kind: DisclosureKind::Fact,
            newer_than_target: true,
            open_source_only: false,
            max_items: 3,
            summary_template: "newer work builds on this: {list}".into(),
        };
        // B appears again after C once ordered newest-first: adjacent-only
        // dedupe would count and later name B twice.
        let links = vec![
            json!({"source_id":"b","target_id":"a","relationship":"draws_from","created_at":"2026-01-03T00:00:00Z"}),
            json!({"source_id":"c","target_id":"a","relationship":"draws_from","created_at":"2026-01-02T00:00:00Z"}),
            json!({"source_id":"b","target_id":"a","relationship":"draws_from","created_at":"2026-01-01T00:00:00Z"}),
        ];
        let selected = select_candidates(&links, "a", &rule);
        assert_eq!(
            selected
                .iter()
                .map(|(far, _, _)| far.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c"]
        );
        // The newest representation of the repeated far end is the one kept.
        assert_eq!(selected[0].2, "2026-01-03T00:00:00Z");
    }

    #[test]
    fn summary_renders_names_refs_and_remainder_from_template() {
        let summary = format_summary(
            "superseded by {list}",
            &[
                ("Beta".into(), "abc123".into()),
                ("".into(), "def456".into()),
            ],
            4,
        );
        assert_eq!(summary, "superseded by Beta (abc123), def456 and 2 more");
    }
}

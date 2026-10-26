//! Record-scoped historical reads. Sealed native events establish state;
//! retained envelopes remain provenance. Every returned record uses live View.
use super::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct RecordState {
    pub home_id: String,
    pub owner_id: Option<String>,
    pub primary_type: Option<String>,
    pub kind: Option<String>,
    pub pin: Option<RevisionIdentity>,
    pub fields: Map<String, Value>,
    pub metadata: RecordMetadata,
    pub body: Option<String>,
    pub archived: bool,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
    pub facets: BTreeMap<String, FacetObservation>,
    pub blob: Option<Value>,
}
impl RecordState {
    pub fn effective_body(&self) -> Option<&str> {
        self.body
            .as_deref()
            .or_else(|| self.fields.get("body").and_then(Value::as_str))
    }
    fn replace(&mut self, p: KernelRecordPayload) {
        self.home_id = p.home_id;
        self.owner_id = p.owner_id;
        self.primary_type = p.primary_type;
        self.kind = p.kind;
        self.pin = p.pin;
        self.fields = p.fields.unwrap_or_default();
    }
    fn observe(&mut self, facet: FacetObservation) -> Result<()> {
        if hq::facet_observation_wins(
            self.facets.get(&facet.key).map(|old| old.as_of.as_str()),
            &facet.as_of,
        )? {
            self.facets.insert(facet.key.clone(), facet);
        }
        Ok(())
    }
    fn snapshot(&mut self, state: ImportRecordState, replace: bool) -> Result<()> {
        if replace {
            self.facets.clear();
            self.body = None;
            if !state
                .facets
                .iter()
                .any(|f| f.key == "blob_ref" && f.value.is_some())
            {
                self.blob = None;
            }
        }
        self.body = state.body.or_else(|| self.body.take());
        if let Some(metadata) = state.metadata {
            self.metadata = metadata;
        }
        self.archived = state.archived;
        for observation in state.facets {
            self.observe(observation)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Snapshot {
    state: ImportRecordState,
}
#[derive(Deserialize)]
struct Delta {
    snapshot: Snapshot,
}
#[derive(Deserialize)]
struct FacetEnvelope {
    facet: Option<FacetObservation>,
}

/// Indexed subject stream, not a workspace prefix. No payload from another
/// record or blob bytes is loaded. Identity disclosure is a separate history
/// oracle concern; state is authorized by current View, as in v1's read lens.
pub(crate) async fn record_at_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    through: i64,
) -> Result<Option<RecordState>> {
    read_at_on(conn, actor, id, through, true).await
}
/// Event context needs only its subject's native field/body transitions.
/// Do not fetch provider activity, provenance, or relation streams for a delta.
pub(crate) async fn body_at_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    through: i64,
) -> Result<Option<String>> {
    Ok(read_at_on(conn, actor, id, through, false)
        .await?
        .map(|record| record.effective_body().unwrap_or_default().to_owned()))
}
async fn read_at_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    through: i64,
    include_relations: bool,
) -> Result<Option<RecordState>> {
    if read_record_on(conn, actor, id).await?.is_none() {
        return Ok(None);
    }
    let started = std::time::Instant::now();
    let mut verified_definitions = std::collections::BTreeMap::<String, i64>::new();
    let rows: Vec<(i64,String,String,String,Option<i64>)> = sqlx::query_as(
        "SELECT seq,type,CASE WHEN type='kernel.legacy_recorded.v1' THEN CASE WHEN ?3 THEN json_object('facet',json_extract(payload,'$.facet')) ELSE '{}' END ELSE payload END,created_at,act FROM content_events WHERE record_id=?1 AND seq<=?2 ORDER BY seq",
    ).bind(id).bind(through).bind(include_relations).fetch_all(&mut *conn).await?;
    let mut state: Option<RecordState> = None;
    let mut metadata_seq = 0;
    for (seq, typ, raw, created, act) in rows {
        // Retained bytes cannot establish body/field state. SQL only loads
        // the explicitly projected facet for a full version, and no retained
        // bytes at all for an event-local body delta.
        let p: Value = if typ == "kernel.legacy_recorded.v1" {
            Value::Null
        } else {
            serde_json::from_str(&raw)?
        };
        match typ.as_str() {
            "kernel.record_created.v1"
            | "kernel.record_created.v2"
            | "kernel.import_record_created.v1" => {
                let p: KernelRecordPayload = serde_json::from_value(p)?;
                let mut record = RecordState {
                    home_id: String::new(),
                    owner_id: None,
                    primary_type: None,
                    kind: None,
                    pin: None,
                    fields: Map::new(),
                    metadata: RecordMetadata {
                        persistence: "enduring".into(),
                        maturity: None,
                        last_activity_at: created.clone(),
                    },
                    body: None,
                    archived: false,
                    revision: seq,
                    created_at: created.clone(),
                    updated_at: created.clone(),
                    facets: BTreeMap::new(),
                    blob: None,
                };
                record.replace(p);
                state = Some(record);
                metadata_seq = seq;
            }
            _ => {
                let Some(record) = state.as_mut() else {
                    continue;
                };
                match typ.as_str() {
                    "kernel.record_revised.v1" | "kernel.record_revised.v2" => {
                        let patch: KernelRevisePayload =
                            serde_json::from_value(serde_json::json!({"fields":p["fields"]}))?;
                        let pin = record.pin.as_ref().ok_or_else(|| {
                            Error::engine("historical revision has no definition pin")
                        })?;
                        // The artifact is immutable; require its installation at
                        // this event's act, never resolve a future adoption.
                        let identity = pin.value_id();
                        if !act.is_some_and(|act| {
                            verified_definitions
                                .get(&identity)
                                .is_some_and(|verified| act >= *verified)
                        }) {
                            definition_at_on(conn, pin, act).await?;
                            verified_definitions
                                .insert(identity, act.expect("definition gate requires an act"));
                        }
                        let bytes: String = sqlx::query_scalar("SELECT artifact_bytes FROM definition_artifacts WHERE family=? AND version=? AND digest=?")
                            .bind(&pin.family).bind(i64::from(pin.version)).bind(&pin.digest).fetch_one(&mut *conn).await?;
                        let descriptor =
                            kind_descriptor(&bytes, record.kind.as_deref().unwrap_or_default())?;
                        record.fields = apply_revise_patch(
                            record.kind.as_deref().unwrap_or_default(),
                            descriptor_identity_field(descriptor.as_ref()),
                            &record.fields,
                            &patch.fields,
                        )?;
                        if typ == "kernel.record_revised.v2" {
                            for value in record.fields.values_mut() {
                                *value = crate::structured_values::normalize(value);
                            }
                        }
                    }
                    "kernel.record_rebound.v1" => {
                        record.replace(serde_json::from_value(p["record"].clone())?)
                    }
                    "kernel.body_set.v1" => {
                        record.body = Some(serde_json::from_value(p["body"].clone())?)
                    }
                    "kernel.import_state.v1" => {
                        record.snapshot(serde_json::from_str::<Snapshot>(&raw)?.state, false)?
                    }
                    "kernel.import_state_delta.v1" => {
                        record.replace(serde_json::from_value(p["record"].clone())?);
                        record
                            .snapshot(serde_json::from_str::<Delta>(&raw)?.snapshot.state, true)?;
                    }
                    "kernel.facet_observed.v1" => record.observe(serde_json::from_str(&raw)?)?,
                    "kernel.legacy_recorded.v1" => {
                        if let Some(facet) = serde_json::from_str::<FacetEnvelope>(&raw)?.facet {
                            record.observe(facet)?;
                        }
                    }
                    "kernel.archive_changed.v1" => {
                        record.archived = serde_json::from_value(p["archived"].clone())?
                    }
                    "kernel.record_rehomed.v1" | "kernel.record_rehomed.v2" => {
                        record.home_id = serde_json::from_value(p["new_home_id"].clone())?
                    }
                    "kernel.metadata_set.v1" => {
                        record_metadata::apply_patch(&mut record.metadata, &p, &created)?
                    }
                    "kernel.attachment_bound.v1" => record.blob = Some(p),
                    "kernel.import_removed.v1"
                        if p["kind"] == "attachment" || p["kind"] == "record" =>
                    {
                        record.blob = None;
                    }
                    _ => {}
                }
                record.revision = seq;
                record.updated_at = created.clone();
            }
        }
        if let Some(record) = state.as_mut() {
            if record_metadata::native_activity_event(&typ) {
                record.metadata.last_activity_at = created;
                metadata_seq = seq;
            } else if matches!(
                typ.as_str(),
                "kernel.import_state.v1" | "kernel.import_state_delta.v1"
            ) {
                metadata_seq = seq;
            }
            if let Some(pin) = record.pin.as_ref() {
                let identity = pin.value_id();
                if !act.is_some_and(|act| {
                    verified_definitions
                        .get(&identity)
                        .is_some_and(|verified| act >= *verified)
                }) {
                    definition_at_on(conn, pin, act).await?;
                    verified_definitions
                        .insert(identity, act.expect("definition gate requires an act"));
                }
            }
        }
    }
    if let Some(record) = state.as_mut().filter(|_| include_relations) {
        // Provider mutations live on aggregate streams. Resolve only indexed
        // direct subjects/anchors; a migrated attribution never touches activity.
        let activity: Option<(i64,String)> = sqlx::query_as(
            "SELECT e.seq,e.created_at FROM kernel_provider_subjects s JOIN kernel_provider_state p ON p.id=s.aggregate_id JOIN content_events e ON e.record_id=p.id WHERE s.subject_id=?1 AND e.type='kernel.provider_outcome.v1' AND e.seq>?2 AND e.seq<=?3 AND (p.provider_key=?4 OR (p.provider_key=?5 AND EXISTS(SELECT 1 FROM kernel_provider_receipts r JOIN kernel_principals a ON a.principal_id=r.principal_id WHERE r.event_seq=e.seq AND json_extract(r.request_json,'$.anchor.record_id')=?1 AND coalesce(a.auth_binding,'')!=?6))) ORDER BY e.seq DESC LIMIT 1",
        ).bind(id).bind(metadata_seq).bind(through).bind(crate::v2_standard::claims_v1::PROVIDER_KEY).bind(crate::v2_standard::relates_to::RELATIONSHIP).bind(relates_to_port::HOST_TRANSFORM_BINDING).fetch_optional(&mut *conn).await?;
        if let Some((_, at)) = activity {
            record.metadata.last_activity_at = at;
        }
        let original: Option<String> = sqlx::query_scalar("SELECT created_at FROM kernel_legacy_sql_events WHERE record_id=? AND source_stream='snapshot_provenance' AND seq<=? ORDER BY seq DESC LIMIT 1")
            .bind(id).bind(through).fetch_optional(&mut *conn).await?;
        if let Some(original) = original {
            record.created_at = original;
        }
    }
    tracing::debug!(target:"native_ce::read_staging",phase="historical_subject",elapsed_us=started.elapsed().as_micros() as u64);
    Ok(state)
}

async fn definition_at_on(
    conn: &mut SqliteConnection,
    pin: &RevisionIdentity,
    act: Option<i64>,
) -> Result<()> {
    let act = act.ok_or_else(|| {
        Error::engine("historical meta position unavailable before workspace act stamping")
    })?;
    let installed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM meta_events WHERE subject_id=? AND type='definition_artifact.installed' AND (act<=? OR (act IS NULL AND seq<=coalesce((SELECT last_legacy_seq FROM act_cutover WHERE domain='meta_events'),0))))")
        .bind(pin.value_id()).bind(act).fetch_one(conn).await?;
    if !installed {
        return Err(Error::engine(
            "historical definition is unavailable at this position",
        ));
    }
    Ok(())
}

/// Candidate relations are not authorization. The adapter gates every endpoint
/// and every provider subject using the live kernel visibility helpers.
pub(crate) async fn links_at_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    through: i64,
) -> Result<Vec<Value>> {
    let sources: Vec<String> = sqlx::query_scalar(
        "SELECT ?1 UNION SELECT source_id FROM kernel_generic_links WHERE target_id=?1 UNION SELECT source_id FROM kernel_links WHERE target_id=?1 UNION SELECT CASE WHEN type='kernel.link_added.v2' THEN json_extract(payload,'$.source.record_id') ELSE record_id END FROM content_events WHERE type IN ('kernel.link_added.v1','kernel.link_removed.v1','kernel.link_added.v2') AND coalesce(json_extract(payload,'$.target_id'),json_extract(payload,'$.target.record_id'))=?1",
    ).bind(id).fetch_all(&mut *conn).await?;
    let mut generic: BTreeMap<String, Value> = BTreeMap::new();
    let mut legacy: BTreeMap<(String, String, String), Value> = BTreeMap::new();
    for source in sources {
        if read_record_on(conn, actor, &source).await?.is_none() {
            continue;
        }
        let rows:Vec<(String,String,String)>=sqlx::query_as("SELECT type,payload,created_at FROM content_events WHERE record_id=? AND seq<=? AND type IN ('kernel.generic_link_added.v1','kernel.generic_link_imported.v1','kernel.generic_link_note_updated.v1','kernel.generic_link_note_imported.v1','kernel.generic_link_removed.v1','kernel.generic_link_removal_imported.v1','kernel.link_added.v1','kernel.link_added.v2','kernel.link_removed.v1') ORDER BY seq")
            .bind(source).bind(through).fetch_all(&mut *conn).await?;
        for (typ, raw, at) in rows {
            let p: Value = serde_json::from_str(&raw)?;
            if typ.starts_with("kernel.generic_link_") {
                let key = p["link_id"]
                    .as_str()
                    .ok_or_else(|| Error::engine("historical link identity unavailable"))?
                    .to_owned();
                match typ.as_str() {
                    "kernel.generic_link_added.v1" | "kernel.generic_link_imported.v1" => {
                        if p["source_id"] == id || p["target_id"] == id {
                            generic.insert(key.clone(),serde_json::json!({"id":key,"source_id":p["source_id"],"target_id":p["target_id"],"relationship":p["relationship"],"note":p["note"],"created_at":p.get("created_at").cloned().unwrap_or(Value::String(at))}));
                        }
                    }
                    "kernel.generic_link_removed.v1"
                    | "kernel.generic_link_removal_imported.v1" => {
                        generic.remove(&key);
                    }
                    _ => {
                        if let Some(link) = generic.get_mut(&key) {
                            link["note"] = p["note"].clone();
                        }
                    }
                }
            } else {
                // /4 directed additions use endpoint witnesses. Their removal
                // uses the same flat v1 triple as older directed additions.
                let (source, target, relationship) = if typ == "kernel.link_added.v2" {
                    (
                        &p["source"]["record_id"],
                        &p["target"]["record_id"],
                        &p["predicate"],
                    )
                } else {
                    (&p["source_id"], &p["target_id"], &p["relationship"])
                };
                if source == id || target == id {
                    let key = (
                        source.as_str().unwrap().to_owned(),
                        target.as_str().unwrap().to_owned(),
                        relationship.as_str().unwrap().to_owned(),
                    );
                    if typ == "kernel.link_removed.v1" {
                        legacy.remove(&key);
                    } else {
                        legacy.insert(key,serde_json::json!({"id":null,"source_id":source,"target_id":target,"relationship":relationship,"note":null,"created_at":at}));
                    }
                }
            }
        }
    }
    let mut links: Vec<Value> = generic.into_values().chain(legacy.into_values()).collect();
    let aggregates:Vec<String>=sqlx::query_scalar("SELECT p.id FROM kernel_provider_subjects s JOIN kernel_provider_state p ON p.id=s.aggregate_id WHERE s.subject_id=? AND p.provider_key='relates_to.v1' ORDER BY p.id")
        .bind(id).fetch_all(&mut *conn).await?;
    for aggregate in aggregates {
        let subjects: Vec<String> = sqlx::query_scalar(
            "SELECT subject_id FROM kernel_provider_subjects WHERE aggregate_id=?",
        )
        .bind(&aggregate)
        .fetch_all(&mut *conn)
        .await?;
        let mut visible = true;
        for subject in &subjects {
            if read_record_on(conn, actor, subject).await?.is_none() {
                visible = false;
                break;
            }
        }
        if !visible {
            continue;
        }
        let rows:Vec<(i64,String,String)>=sqlx::query_as("SELECT seq,payload,created_at FROM content_events WHERE record_id=? AND seq<=? AND type='kernel.provider_outcome.v1' ORDER BY seq")
            .bind(&aggregate).bind(through).fetch_all(&mut *conn).await?;
        let mut state: Option<provider_catalogue::StoredState> = None;
        let mut subjects = Vec::new();
        for (seq, raw, at) in rows {
            let payload: Value = serde_json::from_str(&raw)?;
            let entry = provider_catalogue::recorded(&payload)?;
            let decoded = (entry.decode)(&payload)?;
            subjects = decoded.facts.subjects.clone();
            let folded = (entry.fold)(
                &provider_catalogue::FoldInput {
                    decoded: &decoded,
                    principal: &decoded.facts.principal,
                    timestamp: &at,
                    event_seq: seq,
                },
                state.as_ref(),
            )?;
            state = Some(provider_catalogue::StoredState {
                pins: decoded.facts.pins,
                state: folded.state,
                attribution: folded.attribution,
            });
        }
        if let Some(state) = state {
            if let Some((left, right)) =
                relates_to_port::active_pair_from_state(&serde_json::to_string(&state)?)?
            {
                for (source, target) in [(&left, &right), (&right, &left)] {
                    links.push(serde_json::json!({"id":null,"source_id":source,"target_id":target,"relationship":"relates_to","note":null,"created_at":null,"_subjects":subjects}));
                }
            }
        }
    }
    Ok(links)
}

/// Both past and current filing candidates: a child moved away after the
/// cutoff must still appear before it. Only direct filing homes are inspected.
pub(crate) async fn child_candidates_on(
    conn: &mut SqliteConnection,
    id: &str,
    through: i64,
) -> Result<Vec<String>> {
    let home = hq::v1_import_home_id(id);
    Ok(sqlx::query_scalar(&format!("SELECT DISTINCT record_id FROM content_events WHERE type IN ({}) AND {} IN (?2,?3) AND seq<=?1 ORDER BY record_id",record_metadata::HISTORICAL_HOME_TYPES,record_metadata::HISTORICAL_HOME_EXPR))
        .bind(through).bind(id).bind(home).fetch_all(conn).await?)
}

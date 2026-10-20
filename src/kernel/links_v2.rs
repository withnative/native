//! /4 directed links: one closed admission witness, checked live at the
//! shared append seam and structurally at the recorded replay boundary.
use super::*;
use crate::meta::definition_artifact::{parse_link_target4, LinkTarget4};

pub(super) const LINK4_DDL: &str = r#"CREATE TABLE kernel_link4_edges (
 edge_id TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL,
 operation_key TEXT NOT NULL CHECK(length(trim(operation_key)) > 0),
 source_id TEXT NOT NULL REFERENCES kernel_records(id),
 target_id TEXT NOT NULL REFERENCES kernel_records(id),
 predicate TEXT NOT NULL,
 witness_json TEXT NOT NULL,
 created_seq INTEGER NOT NULL,
 UNIQUE(principal_id, operation_key)
)"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum EndpointBinding {
    Bare,
    Bound {
        pin: RevisionIdentity,
        kind: String,
        interpreter: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointWitness {
    pub record_id: String,
    pub head: i64,
    pub binding_revision: i64,
    pub binding: EndpointBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link4Request {
    pub edge_id: String,
    pub operation_key: String,
    pub principal_id: String,
    pub source: EndpointWitness,
    pub target: EndpointWitness,
    pub predicate: String,
    pub declaration_index: usize,
    pub declaration: serde_json::Value,
    /// None means the expected edge is absent. Present heads are reserved
    /// for later attributed edge correction/retraction operations.
    pub expected_edge_head: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link4Receipt {
    pub edge_id: String,
    pub event_seq: i64,
}

fn stable_id(principal: &str, key: &str) -> String {
    let bytes = serde_json::to_vec(&("kernel.link_added.v2", principal, key)).expect("strings");
    format!(
        "edge:{}",
        crate::meta::definition_artifact::digest_artifact_bytes(&bytes)
    )
}

/// The convenience wrappers identify the same directed tuple on every retry.
/// Explicit prepared operations keep their caller-selected retry keys.
pub(super) async fn wrapper_operation_key(
    db: &Db,
    principal: &str,
    source: &str,
    predicate: &str,
    target: &str,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        "kernel.link.wrapper.v2",
        principal,
        source,
        predicate,
        target,
    ))
    .expect("strings");
    let key = format!(
        "wrapper:{}",
        crate::meta::definition_artifact::digest_artifact_bytes(&bytes)
    );
    let removed: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=? AND type='kernel.link_removed.v1' AND json_extract(payload,'$.target_id')=? AND json_extract(payload,'$.relationship')=?")
        .bind(source).bind(target).bind(predicate).fetch_one(db.pool()).await?;
    Ok(if removed == 0 {
        key
    } else {
        format!("{key}:after:{removed}")
    })
}

pub(super) async fn source_supports_closed_links(db: &Db, source: &str) -> Result<bool> {
    let interpreter: Option<String> =
        sqlx::query_scalar("SELECT interpreter FROM kernel_records WHERE id = ?")
            .bind(source)
            .fetch_optional(db.pool())
            .await?
            .flatten();
    Ok(
        crate::meta::definition_artifact::language_capabilities(interpreter.as_deref())
            .supports_closed_links,
    )
}

type EndpointRow = (
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
);

pub(super) async fn endpoint(
    conn: &mut SqliteConnection,
    id: &str,
    before: i64,
) -> Result<EndpointWitness> {
    let row: Option<EndpointRow> =
        sqlx::query_as("SELECT kind, pin_family, pin_version, pin_digest, interpreter, created_seq FROM kernel_records WHERE id = ?")
        .bind(id).fetch_optional(&mut *conn).await?;
    let Some((kind, family, version, digest, interpreter, created_seq)) = row else {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    };
    let binding = match (kind, family, version, digest, interpreter) {
        (None, None, None, None, None) => EndpointBinding::Bare,
        (Some(kind), Some(family), Some(version), Some(digest), Some(interpreter)) => {
            EndpointBinding::Bound {
                pin: RevisionIdentity {
                    family,
                    version: version
                        .try_into()
                        .map_err(|_| Error::engine("invalid endpoint pin"))?,
                    digest,
                },
                kind,
                interpreter,
            }
        }
        _ => return Err(Error::engine("incomplete endpoint binding")),
    };
    let head: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id = ? AND seq < ? AND type != 'kernel.provider_outcome.v1'",
    )
    .bind(id)
    .bind(before)
    .fetch_one(&mut *conn)
    .await?;
    Ok(EndpointWitness {
        record_id: id.into(),
        head,
        binding_revision: created_seq,
        binding,
    })
}

pub(super) async fn retained_bytes(
    conn: &mut SqliteConnection,
    binding: &EndpointBinding,
) -> Result<Option<String>> {
    let EndpointBinding::Bound {
        pin,
        kind,
        interpreter,
    } = binding
    else {
        return Ok(None);
    };
    let bytes: Option<String> = sqlx::query_scalar("SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?")
        .bind(&pin.family).bind(pin.version).bind(&pin.digest).fetch_optional(&mut *conn).await?;
    let bytes = bytes.ok_or_else(|| Error::engine("missing retained endpoint definition"))?;
    if crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes()) != pin.digest {
        return Err(Error::engine("retained endpoint digest mismatch"));
    }
    crate::meta::definition_artifact::validate_kernel_definition_bytes(&bytes)?;
    if interpreter_for_bytes(&bytes)? != interpreter
        || !crate::meta::definition_artifact::parse_artifact_envelope(&bytes)?
            .kinds
            .as_array()
            .is_some_and(|kinds| {
                kinds
                    .iter()
                    .any(|k| k.as_str() == Some(kind) || k["token"].as_str() == Some(kind))
            })
    {
        return Err(Error::engine("retained endpoint binding mismatch"));
    }
    Ok(Some(bytes))
}

fn declarations(bytes: &str, kind: &str) -> Result<Vec<serde_json::Value>> {
    let doc: serde_json::Value = serde_json::from_str(bytes)?;
    let entry = doc["kinds"]
        .as_array()
        .and_then(|kinds| kinds.iter().find(|k| k["token"].as_str() == Some(kind)))
        .ok_or_else(|| Error::engine("missing retained source kind"))?;
    entry["links"]
        .as_array()
        .cloned()
        .ok_or_else(|| Error::engine("missing retained link declarations"))
}

fn matches(
    declaration: &serde_json::Value,
    predicate: &str,
    binding: &EndpointBinding,
) -> Result<bool> {
    let structural = matches_target(&declaration["target"], binding)?;
    Ok(structural
        && declaration["predicate"].as_str() == Some(predicate)
        && matches!(declaration["direction"].as_str(), Some("out" | "either")))
}

pub(super) fn matches_target(
    target: &serde_json::Value,
    binding: &EndpointBinding,
) -> Result<bool> {
    let target = parse_link_target4(target)?;
    let structural = match (target, binding) {
        (LinkTarget4::AnyRecord(_), _) => true,
        (LinkTarget4::Family(selector), EndpointBinding::Bound { pin, kind, .. }) => {
            selector.family == pin.family && selector.kind == *kind
        }
        _ => false,
    };
    Ok(structural)
}

async fn validate_witness(
    conn: &mut SqliteConnection,
    request: &Link4Request,
    before: i64,
) -> Result<()> {
    if request.operation_key.trim().is_empty()
        || request.predicate.trim().is_empty()
        || request.edge_id != stable_id(&request.principal_id, &request.operation_key)
        || request.source.record_id == request.target.record_id
        || request.expected_edge_head.is_some()
    {
        return Err(Error::engine("invalid directed-link witness"));
    }
    if endpoint(conn, &request.source.record_id, before).await? != request.source
        || endpoint(conn, &request.target.record_id, before).await? != request.target
    {
        return Err(Error::conflict(
            "directed-link endpoint or binding revision mismatch",
        ));
    }
    let bytes = retained_bytes(conn, &request.source.binding)
        .await?
        .ok_or_else(|| Error::engine("defn/4 link needs a bound source"))?;
    let EndpointBinding::Bound {
        kind, interpreter, ..
    } = &request.source.binding
    else {
        unreachable!()
    };
    if !crate::meta::definition_artifact::language_capabilities(Some(interpreter))
        .supports_closed_links
    {
        return Err(Error::engine(
            "directed-link witness requires native.defn/4",
        ));
    }
    retained_bytes(conn, &request.target.binding).await?;
    let links = declarations(&bytes, kind)?;
    if links.get(request.declaration_index) != Some(&request.declaration)
        || !matches(
            &request.declaration,
            &request.predicate,
            &request.target.binding,
        )?
    {
        return Err(Error::engine(
            "directed-link declaration does not permit target",
        ));
    }
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_links WHERE source_id = ? AND target_id = ? AND relationship = ?)")
        .bind(&request.source.record_id).bind(&request.target.record_id).bind(&request.predicate).fetch_one(&mut *conn).await?;
    if present {
        return Err(Error::conflict("directed-link edge head mismatch"));
    }
    Ok(())
}

async fn authority(
    conn: &mut SqliteConnection,
    principal: &str,
    source: &str,
    target: &str,
) -> Result<()> {
    // Authenticate before any schema diagnostic. Principals and homes are
    // uniformly outside the record endpoint domain, including any_record.
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)")
            .bind(principal)
            .fetch_one(&mut *conn)
            .await?;
    if !known {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if !kernel_effective_capability_on(conn, principal, source)
        .await?
        .allows(Capability::Edit)
        || !kernel_effective_capability_on(conn, principal, target)
            .await?
            .allows(Capability::View)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    endpoint(conn, source, i64::MAX).await?;
    endpoint(conn, target, i64::MAX).await?;
    Ok(())
}

/// A retry is a receipt for the recorded act, never permission to bless a
/// corrupted projection or to reevaluate that act under today's bindings.
async fn existing_request(
    conn: &mut SqliteConnection,
    principal: &str,
    key: &str,
) -> Result<Option<(Link4Request, i64)>> {
    let row: Option<(String, i64)> = sqlx::query_as("SELECT witness_json, created_seq FROM kernel_link4_edges WHERE principal_id = ? AND operation_key = ?")
        .bind(principal).bind(key).fetch_optional(&mut *conn).await?;
    let Some((json, seq)) = row else {
        return Ok(None);
    };
    let request: Link4Request = serde_json::from_str(&json)?;
    let event: Option<(String, Option<String>, Option<String>)> = sqlx::query_as("SELECT record_id, actor, payload FROM content_events WHERE seq = ? AND type = 'kernel.link_added.v2'")
        .bind(seq).fetch_optional(&mut *conn).await?;
    let Some((anchor, actor, payload)) = event else {
        return Err(Error::engine("directed-link retry witness mismatch"));
    };
    let logged: Link4Request = serde_json::from_str(payload.as_deref().unwrap_or_default())?;
    let agrees: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_link4_edges e JOIN kernel_links l ON l.source_id=e.source_id AND l.target_id=e.target_id AND l.relationship=e.predicate AND l.created_seq=e.created_seq WHERE e.principal_id=? AND e.operation_key=? AND e.edge_id=? AND e.source_id=? AND e.target_id=? AND e.predicate=?)")
        .bind(principal).bind(key).bind(&request.edge_id).bind(&request.source.record_id).bind(&request.target.record_id).bind(&request.predicate).fetch_one(&mut *conn).await?;
    if logged != request
        || anchor != request.source.record_id
        || actor.as_deref() != Some(principal)
        || request.principal_id != principal
        || request.operation_key != key
        || request.edge_id != stable_id(principal, key)
    {
        return Err(Error::engine("directed-link retry witness mismatch"));
    }
    if !agrees {
        let removed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type='kernel.link_removed.v1' AND record_id=? AND seq>? AND json_extract(payload,'$.target_id')=? AND json_extract(payload,'$.relationship')=?)")
            .bind(&request.source.record_id).bind(seq).bind(&request.target.record_id).bind(&request.predicate).fetch_one(&mut *conn).await?;
        if removed {
            return Err(Error::conflict(
                "directed-link operation was unlinked; use a new operation key",
            ));
        }
        return Err(Error::engine("directed-link retry witness mismatch"));
    }
    Ok(Some((request, seq)))
}

pub async fn prepare_link4_as(
    db: &Db,
    principal: &str,
    source: &str,
    predicate: &str,
    target: &str,
    operation_key: &str,
) -> Result<Link4Request> {
    let mut tx = db.write_pool().begin().await?;
    authority(&mut tx, principal, source, target).await?;
    refuse_governed_directed(&mut tx, source, target, predicate).await?;
    if let Some((request, _)) = existing_request(&mut tx, principal, operation_key).await? {
        if request.source.record_id != source
            || request.target.record_id != target
            || request.predicate != predicate
        {
            return Err(Error::conflict(
                "directed-link idempotency key reused for another operation",
            ));
        }
        return Ok(request);
    }
    let source = endpoint(&mut tx, source, i64::MAX).await?;
    let target = endpoint(&mut tx, target, i64::MAX).await?;
    let bytes = retained_bytes(&mut tx, &source.binding)
        .await?
        .ok_or_else(|| Error::engine("defn/4 link needs a bound source"))?;
    let EndpointBinding::Bound { kind, .. } = &source.binding else {
        unreachable!()
    };
    let links = declarations(&bytes, kind)?;
    let mut selected = None;
    for (index, declaration) in links.into_iter().enumerate() {
        if matches(&declaration, predicate, &target.binding)? {
            selected = Some((index, declaration));
            break;
        }
    }
    let (declaration_index, declaration) = selected
        .ok_or_else(|| Error::engine("directed-link declaration does not permit target"))?;
    let request = Link4Request {
        edge_id: stable_id(principal, operation_key),
        operation_key: operation_key.into(),
        principal_id: principal.into(),
        source,
        target,
        predicate: predicate.into(),
        declaration_index,
        declaration,
        expected_edge_head: None,
    };
    validate_witness(&mut tx, &request, i64::MAX).await?;
    tx.rollback().await?;
    Ok(request)
}

pub async fn link4_as(db: &Db, principal: &str, request: &Link4Request) -> Result<Link4Receipt> {
    let mut tx = begin_write(db.write_pool()).await?;
    authority(
        &mut tx,
        principal,
        &request.source.record_id,
        &request.target.record_id,
    )
    .await?;
    if request.principal_id != principal {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if let Some((existing, event_seq)) =
        existing_request(&mut tx, principal, &request.operation_key).await?
    {
        if existing != *request {
            return Err(Error::conflict(
                "directed-link idempotency key reused for another operation",
            ));
        }
        return Ok(Link4Receipt {
            edge_id: request.edge_id.clone(),
            event_seq,
        });
    }
    refuse_governed_directed(
        &mut tx,
        &request.source.record_id,
        &request.target.record_id,
        &request.predicate,
    )
    .await?;
    validate_witness(&mut tx, request, i64::MAX).await?;
    let mut acts = crate::act::ActAllocation::new();
    let event = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: request.source.record_id.clone(),
            event_type: "kernel.link_added.v2".into(),
            payload: serde_json::to_value(request)?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(Link4Receipt {
        edge_id: request.edge_id.clone(),
        event_seq: event.local_seq,
    })
}

/// All local append callers, including batches, meet the same checks. Replay
/// never calls this live authority gate.
pub(crate) async fn admit_link_event(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    match event.event_type.as_str() {
        "kernel.link_added.v2" => {
            let request: Link4Request = event_payload(event)?;
            if event.record_id != request.source.record_id
                || event.actor.as_deref() != Some(&request.principal_id)
            {
                return Err(Error::engine("invalid directed-link actor or anchor"));
            }
            refuse_governed_directed(
                conn,
                &request.source.record_id,
                &request.target.record_id,
                &request.predicate,
            )
            .await?;
            authority(
                conn,
                &request.principal_id,
                &request.source.record_id,
                &request.target.record_id,
            )
            .await?;
            validate_witness(conn, &request, i64::MAX).await
        }
        "kernel.link_added.v1" => {
            let p: KernelLinkPayload = event_payload(event)?;
            refuse_governed_directed(conn, &p.source_id, &p.target_id, &p.relationship).await?;
            refuse_legacy_defn4(conn, event).await
        }
        _ => Ok(()),
    }
}

pub(crate) async fn refuse_legacy_defn4(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let interpreter: Option<String> =
        sqlx::query_scalar("SELECT interpreter FROM kernel_records WHERE id = ?")
            .bind(&event.record_id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    if crate::meta::definition_artifact::language_capabilities(interpreter.as_deref())
        .supports_closed_links
    {
        return Err(Error::engine(format!(
            "{} requires a pinned kernel.link_added.v2 event",
            interpreter.unwrap()
        )));
    }
    Ok(())
}

pub(crate) async fn check_link4_projection_authority(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let request: Link4Request = event_payload(event)?;
    refuse_governed_directed(
        conn,
        &request.source.record_id,
        &request.target.record_id,
        &request.predicate,
    )
    .await?;
    authority(
        conn,
        &request.principal_id,
        &request.source.record_id,
        &request.target.record_id,
    )
    .await
}

pub(crate) async fn project_link4_added(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let request: Link4Request = event_payload(event)?;
    if event.record_id != request.source.record_id
        || event.actor.as_deref() != Some(&request.principal_id)
    {
        return Err(Error::engine("invalid directed-link actor or anchor"));
    }
    validate_witness(conn, &request, event.local_seq).await?;
    sqlx::query("INSERT INTO kernel_link4_edges (edge_id, principal_id, operation_key, source_id, target_id, predicate, witness_json, created_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&request.edge_id).bind(&request.principal_id).bind(&request.operation_key).bind(&request.source.record_id).bind(&request.target.record_id).bind(&request.predicate).bind(serde_json::to_string(&request)?).bind(event.local_seq).execute(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_links (source_id, target_id, relationship, created_seq) VALUES (?, ?, ?, ?)")
        .bind(&request.source.record_id).bind(&request.target.record_id).bind(&request.predicate).bind(event.local_seq).execute(&mut *conn).await?;
    Ok(())
}

pub(super) fn contract() -> serde_json::Value {
    serde_json::json!({
        "interpreter": "native.defn/4 and later",
        "targets": [{"family": "<definition family>", "kind": "<recorded kind>"}, {"any_record": true}],
        "matching": "family+kind matches any retained recorded version; any_record includes bare records and excludes principals and homes; self-links refuse",
        "authority": {"source": "Edit", "target": "View"},
        "semantics": "directed predicate; direction either permits outgoing admission and does not create symmetry; cardinality is declaration metadata, not a selection reducer",
        "prepare": "prepare_link4_as returns endpoint heads, binding revisions, exact pins and selected declaration; link4_as rechecks these and current authority atomically",
        "harness": {
            "record_discovery": "describe --record <id>",
            "prepare": "link-prepare --source <id> --predicate <declared predicate> --target <id> --operation-key <unique retry key>",
            "commit": "link-commit --json <file containing unchanged prepared request>",
            "read": "read --id <id>",
            "create": "create --family <family> --kind <kind> --home <visible creatable home> --json <field object file>",
            "discovery": "Scope definitions govern creation; record discovery governs existing anchor permissions even when its old version is disabled. Creation of disabled families refuses; retained bound targets still match."
        },
        "retry": "principal-scoped operation_key preserves one stable edge identity; discovery is advisory",
        "dependencies": "selectors create no semantic dependency; active semantic consumers require explicit exact pins; no automatic mapping"
    })
}

pub async fn describe_record_links_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<serde_json::Value> {
    let mut tx = db.write_pool().begin().await?;
    kernel_require(&mut tx, principal, record, Capability::View).await?;
    let witness = endpoint(&mut tx, record, i64::MAX).await?;
    let mut links = Vec::new();
    if let Some(bytes) = retained_bytes(&mut tx, &witness.binding).await? {
        let EndpointBinding::Bound { kind, .. } = &witness.binding else {
            unreachable!()
        };
        if kind_descriptor(&bytes, kind)?.is_some() {
            for declaration in declarations(&bytes, kind)? {
                let mut detail = serde_json::json!({"declaration": declaration});
                if let Some(family) = declaration["target"]["family"].as_str() {
                    // Describe only resolution in this record's visible home;
                    // never enumerate foreign installation or hidden scopes.
                    let home: String =
                        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id = ?")
                            .bind(record)
                            .fetch_one(&mut *tx)
                            .await?;
                    let active = kernel_effective_capability_on(&mut tx, principal, &home)
                        .await?
                        .allows(Capability::View)
                        && matches!(
                            resolve_effective_adoption(&mut tx, family, &home).await?,
                            Some(ScopedAdoption::Adopted(_))
                        );
                    detail["target_creation"] = serde_json::json!(if active {
                        "active in visible home"
                    } else {
                        "unresolved or unavailable; retained bound endpoints still match"
                    });
                }
                links.push(detail);
            }
        }
    }
    let editable = kernel_effective_capability_on(&mut tx, principal, record)
        .await?
        .allows(Capability::Edit);
    tx.rollback().await?;
    let governed = super::relates_to_port::describe_record_as(db, principal, record).await?;
    Ok(
        serde_json::json!({"record": witness, "links": links, "can_anchor": editable, "contract": contract(), "governed_relationships": governed}),
    )
}

/// Live dispatch reservation is package semantics, never a mandatory kernel relation.
pub(crate) async fn refuse_governed_directed(
    conn: &mut SqliteConnection,
    source: &str,
    target: &str,
    predicate: &str,
) -> Result<()> {
    let provider = crate::v2_standard::relates_to::package();
    if !crate::v2_standard::relates_to::reserves(predicate) {
        return Ok(());
    }
    for record in [source, target] {
        let home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
                .bind(record)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some(home) = home {
            if resolve_effective_package_selection(conn, &home, &provider.namespace, &provider.name)
                .await?
                .is_some_and(|selection| selection.selected.is_some())
            {
                return Err(Error::engine(
                    "relates_to requires the governed provider commit port",
                ));
            }
        }
    }
    Ok(())
}

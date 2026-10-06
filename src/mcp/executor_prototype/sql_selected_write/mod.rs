//! Versioned SQL-selected preview. There is deliberately no mutation adapter.
//! Frozen contract: f4d38d6ce3ac3b1975616917a3d0998a6ae6d8f6.
mod evidence;
mod predicate;
mod snapshot;

use crate::{
    authorization::Capability,
    error::{Error, Result},
    mcp::Caller,
};
use evidence::{hash, Budget};
use predicate::{Scalar, Truth};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snapshot::{denial, Tx};
use sqlx::Row;
use std::collections::BTreeMap;

pub(super) const CONTRACT: &str = "native.sql-write-selection.v1";
const VERSIONS: [(&str, &str); 8] = [
    ("contract", CONTRACT),
    ("grammar", "native.sql-write-selection-grammar.v1"),
    ("source_schema", "native.sql-write-children.v1"),
    ("auth", "native.sql-write-selection-auth.v1"),
    ("eligibility", "native.sql-write-ordinary-eligibility.v1"),
    ("schema", "native.sql-write-selection-schema.v1"),
    ("effect_profile", "native.sql-selected-write-effect.v1"),
    ("encoding", "native.sql-selected-canonical-json.v1"),
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Parameter {
    #[serde(rename = "type")]
    kind: String,
    value: Value,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Write {
    SetFacet { key: String, value: String },
    AddLink { target_id: String },
    Archive,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    selection_contract: String,
    folder_id: String,
    statement: String,
    #[serde(default)]
    parameters: Vec<Parameter>,
    write: Write,
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_version: Option<i64>,
}
fn parameters(params: &[Parameter]) -> Result<Vec<Scalar>> {
    if params.len() > 256 {
        return Err(denial("at most 256 parameters are supported"));
    }
    params
        .iter()
        .map(|p| match (p.kind.as_str(), &p.value) {
            ("text" | "boolean", Value::Null) => Ok(Scalar::Null),
            ("text", Value::String(v)) if v.chars().count() <= 1024 => Ok(Scalar::Text(v.clone())),
            ("boolean", Value::Bool(v)) => Ok(Scalar::Boolean(*v)),
            _ => Err(denial(
                "use tagged text/boolean parameters with exact types and bounded text",
            )),
        })
        .collect()
}
fn validate_id(id: &str) -> Result<()> {
    let alphabet = !id.is_empty()
        && id.len() <= 120
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    let native = id
        .strip_prefix("native:")
        .is_some_and(|suffix| !suffix.is_empty());
    let carrier = id
        .strip_prefix("change-summary:carrier:")
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
        });
    let uuid = uuid::Uuid::parse_str(id)
        .is_ok_and(|u| u.to_string() == id && matches!(u.get_version_num(), 4 | 7));
    if alphabet && (native || carrier || uuid) {
        Ok(())
    } else {
        Err(denial(
            "supply an explicit fully resolved canonical record ID",
        ))
    }
}

pub(super) fn validate(arguments: Value) -> Result<()> {
    parse(arguments).map(|_| ())
}

fn parse(arguments: Value) -> Result<(Request, predicate::Program)> {
    if arguments
        .get("expected_version")
        .is_some_and(Value::is_null)
    {
        return Err(denial(
            "expected_version must be a positive integer when supplied",
        ));
    }
    if arguments
        .get("parameters")
        .and_then(Value::as_array)
        .is_some_and(|p| p.len() > 256)
    {
        return Err(denial("at most 256 parameters are supported"));
    }
    let r: Request = serde_json::from_value(arguments)
        .map_err(|_| denial("use one documented request/write object without unknown fields"))?;
    if r.selection_contract != CONTRACT {
        return Err(denial(
            "unsupported selection contract; prepare using native.sql-write-selection.v1",
        ));
    }
    validate_id(&r.folder_id)?;
    if r.reason.trim().is_empty()
        || r.reason.chars().count() > 1024
        || r.expected_version.is_some_and(|v| v < 1)
    {
        return Err(denial(
            "reason must be nonblank, at most 1024 characters; expected_version must be positive",
        ));
    }
    match &r.write {
        Write::SetFacet { key, value } => {
            if key.is_empty() || key.chars().count() > 120 || value.chars().count() > 1024 {
                return Err(denial("facet key/value bounds are 120/1024 characters"));
            }
            crate::domain_transaction::assert_open_facet_key("sql_write", key)
                .map_err(|_| denial("reserved facet key; choose a public open facet"))?;
        }
        Write::AddLink { target_id } => validate_id(target_id)?,
        Write::Archive => {}
    }
    let program = predicate::compile(&r.statement, &parameters(&r.parameters)?)?;
    for (slot, boolean) in &program.parameter_contexts {
        if r.parameters[*slot - 1].kind != if *boolean { "boolean" } else { "text" } {
            return Err(denial(
                "parameter tag must match its field context, including typed NULL",
            ));
        }
    }
    Ok((r, program))
}

pub(super) fn supported_evidence(evidence: &Value) -> bool {
    let s = &evidence["selection"];
    VERSIONS.iter().all(|(k, v)| s[*k].as_str() == Some(v))
        && [
            "folder_id",
            "request_digest",
            "folder_digest",
            "source_digest",
            "authority_digest",
            "schema_digest",
            "selected_versions_digest",
            "effect_dependencies_digest",
            "approval_digest",
        ]
        .iter()
        .all(|k| s[*k].is_string())
        && ["candidate_count", "target_count", "op_count"]
            .iter()
            .all(|k| s[*k].is_u64())
}

pub(super) async fn prepare(
    db: &crate::Db,
    caller: &Caller,
    arguments: Value,
) -> Result<super::SqlWritePreparation> {
    let (request, program) = parse(arguments)?;
    if matches!(request.write, Write::SetFacet { .. }) && db.is_enrolled() {
        return Err(denial(
            "unsupported enrolled/coedit facet path; use the public singular tool",
        ));
    }
    let mut tx = db.write_pool().begin().await.map_err(|_| {
        Error::engine("sql_write: workspace snapshot could not start; repair storage before retry")
    })?;
    let result = prepare_in(&mut tx, caller, request, program).await;
    match result {
        Ok(value) => {
            tx.rollback().await.map_err(|_| {
                Error::engine(
                    "sql_write: workspace snapshot could not finish; repair storage before retry",
                )
            })?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            match error {Error::Conflict(_)=>Err(error),_=>Err(Error::engine("sql_write: snapshot evaluation could not complete; repair authoritative storage/state before retry"))}
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static SNAPSHOT_GATE: std::sync::Arc<super::DispatchGate>;
}

async fn prepare_in(
    tx: &mut Tx,
    caller: &Caller,
    request: Request,
    program: predicate::Program,
) -> Result<super::SqlWritePreparation> {
    let mut budget = Budget::default();
    let folder = snapshot::visible(tx, caller, &request.folder_id, &mut budget)
        .await?
        .ok_or_else(|| {
            denial("Scope or target unavailable; choose an explicit visible live folder/target")
        })?;
    let (persistence,archived):(String,bool)=sqlx::query_as("SELECT persistence,EXISTS(SELECT 1 FROM facet_values WHERE record_id=records.id AND key='archived') FROM records WHERE id=?")
        .bind(&request.folder_id).fetch_one(&mut **tx).await?;
    if folder.record_type != "Collection"
        || folder.kind.as_deref() != Some("folder")
        || persistence != "enduring"
        || archived
    {
        return Err(denial(
            "choose a live unarchived enduring Collection with raw kind folder",
        ));
    }
    let folder_evidence = json!({"id":request.folder_id,"type":folder.record_type,"kind":folder.kind,"persistence":persistence,"deleted":null,"archived":false,"visibility":folder.proof});
    budget.include(&folder_evidence)?;
    #[cfg(test)]
    if let Ok(gate) = SNAPSHOT_GATE.try_with(std::sync::Arc::clone) {
        gate.entered.add_permits(1);
        gate.release
            .acquire()
            .await
            .expect("snapshot gate open")
            .forget();
    }
    let schemas = if !program.keys.is_empty() || matches!(request.write, Write::SetFacet { .. }) {
        snapshot::schemas(tx).await?
    } else {
        Vec::new()
    };
    let mut destination = Value::Null;
    if let Write::AddLink { target_id } = &request.write {
        let target = snapshot::visible(tx, caller, target_id, &mut budget)
            .await?
            .ok_or_else(|| {
                denial("Scope or target unavailable; choose an explicit visible live folder/target")
            })?;
        let previous_seq = crate::mcp::tools::previous_record_seq_in(tx, target_id)
            .await?
            .ok_or_else(|| {
                denial("Scope or target unavailable; choose an explicit visible live folder/target")
            })?;
        destination = json!({"id":target_id,"type":target.record_type,"kind":target.kind,"previous_seq":previous_seq,"visibility":target.proof});
        budget.include(&destination)?;
    }
    let mut source = Vec::new();
    let mut authority = Vec::new();
    let mut schema_evidence = Vec::new();
    let mut selected = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page:Vec<String>=sqlx::query_scalar("SELECT id FROM records WHERE home_id=? AND deleted_at IS NULL AND id<>? AND (? IS NULL OR id>? COLLATE BINARY) ORDER BY id COLLATE BINARY LIMIT 128")
            .bind(&request.folder_id).bind(&request.folder_id).bind(&cursor).bind(&cursor).fetch_all(&mut **tx).await?;
        if page.is_empty() {
            break;
        }
        for id in &page {
            let Some(visible) = snapshot::visible(tx, caller, id, &mut budget).await? else {
                continue;
            };
            // Validation follows strict View and ordinary eligibility: denied
            // IDs never add an integrity dependency to the visible cohort.
            validate_id(id)
                .map_err(|_| Error::engine("sql_write: malformed included record ID"))?;
            if source.len() == 1000 {
                return Err(denial(
                    "visible source exceeds 1000 candidates; narrow folder scope",
                ));
            }
            let raw = snapshot::raw(tx, id).await?;
            let mut facets = BTreeMap::new();
            let mut current_evidence = Vec::new();
            for key in &program.keys {
                let (shape, projection) = snapshot::shape(
                    &schemas,
                    &visible.record_type,
                    visible.kind.as_deref(),
                    key,
                    true,
                )?;
                let (_, governing) = snapshot::governing_identity(tx, shape.as_ref()).await?;
                let current = snapshot::current(tx, id, key).await?;
                let mut validation = Value::Null;
                if let Some(text) = &current.text {
                    (_, validation) = snapshot::assess(
                        tx,
                        &visible.record_type,
                        visible.kind.as_deref(),
                        key,
                        text,
                        current.reference.as_deref(),
                        shape.as_ref(),
                        true,
                        &mut budget,
                    )
                    .await?;
                }
                budget.include(&projection)?;
                schema_evidence
                    .push(json!({"id":id,"projection":projection,"governing":governing,"validation":validation}));
                facets.insert(
                    key.clone(),
                    current
                        .text
                        .clone()
                        .map(Scalar::Text)
                        .unwrap_or(Scalar::Null),
                );
                current_evidence.push(json!({"key":key,"present":current.present,"text":current.text,"reference":current.reference,"time_marker":false}));
            }
            if let Write::SetFacet { key, .. } = &request.write {
                if !program.keys.contains(key) {
                    // Schema/identity proof for every included context is
                    // distinct from selected-only value and shape eligibility.
                    let (shape, projection) = snapshot::shape(
                        &schemas,
                        &visible.record_type,
                        visible.kind.as_deref(),
                        key,
                        false,
                    )?;
                    let (_, governing) = snapshot::governing_identity(tx, shape.as_ref()).await?;
                    budget.include(&projection)?;
                    schema_evidence
                        .push(json!({"id":id,"projection":projection,"governing":governing}));
                }
            }
            let row = json!({"raw":raw,"home_id":request.folder_id,"facets":current_evidence});
            budget.include(&row)?;
            source.push(row);
            authority.push(visible.proof.clone());
            if program.predicate.eval(&raw, &facets) == Truth::True {
                selected.push((id.clone(), visible, raw));
            }
        }
        cursor = page.last().cloned();
    }
    if selected.is_empty() {
        return Err(denial("no visible matches; adjust folder/predicate"));
    }
    if selected.len() > 25 {
        return Err(denial("selection exceeds 25 targets; narrow predicate"));
    }
    if request.expected_version.is_some() && selected.len() != 1 {
        return Err(denial("expected_version pins one selected record only"));
    }
    let mut targets = Vec::new();
    let mut versions = Vec::new();
    let mut dependencies = Vec::new();
    let mut selected_required_capabilities = Vec::new();
    for (id, visible, raw) in selected {
        let required = if matches!(request.write, Write::Archive) {
            Capability::Manage
        } else {
            Capability::Edit
        };
        if !visible.capability.allows(required) {
            return Err(denial(
                "a selected visible target lacks required Edit/Manage; preview refused wholly",
            ));
        }
        selected_required_capabilities.push(json!({"id":id,"required_capability":required}));
        let previous_seq = crate::mcp::tools::previous_record_seq_in(tx, &id)
            .await?
            .ok_or_else(|| Error::engine("missing selected content version"))?;
        if request.expected_version.is_some_and(|v| v != previous_seq) {
            return Err(denial("selected expected content version changed"));
        }
        versions.push(json!({"record_id":id,"previous_seq":previous_seq}));
        let archived = matches!(raw.get("archived"), Some(Scalar::Boolean(true)));
        let (op, dep) = match &request.write {
            Write::SetFacet { key, value } => {
                // Public prospective compiler/attestation and suggestion paths
                // have extra dependencies/events beyond this effect profile.
                // Refuse only affected selected facet paths, never membership.
                if visible.record_type == "Program"
                    || (visible.record_type == "Document"
                        && (visible.kind.as_deref() == Some("artifact")
                            || visible.canonical_kind.as_deref() == Some("artifact")))
                    || (visible.record_type == "Annotation"
                        && visible.canonical_kind.as_deref() == Some("suggestion"))
                {
                    return Err(denial("unsupported selected compiler/attestation or suggestion facet path; use the public singular tool"));
                }
                if archived {
                    return Err(denial("selected archived target cannot receive a facet preview; add archived=false explicitly"));
                }
                if visible.record_type == "Message"
                    && key == crate::message_expectation::EXPECTATION_FACET_KEY
                {
                    return Err(denial(
                        "Message expectation is immutable; use the public superseding route",
                    ));
                }
                let (shape, projection) = snapshot::shape(
                    &schemas,
                    &visible.record_type,
                    visible.kind.as_deref(),
                    key,
                    true,
                )?;
                let current = snapshot::current(tx, &id, key).await?;
                let mut before_validation = Value::Null;
                if let Some(before) = &current.text {
                    (_, before_validation) = snapshot::assess(
                        tx,
                        &visible.record_type,
                        visible.kind.as_deref(),
                        key,
                        before,
                        current.reference.as_deref(),
                        shape.as_ref(),
                        true,
                        &mut budget,
                    )
                    .await?;
                }
                let (reference, validation) = snapshot::assess(
                    tx,
                    &visible.record_type,
                    visible.kind.as_deref(),
                    key,
                    value,
                    None,
                    shape.as_ref(),
                    false,
                    &mut budget,
                )
                .await?;
                let changed =
                    current.text.as_ref() != Some(value) || current.reference != reference;
                let mut payload = json!({"key":key,"value":value,"reason":request.reason});
                if let Some(reference) = &reference {
                    payload["vocab_ref"] = json!(reference);
                }
                let op = json!({"op":"set_facet","key":key,"value":value,"before":current.text,"after":value,"before_present":current.present,"before_vocab_ref":current.reference,"after_vocab_ref":reference,"changed":changed,"state_changed":changed,"would_append":true,"event_intent":{"kind":"facet_assertion","content_events":1,"event_type":"facet.set","payload":payload,"actor":caller.actor()}});
                (
                    op,
                    json!({"projection":projection,"before_validation":before_validation,"proposal_validation":validation}),
                )
            }
            Write::Archive => {
                let event = if archived {
                    json!({"kind":"none","content_events":0})
                } else {
                    json!({"kind":"archive_assertion","content_events":1,"event_type":"facet.set","payload":{"key":"archived","value":"true","reason":request.reason},"actor":caller.actor()})
                };
                (
                    json!({"op":"archive","before":archived,"after":true,"changed":!archived,"state_changed":!archived,"would_append":!archived,"event_intent":event}),
                    json!({"archived":archived}),
                )
            }
            Write::AddLink { target_id } => {
                link(tx, caller, &id, previous_seq, target_id, &destination).await?
            }
        };
        dependencies.push(json!({"id":id,"required_capability":required,"dependencies":dep}));
        let name = match raw.get("name") {
            Some(Scalar::Text(name)) => name.clone(),
            _ => return Err(Error::engine("invalid selected name column")),
        };
        targets.push(json!({"record_id":id,"name":name,"previous_seq":previous_seq,
            "operation":op,"before":op["before"],"after":op["after"],"state_changed":op["state_changed"],
            "would_append":op["would_append"],"event_intent":op["event_intent"],"ops":[op]}));
    }
    let effect = json!({"kind":"sql_write_preview","selection_contract":CONTRACT,"target_count":targets.len(),"op_count":targets.len(),"targets":targets,"reason":request.reason,"preview_only":true});
    let summary = approval_summary(&effect)?;
    let approval = json!({"effect":effect,"effect_summary":summary});
    budget.include(&approval)?;
    budget.include(&json!(dependencies))?;
    let principal = crate::mcp::tools::principal(caller);
    let footing = json!({"account_id":principal.account_id,"is_member":principal.is_member,"trusted_local":principal.is_trusted_local()});
    let canonical_arguments = serde_json::to_value(&request)
        .map_err(|_| Error::engine("could not encode selection request"))?;
    let request_basis = json!({"request":canonical_arguments,"predicate":program.predicate});
    budget.include(&request_basis)?;
    selected_required_capabilities.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let authority_basis = json!({"principal":footing,"folder":folder.proof,"source":authority,"selected_required_capabilities":selected_required_capabilities,"destination":destination});
    let mut selection = json!({"folder_id":request.folder_id,"request_digest":hash("request",&request_basis),"folder_digest":hash("folder",&folder_evidence),"source_digest":hash("source",&json!(source)),
        "authority_digest":hash("authority",&authority_basis),"schema_digest":hash("schema",&json!(schema_evidence)),
        "selected_versions_digest":hash("selected-versions",&json!(versions)),"effect_dependencies_digest":hash("effect-dependencies",&json!(dependencies)),"approval_digest":hash("approval",&approval),"candidate_count":source.len(),"target_count":targets.len(),"op_count":targets.len()});
    for (key, value) in VERSIONS {
        selection[key] = json!(value);
    }
    // Account the complete typed component/wrapper basis, not only scalar
    // constituents. Raw successful traces were charged before hashing; denied
    // scratch was never charged. This is an explicit streamed evidence family.
    budget.finish(
        &json!({"request":request_basis,"folder":folder_evidence,"source":source,
        "authority":authority_basis,
        "schema":schema_evidence,"selected_versions":versions,"effect_dependencies":dependencies,
        "approval":approval,"selection":selection}),
    )?;
    let target_state_digest = hash("selected-versions", &json!(versions));
    Ok(super::SqlWritePreparation {
        canonical_source_arguments: canonical_arguments,
        target_id: if targets.len() == 1 {
            targets[0]["record_id"].as_str().expect("ID").into()
        } else {
            format!("sql-write-target-set:{target_state_digest}")
        },
        target: format!("{} records [{target_state_digest}]", targets.len()),
        state_revision: format!("content-seq-set:{target_state_digest}"),
        target_state_digest,
        effect,
        effect_summary: summary,
        operation_evidence: json!({"kind":"sql_write_preview","selection":selection,"targets":versions,"target_count":targets.len(),"op_count":targets.len()}),
    })
}

fn display(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                format!("\\u{{{:04x}}}", c as u32)
                    .chars()
                    .collect::<Vec<_>>()
            } else if "\\`*_{}[]<>#|".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}
fn approval_summary(effect: &Value) -> Result<String> {
    let targets = effect["targets"]
        .as_array()
        .ok_or_else(|| Error::engine("invalid approval target array"))?;
    let mut lines = vec![format!(
        "Preview only: {} targets / {} operations. No commit, claim or dispatch.",
        targets.len(),
        targets.len()
    )];
    lines.push(format!(
        "Reason: {}",
        display(
            effect["reason"]
                .as_str()
                .ok_or_else(|| Error::engine("invalid approval reason"))?
        )
    ));
    for target in targets {
        let op = &target["operation"];
        let event = op["event_intent"]["kind"]
            .as_str()
            .ok_or_else(|| Error::engine("missing event intent"))?;
        let effect_text=match op["op"].as_str() {
            Some("set_facet")=>format!("set {} to {}; before {}; state {}; one facet.set assertion",op["key"],op["after"],op["before"],if op["state_changed"]==true {"changes"} else {"unchanged"}),
            Some("archive")=>format!("archive {} → true; {}",op["before"],if op["would_append"]==true {"one archive facet.set assertion"} else {"unchanged; zero events"}),
            Some("add_link")=>format!("relates_to {}; {}; {} relationship events; fresh support assertion and attestation",op["target_id"],event,op["event_intent"]["relationship_events"]),
            _=>return Err(Error::engine("unknown approval operation")),
        };
        lines.push(format!(
            "{} ({}, content version {}): {}",
            display(
                target["name"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid approval name"))?
            ),
            display(
                target["record_id"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid approval ID"))?
            ),
            target["previous_seq"],
            display(&effect_text)
        ));
    }
    Ok(lines.join("\n"))
}

async fn link(
    tx: &mut Tx,
    caller: &Caller,
    source: &str,
    source_seq: i64,
    target: &str,
    destination: &Value,
) -> Result<(Value, Value)> {
    if !crate::mcp::tools::links::relationship_owned_in(tx, source, target, "relates_to").await? {
        return Err(denial(
            "relates_to is content-owned for these endpoints; use the public singular route",
        ));
    }
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let source_ref = crate::identity::encode_native_record(&origin, source)?;
    let target_ref = crate::identity::encode_native_record(&origin, target)?;
    let proposition =
        crate::relationship::legacy::proposition_key(&source_ref, &target_ref, "relates_to");
    let row=sqlx::query("SELECT r.relationship_id,r.status,r.relationship_revision,r.relationship_type,r.type_definition_id,r.endpoint_semantics,r.identity_qualifiers,r.reducer_id,r.reducer_version,r.canonical_proposition_key,r.created_event_issuer_origin_db_id,r.created_event_id,e.effective_state,e.epistemic_state,e.assertion_set_digest,e.support_count,e.contest_count FROM relationships r LEFT JOIN effective_relationships e ON e.relationship_origin_db_id=r.relationship_origin_db_id AND e.relationship_id=r.relationship_id WHERE r.relationship_origin_db_id=? AND r.type_definition_id=? AND r.canonical_proposition_key=?")
        .bind(&origin).bind(crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID).bind(&proposition).fetch_optional(&mut **tx).await?;
    let mut existing = Value::Null;
    let mut parents = Vec::new();
    if let Some(row) = row {
        let relationship_id: String = row.try_get("relationship_id")?;
        let status: String = row.try_get("status")?;
        if status != "active" {
            return Err(denial(
                "relationship is retired/unavailable; use manage_relationships",
            ));
        }
        let created_issuer: String = row.try_get("created_event_issuer_origin_db_id")?;
        let created_id: String = row.try_get("created_event_id")?;
        let creation:(String,String,String,String,String,i64)=sqlx::query_as("SELECT type,payload,relationship_origin_db_id,relationship_id,stream_kind,stream_version FROM relationship_events WHERE issuer_origin_db_id=? AND id=?")
            .bind(&created_issuer).bind(&created_id).fetch_one(&mut **tx).await?;
        if creation.2 != origin
            || creation.3 != relationship_id
            || creation.4 != "relationship"
            || creation.5 != 1
        {
            return Err(Error::engine("invalid relationship creation coordinates"));
        }
        let payload = crate::relationship::parse_event_payload(
            &creation.0,
            serde_json::from_str(&creation.1)?,
        )?;
        let crate::relationship::RelationshipEventPayload::RelationshipCreated(created) = payload
        else {
            return Err(Error::engine(
                "relationship creation event is not a creation",
            ));
        };
        let qualifiers: Value =
            serde_json::from_str(&row.try_get::<String, _>("identity_qualifiers")?)?;
        type EndpointRow = (
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let endpoints:Vec<EndpointRow>=sqlx::query_as("SELECT ordinal,role,portable_ref,record_type,record_kind,record_id FROM relationship_endpoints WHERE relationship_origin_db_id=? AND relationship_id=? ORDER BY ordinal")
            .bind(&origin).bind(&relationship_id).fetch_all(&mut **tx).await?;
        let expected_endpoints = created
            .endpoints
            .iter()
            .enumerate()
            .map(|(ordinal, e)| {
                (
                    ordinal as i64,
                    e.role.clone(),
                    e.portable_ref.clone(),
                    e.record_type.clone(),
                    e.record_kind.clone(),
                    e.record_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        if created.type_definition_id != crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID
            || created.relationship_type != "relates_to"
            || created.canonical_proposition_key != proposition
            || created.endpoints.len() != 2
            || created.endpoints[0].portable_ref != source_ref
            || created.endpoints[1].portable_ref != target_ref
            || row.try_get::<i64, _>("relationship_revision")?
                != created.relationship_revision as i64
            || row.try_get::<String, _>("relationship_type")? != created.relationship_type
            || row.try_get::<String, _>("type_definition_id")? != created.type_definition_id
            || row.try_get::<String, _>("endpoint_semantics")? != "directed"
            || row.try_get::<String, _>("reducer_id")? != created.reducer_id
            || row.try_get::<i64, _>("reducer_version")? != created.reducer_version as i64
            || row.try_get::<String, _>("canonical_proposition_key")?
                != created.canonical_proposition_key
            || qualifiers != json!(created.identity_qualifiers)
            || endpoints != expected_endpoints
        {
            return Err(Error::engine(
                "relationship projection disagrees with its sealed creation",
            ));
        }
        let heads=sqlx::query("SELECT issuer_origin_db_id,assertion_id,stream_version,last_event_issuer_origin_db_id,last_event_id FROM relationship_assertion_heads WHERE relationship_origin_db_id=? AND relationship_id=? AND state='active' ORDER BY issuer_origin_db_id,assertion_id")
            .bind(&origin).bind(&relationship_id).fetch_all(&mut **tx).await?;
        for head in heads {
            let version: i64 = head.try_get("stream_version")?;
            if version < 1 {
                return Err(Error::engine("invalid assertion stream version"));
            }
            let parent = crate::relationship::CausalAssertionParent {
                assertion_issuer_origin_db_id: head.try_get("issuer_origin_db_id")?,
                assertion_id: head.try_get("assertion_id")?,
                head_event_issuer_origin_db_id: head.try_get("last_event_issuer_origin_db_id")?,
                head_event_id: head.try_get("last_event_id")?,
                head_stream_version: version as u64,
            };
            crate::relationship::validate_causal_assertion_parent(&parent)?;
            parents.push(serde_json::to_value(parent)?);
        }
        existing = json!({"sealed_creation":created,"endpoints":endpoints,"relationship_id":relationship_id,"status":status,"created_event_issuer_origin_db_id":row.try_get::<String,_>("created_event_issuer_origin_db_id")?,"created_event_id":row.try_get::<String,_>("created_event_id")?,"effective_state":row.try_get::<Option<String>,_>("effective_state")?,"epistemic_state":row.try_get::<Option<String>,_>("epistemic_state")?,"assertion_set_digest":row.try_get::<Option<String>,_>("assertion_set_digest")?,"support_count":row.try_get::<Option<i64>,_>("support_count")?,"contest_count":row.try_get::<Option<i64>,_>("contest_count")?});
    }
    let create = existing.is_null();
    let event = json!({"kind":if create{"create_proposition_and_support"}else{"support_existing"},"relationship_events":if create{2}else{1},"content_events":0,"stance":"support","semantic_claimant":caller.credential(),"actor":caller.actor(),"class":"source_authorised_support","admission_rule":"edit_source_view_target.v1","rationale":"manage_links compatibility add","causal_parents":parents,"fresh_attestation":true});
    let op = json!({"op":"add_link","relationship":"relates_to","route":"directed_legacy_link","source_id":source,"source_previous_seq":source_seq,"target_id":target,"target_previous_seq":destination["previous_seq"],"proposition_key":proposition,"existing":existing,"intent":if create{"would_create_relationship"}else{"would_append_support"},"before":existing,"after":{"intent":event["kind"]},"changed":true,"state_changed":null,"would_append":true,"event_intent":event});
    Ok((
        op,
        json!({"definition":{"id":crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID,"event_schema_version":1,"relationship_revision":1,
        "endpoint_semantics":"directed","endpoint_roles":[{"role":"source","minimum":1,"maximum":1},{"role":"target","minimum":1,"maximum":1}],
        "identity_qualifiers":{"relationship_token":"relates_to"},"reducer_id":crate::relationship::legacy::LEGACY_LINK_REDUCER_ID,"reducer_version":1,
        "sealed_envelope_schema_version":1,"admission_class":crate::relationship::legacy::LEGACY_SUPPORT_CLASS,
        "authority_anchor_role":"source","admission_rule":"edit_source_view_target.v1","note":null},"origin":origin,"source_ref":source_ref,"target_ref":target_ref,"destination":destination,"proposition":proposition,"existing":existing,"causal_parents":parents}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        json!({"selection_contract":CONTRACT,"folder_id":"c0510000-0000-4000-8000-000000000001","statement":"SELECT id FROM children WHERE archived=?1","parameters":[{"type":"boolean","value":null}],"write":{"op":"archive"},"reason":"reason"})
    }
    #[test]
    fn request_retains_parameter_tags_and_rejects_null_version_before_allocation() {
        let r = request();
        parse(r.clone()).unwrap();
        let mut wrong = r.clone();
        wrong["parameters"][0]["type"] = json!("text");
        assert!(parse(wrong).is_err());
        let mut wrong = r.clone();
        wrong["statement"] = json!("SELECT id FROM children WHERE name=?1");
        assert!(parse(wrong).is_err());
        let mut null = r.clone();
        null["expected_version"] = Value::Null;
        assert!(parse(null).is_err());
        let mut excess = r;
        excess["parameters"] = json!(vec![json!({"type":"text","value":"x"}); 257]);
        assert!(parse(excess).is_err());
    }
    #[test]
    fn statement_reason_key_value_and_parameter_exact_bounds() {
        let r = json!({"selection_contract":CONTRACT,"folder_id":"native:test","statement":"SELECT id FROM children","write":{"op":"set_facet","key":"k","value":"v"},"reason":"Reason"});
        {
            let mut v = r.clone();
            v["reason"] = json!("x".repeat(1024));
            parse(v.clone()).unwrap();
            v["reason"] = json!("x".repeat(1025));
            assert!(parse(v).is_err());
        }
        for (key, bound) in [("key", 120), ("value", 1024)] {
            let mut v = r.clone();
            v["write"][key] = json!("x".repeat(bound));
            parse(v.clone()).unwrap();
            v["write"][key] = json!("x".repeat(bound + 1));
            assert!(parse(v).is_err());
        }
        let mut v = r.clone();
        let prefix = "SELECT id FROM children";
        v["statement"] = json!(format!("{prefix}{}", " ".repeat(65536 - prefix.len())));
        parse(v.clone()).unwrap();
        v["statement"] = json!(format!("{prefix}{}", " ".repeat(65537 - prefix.len())));
        assert!(parse(v).is_err());
        let mut v = r.clone();
        v["statement"] = json!(format!(
            "SELECT id FROM children WHERE id IN ({})",
            (1..=256)
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
        v["parameters"] = json!(vec![json!({"type":"text","value":"x"}); 256]);
        parse(v.clone()).unwrap();
        v["parameters"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"text","value":"x"}));
        assert!(parse(v).is_err());
        let mut v = r;
        v["statement"] = json!("SELECT id FROM children WHERE name=?1");
        v["parameters"] = json!([{"type":"boolean","value":null}]);
        assert!(parse(v).is_err());
    }
    #[test]
    fn canonical_ids_preserve_engine_alphabet_and_exact_derived_carrier() {
        for id in [
            "native:root",
            "native:scope:nested.A-1_2",
            &format!("change-summary:carrier:{}", "a".repeat(64)),
            "ec00b000-0000-4000-8000-000000000bd1",
        ] {
            validate_id(id).unwrap();
        }
        for id in [
            "",
            "native:",
            "native:bad\0id",
            "native:bad/child",
            "native:bad child",
            &format!("change-summary:carrier:{}", "A".repeat(64)),
            &format!("change-summary:series:{}", "a".repeat(64)),
        ] {
            assert!(matches!(validate_id(id), Err(Error::Conflict(_))), "{id:?}");
        }
    }
    #[test]
    fn full_approval_escapes_controls_markup_and_keeps_every_target() {
        let targets=(0..25).map(|i|json!({"record_id":format!("target-{i}"),"name":"<script>\n`approve`","previous_seq":i+1,"operation":{"op":"archive","before":true,"after":true,"state_changed":false,"would_append":false,"event_intent":{"kind":"none","content_events":0}}})).collect::<Vec<_>>();
        let summary =
            approval_summary(&json!({"targets":targets,"reason":"reason\nnext"})).unwrap();
        assert_eq!(summary.lines().count(), 27);
        assert!(summary.contains("target-24"));
        assert!(summary.contains("\\<script\\>\\u{000a}\\`approve\\`"));
        assert!(!summary.contains("<script>\n"));
    }
}

#[cfg(test)]
mod snapshot_interleaving_tests {
    use super::*;
    #[tokio::test]
    async fn coherent_snapshot_survives_public_interleaved_facet_and_source_writes() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut r = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut r).unwrap();
        crate::mcp::register_surface_tools(&mut r).unwrap();
        let folder = "ec00b000-0000-4000-8000-000000000be1";
        let a = "ec00b000-0000-4000-8000-000000000be2";
        let b = "ec00b000-0000-4000-8000-000000000be3";
        // Public independent protocol manifest is fixed before compilation.
        for record in [
            json!({"id":folder,"type":"Collection","kind":"folder","name":"Snapshot scope","persistence":"enduring","reason":"Public snapshot scope setup."}),
            json!({"id":a,"type":"Document","kind":"note","name":"Snapshot A","home_id":folder,"facets":{"triage_state":"ready","review_state":"pending"},"reason":"Public snapshot target setup."}),
        ] {
            r.call(db.clone(), Caller::local(), "create_record", record)
                .await
                .unwrap();
        }
        let request = json!({"selection_contract":CONTRACT,"folder_id":folder,"statement":"SELECT id FROM children WHERE current_facet('triage_state')='ready'","write":{"op":"set_facet","key":"review_state","value":"approved"},"reason":"One coherent snapshot despite interleaving."});
        let (req, program) = parse(request.clone()).unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        // Establish precisely the folder read used at normal prepare ingress.
        snapshot::visible(&mut tx, &Caller::local(), folder, &mut Budget::default())
            .await
            .unwrap()
            .unwrap();
        r.call(db.clone(),Caller::local(),"update_record",json!({"id":a,"facets":{"triage_state":"hold","review_state":"different"},"reason":"Interleave current/effect input change."})).await.unwrap();
        r.call(db.clone(),Caller::local(),"create_record",json!({"id":b,"type":"Document","kind":"note","name":"Snapshot B","home_id":folder,"facets":{"triage_state":"ready","review_state":"pending"},"reason":"Interleave source membership change."})).await.unwrap();
        let head: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let old = prepare_in(&mut tx, &Caller::local(), req, program)
            .await
            .unwrap();
        assert_eq!(old.effect["targets"][0]["record_id"], a);
        assert_eq!(old.effect["targets"][0]["before"], "pending");
        assert_eq!(old.operation_evidence["selection"]["candidate_count"], 1);
        tx.rollback().await.unwrap();
        let fresh = prepare(&db, &Caller::local(), request).await.unwrap();
        assert_eq!(fresh.effect["targets"][0]["record_id"], b);
        assert_eq!(fresh.operation_evidence["selection"]["candidate_count"], 2);
        assert_ne!(old.operation_evidence, fresh.operation_evidence);
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(head, after, "both observations are preview-only");
    }
}

//! The shared record-minting kernel for composite write operations.
//!
//! `create_exploration` and `manage_canvas.promote` both mint records inside a
//! transaction the caller owns, under one reserved action attestation, with
//! the same validation: closed spine type, kind resolution and canonical
//! rewrite, home shape and Edit authorization, comment invariants, facet
//! governance, then the `record.created`, `facet.set` and link appends.
//!
//! Extracted rather than copied a third time (decisions note E4). The
//! differences between callers are policy rather than mechanism, and every one
//! of them is passed explicitly, so that extracting this kernel cannot quietly
//! hand one caller another's rules.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::lifecycle::{
    assert_facet_value_predicates_in, assert_home_target_in, facet_set_spec, parse_facet_entry,
    FacetWrite, NewLink,
};
use super::require_record_in;
use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::query::cascade;
use crate::schema::contract::SPINE_TYPES;
use crate::store::{append_in, AppendSpec};

/// The caller's own person record, used as `owner_id` on everything minted.
pub(super) async fn caller_owner_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    tool: &str,
) -> Result<Option<String>> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM bindings
          WHERE system = 'account' AND identifier = ? AND is_canonical = 1
          ORDER BY record_id LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?;
    if owner.is_none() && !super::is_legacy_local(caller) {
        return Err(Error::engine(format!(
            "{tool}: caller has no portable account binding"
        )));
    }
    Ok(owner)
}

/// What a caller wants minted. Borrowed rather than owned so neither caller
/// has to restructure its own argument type to use the kernel.
pub(super) struct MintRequest<'a> {
    pub(super) record_type: &'a str,
    pub(super) kind: &'a str,
    pub(super) name: Option<&'a str>,
    pub(super) body: Option<&'a str>,
    pub(super) summary: Option<&'a str>,
    pub(super) lifecycle: Option<&'a str>,
    pub(super) home_id: Option<&'a str>,
    pub(super) facets: Option<&'a Map<String, Value>>,
    pub(super) links: &'a [NewLink],
}

/// The rules that differ between callers.
pub(super) struct MintPolicy {
    /// Names this tool in every diagnostic the kernel raises.
    pub(super) tool: &'static str,
    /// A `Message` needs delivery semantics that neither composite caller
    /// provides.
    pub(super) refuse_message: bool,
    /// `create_exploration` adds `member_of` itself, so a supplied one would
    /// claim membership of a collection the transaction never authorized.
    /// Promotion has no such implicit link and lets the caller ask for one.
    pub(super) refuse_supplied_member_of: bool,
    /// `create_record` defaults a WorkItem task or epic to `open`;
    /// `create_exploration` does not, and must keep not doing so.
    pub(super) workitem_lifecycle_default: bool,
}

/// Mint one record inside the caller's transaction. Returns its id.
///
/// The caller owns the transaction, has already loaded `schema_rows` and
/// resolved `caller_owner`, and must issue `draft` over every output before
/// committing.
#[allow(clippy::too_many_arguments)]
pub(super) async fn mint_record_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    schema_rows: &[cascade::SchemaConfigRow],
    caller_owner: Option<&str>,
    reason: &str,
    request: &MintRequest<'_>,
    policy: &MintPolicy,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<String> {
    let tool = policy.tool;

    if !SPINE_TYPES.contains(&request.record_type) {
        return Err(Error::engine(format!(
            "{tool}: type '{}' is not a spine type (closed set: {})",
            request.record_type,
            SPINE_TYPES.join(", ")
        )));
    }
    if policy.refuse_message && request.record_type == "Message" {
        return Err(Error::engine(format!(
            "{tool}: a Message record would need delivery semantics; use manage_messages"
        )));
    }
    if request.kind.trim().is_empty() {
        return Err(Error::engine(format!(
            "{tool}: candidate kind must not be empty"
        )));
    }
    crate::freshness::reject_reserved_semantic_unit_kind(request.kind, tool)?;
    let id = crate::domain_transaction::record_id_for_create(None)?;

    let mut fields = Map::new();
    fields.insert("type".into(), json!(request.record_type));
    fields.insert("reason".into(), json!(reason));
    let mut record_kind = request.kind.to_string();
    fields.insert("kind".into(), json!(record_kind));
    for (key, value) in [
        ("name", request.name),
        ("body", request.body),
        ("summary", request.summary),
        ("lifecycle", request.lifecycle),
        ("home_id", request.home_id),
    ] {
        if let Some(value) = value {
            fields.insert(key.into(), json!(value));
        }
    }
    if let Some(owner) = caller_owner {
        fields.insert("owner_id".into(), json!(owner));
    }

    let destination = request.home_id.unwrap_or(crate::schema::ROOT_RECORD_ID);
    if let Some(home_id) = request.home_id {
        assert_home_target_in(tx, tool, home_id).await?;
    }
    require_record_in(tx, caller, tool, destination, Capability::Edit).await?;

    let resolution = crate::meta::kind::resolve_on(tx, request.record_type, &record_kind).await?;
    if !resolution.quarantined
        && resolution.canonical_value_id.as_deref() == Some("vv:voc:kind:Annotation:attribution")
    {
        return Err(Error::engine(format!(
            "{tool}: an attribution candidate must be created with create_attribution"
        )));
    }
    if let Some(canonical) = resolution.canonical_kind_for_write() {
        record_kind = canonical.to_string();
        fields.insert("kind".into(), json!(canonical));
    }

    // `create_record` defaults a WorkItem task or epic to lifecycle "open";
    // `create_exploration` deliberately does not. The choice travels with the
    // caller rather than with this kernel, so extracting it cannot silently
    // give either caller the other's behaviour.
    if policy.workitem_lifecycle_default
        && request.record_type == "WorkItem"
        && matches!(record_kind.as_str(), "task" | "epic")
        && !fields.contains_key("lifecycle")
    {
        fields.insert("lifecycle".into(), json!("open"));
    }

    // A comment candidate must satisfy the ordinary comment invariants: one
    // immutable bearer, flat replies, a root-owned lifecycle. The `member_of`
    // this operation adds is an additional link, which comment governance
    // permits — it constrains the count of `part_of`, not of every link.
    let is_comment = crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution);
    let mut relationship_link_indexes = BTreeSet::new();
    for (index, link) in request.links.iter().enumerate() {
        if policy.refuse_supplied_member_of && link.relationship == "member_of" {
            // Membership is what this operation admits. Accepting a supplied
            // one would let a candidate claim membership of a collection the
            // transaction never validated or authorized.
            return Err(Error::engine(format!(
                "{tool}: candidate member_of links are added by this operation and must not be supplied"
            )));
        }
        require_record_in(tx, caller, tool, &link.target_id, Capability::View).await?;
        let target_type: String =
            sqlx::query_scalar("SELECT type FROM records WHERE id=? AND deleted_at IS NULL")
                .bind(&link.target_id)
                .fetch_one(&mut **tx)
                .await?;
        if crate::relationship::legacy::classify(
            Some(request.record_type),
            Some(&target_type),
            None,
            &link.relationship,
        ) == crate::relationship::legacy::LinkOwnership::Relationship
        {
            relationship_link_indexes.insert(index);
        }
    }
    if is_comment {
        let bearer_ids = request
            .links
            .iter()
            .filter(|link| link.relationship == "part_of")
            .map(|link| link.target_id.clone())
            .collect::<Vec<_>>();
        let position = crate::comments::validate_create_on(
            tx,
            tool,
            &bearer_ids,
            fields.get("body").and_then(Value::as_str),
            fields.get("lifecycle").and_then(Value::as_str),
            fields.get("summary").and_then(Value::as_str),
        )
        .await?;
        if let Some(lifecycle) = crate::comments::created_lifecycle(
            position,
            fields.get("lifecycle").and_then(Value::as_str),
        ) {
            fields.insert("lifecycle".into(), json!(lifecycle));
        }
    }

    let mut facets = Vec::new();
    for (key, value) in request.facets.into_iter().flatten() {
        facets.push(
            parse_facet_entry(tool, key, value, false)?
                .expect("allow_unset=false never yields None"),
        );
    }
    let mut governed_writes = facets.clone();
    if let Some(lifecycle) = fields.get("lifecycle").and_then(Value::as_str) {
        governed_writes.push(FacetWrite {
            key: "lifecycle".into(),
            value: Value::String(lifecycle.into()),
            vocab_ref: None,
        });
    }
    assert_facet_value_predicates_in(
        tx,
        schema_rows,
        tool,
        request.record_type,
        Some(&record_kind),
        None,
        &mut governed_writes,
    )
    .await?;
    for facet in &mut facets {
        facet.vocab_ref = governed_writes
            .iter()
            .find(|checked| checked.key == facet.key)
            .and_then(|checked| checked.vocab_ref.clone());
    }

    append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "record.created".into(),
            payload: Value::Object(fields),
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    for facet in &facets {
        append_in(db, tx, facet_set_spec(&id, facet, caller.actor())).await?;
    }
    for (index, link) in request.links.iter().enumerate() {
        if relationship_link_indexes.contains(&index) {
            // The SAME reserved identity the whole exploration commits under.
            // Reserving a fresh one per link would split one accepted action
            // across several attestations that nothing relates back together.
            crate::relationship::legacy::mutate_from_create_record_in(
                tx,
                caller,
                &id,
                &link.target_id,
                &link.relationship,
                link.note.clone(),
                draft,
            )
            .await?;
        } else {
            append_in(
                db,
                tx,
                AppendSpec {
                    record_id: id.clone(),
                    event_type: "link.added".into(),
                    payload: serde_json::to_value(crate::events::LinkAddedPayload {
                        id: None,
                        source_id: id.clone(),
                        target_id: link.target_id.clone(),
                        relationship: link.relationship.clone(),
                        note: link.note.clone(),
                    })?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;
        }
    }

    Ok(id)
}

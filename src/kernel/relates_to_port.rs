//! Relation host adapter: admission and compatibility for retained relates_to.
use super::commit_port::PROVIDER_OUTCOME_EVENT;
use super::links_v2::{endpoint, retained_bytes, EndpointBinding, EndpointWitness};
use super::provider_catalogue::{self as catalogue, Decoded, StoredState};
use super::*;
use crate::v2_standard::relates_to as provider;

pub const HOST_TRANSFORM_BINDING: &str = "host:relates-to:transform";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub principal_id: String,
    pub operation_key: String,
    pub anchor: EndpointWitness,
    pub counterpart: EndpointWitness,
    pub declaration: Option<serde_json::Value>,
    pub scope_home: String,
    pub selection_head: i64,
    /// Conservative global frontier for authority-affecting kernel transitions.
    pub authority_head: i64,
    pub expected_head: Option<i64>,
    pub aggregate_id: String,
    pub pins: InterpretationPins,
    pub command: provider::Command,
    /// Compatibility wire name: a checksum only, never an authorization binding.
    /// Admission independently rechecks every premise and command.
    pub request_digest: String,
    pub policy_head: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderReceipt {
    pub aggregate_id: String,
    pub assertion_id: String,
    pub event_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outcome {
    pub request: ProviderRequest,
    pub assertion_id: String,
}
pub(crate) fn request_checksum(r: &ProviderRequest) -> Result<String> {
    let mut unsigned = r.clone();
    unsigned.request_digest.clear();
    Ok(crate::meta::definition_artifact::digest_artifact_bytes(
        &serde_json::to_vec(&unsigned)?,
    ))
}
async fn policy_head(conn: &mut SqliteConnection) -> Result<i64> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='policy_events' AND type='table')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !exists {
        return Ok(0);
    }
    Ok(
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM policy_events")
            .fetch_one(conn)
            .await?,
    )
}
// Trusted host provenance is checked against genesis, never a claimed author
// string. The transform identity stamps the sealed v1 link import outcomes.
pub(crate) async fn is_legacy_assertion_on(
    conn: &mut SqliteConnection,
    asserted_by: Option<&str>,
) -> Result<bool> {
    let Some(author) = asserted_by else {
        return Ok(false);
    };
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals p JOIN content_events e ON e.record_id=p.principal_id WHERE p.principal_id=? AND ((p.auth_binding=? AND e.type=?) OR (p.auth_binding=? AND e.type='kernel.host_import_created.v1')) AND e.actor=?)")
        .bind(author).bind(HOST_TRANSFORM_BINDING).bind(HOST_TRANSFORM_CREATED_EVENT)
        .bind(hq::HOST_IMPORT_BINDING).bind(KERNEL_GENESIS_ACTOR)
        .fetch_one(conn).await?)
}

// Internal unredacted read, used only after both endpoints pass visibility.
// Public relations_in deliberately redacts other principals' provenance.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn removable_assertions_on(
    conn: &mut SqliteConnection,
    principal: &str,
    source: &str,
    target: &str,
) -> Result<Vec<String>> {
    if !kernel_effective_capability_on(conn, principal, source)
        .await?
        .allows(Capability::Edit)
        || !kernel_effective_capability_on(conn, principal, target)
            .await?
            .allows(Capability::View)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let states: Vec<String> = sqlx::query_scalar("SELECT state_json FROM kernel_provider_state WHERE provider_key=? AND id IN (SELECT aggregate_id FROM kernel_provider_subjects WHERE subject_id=?)")
        .bind(provider::RELATIONSHIP).bind(source).fetch_all(&mut *conn).await?;
    let mut ids = Vec::new();
    for json in states {
        let stored: StoredState = serde_json::from_str(&json)?;
        let state: provider::State = serde_json::from_value(stored.view()?)?;
        if !((state.left == source && state.right == target)
            || (state.right == source && state.left == target))
        {
            continue;
        }
        for assertion in state.assertions {
            if !assertion.retracted
                && (assertion.asserted_by.as_deref() == Some(principal)
                    || is_legacy_assertion_on(conn, assertion.asserted_by.as_deref()).await?)
            {
                ids.push(assertion.id);
            }
        }
    }
    Ok(ids)
}

async fn command_authority(
    conn: &mut SqliteConnection,
    r: &ProviderRequest,
    current: Option<&provider::State>,
) -> Result<()> {
    match &r.command {
        provider::Command::Assert { sources }
            if sources.iter().any(|s| s.claimed_author.is_some()) =>
        {
            let binding: String = sqlx::query_scalar(
                "SELECT auth_binding FROM kernel_principals WHERE principal_id=?",
            )
            .bind(&r.principal_id)
            .fetch_one(&mut *conn)
            .await?;
            let minted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND actor=?)").bind(&r.principal_id).bind(HOST_TRANSFORM_CREATED_EVENT).bind(KERNEL_GENESIS_ACTOR).fetch_one(&mut *conn).await?;
            if binding != HOST_TRANSFORM_BINDING || !minted {
                return Err(Error::engine(
                    "claimed provenance authors require the designated host transform principal",
                ));
            }
        }
        provider::Command::Retract { assertion_id } => {
            let assertion = current
                .and_then(|s| s.assertions.iter().find(|a| &a.id == assertion_id))
                .ok_or_else(|| Error::engine("unknown relationship assertion"))?;
            if assertion.asserted_by.as_deref() != Some(&r.principal_id)
                && !is_legacy_assertion_on(conn, assertion.asserted_by.as_deref()).await?
                && !kernel_effective_capability_on(conn, &r.principal_id, &r.anchor.record_id)
                    .await?
                    .allows(Capability::Manage)
            {
                return Err(Error::engine(
                    "retraction requires assertion ownership or Manage on the eligible anchor",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn stable_id(domain: &str, parts: &[&str]) -> String {
    format!(
        "{domain}:{}",
        crate::meta::definition_artifact::digest_artifact_bytes(
            &serde_json::to_vec(&(domain, parts)).expect("strings")
        )
    )
}

/// The sealed importer temporarily grants its minted transform Edit on
/// imported policy homes. Those grants admit relation maintenance only; they
/// must never bypass a Message audience in ordinary record/relation reads.
async fn sealed_import_transform(
    conn: &mut SqliteConnection,
    principal: &str,
    anchor: &str,
    other: &str,
) -> Result<bool> {
    let minted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals p JOIN main.content_events e ON e.record_id=p.principal_id WHERE p.principal_id=? AND p.auth_binding=? AND e.type=? AND e.actor=?)")
        .bind(principal).bind(HOST_TRANSFORM_BINDING).bind(HOST_TRANSFORM_CREATED_EVENT).bind(KERNEL_GENESIS_ACTOR)
        .fetch_one(&mut *conn).await?;
    if !minted
        || !(messaging::is_message_record(conn, anchor).await?
            || messaging::is_message_record(conn, other).await?)
    {
        return Ok(false);
    }
    for id in [anchor, other] {
        let home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some(home) = home else { return Ok(false) };
        let policy_root = kernel_policy_anchor_on(conn, &home).await?;
        let scoped: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_policy_entries grant_entry ON grant_entry.root_id=? JOIN main.content_events policy ON policy.seq=(SELECT max(seq) FROM main.content_events WHERE record_id=grant_entry.root_id AND type IN ('kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')) JOIN kernel_principals host ON host.principal_id=policy.actor WHERE r.id=? AND grant_entry.subject_kind='account' AND grant_entry.subject_id=? AND grant_entry.effect='allow' AND grant_entry.capability IN ('edit','manage') AND policy.type='kernel.import_home_policy.v1' AND host.auth_binding=? AND EXISTS(SELECT 1 FROM main.content_events imported WHERE imported.record_id=r.id AND imported.type='kernel.import_state.v1' AND imported.actor=host.principal_id))")
            .bind(&policy_root).bind(id).bind(principal).bind(hq::HOST_IMPORT_BINDING).fetch_one(&mut *conn).await?;
        if !scoped {
            return Ok(false);
        }
    }
    Ok(true)
}
async fn visible(
    conn: &mut SqliteConnection,
    principal: &str,
    anchor: &str,
    other: &str,
) -> Result<()> {
    if sealed_import_transform(conn, principal, anchor, other).await? {
        endpoint(conn, anchor, i64::MAX).await?;
        endpoint(conn, other, i64::MAX).await?;
        return Ok(());
    }
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=?)")
            .bind(principal)
            .fetch_one(&mut *conn)
            .await?;
    if !known
        || !kernel_effective_capability_on(conn, principal, anchor)
            .await?
            .allows(Capability::View)
        || !kernel_effective_capability_on(conn, principal, other)
            .await?
            .allows(Capability::View)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    endpoint(conn, anchor, i64::MAX).await?;
    endpoint(conn, other, i64::MAX).await?;
    Ok(())
}
async fn authority(
    conn: &mut SqliteConnection,
    principal: &str,
    anchor: &str,
    other: &str,
) -> Result<()> {
    if sealed_import_transform(conn, principal, anchor, other).await? {
        return Ok(());
    }
    visible(conn, principal, anchor, other).await?;
    if !kernel_effective_capability_on(conn, principal, anchor)
        .await?
        .allows(Capability::Edit)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}
async fn declaration(
    conn: &mut SqliteConnection,
    anchor: &EndpointWitness,
    other: &EndpointWitness,
) -> Result<Option<serde_json::Value>> {
    let Some(bytes) = retained_bytes(conn, &anchor.binding).await? else {
        return Ok(None);
    };
    let EndpointBinding::Bound { kind, .. } = &anchor.binding else {
        unreachable!()
    };
    let doc: serde_json::Value = serde_json::from_str(&bytes)?;
    let links = doc["kinds"]
        .as_array()
        .and_then(|k| k.iter().find(|k| k["token"].as_str() == Some(kind)))
        .and_then(|k| k["links"].as_array())
        .ok_or_else(|| Error::engine("anchor does not declare relationship"))?;
    for link in links {
        if link["relationship_ref"] == provider::relationship_ref()
            && links_v2::matches_target(&link["target"], &other.binding)?
            && link["direction"] == "either"
        {
            return Ok(Some(link.clone()));
        }
    }
    Err(Error::engine("anchor does not declare relationship"))
}
async fn state(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<(Option<i64>, Option<provider::State>)> {
    let row: Option<(i64, String, String)> =
        sqlx::query_as("SELECT head,state_json,subjects_json FROM kernel_provider_state WHERE id=? AND provider_key=?")
            .bind(id)
            .bind(provider::RELATIONSHIP)
            .fetch_optional(&mut *conn)
            .await?;
    match row {
        Some((h, s, subjects)) => {
            let stored: StoredState = serde_json::from_str(&s)?;
            let state: provider::State = serde_json::from_value(stored.view()?)?;
            if serde_json::from_str::<Vec<String>>(&subjects)?
                != vec![state.left.clone(), state.right.clone()]
            {
                return Err(Error::engine("provider state subject mismatch"));
            }
            Ok((Some(h), Some(state)))
        }
        None => Ok((None, None)),
    }
}
async fn authority_head(conn: &mut SqliteConnection, before: i64) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE seq < ? AND type IN ('kernel.home_created.v1','kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_state_delta.v1','kernel.import_removed.v1','kernel.home_created_for.v1','kernel.home_policy_replaced.v1','kernel.import_home_policy.v1','kernel.hosted_offboarding.v1','kernel.hosted_membership.v1','kernel.import_member_policy.v1','kernel.root_admin_bootstrapped.v1','kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.principal_created.v1','kernel.host_transform_created.v1')")
        .bind(before).fetch_one(&mut *conn).await?)
}
async fn active(conn: &mut SqliteConnection, home: &str) -> Result<StoredPackageSelection> {
    let (selection, manifest) =
        require_package_active_in(conn, home, provider::NAMESPACE, provider::PACKAGE).await?;
    if manifest != provider::package() {
        return Err(Error::engine("unsupported relationship provider"));
    }
    Ok(selection)
}
async fn retry(
    conn: &mut SqliteConnection,
    principal: &str,
    key: &str,
) -> Result<Option<(ProviderRequest, ProviderReceipt)>> {
    let row: Option<(String,String,i64)> = sqlx::query_as("SELECT request_json,assertion_id,event_seq FROM kernel_provider_receipts WHERE principal_id=? AND operation=? AND operation_key=?").bind(principal).bind(provider::RELATIONSHIP).bind(key).fetch_optional(&mut *conn).await?;
    let Some((json, assertion_id, seq)) = row else {
        return Ok(None);
    };
    let request: ProviderRequest = serde_json::from_str(&json)?;
    let row: Option<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT record_id,actor,payload FROM content_events WHERE seq=? AND type=?")
            .bind(seq)
            .bind(PROVIDER_OUTCOME_EVENT)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((record, actor, payload)) = row else {
        return Err(Error::engine("provider receipt/log mismatch"));
    };
    let payload: serde_json::Value = serde_json::from_str(payload.as_deref().unwrap_or_default())?;
    let (logged_request, logged_assertion, legacy) = decode_request(&payload)?;
    if request.principal_id != principal
        || request.operation_key != key
        || &record
            != if legacy {
                &request.anchor.record_id
            } else {
                &request.aggregate_id
            }
        || actor.as_deref() != Some(principal)
        || logged_request != request
        || logged_assertion != assertion_id
    {
        return Err(Error::engine("provider receipt/log mismatch"));
    }
    let retained_assertion = if legacy {
        match &request.command {
            provider::Command::Retract { assertion_id } => assertion_id,
            _ => &assertion_id,
        }
    } else {
        &assertion_id
    };
    let (head, current) = state(conn, &request.aggregate_id).await?;
    if head.is_none_or(|h| h < seq)
        || !current.is_some_and(|s| s.assertions.iter().any(|a| &a.id == retained_assertion))
    {
        return Err(Error::engine("provider receipt/state mismatch"));
    }
    Ok(Some((
        request.clone(),
        ProviderReceipt {
            aggregate_id: request.aggregate_id,
            assertion_id,
            event_seq: seq,
        },
    )))
}

/// read_visible and prepare: all mutable premises are captured in one snapshot.
pub async fn prepare_provider_as(
    db: &Db,
    principal: &str,
    anchor: &str,
    counterpart: &str,
    key: &str,
    command: provider::Command,
) -> Result<ProviderRequest> {
    let mut tx = db.write_pool().begin().await?;
    let request =
        prepare_provider_on(&mut tx, principal, anchor, counterpart, key, command).await?;
    tx.rollback().await?;
    Ok(request)
}

/// Compose a provider operation with record writes in the caller's transaction.
pub(crate) async fn prepare_provider_on(
    conn: &mut SqliteConnection,
    principal: &str,
    anchor: &str,
    counterpart: &str,
    key: &str,
    command: provider::Command,
) -> Result<ProviderRequest> {
    visible(conn, principal, anchor, counterpart).await?;
    if let Some((request, _)) = retry(conn, principal, key).await? {
        if request.anchor.record_id != anchor
            || request.counterpart.record_id != counterpart
            || request.command != command
        {
            return Err(Error::conflict("provider retry key reused"));
        }
        return Ok(request);
    }
    authority(conn, principal, anchor, counterpart).await?;
    let anchor = endpoint(conn, anchor, i64::MAX).await?;
    let counterpart = endpoint(conn, counterpart, i64::MAX).await?;
    let declaration = declaration(conn, &anchor, &counterpart).await?;
    retained_bytes(conn, &counterpart.binding).await?;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&anchor.record_id)
        .fetch_one(&mut *conn)
        .await?;
    let selection = active(conn, &home).await?;
    let (left, right) = provider::pair(&anchor.record_id, &counterpart.record_id)?;
    let aggregate_id = stable_id("relation", &[provider::RELATIONSHIP, left, right]);
    let (expected_head, current) = state(conn, &aggregate_id).await?;
    let mut request = ProviderRequest {
        principal_id: principal.into(),
        operation_key: key.into(),
        anchor,
        counterpart,
        declaration,
        scope_home: home,
        selection_head: selection.event_seq,
        authority_head: authority_head(conn, i64::MAX).await?,
        expected_head,
        aggregate_id,
        pins: provider::pins(),
        command,
        request_digest: String::new(),
        policy_head: policy_head(conn).await?,
    };
    request.request_digest = request_checksum(&request)?;
    command_authority(conn, &request, current.as_ref()).await?;
    let (left, right) = provider::pair(&request.anchor.record_id, &request.counterpart.record_id)?;
    // Validation uses a discarded host stamp; no attribution or folded state escapes.
    provider::fold(
        &request.command,
        left,
        right,
        "validation",
        current.as_ref(),
        &provider::HostStamp {
            principal: principal.into(),
            timestamp: String::new(),
            event_seq: 0,
        },
    )?;
    validate(conn, &request, i64::MAX, false).await?;
    Ok(request)
}
async fn validate(
    conn: &mut SqliteConnection,
    r: &ProviderRequest,
    before: i64,
    legacy: bool,
) -> Result<()> {
    if r.operation_key.trim().is_empty()
        || r.operation_key.len() > 256
        || r.request_digest != request_checksum(r)?
    {
        return Err(Error::engine("provider request checksum mismatch"));
    }
    provider::interpreter(&r.pins)?;
    if authority_head(conn, before).await? != r.authority_head {
        return Err(Error::conflict("provider authority frontier moved"));
    }
    // Selection is a retained historical witness, not today's live permission.
    let selection = resolve_effective_package_selection_before(
        conn,
        &r.scope_home,
        provider::NAMESPACE,
        provider::PACKAGE,
        before,
    )
    .await?
    .ok_or_else(|| Error::engine("missing provider selection witness"))?;
    if selection.event_seq != r.selection_head
        || selection.selected.as_ref() != Some(&r.pins.package)
        || selection.event_seq >= before
    {
        return Err(Error::conflict("provider selection witness mismatch"));
    }
    // Verify the retained package closure independently of live activation.
    let stored = crate::meta::package::read_package_in(
        conn,
        &r.pins.package.namespace,
        &r.pins.package.name,
        r.pins.package.version,
        &r.pins.package.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("missing retained provider package"))?;
    if stored.manifest != provider::retained_package(&r.pins)? {
        return Err(Error::engine("retained provider package mismatch"));
    }
    if endpoint_at(conn, &r.anchor.record_id, before, legacy).await? != r.anchor
        || endpoint_at(conn, &r.counterpart.record_id, before, legacy).await? != r.counterpart
    {
        return Err(Error::conflict("provider endpoint or binding head moved"));
    }
    retained_bytes(conn, &r.counterpart.binding).await?;
    if declaration(conn, &r.anchor, &r.counterpart).await? != r.declaration {
        return Err(Error::engine("provider declaration mismatch"));
    }
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&r.anchor.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if home != r.scope_home {
        return Err(Error::conflict("provider anchor scope moved"));
    }
    let (left, right) = provider::pair(&r.anchor.record_id, &r.counterpart.record_id)?;
    if r.aggregate_id != stable_id("relation", &[provider::RELATIONSHIP, left, right]) {
        return Err(Error::engine("provider stable identity mismatch"));
    }
    let (head, _) = state(conn, &r.aggregate_id).await?;
    if head != r.expected_head {
        return Err(Error::conflict("provider aggregate head moved"));
    }

    Ok(())
}
fn assertion_envelope(outcome: &Outcome) -> Result<()> {
    match &outcome.request.command {
        provider::Command::Assert { .. } => {
            let id = Uuid::parse_str(&outcome.assertion_id)
                .map_err(|_| Error::engine("provider assertion ID must be a host UUID"))?;
            if id.get_version_num() != 4 || id.to_string() != outcome.assertion_id {
                return Err(Error::engine("provider assertion ID must be a host UUID"));
            }
        }
        provider::Command::Retract { assertion_id } => {
            // Retractions can target IDs minted by a retained interpreter, too.
            if assertion_id != &outcome.assertion_id {
                return Err(Error::engine("provider retraction assertion mismatch"));
            }
        }
    }
    Ok(())
}
async fn live(conn: &mut SqliteConnection, r: &ProviderRequest) -> Result<()> {
    if r.pins != provider::pins() {
        return Err(Error::engine(
            "live admission requires current provider interpretation pins",
        ));
    }
    if policy_head(conn).await? != r.policy_head {
        return Err(Error::conflict("provider policy frontier moved"));
    }
    authority(
        conn,
        &r.principal_id,
        &r.anchor.record_id,
        &r.counterpart.record_id,
    )
    .await?;
    let selection = active(conn, &r.scope_home).await?;
    if selection.event_seq != r.selection_head
        || selection.selected.as_ref() != Some(&r.pins.package)
    {
        return Err(Error::conflict("provider selection head moved"));
    }
    let (_, current) = state(conn, &r.aggregate_id).await?;
    command_authority(conn, r, current.as_ref()).await?;
    Ok(())
}
pub async fn commit_provider_as(
    db: &Db,
    principal: &str,
    r: &ProviderRequest,
) -> Result<ProviderReceipt> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let receipt = commit_provider_in(db, &mut tx, &mut acts, principal, r).await?;
    tx.commit().await?;
    Ok(receipt)
}

pub(crate) async fn commit_provider_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    r: &ProviderRequest,
) -> Result<ProviderReceipt> {
    visible(tx, principal, &r.anchor.record_id, &r.counterpart.record_id).await?;
    if principal != r.principal_id {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if let Some((old, receipt)) = retry(tx, principal, &r.operation_key).await? {
        if old != *r {
            return Err(Error::conflict("provider retry key reused"));
        }
        return Ok(receipt);
    }
    live(tx, r).await?;
    validate(tx, r, i64::MAX, false).await?;
    let assertion_id = match &r.command {
        provider::Command::Assert { .. } => Uuid::new_v4().to_string(),
        provider::Command::Retract { assertion_id } => assertion_id.clone(),
    };
    let outcome = Outcome {
        request: r.clone(),
        assertion_id: assertion_id.clone(),
    };
    let event = crate::store::append_kernel_provider_in(
        db,
        tx,
        AppendSpec {
            record_id: r.aggregate_id.clone(),
            event_type: PROVIDER_OUTCOME_EVENT.into(),
            payload: serde_json::to_value(&outcome)?,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    Ok(ProviderReceipt {
        aggregate_id: r.aggregate_id.clone(),
        assertion_id,
        event_seq: event.local_seq,
    })
}
pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != PROVIDER_OUTCOME_EVENT {
        return Ok(());
    }
    let outcome: Outcome = event_payload(event)?;
    envelope(event, &outcome.request)?;
    assertion_envelope(&outcome)?;
    live(conn, &outcome.request).await?;
    validate(conn, &outcome.request, i64::MAX, false).await
}
fn envelope(event: &EventRow, r: &ProviderRequest) -> Result<()> {
    if event.record_id != r.aggregate_id || event.actor.as_deref() != Some(&r.principal_id) {
        return Err(Error::engine("provider actor or aggregate mismatch"));
    }
    Ok(())
}
pub(crate) fn validate_recorded<'a>(
    conn: &'a mut SqliteConnection,
    event: &'a EventRow,
    decoded: &'a Decoded,
    replay: bool,
) -> catalogue::ValidationFuture<'a> {
    Box::pin(async move {
        let domain = provider::retained::relation_decoded(decoded)?;
        let r = provider::retained::host_request(&domain)?;
        if domain.legacy {
            if domain.assertion_id
                != stable_id(
                    "assertion",
                    &[provider::RELATIONSHIP, &r.principal_id, &r.operation_key],
                )
            {
                return Err(Error::engine("retained provider stable identity mismatch"));
            }
        } else {
            assertion_envelope(&Outcome {
                request: r.clone(),
                assertion_id: domain.assertion_id.clone(),
            })?;
        }
        if !replay {
            live(conn, &r).await?;
        }
        validate(conn, &r, event.local_seq, domain.legacy).await
    })
}

async fn endpoint_at(
    conn: &mut SqliteConnection,
    id: &str,
    before: i64,
    legacy: bool,
) -> Result<EndpointWitness> {
    let mut witness = endpoint(conn, id, before).await?;
    if legacy {
        witness.head = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=? AND seq<?",
        )
        .bind(id)
        .bind(before)
        .fetch_one(conn)
        .await?;
    }
    Ok(witness)
}
fn decode_request(payload: &serde_json::Value) -> Result<(ProviderRequest, String, bool)> {
    let entry = catalogue::recorded(payload)?;
    let decoded = (entry.decode)(payload)?;
    let domain = provider::retained::relation_decoded(&decoded)?;
    Ok((
        provider::retained::host_request(&domain)?,
        domain.assertion_id,
        domain.legacy,
    ))
}
/// Decode a retained provider through the same versioned interpreter as
/// ordinary reads. Bulk SQL has already fenced all subjects before calling.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) fn active_pair_from_state(json: &str) -> Result<Option<(String, String)>> {
    let stored: StoredState = serde_json::from_str(json)?;
    let state: provider::State = serde_json::from_value(stored.view()?)?;
    Ok(state.active().then_some((state.left, state.right)))
}

pub(crate) async fn active_links_in(
    conn: &mut SqliteConnection,
    principal: &str,
    source: &str,
) -> Result<Vec<(String, String)>> {
    let mut links = Vec::new();
    for relation in relations_in(conn, principal, source).await? {
        let state: provider::State = serde_json::from_value(relation["state"].clone())?;
        if state.active() {
            let other = if state.left == source {
                state.right
            } else {
                state.left
            };
            links.push((other, provider::RELATIONSHIP.into()));
        }
    }
    Ok(links)
}

pub async fn relations_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<Vec<serde_json::Value>> {
    let mut tx = db.write_pool().begin().await?;
    relations_in(&mut tx, principal, record).await
}
pub(crate) async fn relations_in(
    tx: &mut SqliteConnection,
    principal: &str,
    record: &str,
) -> Result<Vec<serde_json::Value>> {
    if !kernel_effective_capability_on(tx, principal, record)
        .await?
        .allows(Capability::View)
    {
        return Ok(vec![]);
    }
    let rows: Vec<(String, String, i64)> = sqlx::query_as("SELECT id,state_json,head FROM kernel_provider_state WHERE provider_key=? AND id IN (SELECT aggregate_id FROM kernel_provider_subjects WHERE subject_id=?) ORDER BY id")
        .bind(provider::RELATIONSHIP).bind(record).fetch_all(&mut *tx).await?;
    let root_visible = kernel_effective_capability_on(tx, principal, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View);
    let mut out = vec![];
    for (id, json, head) in rows {
        let stored: StoredState = serde_json::from_str(&json)?;
        let mut state: provider::State = serde_json::from_value(stored.view()?)?;
        if state.left != record && state.right != record {
            continue;
        }
        let other = if state.left == record {
            &state.right
        } else {
            &state.left
        };
        if !kernel_effective_capability_on(tx, principal, other)
            .await?
            .allows(Capability::View)
        {
            continue;
        }
        // Semantic source authors are provenance, independently redacted by the host.
        if !root_visible {
            for a in &mut state.assertions {
                if a.asserted_by.as_deref() != Some(principal) {
                    a.asserted_by = None;
                }
                if a.retracted_by.as_deref() != Some(principal) {
                    a.retracted_by = None;
                }
                for s in &mut a.sources {
                    if s.claimed_author.as_deref() != Some(principal) {
                        s.claimed_author = None;
                    }
                }
            }
        }
        out.push(serde_json::json!({"id":id,"head":head,"state":state}));
    }
    Ok(out)
}
pub(super) fn contract() -> serde_json::Value {
    serde_json::json!({"relationship_ref":provider::relationship_ref(),"pins":provider::pins(),"semantics":"one symmetric relation per unordered pair; assertions retain distinct provenance; retraction references assertion ID", "authority":"View both endpoints plus Edit on chosen eligible anchor; bound anchors opt in through relationship_ref; bare anchors use the selected relationship contract", "port":"prepare_provider_as(read_visible snapshot, pure prepare, request checksum); commit_provider_as rechecks endpoint/binding/aggregate/selection heads and conservative authority frontier and authority atomically; checksum is not an authorization binding; every premise is independently rechecked at commit; principal-scoped operation_key retries return stable receipt after current visibility checks", "provider":"storage-free semantic implementation; no credentials, writable handle, authority or effects", "dispatch":"generic directed relates_to writes refuse while the relationship is selected; retained legacy events keep original dispatch", "retraction":"own or genesis-minted v1 host assertions require Edit; other assertions require Manage on the eligible anchor; MCP manage_links removes only own or v1 host assertions", "provenance":"asserted_by/asserted_at/asserted_seq are host stamped; claimed_author/claimed_timestamp are untrusted legacy provenance; claimed authors require the kernel-minted host:relates-to:transform; claimed_timestamp is optional without a claimed author", "retention":"recorded pins dispatch through immutable versioned interpreters; unknown pins refuse", "authority_frontier":"conservative content authority frontier plus policy_events frontier in live admission; gated v2 currently has no policy_events table", "disable":"stops new admission; retained pinned outcomes replay; retractions need active selection", "harness":{"prepare":"relation-prepare --anchor <eligible id> --counterpart <visible id> --operation-key <retry key> --json <command file>","commit":"relation-commit --json <unchanged request file>","read":"relations --id <either endpoint>","discovery":"describe --record <anchor>"}, "api":{"prepare":"prepare_provider_as(db, principal, anchor, counterpart, operation_key, Command)","commit":"commit_provider_as(db, principal, unchanged request)","read":"relations_as(db, principal, either endpoint)","assert":{"Assert":{"sources":[]}},"retract":{"Retract":{"assertion_id":"<stable assertion ID>"}}}})
}

pub(super) async fn describe_record_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<serde_json::Value> {
    let mut tx = db.write_pool().begin().await?;
    kernel_require(&mut tx, principal, record, Capability::View).await?;
    let witness = endpoint(&mut tx, record, i64::MAX).await?;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(record)
        .fetch_one(&mut *tx)
        .await?;
    let available = active(&mut tx, &home).await.is_ok();
    let eligible = match &witness.binding {
        EndpointBinding::Bare => true,
        EndpointBinding::Bound { kind, .. } => {
            let bytes = retained_bytes(&mut tx, &witness.binding)
                .await?
                .ok_or_else(|| Error::engine("missing bound definition bytes"))?;
            let doc: serde_json::Value = serde_json::from_str(&bytes)?;
            doc["kinds"]
                .as_array()
                .and_then(|k| k.iter().find(|k| k["token"].as_str() == Some(kind)))
                .and_then(|k| k["links"].as_array())
                .is_some_and(|links| {
                    links
                        .iter()
                        .any(|l| l["relationship_ref"] == provider::relationship_ref())
                })
        }
    };
    let editable = kernel_effective_capability_on(&mut tx, principal, record)
        .await?
        .allows(Capability::Edit);
    Ok(
        serde_json::json!({"contract":contract(),"available":available,"eligible_anchor":eligible,"can_assert":available && eligible && editable,"availability":"advisory; selected provider, current guards and all heads rechecked at commit"}),
    )
}

pub(crate) fn admit_recorded<'a>(
    conn: &'a mut SqliteConnection,
    event: &'a EventRow,
) -> catalogue::ValidationFuture<'a> {
    Box::pin(admit(conn, event))
}

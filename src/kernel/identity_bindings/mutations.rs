//! Event-owned external binding removal/transfer; never changes kernel principals.
use super::*;

pub(crate) const REMOVED_EVENT: &str = "kernel.identity_binding_removed.v1";
pub(crate) const RECONCILED_EVENT: &str = "kernel.identity_bindings_reconciled.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Removal {
    pub record_id: String,
    pub binding: BindingClaim,
    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reconciliation {
    pub target_record_id: String,
    pub expected_source_record_id: String,
    pub bindings: Vec<BindingClaim>,
    pub reason: String,
}

pub(crate) async fn require_revision_on(
    conn: &mut SqliteConnection,
    records: &[&str],
    expected: Option<&str>,
) -> Result<()> {
    if let Some(expected) = expected {
        let current = revision_for_on(conn, records).await?;
        if current != expected {
            return Err(Error::engine(format!(
                "binding state revision conflict: expected {expected}, current {current}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn canonicalize_on(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    binding: &BindingClaim,
    expected: Option<&str>,
) -> Result<binding_plan::CanonicalizeBindingPlan> {
    kernel_require_on(conn, actor, record, Capability::Manage).await?;
    let claim = claim_on(conn, record, binding).await?;
    require_revision_on(conn, &[record], expected).await?;
    let canonical: Option<bool> = sqlx::query_scalar("SELECT is_canonical FROM kernel_identity_bindings WHERE record_id=? AND system=? AND identifier=?")
        .bind(record).bind(&claim.system).bind(&claim.identifier).fetch_optional(&mut *conn).await?;
    let previous = sqlx::query_scalar("SELECT identifier FROM kernel_identity_bindings WHERE record_id=? AND system=? AND is_canonical=1")
        .bind(record).bind(&claim.system).fetch_optional(&mut *conn).await?;
    binding_plan::plan_canonicalize(record, claim, canonical, previous)
        .map_err(|e| Error::engine(e.to_string()))
}

pub(crate) async fn remove_on(
    conn: &mut SqliteConnection,
    actor: Option<&str>,
    removal: &Removal,
    expected: Option<&str>,
) -> Result<binding_plan::RemoveBindingPlan> {
    if removal.reason.trim().is_empty() {
        return Err(Error::engine("manage_bindings: reason must be nonblank"));
    }
    if let Some(actor) = actor {
        kernel_require_on(conn, actor, &removal.record_id, Capability::Manage).await?;
    }
    let claim = claim_on(conn, &removal.record_id, &removal.binding).await?;
    require_revision_on(conn, &[&removal.record_id], expected).await?;
    let canonical: Option<bool> = sqlx::query_scalar("SELECT is_canonical FROM kernel_identity_bindings WHERE record_id=? AND system=? AND identifier=?")
        .bind(&removal.record_id).bind(&claim.system).bind(&claim.identifier).fetch_optional(&mut *conn).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel_identity_bindings WHERE record_id=? AND system=?",
    )
    .bind(&removal.record_id)
    .bind(&claim.system)
    .fetch_one(conn)
    .await?;
    // Both supported public systems are built-in required durable identities.
    binding_plan::plan_remove(&removal.record_id, claim, canonical, true, count)
        .map_err(|e| Error::engine(e.to_string()))
}

pub(crate) async fn reconcile_on(
    conn: &mut SqliteConnection,
    actor: Option<&str>,
    reconciliation: &Reconciliation,
    expected: Option<&str>,
) -> Result<binding_plan::ReconcileBindingPlan> {
    let source = &reconciliation.expected_source_record_id;
    let target = &reconciliation.target_record_id;
    if reconciliation.bindings.is_empty() {
        return Err(Error::engine(
            "reconcile requires at least one selected binding",
        ));
    }
    if source == target {
        return Err(Error::engine(
            "reconcile target and expected source records must be different",
        ));
    }
    if let Some(actor) = actor {
        kernel_require_on(conn, actor, target, Capability::Manage).await?;
        kernel_require_on(conn, actor, source, Capability::Manage).await?;
    }
    let mut seen = std::collections::HashSet::new();
    let mut facts = Vec::new();
    for binding in &reconciliation.bindings {
        let claim = claim_on(conn, target, binding).await?;
        if !seen.insert((claim.system.clone(), claim.identifier.clone())) {
            return Err(Error::engine("reconcile selected duplicate binding"));
        }
        let owner: Option<(String,bool)> = sqlx::query_as("SELECT record_id,is_canonical FROM kernel_identity_bindings WHERE system=? AND identifier=?")
            .bind(&claim.system).bind(&claim.identifier).fetch_optional(&mut *conn).await?;
        if let (Some(actor), Some((owner, _))) = (actor, &owner) {
            if owner != source && !matches!(read_record_on(conn, actor, owner).await, Ok(Some(_))) {
                return Err(Error::engine(
                    "binding_not_visible: the external identity is not visible to this caller",
                ));
            }
        }
        let fact = binding_plan::ReconcileBindingFact {
            claim,
            owner_record_id: owner.as_ref().map(|(id, _)| id.clone()),
            canonical: owner.is_some_and(|(_, canonical)| canonical),
            target_canonical_identifier: None,
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
        };
        binding_plan::validate_reconcile_owners(source, std::slice::from_ref(&fact))
            .map_err(|e| Error::engine(e.to_string()))?;
        facts.push(fact);
    }
    require_revision_on(conn, &[source, target], expected).await?;
    for fact in &mut facts {
        if fact.canonical {
            fact.target_canonical_identifier = sqlx::query_scalar("SELECT identifier FROM kernel_identity_bindings WHERE record_id=? AND system=? AND is_canonical=1")
                .bind(target).bind(&fact.claim.system).fetch_optional(&mut *conn).await?;
        }
    }
    binding_plan::plan_reconcile(target, source, facts).map_err(|e| Error::engine(e.to_string()))
}

fn root_event(event: &EventRow) -> Result<()> {
    if event.record_id != crate::events::KERNEL_ROOT_ID {
        return Err(Error::engine(
            "binding audit requires the kernel root stream",
        ));
    }
    Ok(())
}

pub(super) async fn admit_mutation(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    match event.event_type.as_str() {
        REMOVED_EVENT => {
            root_event(event)?;
            remove_on(
                conn,
                Some(event.actor.as_deref().unwrap_or_default()),
                &event_payload(event)?,
                None,
            )
            .await?;
        }
        RECONCILED_EVENT => {
            root_event(event)?;
            let value: Reconciliation = event_payload(event)?;
            if value.reason.trim().is_empty() {
                return Err(Error::engine("manage_bindings: reason must be nonblank"));
            }
            reconcile_on(
                conn,
                Some(event.actor.as_deref().unwrap_or_default()),
                &value,
                None,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) async fn project_mutation(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    root_event(event)?;
    match event.event_type.as_str() {
        REMOVED_EVENT => {
            let value: Removal = event_payload(event)?;
            let plan = remove_on(conn, None, &value, None).await?;
            if value.binding != plan.claim || !plan.changed {
                return Err(Error::engine(
                    "binding removal must be normalized and change its state",
                ));
            }
            sqlx::query("DELETE FROM kernel_identity_bindings WHERE record_id=? AND system=? AND identifier=?")
                .bind(&value.record_id).bind(&plan.claim.system).bind(&plan.claim.identifier).execute(conn).await?;
        }
        RECONCILED_EVENT => {
            let value: Reconciliation = event_payload(event)?;
            if value.reason.trim().is_empty() {
                return Err(Error::engine("manage_bindings: reason must be nonblank"));
            }
            let plan = reconcile_on(conn, None, &value, None).await?;
            if value.bindings
                != plan
                    .bindings
                    .iter()
                    .map(|f| f.claim.clone())
                    .collect::<Vec<_>>()
            {
                return Err(Error::engine("binding transfer must be normalized"));
            }
            for fact in plan.bindings {
                sqlx::query("UPDATE kernel_identity_bindings SET record_id=?,event_seq=? WHERE system=? AND identifier=? AND record_id=?")
                    .bind(&value.target_record_id).bind(event.local_seq).bind(&fact.claim.system).bind(&fact.claim.identifier).bind(&value.expected_source_record_id).execute(&mut *conn).await?;
            }
        }
        _ => return Err(Error::engine("unknown binding event")),
    }
    Ok(())
}

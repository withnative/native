//! Public external identities. Kernel principals are a separate identity domain.
use super::*;
use crate::identity::{binding_plan, BindingClaim};
use serde_json::json;
#[cfg(feature = "v2-kernel-probe")]
use serde_json::Value;

mod mutations;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use mutations::{
    canonicalize_on, reconcile_on, remove_on, Reconciliation, Removal, RECONCILED_EVENT,
    REMOVED_EVENT,
};

pub(crate) const EVENT: &str = "kernel.identity_binding_added.v1";
pub(crate) const DDL: &str = "CREATE TABLE kernel_identity_bindings (
 system TEXT NOT NULL CHECK(system IN ('native-principal','native-record')),
 identifier TEXT NOT NULL, record_id TEXT NOT NULL REFERENCES kernel_records(id),
 is_canonical INTEGER NOT NULL CHECK(is_canonical IN (0,1)), event_seq INTEGER NOT NULL,
 PRIMARY KEY(system,identifier))";
pub(crate) const CANONICAL_INDEX: &str = "CREATE UNIQUE INDEX idx_kernel_identity_canonical ON kernel_identity_bindings(record_id,system) WHERE is_canonical=1";

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [DDL, CANONICAL_INDEX] {
        let ddl = ddl
            .replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
            .replacen(
                "CREATE UNIQUE INDEX",
                "CREATE UNIQUE INDEX IF NOT EXISTS",
                1,
            );
        sqlx::query(&ddl).execute(&mut *conn).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Addition {
    pub record_id: String,
    pub binding: BindingClaim,
    pub canonical: bool,
    pub reason: String,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn list_on(conn: &mut SqliteConnection, record: &str) -> Result<Vec<Value>> {
    let rows: Vec<(String,String,bool)> = sqlx::query_as("SELECT system,identifier,is_canonical FROM kernel_identity_bindings WHERE record_id=? ORDER BY system,is_canonical DESC,identifier")
        .bind(record).fetch_all(conn).await?;
    Ok(rows
        .into_iter()
        .map(|(system, identifier, canonical)| {
            json!({
                "system":system,"identifier":identifier,"is_canonical":canonical,
                "url":null,"etag":null,"last_seen_at":null,
            })
        })
        .collect())
}

/// Opaque CAS over canonical event IDs for binding audit and subject content.
/// A token from the v1 engine cannot authorize a write against a v2 snapshot.
pub(crate) async fn revision_on(conn: &mut SqliteConnection, record: &str) -> Result<String> {
    revision_for_on(conn, &[record]).await
}

pub(crate) async fn revision_for_on(
    conn: &mut SqliteConnection,
    records: &[&str],
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let audit: Option<String> = sqlx::query_scalar("SELECT id FROM main.content_events WHERE type IN ('kernel.identity_binding_added.v1','kernel.identity_binding_removed.v1','kernel.identity_bindings_reconciled.v1') ORDER BY seq DESC LIMIT 1")
        .fetch_optional(&mut *conn).await?;
    let mut records = records.to_vec();
    records.sort_unstable();
    records.dedup();
    let mut heads = Vec::new();
    for record in records {
        let head: Option<String> = sqlx::query_scalar(
            "SELECT id FROM main.content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(record)
        .fetch_optional(&mut *conn)
        .await?;
        heads.push((record, head));
    }
    Ok(format!(
        "ibsv2:{}",
        hex::encode(Sha256::digest(serde_jcs::to_vec(
            &json!({"records":heads,"binding_audit_id":audit})
        )?))
    ))
}

pub(crate) async fn plan_on(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    addition: &Addition,
    expected_revision: Option<&str>,
) -> Result<binding_plan::AddBindingPlan> {
    kernel_require_on(conn, actor, record, Capability::Manage).await?;
    transition_on(conn, Some(actor), record, addition, expected_revision).await
}

async fn transition_on(
    conn: &mut SqliteConnection,
    actor: Option<&str>,
    record: &str,
    addition: &Addition,
    expected_revision: Option<&str>,
) -> Result<binding_plan::AddBindingPlan> {
    if addition.reason.trim().is_empty() {
        return Err(Error::engine("manage_bindings: reason must be nonblank"));
    }
    let claim = claim_on(conn, record, &addition.binding).await?;
    if let Some(expected) = expected_revision {
        let current = revision_on(conn, record).await?;
        if current != expected {
            return Err(Error::engine(format!(
                "binding state revision conflict: expected {expected}, current {current}"
            )));
        }
    }
    let existing: Option<(String,bool)> = sqlx::query_as("SELECT record_id,is_canonical FROM kernel_identity_bindings WHERE system=? AND identifier=?")
        .bind(&claim.system).bind(&claim.identifier).fetch_optional(&mut *conn).await?;
    if let Some((owner, _)) = &existing {
        if let Some(actor) = actor {
            if owner != record && !matches!(read_record_on(conn, actor, owner).await, Ok(Some(_))) {
                return Err(Error::engine(
                    "binding_not_visible: the external identity is not visible to this caller",
                ));
            }
        }
    }
    binding_plan::validate_add_owner(
        record,
        existing
            .as_ref()
            .map(|(record_id, canonical)| binding_plan::ExistingBinding {
                record_id: record_id.clone(),
                canonical: *canonical,
            })
            .as_ref(),
    )
    .map_err(|e| Error::engine(e.to_string()))?;
    let previous = if addition.canonical
        && !existing.as_ref().is_some_and(|(_, canonical)| *canonical)
    {
        sqlx::query_scalar("SELECT identifier FROM kernel_identity_bindings WHERE record_id=? AND system=? AND is_canonical=1")
            .bind(record).bind(&claim.system).fetch_optional(&mut *conn).await?
    } else {
        None
    };
    binding_plan::plan_add(
        record,
        claim,
        addition.canonical,
        existing.map(|(record_id, canonical)| binding_plan::ExistingBinding {
            record_id,
            canonical,
        }),
        previous,
    )
    .map_err(|e| Error::engine(e.to_string()))
}

async fn claim_on(
    conn: &mut SqliteConnection,
    record: &str,
    binding: &BindingClaim,
) -> Result<BindingClaim> {
    match binding.system.as_str() {
        "email" | "account" => {
            return Err(Error::engine(format!(
                "forbidden binding-system operation: '{}' is reserved",
                binding.system
            )))
        }
        "native-principal" | "native-record" => {}
        _ => {
            return Err(Error::engine(format!(
                "unknown binding system '{}'",
                binding.system
            )))
        }
    }
    let claim = BindingClaim {
        system: binding.system.clone(),
        identifier: crate::identity::normalize_identifier(&binding.system, &binding.identifier)?,
    };
    // Replay validates historical shape without reauthorizing today's roster.
    let (typ,kind): (Option<String>,Option<String>) = sqlx::query_as("SELECT CASE WHEN r.pin_family=? AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END,CASE WHEN r.pin_family=? AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE r.id=?")
        .bind(crate::v2_standard::v1_compat::FAMILY).bind(crate::v2_standard::v1_compat::FAMILY).bind(record).fetch_optional(&mut *conn).await?.ok_or_else(||Error::engine(HIDDEN_OR_MISSING))?;
    if claim.system == "native-principal"
        && (typ.as_deref() != Some("Entity") || kind.as_deref() != Some("person"))
    {
        return Err(Error::engine(format!(
            "incompatible record kind for binding system '{}' on record '{}'",
            claim.system, record
        )));
    }
    Ok(claim)
}

async fn kernel_require_on(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    required: Capability,
) -> Result<()> {
    if !kernel_effective_capability_on(conn, actor, record)
        .await?
        .allows(required)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    mutations::admit_mutation(conn, event).await?;
    if event.event_type == EVENT {
        if event.record_id != crate::events::KERNEL_ROOT_ID {
            return Err(Error::engine(
                "binding audit requires the kernel root stream",
            ));
        }
        let addition: Addition = event_payload(event)?;
        plan_on(
            conn,
            event.actor.as_deref().unwrap_or_default(),
            &addition.record_id,
            &addition,
            None,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != EVENT {
        return mutations::project_mutation(conn, event).await;
    }
    let addition: Addition = event_payload(event)?;
    if event.record_id != crate::events::KERNEL_ROOT_ID {
        return Err(Error::engine(
            "binding audit requires the kernel root stream",
        ));
    }
    let plan = transition_on(conn, None, &addition.record_id, &addition, None).await?;
    if addition.binding != plan.claim || !plan.changed {
        return Err(Error::engine(
            "binding addition must be normalized and change its state",
        ));
    }
    if plan.requested_canonical {
        sqlx::query("UPDATE kernel_identity_bindings SET is_canonical=0,event_seq=? WHERE record_id=? AND system=? AND is_canonical=1")
            .bind(event.local_seq).bind(&addition.record_id).bind(&plan.claim.system).execute(&mut *conn).await?;
    }
    sqlx::query("INSERT INTO kernel_identity_bindings(system,identifier,record_id,is_canonical,event_seq) VALUES(?,?,?,?,?) ON CONFLICT(system,identifier) DO UPDATE SET is_canonical=excluded.is_canonical,event_seq=excluded.event_seq")
        .bind(&plan.claim.system).bind(&plan.claim.identifier).bind(&addition.record_id).bind(plan.requested_canonical).bind(event.local_seq).execute(conn).await?;
    Ok(())
}

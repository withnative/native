//! Attributed policy boundaries over the existing home/event model.
//! Product admission owns the verified caller, Manage and version checks.
//! Replay checks the structural binding; it never invents a hosted role.
use super::*;
use native_policy_kernel::{AllowEntry, PolicySubject};
use std::collections::BTreeMap;

struct Admission {
    actor: String,
    targets: std::collections::BTreeSet<String>,
}
tokio::task_local! { static ADMISSION: Admission; }

/// Product-owned, transaction-scoped admission after every target has passed
/// authorization and guards. This permits a batch to revoke its own grant
/// without reauthorizing later items against its intermediate projections.
/// It is never selected from public arguments or persisted as an owner flag.
pub(crate) async fn scope_admission<F: std::future::Future>(
    actor: &str,
    targets: std::collections::BTreeSet<String>,
    work: F,
) -> F::Output {
    ADMISSION
        .scope(
            Admission {
                actor: actor.into(),
                targets,
            },
            work,
        )
        .await
}
pub(super) fn admitted(actor: &str, target: &str) -> bool {
    ADMISSION
        .try_with(|admission| admission.actor == actor && admission.targets.contains(target))
        .unwrap_or(false)
}

pub(crate) async fn physical_home_on(conn: &mut SqliteConnection, target: &str) -> Result<String> {
    let home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(target)
            .fetch_one(&mut *conn)
            .await?;
    if home {
        return Ok(target.into());
    }
    sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(target)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))
}

pub(crate) async fn inherited_on(
    conn: &mut SqliteConnection,
    actor: &str,
    target: &str,
) -> Result<policy_read::Snapshot> {
    let home = physical_home_on(conn, target).await?;
    let parent: Option<String> =
        sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id=?")
            .bind(&home)
            .fetch_one(&mut *conn)
            .await?;
    let parent =
        parent.ok_or_else(|| Error::engine("the workspace root cannot inherit a policy"))?;
    policy_read::inherited_on(conn, actor, &parent).await
}

async fn bound_target_on(conn: &mut SqliteConnection, home: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND type IN ('kernel.home_created.v1','kernel.import_home.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
        .bind(home).fetch_optional(conn).await?)
}

/// Bind only this logical record, preserving its real owner's floor and its
/// original logical filing. Never replace the shared parent home's policy.
async fn ensure_home_in(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    target: &str,
) -> Result<(String, Option<String>)> {
    let old = physical_home_on(conn, target).await?;
    if old == target || bound_target_on(conn, &old).await?.as_deref() == Some(target) {
        return Ok((old, None));
    }
    let home = v1_import_home_id(target);
    if bound_target_on(conn, &home).await?.as_deref() != Some(target) {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                .bind(&home)
                .fetch_one(&mut *conn)
                .await?;
        if exists {
            return Err(Error::engine("record policy home binding conflict"));
        }
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id=?")
                .bind(target)
                .fetch_one(&mut *conn)
                .await?;
        validate_move_parent(
            conn,
            &MoveHomeParent {
                home_id: home.clone(),
                parent_id: old.clone(),
            },
        )
        .await?;
        crate::store::append_on(
            db,
            conn,
            AppendSpec {
                record_id: home.clone(),
                event_type: KERNEL_HOME_CREATED_EVENT.into(),
                payload: serde_json::to_value(KernelHomeCreatedPayload {
                    source_record_id: Some(target.into()),
                    parent_id: old.clone(),
                    owner_id: owner,
                    entries: None,
                })?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
    }
    Ok((home, Some(old)))
}

async fn rehome_cohort_in(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    target: &str,
    old: &str,
    home: &str,
) -> Result<()> {
    let logical_home = v1_state::lifecycle_bearer_on(conn, old, Some(target)).await?;
    let mut cohort = vec![(target.to_owned(), 0usize)];
    let mut seen = std::collections::BTreeSet::from([target.to_owned()]);
    let mut index = 0;
    while index < cohort.len() {
        let children: Vec<String> = sqlx::query_scalar(&format!("SELECT DISTINCT l.source_id FROM kernel_generic_links l JOIN kernel_records c ON c.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND l.active=1 AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones dead WHERE dead.record_id=c.id) AND {} ORDER BY c.id", sql_is_derived_artifact("c")))
            .bind(&cohort[index].0).fetch_all(&mut *conn).await?;
        for child in children {
            let bearers = comments_v2::bearer_on(conn, &child).await?;
            if !seen.insert(child.clone())
                || bearers.as_slice() != [cohort[index].0.as_str()]
                || cohort[index].1 >= crate::authorization::MAX_DERIVED_BEARER_DEPTH
            {
                return Err(Error::engine(
                    "invalid derived artifact bearer; policy unchanged",
                ));
            }
            cohort.push((child, cohort[index].1 + 1));
        }
        index += 1;
    }
    for (record, _) in cohort {
        crate::store::append_on(
            db,
            conn,
            AppendSpec {
                record_id: record,
                event_type: "kernel.record_rehomed.v2".into(),
                payload: serde_json::to_value(KernelMovePayload {
                    new_home_id: home.into(),
                    logical_home_id: logical_home.clone(),
                    parent_update: None,
                })?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn apply_in(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    target: &str,
    entries: Option<Vec<AllowEntry>>,
    reason: &str,
) -> Result<EventRow> {
    let inherit = entries.is_none();
    let (home, moving_from) = if inherit {
        (physical_home_on(conn, target).await?, None)
    } else {
        ensure_home_in(db, conn, acts, actor, target).await?
    };
    let mut explicit = BTreeMap::new();
    let mut members = None;
    for entry in entries.unwrap_or_default() {
        let cap = entry
            .capability
            .as_policy_str()
            .ok_or_else(|| Error::engine("invalid policy capability"))?
            .to_owned();
        match entry.subject {
            PolicySubject::Account(principal) => {
                explicit.insert(principal, cap);
            }
            PolicySubject::Members => {
                members = Some(cap);
            }
        }
    }
    let event = crate::store::append_on(
        db,
        conn,
        AppendSpec {
            record_id: home.clone(),
            event_type: KERNEL_POLICY_REPLACED_EVENT.into(),
            payload: serde_json::to_value(KernelPolicyReplacedPayload {
                entries: explicit
                    .into_iter()
                    .map(|(subject_id, capability)| KernelHomeEntryPayload {
                        subject_id,
                        capability,
                    })
                    .collect(),
                record_policy: Some(RecordPolicyMetadata {
                    inherit,
                    members,
                    reason: reason.into(),
                    target: target.into(),
                }),
            })?,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    if let Some(old) = moving_from {
        rehome_cohort_in(db, conn, acts, actor, target, &old, &home).await?;
    }
    Ok(event)
}

//! Turso-local fold for the authoritative policy event vocabulary.
//!
//! The portable policy module owns event shape and validation. This module is
//! the Turso substrate's sole policy projection seam: callers append events in
//! their admitted transaction, then invoke this fold before committing.

#[cfg(feature = "turso-tests")]
use super::*;

// This exact seam is feature-gated only until the product manage-policy route
// is ported to Turso-local. Wave 1 must wire that route here rather than create
// a second projection implementation.
#[cfg(feature = "turso-tests")]
pub(super) async fn project_policy(
    transaction: &mut TursoDomainTransaction<'_>,
    event: &crate::policy::PolicyEventRow,
) -> Result<()> {
    crate::policy::validate_event(event)?;
    match event.event_type.as_str() {
        "policy.replaced" => {
            let payload = crate::policy::replaced_payload(event)?;
            let insert_policy = statement(
                StatementKind::Insert,
                "record_policies",
                &[
                    "INSERT OR IGNORE INTO {{relation}} (record_id, created_at) VALUES (",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("project Turso policy", error))?;
            transaction
                .execute(
                    "project Turso policy",
                    &insert_policy,
                    &[
                        BindValue::Text(event.record_id.clone()),
                        BindValue::Text(event.created_at.clone()),
                    ],
                )
                .await?;

            let delete_entries = statement(
                StatementKind::Delete,
                "policy_entries",
                &["DELETE FROM {{relation}} WHERE policy_anchor_id=", ""],
            )
            .map_err(|error| stable("replace Turso policy", error))?;
            transaction
                .execute(
                    "replace Turso policy",
                    &delete_entries,
                    &[BindValue::Text(event.record_id.clone())],
                )
                .await?;

            let insert_entry = statement(
                StatementKind::Insert,
                "policy_entries",
                &[
                    "INSERT INTO {{relation}} (policy_anchor_id, subject_kind, subject_id, effect, capability) VALUES (",
                    ", ",
                    ", ",
                    ", ",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("project Turso policy entry", error))?;
            for entry in payload.entries {
                transaction
                    .execute(
                        "project Turso policy entry",
                        &insert_entry,
                        &[
                            BindValue::Text(event.record_id.clone()),
                            BindValue::Text(entry.subject_kind),
                            BindValue::Text(entry.subject_id),
                            BindValue::Text(entry.effect),
                            BindValue::Text(entry.capability),
                        ],
                    )
                    .await?;
            }
        }
        "policy.inheritance_restored" => {
            let delete_policy = statement(
                StatementKind::Delete,
                "record_policies",
                &["DELETE FROM {{relation}} WHERE record_id=", ""],
            )
            .map_err(|error| stable("restore Turso policy inheritance", error))?;
            if transaction
                .execute(
                    "restore Turso policy inheritance",
                    &delete_policy,
                    &[BindValue::Text(event.record_id.clone())],
                )
                .await?
                != 1
            {
                return Err(Error::engine(format!(
                    "policy event {} restores inheritance for non-explicit record '{}'",
                    event.id, event.record_id
                )));
            }
        }
        other => return Err(Error::engine(format!("unknown policy event type: {other}"))),
    }

    transaction
        .refresh_policy_anchor_subtree(&event.record_id)
        .await?;

    // Every applied policy operation advances the epoch at least once, even
    // when it wrote no projection row — hosted clients use the authorization
    // frame as their acknowledgement that a policy write landed, and
    // re-asserting an identical empty explicit policy writes nothing. Mirrors
    // `crate::policy::project_policy`; see its comment for the full case.
    let bump = statement(
        StatementKind::Update,
        "authorization_revision",
        &["UPDATE {{relation}} SET epoch = epoch + 1 WHERE id = ", ""],
    )
    .map_err(|error| stable("acknowledge Turso policy operation", error))?;
    transaction
        .execute(
            "acknowledge Turso policy operation",
            &bump,
            &[BindValue::Integer(1)],
        )
        .await?;
    Ok(())
}

/// Reset only the policy projections in a fresh replay-owned database. The
/// authoritative source events remain outside this seam and are folded again
/// through the production `project_policy` fold.
#[cfg(feature = "turso-tests")]
pub(super) async fn clear_projections_for_replay(connection: &turso::Connection) -> Result<()> {
    for table in crate::schema::POLICY_PROJECTION_TABLES.iter().rev() {
        connection
            .execute(&format!("DELETE FROM {table}"), ())
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "cannot clear Turso replay policy projection {table}: {error}"
                ))
            })?;
    }
    Ok(())
}

//! Typed current caller associations. Never infer from directory/config/home.
use super::*;
use k::v1_state::member_context::{Context, CAPTURE, CAPTURE_ID, SECTION};

pub(super) async fn capture(
    source: &mut SqliteConnection,
    db: &Db,
    origin: &str,
    report: &mut Report,
    sections: &mut BTreeMap<String, Vec<(String, serde_json::Value)>>,
) -> Result<()> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='member_contexts')",
    )
    .fetch_one(&mut *source)
    .await?;
    report.state.member_contexts_source_present = present;
    if !present {
        let previous: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_v1_state WHERE section IN (?,?) AND origin=?)",
        )
        .bind(SECTION)
        .bind(CAPTURE)
        .bind(origin)
        .fetch_one(db.pool())
        .await?;
        if previous {
            return Err("member contexts source table missing after capture".into());
        }
        // Generic subset imports remain possible; absence cannot qualify cutover.
        return Ok(());
    }
    let rows=sqlx::query("SELECT mc.account_id,mc.person_record_id,mc.root_record_id,mc.created_at,p.id AS person_found,p.deleted_at AS person_deleted,p.type AS person_type,p.kind AS person_kind,r.id AS root_found,r.deleted_at AS root_deleted,r.type AS root_type,r.kind AS root_kind,(SELECT count(*) FROM bindings b WHERE b.system='account' AND b.identifier=mc.account_id AND b.is_canonical=1 AND b.record_id<>mc.person_record_id) AS conflicting_person,(SELECT count(*) FROM member_contexts other WHERE other.root_record_id=mc.root_record_id) AS root_uses FROM member_contexts mc LEFT JOIN records p ON p.id=mc.person_record_id LEFT JOIN records r ON r.id=mc.root_record_id ORDER BY mc.account_id")
        .fetch_all(source).await?;
    let mut values = Vec::new();
    for row in rows {
        let person_found: Option<String> = row.get("person_found");
        let root_found: Option<String> = row.get("root_found");
        let invalid = (person_found.is_some()
            && (row.get::<Option<String>, _>("person_type").as_deref() != Some("Entity")
                || row.get::<Option<String>, _>("person_kind").as_deref() != Some("person")))
            || (root_found.is_some()
                && (row.get::<Option<String>, _>("root_type").as_deref() != Some("Collection")
                    || row.get::<Option<String>, _>("root_kind").as_deref() != Some("folder")))
            || row.get::<i64, _>("conflicting_person") != 0
            || row.get::<i64, _>("root_uses") != 1;
        let context = Context {
            account_id: row.get("account_id"),
            person_record_id: row.get("person_record_id"),
            root_record_id: row.get("root_record_id"),
            created_at: row.get("created_at"),
            person_missing: person_found.is_none(),
            person_deleted: row.get::<Option<String>, _>("person_deleted").is_some(),
            root_missing: root_found.is_none(),
            root_deleted: row.get::<Option<String>, _>("root_deleted").is_some(),
            invalid,
        };
        if invalid {
            report.state.member_contexts_invalid += 1;
            report.refusals.push(issue(
                &context.account_id,
                "conflicting or malformed source member context retained without authority",
            ));
        }
        values.push((
            serde_json::to_string(&[&context.account_id])?,
            serde_json::to_value(context)?,
        ));
    }
    sections.insert(SECTION.into(), values);
    Ok(())
}
pub(super) async fn receipt(
    db: &Db,
    host: &str,
    origin: &str,
    observed_at: &str,
    snapshot: &serde_json::Value,
    report: &mut Report,
) -> Result<()> {
    if !report.state.member_contexts_source_present {
        return Ok(());
    }
    let counts = report
        .state
        .sections
        .get(SECTION)
        .ok_or("member context capture not inspected")?;
    let refused = counts.refused + report.state.member_contexts_invalid;
    let complete = refused == 0 && counts.verified == counts.source + counts.removed;
    // Write a failing receipt too: an old successful empty receipt must not
    // survive a later conflicting source tuple and falsely qualify preparation.
    k::v1_state::import_state_batch_as(
        db,
        host,
        &[k::v1_state::ImportedState {
            section: CAPTURE.into(),
            source_id: CAPTURE_ID.into(),
            origin: origin.into(),
            value_json: Some(serde_json::to_string(
                &json!({"version":1,"rows":counts.source,"refused":refused}),
            )?),
            account_principal: None,
            record_id: None,
            observed_at: observed_at.into(),
            snapshot: snapshot.clone(),
        }],
    )
    .await?;
    report.state.member_contexts_prepared = complete;
    Ok(())
}

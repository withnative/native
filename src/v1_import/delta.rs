//! Reconcile negative facts against the whole source snapshot, never merely
//! against the chosen seeds. Only target identities with sealed import
//! lineage are eligible; native rows and excluded-but-present rows survive.
use super::*;
type SourceRemovalEventRow = (String, String, Option<String>, String, Option<String>);

pub(super) async fn control_head(source: &mut SqliteConnection) -> Result<Option<(i64, String)>> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='control_events')",
    )
    .fetch_one(&mut *source)
    .await?;
    if present {
        Ok(
            sqlx::query_as("SELECT seq,id FROM control_events ORDER BY seq DESC LIMIT 1")
                .fetch_optional(source)
                .await?,
        )
    } else {
        Ok(None)
    }
}
#[derive(Clone, Copy)]
pub(super) enum EvidenceKind {
    Record,
    Link,
    Attachment,
    CommentAnchor,
    InstructionBinding,
    BindingRetarget,
    CommentBearer,
}

pub(super) async fn evidence(
    source: &mut SqliteConnection,
    origin: &str,
    id: &str,
    kind: EvidenceKind,
    reason: &str,
    deleted_at: Option<String>,
) -> Result<k::ImportRemovalEvidence> {
    let head: Option<(i64, String)> =
        sqlx::query_as("SELECT seq,id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *source)
            .await?;
    let controls = control_head(source).await?;
    let event_type = match kind {
        EvidenceKind::Record => Some("record.deleted"),
        EvidenceKind::Attachment => Some("facet.unset"),
        EvidenceKind::CommentAnchor => Some("annotation.target.removed"),
        _ => None,
    };
    let event: Option<SourceRemovalEventRow> = if matches!(kind, EvidenceKind::InstructionBinding)
        && controls.is_some()
    {
        sqlx::query_as("SELECT id,type,payload,created_at,actor FROM control_events WHERE aggregate_id=? AND type='instruction_binding.removed' ORDER BY seq DESC LIMIT 1").bind(id).fetch_optional(&mut *source).await?
    } else if let Some(event_type) = event_type {
        sqlx::query_as("SELECT id,type,payload,created_at,actor FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1").bind(id).bind(event_type).fetch_optional(&mut *source).await?
    } else {
        None
    };
    Ok(k::ImportRemovalEvidence {source_origin:origin.into(),snapshot:serde_json::to_string(&json!({"content":head,"control":controls}))?,reason:reason.into(),deleted_at,source_event:event.map(|(id,typ,payload,created_at,actor)|json!({"id":id,"type":typ,"payload":payload,"created_at":created_at,"actor":actor.map(|a|format!("v1:{a}"))}))})
}

pub(super) async fn reconcile(
    db: &Db,
    host: &str,
    source: &mut SqliteConnection,
    origin: &str,
    records_only: bool,
    report: &mut Report,
) -> Result<()> {
    if records_only {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT record_id FROM content_events WHERE type='kernel.import_state.v1' AND actor=?",
        )
        .bind(host)
        .fetch_all(db.pool())
        .await?;
        for id in ids {
            let row: Option<(Option<String>, String, Option<String>)> =
                sqlx::query_as("SELECT deleted_at,type,kind FROM records WHERE id=?")
                    .bind(&id)
                    .fetch_optional(&mut *source)
                    .await?;
            let reason = match &row {
                None => Some("record missing from source snapshot"),
                Some((Some(_), _, _)) => Some("source record tombstone"),
                _ => None,
            };
            let detached = if matches!(&row,Some((None,t,k)) if t=="Annotation" || (t=="Document" && k.as_deref()==Some("attachment")))
            {
                let count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM links WHERE source_id=? AND relationship='part_of'",
                )
                .bind(&id)
                .fetch_one(&mut *source)
                .await?;
                count == 0
            } else {
                false
            };
            let reason = reason.or(if detached {
                Some("comment detached from its bearer in source snapshot")
            } else {
                None
            });
            if let Some(reason) = reason {
                let evidence = evidence(
                    source,
                    origin,
                    &id,
                    if detached {
                        EvidenceKind::CommentBearer
                    } else {
                        EvidenceKind::Record
                    },
                    reason,
                    row.as_ref().and_then(|r| r.0.clone()),
                )
                .await?;
                record_removal(
                    db,
                    host,
                    &id,
                    k::ImportedRemovalKind::Record,
                    if detached {
                        "comments_detached"
                    } else {
                        "records_tombstoned"
                    },
                    &evidence,
                    report,
                )
                .await?;
            }
        }
        return Ok(());
    }
    let links: Vec<String> = sqlx::query_scalar(
        "SELECT link_id FROM kernel_generic_links WHERE imported=1 AND active=1",
    )
    .fetch_all(db.pool())
    .await?;
    for id in links {
        let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM links WHERE id=?)")
            .bind(&id)
            .fetch_one(&mut *source)
            .await?;
        if !present {
            let evidence = evidence(
                source,
                origin,
                &id,
                EvidenceKind::Link,
                "link missing from source snapshot",
                None,
            )
            .await?;
            match k::import_generic_link_removal_as(db, host, &id, &evidence).await {
                Ok(k::GenericLinkOutcome::Updated) => {
                    *report
                        .delta
                        .entry("generic_links_removed".into())
                        .or_default() += 1;
                }
                Ok(_) => {}
                Err(e) => report
                    .review
                    .push(issue(&id, &format!("sealed link removal refused: {e}"))),
            }
        }
    }
    let attachments: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.record_id,json_extract(a.metadata,'$.id') FROM kernel_attachment_blobs a WHERE EXISTS(SELECT 1 FROM content_events e WHERE e.record_id=a.record_id AND e.type='kernel.import_state.v1' AND e.actor=?) AND (SELECT actor FROM content_events e WHERE e.record_id=a.record_id AND e.type='kernel.attachment_bound.v1' ORDER BY seq DESC LIMIT 1)=?",
    ).bind(host).bind(host)
    .fetch_all(db.pool())
    .await?;
    for (id, handle) in attachments {
        let retained:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM facet_values WHERE record_id=? AND key='blob_ref' AND value=?)").bind(&id).bind(&handle).fetch_one(&mut *source).await?;
        if !retained {
            let evidence = evidence(
                source,
                origin,
                &id,
                EvidenceKind::Attachment,
                "attachment reference detached in source snapshot",
                None,
            )
            .await?;
            record_removal(
                db,
                host,
                &id,
                k::ImportedRemovalKind::Attachment,
                "attachments_detached",
                &evidence,
                report,
            )
            .await?;
        }
    }
    let bindings:Vec<String>=sqlx::query_scalar("SELECT record_id FROM content_events WHERE type='kernel.instruction_binding_imported.v1' AND actor=?").bind(host).fetch_all(db.pool()).await?;
    for id in bindings {
        if !report.instruction_bindings.source_table_present {
            report.review.push(issue(
                &id,
                "source instruction_bindings table missing; retained for review",
            ));
            continue;
        }
        let present = if report.instruction_bindings.source_table_present {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM instruction_bindings WHERE id=?)",
            )
            .bind(&id)
            .fetch_one(&mut *source)
            .await?
        } else {
            false
        };
        if !present {
            let evidence = evidence(
                source,
                origin,
                &id,
                EvidenceKind::InstructionBinding,
                "instruction binding missing from source snapshot",
                None,
            )
            .await?;
            record_removal(
                db,
                host,
                &id,
                k::ImportedRemovalKind::InstructionBinding,
                "instruction_bindings_removed",
                &evidence,
                report,
            )
            .await?;
        }
    }
    let anchors: Vec<String> =
        sqlx::query_scalar("SELECT a.annotation_id FROM kernel_comment_anchors a JOIN content_events e ON e.seq=a.event_seq WHERE e.type='kernel.comment_anchor_imported.v1' AND e.actor=? AND EXISTS(SELECT 1 FROM content_events i WHERE i.record_id=a.annotation_id AND i.type='kernel.import_state.v1' AND i.actor=?)")
            .bind(host).bind(host).fetch_all(db.pool())
            .await?;
    let has_anchors: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='annotation_targets')",
    )
    .fetch_one(&mut *source)
    .await?;
    for id in anchors {
        if !has_anchors {
            report.review.push(issue(
                &id,
                "source annotation_targets table missing; retained for review",
            ));
            continue;
        }
        let present = if has_anchors {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id=?)",
            )
            .bind(&id)
            .fetch_one(&mut *source)
            .await?
        } else {
            false
        };
        if !present {
            let evidence = evidence(
                source,
                origin,
                &id,
                EvidenceKind::CommentAnchor,
                "comment anchor missing from source snapshot",
                None,
            )
            .await?;
            record_removal(
                db,
                host,
                &id,
                k::ImportedRemovalKind::CommentAnchor,
                "comment_anchors_removed",
                &evidence,
                report,
            )
            .await?;
        }
    }
    // Missing homes cannot be erased while they bear records. Retain their
    // durable source mapping and disclose the absence for placement review.
    let homes:Vec<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE type='kernel.import_home.v1'").fetch_all(db.pool()).await?;
    for id in homes {
        let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
            .bind(&id)
            .fetch_one(&mut *source)
            .await?;
        let deleted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NOT NULL)",
        )
        .bind(&id)
        .fetch_one(&mut *source)
        .await?;
        if deleted {
            report.review.push(issue(
                &id,
                "imported home is a source tombstone; retained for placement review",
            ));
        }
        if !present {
            report.review.push(issue(
                &id,
                "imported home missing from source; retained for placement review",
            ));
        }
    }
    Ok(())
}
async fn record_removal(
    db: &Db,
    host: &str,
    id: &str,
    kind: k::ImportedRemovalKind,
    count: &str,
    evidence: &k::ImportRemovalEvidence,
    report: &mut Report,
) -> Result<()> {
    match k::import_removal_as(db, host, id, kind, evidence).await {
        Ok(k::ImportResult::Updated) => {
            *report.delta.entry(count.into()).or_default() += 1;
        }
        Ok(_) => {}
        Err(e) => report
            .review
            .push(issue(id, &format!("sealed removal refused: {e}"))),
    }
    Ok(())
}

/// D9 provenance is an assertion's immutable source set. A changed source
/// set retracts the old import assertion and asserts its surviving directions;
/// native assertions on the same pair are never touched.
pub(super) async fn relations(
    db: &Db,
    transform: &str,
    source: &mut SqliteConnection,
    origin: &str,
    mut current: BTreeMap<(String, String), Vec<standard::relates_to::Source>>,
    report: &mut Report,
) -> Result<()> {
    let raw: Vec<(i64, String)> =
        sqlx::query_as("SELECT head,state_json FROM kernel_provider_state WHERE provider_key=?")
            .bind(standard::relates_to::RELATIONSHIP)
            .fetch_all(db.pool())
            .await?;
    let mut heads = BTreeMap::new();
    let mut active = BTreeMap::<(String, String), Vec<standard::relates_to::Assertion>>::new();
    for (head, raw) in raw {
        let retained: k::provider_catalogue::StoredState = serde_json::from_str(&raw)?;
        let state: standard::relates_to::State = serde_json::from_value(retained.view()?)?;
        heads.insert((state.left.clone(), state.right.clone()), head);
        let assertions: Vec<_> = state
            .assertions
            .into_iter()
            .filter(|a| !a.retracted && a.asserted_by.as_deref() == Some(transform))
            .collect();
        if !assertions.is_empty() {
            active.insert((state.left, state.right), assertions);
        }
    }
    let pairs: BTreeSet<_> = current.keys().chain(active.keys()).cloned().collect();
    for (left, right) in pairs {
        let mut provider_head = heads.get(&(left.clone(), right.clone())).copied();
        let prior = active
            .remove(&(left.clone(), right.clone()))
            .unwrap_or_default();
        let in_subset = current.contains_key(&(left.clone(), right.clone()));
        let mut desired = if let Some(sources) = current.remove(&(left.clone(), right.clone())) {
            sources
        } else {
            let mut keep = Vec::new();
            for assertion in &prior {
                for item in &assertion.sources {
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM links l JOIN records s ON s.id=l.source_id JOIN records t ON t.id=l.target_id WHERE l.id=? AND s.deleted_at IS NULL AND t.deleted_at IS NULL)").bind(&item.source_id).fetch_one(&mut *source).await?;
                    if exists {
                        keep.push(item.clone());
                    }
                }
            }
            keep
        };
        desired.sort_by(|a, b| a.source_id.cmp(&b.source_id));
        let unchanged = prior.len() == 1 && {
            let mut old = prior[0].sources.clone();
            old.sort_by(|a, b| a.source_id.cmp(&b.source_id));
            old == desired
        };
        if !unchanged {
            let mut refused = false;
            for assertion in &prior {
                let key = format!("v1:{origin}:retract:{}", assertion.id);
                let result = async {
                    let request = k::prepare_provider_as(
                        db,
                        transform,
                        &left,
                        &right,
                        &key,
                        standard::relates_to::Command::Retract {
                            assertion_id: assertion.id.clone(),
                        },
                    )
                    .await?;
                    k::commit_provider_as(db, transform, &request).await
                }
                .await;
                match result {
                    Ok(receipt) => {
                        provider_head = Some(receipt.event_seq);
                        *report
                            .delta
                            .entry("relates_to_assertions_retracted".into())
                            .or_default() += 1;
                    }
                    Err(_) => {
                        report.review.push(issue(
                            &left,
                            "sealed D9 removal refused; existing assertion retained",
                        ));
                        refused = true;
                    }
                }
            }
            if refused {
                continue;
            }
            if !desired.is_empty() {
                let head: Option<String> =
                    sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq DESC LIMIT 1")
                        .fetch_optional(&mut *source)
                        .await?;
                let digest = crate::meta::definition_artifact::digest_artifact_bytes(
                    serde_json::to_string(&(&left, &right, &desired, &head, provider_head))?
                        .as_bytes(),
                );
                let key = format!("v1:{origin}:relation:{digest}");
                let started = Instant::now();
                let request = k::prepare_provider_as(
                    db,
                    transform,
                    &left,
                    &right,
                    &key,
                    standard::relates_to::Command::Assert {
                        sources: desired.clone(),
                    },
                )
                .await;
                phase(report, "links.relates_to_prepare", started);
                let started = Instant::now();
                let result = match request {
                    Ok(request) => k::commit_provider_as(db, transform, &request).await,
                    Err(e) => Err(e),
                };
                phase(report, "links.relates_to_commit", started);
                if result.is_err() {
                    report
                        .refusals
                        .push(issue(&left, "relates_to delta assertion refused"));
                    report
                        .links_by_relationship
                        .entry("relates_to".into())
                        .or_default()
                        .refused += desired.len();
                    continue;
                }
                *report
                    .delta
                    .entry("relates_to_assertions_created".into())
                    .or_default() += 1;
                let added = desired
                    .iter()
                    .filter(|new| {
                        !prior
                            .iter()
                            .flat_map(|a| &a.sources)
                            .any(|old| old.source_id == new.source_id)
                    })
                    .count();
                *report
                    .delta
                    .entry("relates_to_directions_added".into())
                    .or_default() += added;
                report
                    .links_by_relationship
                    .entry("relates_to".into())
                    .or_default()
                    .created += added;
            }
            if !prior.is_empty() {
                let removed = prior
                    .iter()
                    .flat_map(|a| &a.sources)
                    .filter(|old| !desired.iter().any(|d| d.source_id == old.source_id))
                    .count();
                *report
                    .delta
                    .entry("relates_to_directions_removed".into())
                    .or_default() += removed;
            }
        }
        if in_subset {
            report.links_imported += desired.len();
            report
                .links_by_relationship
                .entry("relates_to".into())
                .or_default()
                .imported += desired.len();
        }
    }
    Ok(())
}

/// Structural loss of a bearer is different from a reversible policy change.
/// Only broken/missing/tombstoned chains qualify as unavailable here.
pub(super) async fn unavailable_comment(
    source: &mut SqliteConnection,
    record: &Record,
) -> Result<bool> {
    if !is_derived_record(record) {
        return Ok(false);
    }
    let mut current = record.id.clone();
    let mut seen = BTreeSet::new();
    for _ in 0..crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        if !seen.insert(current.clone()) {
            return Ok(true);
        }
        let parents: Vec<String> = sqlx::query_scalar(
            "SELECT target_id FROM links WHERE source_id=? AND relationship='part_of'",
        )
        .bind(&current)
        .fetch_all(&mut *source)
        .await?;
        let [bearer] = parents.as_slice() else {
            return Ok(true);
        };
        let row: Option<(String, Option<String>, Option<String>)> =
            sqlx::query_as("SELECT type,kind,deleted_at FROM records WHERE id=?")
                .bind(bearer)
                .fetch_optional(&mut *source)
                .await?;
        let Some((typ, kind, deleted_at)) = row else {
            return Ok(true);
        };
        if deleted_at.is_some() {
            return Ok(true);
        }
        if typ != "Annotation" && !(typ == "Document" && kind.as_deref() == Some("attachment")) {
            return Ok(false);
        }
        current = bearer.clone();
    }
    Ok(true)
}

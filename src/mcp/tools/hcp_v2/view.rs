//! The private Native record that views an entry.
//!
//! One `Resolution/hcp_entry` record per entry, created `account_only` so it
//! lives in the person's private space. Its id **is** the entry's identifier
//! (`urn:uuid:<record id>`). The body is the entry as canonical grouped-form
//! JSON (HCP v2 §4.2), and facets mirror what a person filters on. It exists
//! so the person can see and manage their context in Native; **nothing here
//! is evidence**. Trusted state is the fold of the person's events
//! ([`super::fold`]), and what a client sees never depends on this record.
//!
//! The view is written after the transaction that made the change, best
//! effort. Each event records the digest of the body it projects, so a body
//! that matches a recorded digest is merely stale and is rewritten. A body
//! that matches none is an edit made in Native, and is folded into the state
//! first ([`Store::reconcile_view`], rules in [`super::reconcile`]): the
//! person's statement and content become a `native-edit` version, in the
//! transaction that reads the body, before an operation reads the entry. An
//! edit that cannot be taken (not JSON, not an entry, a blank statement...)
//! changes nothing and is **not** overwritten: the record keeps the person's
//! text and carries a note (the `hcp2.edit_note` facet) saying why it was not
//! applied. The record is touched only while it is still private to the
//! caller: a view that was shared or moved is left alone, and has no effect on
//! anyone's trusted state.

use chrono::Utc;
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};

use super::fold::FoldedEntry;
use super::model::{self, Entry};
use super::reconcile;
use super::setup::KIND;
use super::store::{record_id_of, sha256_hex, Store};

const FACET_PERSON: &str = "hcp2.person";
const FACET_CLIENT: &str = "hcp2.client";
const FACET_CORRELATION: &str = "hcp2.correlation";
const FACET_CATEGORY: &str = "hcp2.category";
const FACET_DIMENSION: &str = "hcp2.dimension";
const FACET_DECLARATION: &str = "hcp2.declaration_type";
const FACET_STATUS: &str = "hcp2.status";
const FACET_VERSION: &str = "hcp2.version";
const FACET_CONFIDENCE: &str = "hcp2.confidence";
const FACET_CREDENTIAL: &str = "hcp2.credential_type";
/// Why the person's last edit of the body was not applied; absent otherwise.
const FACET_EDIT_NOTE: &str = "hcp2.edit_note";
/// How many body revisions back the version an edit was made from is sought.
const MAX_REVISIONS_BACK: usize = 64;

/// What a view body is, measured against the digests the events recorded.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ViewBody {
    /// It is what the state says.
    Current,
    /// It is a body an earlier event projected.
    Stale,
    /// It is neither: someone edited the record in Native.
    Edited,
}

pub(super) fn classify(folded: &FoldedEntry, body: &str) -> ViewBody {
    let digest = sha256_hex(body);
    if digest == folded.current_digest() {
        ViewBody::Current
    } else if folded.knows_digest(&digest) {
        ViewBody::Stale
    } else {
        ViewBody::Edited
    }
}

/// What reconciling found to do about a view: it is behind, carries an edit,
/// or carries a note that no longer applies.
pub(super) struct Judged {
    /// Digest of the body that was judged.
    digest: String,
    /// The note for the person when the edit could not be taken.
    problem: Option<String>,
}

/// One revision of a view body, from the record's own history.
struct BodyRevision {
    /// The account that saved it.
    actor: Option<String>,
    body: String,
}

/// The note on a view whose edit was not applied.
fn not_applied(why: &str, advice: &str) -> String {
    format!("Not applied, the entry is unchanged: {why}. Your text is still here. {advice}")
}

const FIX_IT: &str = "Fix it and it is picked up the next time the entry is used.";

/// Inside a snapshot: the policy revision of `record_id` if it is the
/// caller's own private view — still viewable by them, with a policy whose
/// only entry gives their account Manage, which is what creating a record
/// `account_only` installs. Anything else (a share, a
/// transfer, an inherited placement) is not the person's private space.
pub(super) async fn private_revision(
    store: &Store<'_>,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<Option<String>> {
    #[cfg(feature = "v2-kernel-probe")]
    if store.is_kernel() {
        return super::kernel_view::private_revision(store, tx, record_id, true).await;
    }
    use native_policy_kernel::{AllowEntry, Capability, PolicyMode};
    // The record must be an entry view and the caller must still hold it. Its
    // facets are not consulted: they are the person's to edit.
    let is_view: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT 1 FROM records r \
         WHERE r.id = ?1 AND r.type = 'Resolution' AND r.kind = '{KIND}' AND r.archived = 0 \
           AND r.deleted_at IS NULL"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    if is_view.is_none()
        || !crate::mcp::tools::can_record_in(tx, store.caller, record_id, Capability::View).await?
    {
        return Ok(None);
    }
    let target = crate::authorization::authorization_target_on(tx, record_id).await?;
    let snapshot = crate::mcp::tools::policy::policy_snapshot(tx, &target).await?;
    let private = snapshot.mode == PolicyMode::Explicit
        && snapshot.entries
            == [AllowEntry::account(
                store.caller.actor(),
                Capability::Manage,
            )];
    Ok(private.then_some(snapshot.revision))
}

/// The body of the view record `record_id`, if there is such a record.
async fn view_body(
    store: &Store<'_>,
    conn: &mut sqlx::SqliteConnection,
    record_id: &str,
) -> Result<Option<String>> {
    let table = if store.is_kernel() {
        "kernel_record_bodies"
    } else {
        "records"
    };
    let held: Option<Option<String>> = sqlx::query_scalar(&format!(
        "SELECT body FROM {table} WHERE {} = ?1",
        if store.is_kernel() { "record_id" } else { "id" }
    ))
    .bind(record_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(held.map(Option::unwrap_or_default))
}

/// The latest body revisions of the view `record_id`, newest first.
async fn body_revisions(
    store: &Store<'_>,
    conn: &mut sqlx::SqliteConnection,
    record_id: &str,
) -> Result<Vec<BodyRevision>> {
    use sqlx::Row;
    let predicate = if store.is_kernel() {
        "type='kernel.body_set.v1'"
    } else {
        crate::record_body::BODY_CARRYING_EVENT_SQL
    };
    let rows = sqlx::query(&format!(
        "SELECT type, payload, actor FROM content_events \
          WHERE record_id = ?1 AND ({}) ORDER BY seq DESC LIMIT {MAX_REVISIONS_BACK}",
        predicate
    ))
    .bind(record_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut revisions = Vec::new();
    for row in rows {
        let event_type: String = row.try_get("type")?;
        let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        let projected = if store.is_kernel() {
            Some(payload["body"].as_str().map(str::to_owned))
        } else {
            crate::record_body::projected_body(&event_type, &payload)
        };
        if let Some(body) = projected {
            revisions.push(BodyRevision {
                actor: row.try_get("actor")?,
                body: body.unwrap_or_default(),
            });
        }
    }
    Ok(revisions)
}

/// The note on the view that says its last edit was not applied, if any.
async fn edit_note(
    store: &Store<'_>,
    conn: &mut sqlx::SqliteConnection,
    record_id: &str,
) -> Result<Option<String>> {
    // A text facet is stored as the text itself.
    let table = if store.is_kernel() {
        "kernel_facets"
    } else {
        "facet_values"
    };
    let note: Option<Option<String>> = sqlx::query_scalar(&format!(
        "SELECT value FROM {table} WHERE record_id = ?1 AND key = ?2"
    ))
    .bind(record_id)
    .bind(FACET_EDIT_NOTE)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(note.flatten())
}

impl Store<'_> {
    fn facets(&self, entry: &Entry) -> Map<String, Value> {
        let mut facets = Map::new();
        facets.insert(FACET_PERSON.into(), json!(self.person));
        facets.insert(FACET_CLIENT.into(), json!(self.client.id));
        facets.insert(FACET_CORRELATION.into(), json!(self.correlation_id));
        facets.insert(FACET_CREDENTIAL.into(), json!("NLPreference"));
        facets.insert(FACET_CATEGORY.into(), json!(entry.category()));
        facets.insert(
            FACET_DIMENSION.into(),
            match entry.dimension().map(model::normalize_dimension) {
                Some(normalised) if !normalised.is_empty() => json!(normalised),
                _ => Value::Null,
            },
        );
        facets.insert(FACET_DECLARATION.into(), json!(entry.declaration_type()));
        facets.insert(FACET_STATUS.into(), json!(entry.status()));
        facets.insert(FACET_VERSION.into(), json!(entry.version().to_string()));
        facets.insert(
            FACET_CONFIDENCE.into(),
            entry.0["record"]["confidence"].clone(),
        );
        // Writing the view from the state answers any earlier edit.
        facets.insert(FACET_EDIT_NOTE.into(), Value::Null);
        facets
    }

    /// The record name shown to the person in Native: category and the start
    /// of the preference.
    fn display_name(entry: &Entry) -> String {
        let preference = match entry.preference() {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let single_line: String = preference
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(80)
            .collect();
        format!("{}: {}", entry.category(), single_line)
    }

    /// Fold the person's edit of the view of `urn`, if there is one, into the
    /// entry's state, before the caller reads the entry. Event failures
    /// propagate; view projection remains best effort after the durable change.
    pub(super) async fn pick_up_edit(&self, urn: &str) -> Result<()> {
        if Box::pin(self.reconcile_view(urn)).await?.is_some() {
            self.sync_version_views(urn).await;
        }
        self.sync_suggestions().await;
        Ok(())
    }

    /// A search discovers entries across categories, including Native edits.
    /// A failed event append propagates: never acknowledge an unlogged edit.
    pub(super) async fn pick_up_edits(&self) -> Result<()> {
        for urn in self.fold_all().await?.entries.keys() {
            self.pick_up_edit(urn).await?;
        }
        Ok(())
    }

    /// Fold an edit of the view of `urn` into its state, as one write
    /// transaction that reads the body, folds the log and appends the
    /// `native-edit` version. `None` when the body is not an edit (it is the
    /// current body or a stale one, the view is absent, or it is no longer the
    /// caller's private view); otherwise what the body was judged to be.
    pub(super) async fn reconcile_view(&self, urn: &str) -> Result<Option<Judged>> {
        Box::pin(self.consume_resolutions(urn)).await?;
        let Some(record_id) = record_id_of(urn) else {
            return Ok(None);
        };
        // A look that takes no write lock: most calls find nothing to do.
        let Some(folded) = self.folded(urn).await? else {
            return Ok(None);
        };
        let looked = {
            let mut conn = self.db.write_pool().acquire().await?;
            view_body(self, &mut conn, &record_id).await?
        };
        match looked {
            Some(body) if classify(&folded, &body) == ViewBody::Edited => {}
            // Put right by the person: a note that is left explains nothing.
            Some(body) if classify(&folded, &body) == ViewBody::Current => {
                let mut conn = self.db.write_pool().acquire().await?;
                return Ok(edit_note(self, &mut conn, &record_id)
                    .await?
                    .map(|_| Judged {
                        digest: sha256_hex(&body),
                        problem: None,
                    }));
            }
            _ => return Ok(None),
        }

        // Judge it again, with the write lock held.
        let mut tx = self.begin().await?;
        let mut act = crate::act::ActAllocation::new();
        self.consume_resolutions_in(&mut tx, &mut act, urn).await?;
        let held = view_body(self, &mut tx, &record_id).await?;
        let (Some(held), Some(_)) = (held, private_revision(self, &mut tx, &record_id).await?)
        else {
            tx.rollback().await?;
            return Ok(None);
        };
        let Some(folded) = self.folded_in(&mut tx, urn).await? else {
            tx.rollback().await?;
            return Ok(None);
        };
        if classify(&folded, &held) != ViewBody::Edited {
            tx.rollback().await?;
            return Ok(None);
        }
        let digest = sha256_hex(&held);
        let recorded_at = model::timestamp(Utc::now());
        let judged = |problem: Option<String>| Judged {
            digest: digest.clone(),
            problem,
        };

        // Whose text is it, and which version was it written over?
        let revisions = body_revisions(self, &mut tx, &record_id).await?;
        let Some(latest) = revisions.first().filter(|latest| latest.body == held) else {
            tx.rollback().await?;
            return Ok(Some(judged(Some(not_applied(
                "Native cannot tell who saved this text",
                "Change it and save it yourself to apply it.",
            )))));
        };
        if latest.actor.as_deref()
            != Some(if self.is_kernel() {
                self.account()
            } else {
                self.caller.actor()
            })
        {
            // Shared or handed over when it was written: not the person's
            // text, whoever holds the record now.
            tx.rollback().await?;
            return Ok(Some(judged(Some(not_applied(
                "this text was last saved by someone else, not by you",
                "To apply it, change it and save it yourself.",
            )))));
        }
        let base = revisions[1..]
            .iter()
            .find_map(|revision| folded.version_of_digest(&sha256_hex(&revision.body)))
            .and_then(|version| folded.versions.get(version as usize - 1));
        let Some(base) = base else {
            tx.rollback().await?;
            return Ok(Some(judged(Some(not_applied(
                "Native cannot tell which version of the entry this text was edited from",
                "Restore an earlier version of the text from the record's history, then edit it.",
            )))));
        };

        match reconcile::reconcile(
            folded.current(),
            base,
            &held,
            &self.stored_subject_id(),
            &recorded_at,
        ) {
            Ok(Some(next)) => {
                self.append_native_edit(&mut tx, &mut act, folded.current(), &next, &digest)
                    .await?;
                self.commit(tx).await?;
                Ok(Some(judged(None)))
            }
            Ok(None) => {
                tx.rollback().await?;
                Ok(Some(judged(None)))
            }
            Err(problem) => {
                tx.rollback().await?;
                Ok(Some(judged(Some(not_applied(&problem, FIX_IT)))))
            }
        }
    }

    /// Project all status effects of the latest version's act, including a
    /// counterpart quarantined or released by it. Event authority committed
    /// already; view failures are best effort and cannot undo that decision.
    pub(super) async fn sync_version_views(&self, urn: &str) {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            match self.fold_all().await {
                Ok(fold) => {
                    for id in fold.entries.keys() {
                        self.sync_view(id).await;
                    }
                }
                Err(error) => eprintln!("[native-ce] kernel HCP views: {error}"),
            }
            self.sync_suggestions().await;
            return;
        }

        let related: Result<Vec<String>> = async {
            Ok(sqlx::query_scalar(
                "SELECT DISTINCT json_extract(payload, '$.entry_id') FROM control_events \
                 WHERE aggregate_kind = 'hcp_state' AND aggregate_id = ?1 \
                 AND type = 'hcp.entry.status_set.v1' AND act = \
                   (SELECT act FROM control_events WHERE aggregate_kind = 'hcp_state' \
                    AND aggregate_id = ?1 AND type IN ('hcp.entry.versioned.v1','hcp.entry.confirmed.v1') \
                    AND json_extract(payload, '$.entry_id') = ?2 ORDER BY seq DESC LIMIT 1)",
            )
            .bind(crate::control::hcp_state_aggregate_id(
                self.caller.credential(),
            ))
            .bind(urn)
            .fetch_all(self.db.write_pool())
            .await?)
        }
        .await;
        self.sync_view(urn).await;
        match related {
            Ok(related) => {
                for other in related {
                    if other != urn {
                        self.sync_view(&other).await;
                    }
                }
            }
            Err(error) => eprintln!("[native-ce] hcp_v2: related views not written: {error}"),
        }
        self.sync_suggestions().await;
    }

    /// Bring the view of `urn` up to the state the events hold, best effort:
    /// the change it follows is already durable, so a failure here leaves a
    /// stale or missing view that the next sync repairs, and is logged, never
    /// returned.
    pub(super) async fn sync_view(&self, urn: &str) {
        if let Err(error) = Box::pin(self.try_sync_view(urn)).await {
            eprintln!("[native-ce] hcp_v2: view of {urn} not written: {error}");
        }
    }

    async fn try_sync_view(&self, urn: &str) -> Result<()> {
        let Some(record_id) = record_id_of(urn) else {
            return Ok(());
        };
        // An edit of the view is part of the state before the view is written.
        let judged = Box::pin(self.reconcile_view(urn)).await?;
        let Some(folded) = self.folded(urn).await? else {
            return Ok(());
        };
        let entry = folded.current().clone();
        let body = entry.view_body();

        let mut tx = self.db.write_pool().begin().await?;
        let held = view_body(self, &mut tx, &record_id).await?;
        let Some(held) = held else {
            tx.rollback().await?;
            return self.create_view(&record_id, &entry, &body).await;
        };
        let Some(policy_revision) = private_revision(self, &mut tx, &record_id).await? else {
            // Not the caller's private view any more: leave it alone.
            tx.rollback().await?;
            return Ok(());
        };
        let note = edit_note(self, &mut tx, &record_id).await?;
        tx.rollback().await?;

        match classify(&folded, &held) {
            ViewBody::Current => {
                // Put right by the person: nothing left to explain.
                if note.is_some() {
                    self.set_edit_note(&record_id, &policy_revision, None)
                        .await?;
                }
                return Ok(());
            }
            ViewBody::Stale => {}
            ViewBody::Edited => match &judged {
                // Changed since it was judged: the next sync reads it afresh.
                Some(judged) if judged.digest != sha256_hex(&held) => return Ok(()),
                None => return Ok(()),
                // An edit that cannot be taken: the person's text stays.
                Some(Judged {
                    problem: Some(text),
                    ..
                }) => {
                    if note.as_deref() != Some(text.as_str()) {
                        self.set_edit_note(&record_id, &policy_revision, Some(text))
                            .await?;
                    }
                    return Ok(());
                }
                // Nothing the person manages changed, or it is now a version:
                // the body is brought to the state.
                Some(_) => {}
            },
        }
        Box::pin(managed_update(
            self,
            json!({
                "id": record_id,
                "name": Self::display_name(&entry),
                "body_set": body,
                "if_body_digest": sha256_hex(&held),
                "if_policy_revision": policy_revision,
                "facets": self.facets(&entry),
                "reason": self.reason("view sync", None),
                "sources": [],
            }),
        ))
        .await
        .map(|_| ())
        .map_err(|error| match error {
            // Moved under us (the person edited it again, or shared it):
            // the next sync reads it afresh.
            Error::Conflict(_) => Error::engine("the view changed while it was written"),
            other => other,
        })
    }

    /// Set (or, with `None`, clear) the note on the view that says why the
    /// person's last edit was not applied. The body is not touched.
    async fn set_edit_note(
        &self,
        record_id: &str,
        policy_revision: &str,
        note: Option<&str>,
    ) -> Result<()> {
        Box::pin(managed_update(
            self,
            json!({
                "id": record_id,
                "if_policy_revision": policy_revision,
                "facets": { FACET_EDIT_NOTE: note },
                "reason": self.reason("view note", None),
                "sources": [],
            }),
        ))
        .await
        .map(|_| ())
        .map_err(|error| match error {
            Error::Conflict(_) => Error::engine("the view changed while it was noted"),
            other => other,
        })
    }

    async fn create_view(&self, record_id: &str, entry: &Entry, body: &str) -> Result<()> {
        let mut facets = self.facets(entry);
        facets.retain(|_, value| !value.is_null());
        Box::pin(managed_create(
            self,
            json!({
                "id": record_id,
                "type": "Resolution",
                "kind": KIND,
                "name": Self::display_name(entry),
                "body": body,
                "facets": facets,
                "access_policy": "account_only",
                "reason": self.reason("view create", None),
                "sources": [],
            }),
        ))
        .await?;
        Ok(())
    }
}

pub(super) async fn managed_update(store: &Store<'_>, arguments: Value) -> Result<Value> {
    #[cfg(feature = "v2-kernel-probe")]
    if store.is_kernel() {
        return super::kernel_view::update(store, arguments).await;
    }
    crate::mcp::tools::lifecycle::update_record(store.db.clone(), store.caller.clone(), arguments)
        .await
}
pub(super) async fn managed_create(store: &Store<'_>, arguments: Value) -> Result<Value> {
    #[cfg(feature = "v2-kernel-probe")]
    if store.is_kernel() {
        return super::kernel_view::create(store, arguments).await;
    }
    crate::mcp::tools::lifecycle::create_record(store.db.clone(), store.caller.clone(), arguments)
        .await
}

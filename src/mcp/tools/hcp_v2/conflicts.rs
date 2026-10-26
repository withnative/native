//! Memory Manager §15.2 and Core §4.7. The fold is the only candidate source.
//! Every transition is appended inside the version writer's transaction.
//! C3 can use append_transition for version-bound confirmation effects; no
//! suggestion or editable facet is a conflict/confirmation authority here.

use super::client::ClientIdentity;
use super::model::{normalize_dimension, Entry, MODEL_INFERRED, USER_DECLARED};
use super::store::{Store, Stored, WriteTx};
use crate::error::Result;
use chrono::{DateTime, Utc};

fn dimension(entry: &Entry) -> Option<String> {
    entry
        .dimension()
        .map(normalize_dimension)
        .filter(|d| !d.is_empty())
}

pub(super) fn authoritative(entry: &Entry) -> bool {
    (entry.declaration_type() == USER_DECLARED
        && matches!(
            entry.assurance(),
            "authenticated" | "cryptographically-verified"
        ))
        || entry.confirmed()
}

fn opposed(a: &Entry, b: &Entry) -> bool {
    matches!(
        (a.declaration_type(), b.declaration_type()),
        (MODEL_INFERRED, USER_DECLARED) | (USER_DECLARED, MODEL_INFERRED)
    )
}

fn live(entry: &Entry, now: DateTime<Utc>) -> bool {
    matches!(entry.status(), "active" | "conflicted") && !entry.expired(now)
}

pub(super) fn in_conflict(a: &Entry, b: &Entry, now: DateTime<Utc>) -> bool {
    live(a, now)
        && live(b, now)
        && opposed(a, b)
        && a.category() == b.category()
        && dimension(a).is_some()
        && dimension(a) == dimension(b)
}

fn arises(a: &Entry, b: &Entry, now: DateTime<Utc>) -> bool {
    let declared = if a.declaration_type() == USER_DECLARED {
        a
    } else {
        b
    };
    in_conflict(a, b, now) && declared.status() == "active"
}

fn quarantined(a: bool, b: bool) -> Option<(bool, bool)> {
    match (a, b) {
        (true, true) => None,
        (true, false) => Some((false, true)),
        (false, true) => Some((true, false)),
        (false, false) => Some((true, true)),
    }
}

impl Store<'_> {
    pub(super) async fn evaluate_conflicts(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        urn: &str,
        before: Option<&Entry>,
    ) -> Result<()> {
        let now = Utc::now();
        let fold = self.fold_all_in(tx).await?;
        let Some(subject) = fold.entries.get(urn) else {
            return Ok(());
        };
        let mut subject = Stored::from(subject);
        // Freeze the arising set before quarantining either side. In particular
        // §15.2 says an *active* user declaration; a later third inference
        // against a quarantined declaration does not newly arise as a conflict.
        let matched: Vec<Stored> = fold
            .entries
            .values()
            .filter(|f| f.current().id() != urn && arises(&subject.entry, f.current(), now))
            .map(Stored::from)
            .collect();
        let client = || super::store::payload_of(&ClientIdentity::native());
        for mut other in matched {
            let Some((hit_subject, hit_other)) =
                quarantined(authoritative(&subject.entry), authoritative(&other.entry))
            else {
                continue;
            };
            if hit_other && other.entry.status() != "conflicted" {
                self.append_transition(
                    tx,
                    act,
                    &other,
                    "conflicted",
                    "conflict",
                    "entries address the same category and dimension",
                    Some(urn),
                    client(),
                )
                .await?;
                other.entry.set_status("conflicted");
            }
            if hit_subject && subject.entry.status() != "conflicted" {
                self.append_transition(
                    tx,
                    act,
                    &subject,
                    "conflicted",
                    "conflict",
                    "entries address the same category and dimension",
                    Some(other.entry.id()),
                    client(),
                )
                .await?;
                subject.entry.set_status("conflicted");
            }
        }
        // Delete/reject never invokes this pass. Per §4.7.3 the counterpart
        // stays quarantined until a later revision, even after a deletion.
        // Reevaluate the revised entry and former counterparts only; unrelated
        // writes must not repair the deliberately retained reject/delete gap.
        let fold = self.fold_all_in(tx).await?;
        let mut release = Vec::new();
        for candidate in fold.entries.values() {
            let entry = candidate.current();
            let former = before.is_some_and(|old| {
                old.id() != entry.id()
                    && opposed(old, entry)
                    && old.category() == entry.category()
                    && dimension(old).is_some()
                    && dimension(old) == dimension(entry)
            });
            if entry.status() == "conflicted"
                && (entry.id() == urn || former)
                && !fold.entries.values().any(|other| {
                    other.current().id() != entry.id() && in_conflict(entry, other.current(), now)
                })
            {
                release.push(Stored::from(candidate));
            }
        }
        for entry in release {
            let related = if entry.entry.id() != urn {
                Some(urn)
            } else {
                before.and_then(|old| {
                    fold.entries
                        .values()
                        .map(|f| f.current())
                        .find(|other| {
                            other.id() != urn
                                && opposed(old, other)
                                && old.category() == other.category()
                                && dimension(old).is_some()
                                && dimension(old) == dimension(other)
                        })
                        .map(Entry::id)
                })
            };
            self.append_transition(
                tx,
                act,
                &entry,
                "active",
                "release",
                "the revised entry no longer conflicts",
                related,
                client(),
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn standing_never_quarantines_authoritative_entries() {
        assert_eq!(quarantined(true, true), None);
        assert_eq!(quarantined(true, false), Some((false, true)));
        assert_eq!(quarantined(false, true), Some((true, false)));
        assert_eq!(quarantined(false, false), Some((true, true)));
        let entry = |declared, assurance, confirmations| {
            Entry(json!({"record":{
            "declarationType":declared,"provenance":{"assertedBy":{"assurance":assurance},"confirmations":confirmations}}}))
        };
        assert!(authoritative(&entry(
            USER_DECLARED,
            "authenticated",
            json!([])
        )));
        assert!(!authoritative(&entry(
            USER_DECLARED,
            "unverified",
            json!([])
        )));
        assert!(!authoritative(&entry(
            MODEL_INFERRED,
            "authenticated",
            json!([])
        )));
        assert!(authoritative(&entry(
            MODEL_INFERRED,
            "unverified",
            json!([{"disposition":"confirmed"}])
        )));
        assert!(!authoritative(&entry(
            MODEL_INFERRED,
            "unverified",
            json!([{"disposition":"confirmed"},{"disposition":"rejected"}])
        )));
    }
}

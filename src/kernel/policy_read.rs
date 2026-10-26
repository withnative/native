//! Immutable policy descriptions and content-write guards over kernel authority.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub(crate) struct Entry {
    pub kind: String,
    pub subject: String,
    pub capability: String,
}
pub(crate) struct Snapshot {
    pub target: String,
    pub anchor: String,
    pub mode: &'static str,
    pub entries: Vec<Entry>,
    pub revision: String,
    pub capability: Capability,
}

/// The caller authorizes enumeration separately; guard-only consumers need
/// View, not policy administration. The exact-root exception belongs only to
/// the verified hosted owner, as in v1's policy-access repair path.
pub(crate) async fn snapshot_on(
    conn: &mut SqliteConnection,
    actor: &str,
    requested: &str,
    root_operator: bool,
) -> Result<Snapshot> {
    let requested = if requested == "native:root" {
        KERNEL_ROOT_ID
    } else {
        requested
    };
    let capability = kernel_effective_capability_on(conn, actor, requested).await?;
    if !capability.allows(Capability::View) && !(root_operator && requested == KERNEL_ROOT_ID) {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let is_home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(requested)
            .fetch_one(&mut *conn)
            .await?;
    let target = if is_home {
        requested.to_owned()
    } else {
        comments_v2::derived_terminal_on(conn, requested)
            .await?
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?
    };
    let (home, owner): (String, Option<String>) = if is_home {
        (
            target.clone(),
            sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
                .bind(&target)
                .fetch_one(&mut *conn)
                .await?,
        )
    } else {
        sqlx::query_as("SELECT home_id,owner_id FROM kernel_records WHERE id=?")
            .bind(&target)
            .fetch_one(&mut *conn)
            .await?
    };
    // Use the evaluator's own nearest-anchor walk, not a second ACL model.
    let anchor = kernel_policy_anchor_on(conn, &home).await?;
    let logical = v1_state::lifecycle_bearer_on(conn, &anchor, None).await?;
    let mode = if (is_home && anchor == target) || logical == target {
        "explicit"
    } else {
        "inherit"
    };
    let physical: Vec<(String,String,String,String)> = sqlx::query_as(
        "SELECT subject_kind,subject_id,effect,capability FROM kernel_policy_entries WHERE root_id=?"
    ).bind(&anchor).fetch_all(&mut *conn).await?;
    let rows = hosted_identity::policy_description_on(conn, &anchor)
        .await?
        .unwrap_or(physical);
    let mut normalized = BTreeMap::new();
    for (kind, subject, effect, cap) in rows {
        if effect != "allow" || !matches!(kind.as_str(), "account" | "members") {
            return Err(Error::engine(
                "policy contains an unsupported subject or effect",
            ));
        }
        let cap = parse_kernel_capability(&cap)?;
        let old = normalized
            .entry((kind, subject))
            .or_insert(Capability::None);
        if cap > *old {
            *old = cap;
        }
    }
    let entries: Vec<_> = normalized
        .into_iter()
        .map(|((kind, subject), cap)| Entry {
            kind,
            subject,
            capability: cap.as_policy_str().unwrap_or("none").into(),
        })
        .collect();
    let seq: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=? AND type IN ('kernel.home_created.v1','kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')")
        .bind(&anchor).fetch_one(&mut *conn).await?;
    let mut digest = Sha256::new();
    digest.update(b"native.kernel.policy-revision.v1\0");
    digest.update(serde_json::to_vec(&serde_json::json!([
        target, owner, mode, anchor, seq, entries
    ]))?);
    let revision = format!("prv2:{}", hex::encode(digest.finalize()));
    Ok(Snapshot {
        target,
        anchor: logical,
        mode,
        entries,
        revision,
        capability,
    })
}

pub(crate) async fn assert_revision_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.trim().is_empty() {
        return Err(Error::engine(
            "update_record: 'if_policy_revision' must be a non-empty opaque policy revision",
        ));
    }
    if snapshot_on(conn, actor, id, false).await?.revision != expected {
        return Err(Error::conflict(
            "update_record: policy revision conflict; list the policy and retry",
        ));
    }
    Ok(())
}

//! Authenticated selector-only read. The owned proof never leaves this module.
use super::{facet_resolver, generated};
use crate::{db::DatabaseOpenMode, mcp::Caller, Db, Error, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    id: String,
    record_type: String,
    kind: Option<String>,
    home: String,
    selection: Selection,
    #[serde(default)]
    profile: facet_resolver::Profile,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Selection {
    Keys { keys: Vec<String> },
    All,
}

pub(crate) async fn execute(db: &Db, actor: &str, caller: &Caller, args: Value) -> Result<Value> {
    if db.open_mode() != DatabaseOpenMode::ReadWrite {
        return Err(Error::engine(
            "view_profile_unsupported: proposal requires the hosted v2 writer",
        ));
    }
    let request: Request = serde_json::from_value(args)?;
    if request.action != "propose_view" {
        return Err(Error::engine("invalid proposal action"));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    tokio::time::timeout_at(
        deadline.into(),
        Box::pin(async {
            let workspace = {
                let mut conn = db.pool().begin().await?;

                // This is exactly admit_dispatched_on's no-claim branch. Avoid
                // constructing its large consent future for an ordinary caller.
                if crate::provenance::current_app_claim().is_some() {
                    Box::pin(crate::kernel::app_installs::admit_dispatched_on(
                        &mut conn, actor,
                    ))
                    .await?;
                }

                let workspace = generated::workspace_on(&mut conn).await?;
                conn.rollback().await?;
                workspace
            };

            let selection = match request.selection {
                Selection::Keys { keys } => {
                    let count = keys.len();
                    if !(1..=18).contains(&count) {
                        return Err(Error::engine(
                            "proposal selection requires 1..18 unique keys",
                        ));
                    }
                    let keys: BTreeSet<_> = keys.into_iter().collect();
                    if keys.len() != count {
                        return Err(Error::engine(
                            "proposal selection requires 1..18 unique keys",
                        ));
                    }
                    crate::query::generated_facets::Selection::Keys(keys)
                }
                Selection::All => crate::query::generated_facets::Selection::All,
            };

            let candidate = Box::pin(facet_resolver::prepare_profile(
                db,
                actor,
                &workspace,
                &request.id,
                facet_resolver::Request {
                    record_type: request.record_type,
                    kind: request.kind,
                    home: request.home,
                    selection,
                },
                request.profile.compiler(),
                deadline,
            ))
            .await?;

            candidate.validate(deadline).await?;

            // Same post-read consent fence as other composed hosted reads.
            if let Some(app) = caller.host_asserted_app() {
                Box::pin(crate::kernel::app_installs::admit_account_app_as(
                    db,
                    caller.credential(),
                    app,
                ))
                .await?;
            }
            Ok(
                json!({"format":"native.named-view-proposal.v1", "name":candidate.name,
            "definition_sha256":candidate.revision.definition_sha256,
            "definition":candidate.revision.definition}),
            )
        }),
    )
    .await
    .map_err(|_| Error::engine("generated proposal deadline exceeded"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proposal_refuses_physically_read_only_profiles_without_effects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canonical.db");
        let (db, actor) = crate::kernel::create_v2_database(
            path.to_str().unwrap(),
            "account",
            "Owner",
            "acct:profile",
        )
        .await
        .unwrap();
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let standby = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
            .await
            .unwrap();
        // member-read-v1 uses its real closed physical profile, not a forged
        // open-mode bit or a canonical file masquerading as a member copy.
        let member_path = dir.path().join("member.db");
        let member = rusqlite::Connection::open(&member_path).unwrap();
        member
            .execute_batch(&crate::schema::member_schema::member_ddl_statements().join(";\n"))
            .unwrap();
        drop(member);
        let member_before = std::fs::read(&member_path).unwrap();
        let member = crate::db::open_member_database_read_only(member_path.to_str().unwrap())
            .await
            .unwrap();
        for profile in [&standby, &member] {
            for run in [None, Some("scout-chair-a748b2")] {
                let caller = Caller::authenticated("acct:profile")
                    .with_run_context(run.map(str::to_owned), None);
                // Bad selector deliberately proves profile refusal comes first:
                // neither source scan nor authority/proposal preparation runs.
                let error = execute(profile, &actor, &caller, json!({"action":"propose_view"}))
                    .await
                    .unwrap_err();
                assert!(
                    error.to_string().starts_with("view_profile_unsupported:"),
                    "{error}"
                );
            }
        }
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        assert_eq!(
            0,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_runs")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        member.close().await;
        assert_eq!(member_before, std::fs::read(&member_path).unwrap());
        assert!(!member_path.with_extension("db-wal").exists());
    }
}

//! Dashboard reads retain the canonical pool path or use a sealed member
//! transaction. A held file never supplies a canonical database capability.
use super::*;

pub(super) enum DashboardReadSource<'a> {
    Pool(&'a Db),
    #[cfg(feature = "v2-kernel-probe")]
    Native(&'a mut crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession),
}

impl DashboardReadSource<'_> {
    pub(super) fn live(&self, alias: &str, member: bool) -> String {
        #[cfg(feature = "v2-kernel-probe")]
        if matches!(self, Self::Native(_)) {
            return format!(
                "{} AND {alias}.archived=0",
                crate::mcp::kernel_v2::native_query_hidden_predicate(alias, &[])
            );
        }
        let hidden = if member {
            crate::query::member_not_hidden_predicate(alias)
        } else {
            crate::query::not_hidden_predicate(alias)
        };
        format!("{hidden} AND NOT EXISTS (SELECT 1 FROM facet_values av WHERE av.record_id={alias}.id AND av.key='archived')")
    }

    pub(super) async fn rows(&mut self, statement: String) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
        Ok(match self {
            Self::Pool(db) => sqlx::query(&statement).fetch_all(db.write_pool()).await?,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                sqlx::query(&statement)
                    .fetch_all(&mut **session.transaction())
                    .await?
            }
        })
    }

    pub(super) async fn scope(
        &mut self,
        caller: &Caller,
        root: &mut String,
    ) -> Result<Vec<String>> {
        const TOOL: &str = "get_dashboard";
        match self {
            Self::Pool(db) => {
                if caller.is_member_copy() {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
                    )
                    .bind(&*root)
                    .fetch_one(db.pool())
                    .await?;
                    if !exists {
                        return Err(super::super::record_not_found(TOOL, root));
                    }
                    tree::member_subtree_ids(db, root, false).await
                } else {
                    require_record(db, caller, TOOL, root, Capability::View).await?;
                    tree::subtree_ids(db, root).await
                }
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                *root =
                    super::super::lifecycle::native_member_resolve_reference(session, root, TOOL)
                        .await?;
                if !crate::query::read::ordinary_record_read_eligible_native_member_in(
                    session.transaction(),
                    root,
                )
                .await?
                {
                    return Err(super::super::record_not_found(TOOL, root));
                }
                tree::native_member_subtree_ids_in(session.transaction(), root, false).await
            }
        }
    }

    pub(super) async fn record_visible(&mut self, caller: &Caller, id: &str) -> Result<bool> {
        match self {
            Self::Pool(db) if !caller.is_member_copy() => {
                can_record(db, caller, id, Capability::View).await
            }
            // Both member sources select candidates only from their closed E(m).
            _ => Ok(true),
        }
    }

    pub(super) async fn visible(
        &mut self,
        caller: &Caller,
        ids: Vec<String>,
    ) -> Result<HashSet<String>> {
        match self {
            Self::Pool(db) => visible_ids(db, caller, ids).await,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => Ok(sqlx::query_scalar("SELECT id FROM records WHERE deleted_at IS NULL AND id IN (SELECT value FROM json_each(?))")
                .bind(serde_json::to_string(&ids)?).fetch_all(&mut **session.transaction()).await?.into_iter().collect()),
        }
    }

    pub(super) async fn interpreter(&mut self, caller: &Caller) -> Result<LifecycleInterpreter> {
        match self {
            Self::Pool(db) => {
                if caller.is_member_copy() {
                    let rows =
                        crate::query::cascade::schema_config_rows_in_pool(db.pool(), None).await?;
                    LifecycleInterpreter::load_from_pool(db.pool(), rows).await
                } else {
                    let principal = (!super::super::is_legacy_local(caller))
                        .then(|| super::super::principal(caller));
                    LifecycleInterpreter::load(db, principal).await
                }
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                let rows =
                    crate::query::cascade::schema_config_rows_on(session.transaction()).await?;
                LifecycleInterpreter::load_from_connection(session.transaction(), rows).await
            }
        }
    }

    pub(super) async fn superseded(
        &mut self,
        caller: &Caller,
        entries: &mut [Value],
    ) -> Result<()> {
        match self {
            Self::Pool(db) => {
                super::super::lifecycle::annotate_superseded_by_in_pools(
                    db.write_pool(),
                    db.write_pool(),
                    caller,
                    entries,
                )
                .await
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                super::super::lifecycle::annotate_superseded_by_in_tx(
                    session.transaction(),
                    caller,
                    entries,
                )
                .await
            }
        }
    }

    pub(super) async fn census(
        &mut self,
        caller: &Caller,
        steps: &[pipeline::Step],
    ) -> Result<pipeline::PipelineOutput> {
        let opts = pipeline::PipelineOptions::default();
        let (output, _) = match self {
            Self::Pool(db) if super::super::is_legacy_local(caller) => {
                pipeline::run_with_diagnostics(
                    db,
                    steps,
                    Some(pipeline::CountAxis::Lifecycle),
                    &opts,
                )
                .await?
            }
            Self::Pool(db) => {
                pipeline::run_with_diagnostics_as(
                    db,
                    super::super::principal(caller),
                    steps,
                    Some(pipeline::CountAxis::Lifecycle),
                    &opts,
                )
                .await?
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                pipeline::run_member_with_diagnostics(
                    session,
                    steps,
                    Some(pipeline::CountAxis::Lifecycle),
                    &opts,
                )
                .await?
            }
        };
        Ok(output)
    }
}

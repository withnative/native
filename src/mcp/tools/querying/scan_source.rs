//! Scan-only source seam. Native selection requires the sealed admitted
//! transaction; pool callers retain their original caller-relative reads.
use super::*;

pub(super) enum ScanReadSource<'a> {
    Pool(&'a Db),
    #[cfg(feature = "v2-kernel-probe")]
    Native(&'a mut crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession),
}
impl ScanReadSource<'_> {
    pub(super) fn native(&self) -> bool {
        match self {
            Self::Pool(_) => false,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(_) => true,
        }
    }
    pub(super) fn hidden(&self, alias: &str, member: bool) -> String {
        #[cfg(feature = "v2-kernel-probe")]
        if self.native() {
            return crate::mcp::kernel_v2::native_query_hidden_predicate(alias, &[]);
        }
        if member {
            crate::query::member_not_hidden_predicate(alias)
        } else {
            crate::query::not_hidden_predicate(alias)
        }
    }
    pub(super) async fn rows(
        &mut self,
        statement: &str,
        binds: &[String],
    ) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
        let mut query = sqlx::query(statement);
        for bind in binds {
            query = query.bind(bind.clone());
        }
        Ok(match self {
            Self::Pool(db) => query.fetch_all(db.write_pool()).await?,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => query.fetch_all(&mut **session.transaction()).await?,
        })
    }
    pub(super) async fn visible(
        &mut self,
        caller: &Caller,
        ids: Vec<String>,
    ) -> Result<HashSet<String>> {
        match self {
            Self::Pool(db) => super::super::visible_ids(db, caller, ids).await,
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                // Closed profile membership is E(m). Related endpoints may
                // have dedicated presentation (e.g. comments); independent
                // visibility is not the generic corpus's hidden-family filter.
                let encoded = serde_json::to_string(&ids)?;
                Ok(sqlx::query_scalar("SELECT id FROM records WHERE deleted_at IS NULL AND id IN (SELECT value FROM json_each(?))")
                    .bind(encoded).fetch_all(&mut **session.transaction()).await?.into_iter().collect())
            }
        }
    }
    pub(super) async fn subtree(
        &mut self,
        root: &str,
        include_archived: bool,
    ) -> Result<Vec<String>> {
        match self {
            Self::Pool(db) => {
                crate::query::tree::member_subtree_ids(db, root, include_archived).await
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                crate::query::tree::native_member_subtree_ids_in(
                    session.transaction(),
                    root,
                    include_archived,
                )
                .await
            }
        }
    }
    pub(super) async fn references(
        &mut self,
        caller: &Caller,
        ids: &[String],
    ) -> Result<HashMap<String, Option<String>>> {
        match self {
            Self::Pool(db) => {
                if caller.is_member_copy() {
                    member_scan_display_references(db.write_pool(), ids).await
                } else {
                    let borrowed = ids.iter().map(String::as_str).collect::<Vec<_>>();
                    crate::mcp::record_ref::display_references(db, &borrowed).await
                }
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                let encoded = serde_json::to_string(ids)?;
                let rows=sqlx::query("SELECT record_id,display_reference FROM member_display_references WHERE record_id IN (SELECT value FROM json_each(?))")
                    .bind(encoded).fetch_all(&mut **session.transaction()).await?;
                rows.into_iter()
                    .map(|row| {
                        Ok((
                            row.try_get("record_id")?,
                            Some(row.try_get("display_reference")?),
                        ))
                    })
                    .collect()
            }
        }
    }
    pub(super) async fn superseded(
        &mut self,
        caller: &Caller,
        samples: &mut [Value],
    ) -> Result<()> {
        match self {
            Self::Pool(db) => {
                super::super::lifecycle::annotate_superseded_by_in_pools(
                    db.write_pool(),
                    db.write_pool(),
                    caller,
                    samples,
                )
                .await
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                super::super::lifecycle::annotate_superseded_by_in_tx(
                    session.transaction(),
                    caller,
                    samples,
                )
                .await
            }
        }
    }
    pub(super) async fn interpreter(
        &mut self,
        caller: &Caller,
    ) -> Result<crate::query::lifecycle::LifecycleInterpreter> {
        match self {
            Self::Pool(db) => {
                if caller.is_member_copy() {
                    let rows =
                        crate::query::cascade::schema_config_rows_in_pool(db.write_pool(), None)
                            .await?;
                    crate::query::lifecycle::LifecycleInterpreter::load_from_pool(
                        db.write_pool(),
                        rows,
                    )
                    .await
                } else {
                    let principal = (!super::super::is_legacy_local(caller))
                        .then(|| super::super::principal(caller));
                    crate::query::lifecycle::LifecycleInterpreter::load(db, principal).await
                }
            }
            #[cfg(feature = "v2-kernel-probe")]
            Self::Native(session) => {
                let rows =
                    crate::query::cascade::schema_config_rows_on(session.transaction()).await?;
                crate::query::lifecycle::LifecycleInterpreter::load_from_connection(
                    session.transaction(),
                    rows,
                )
                .await
            }
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn native_member_scan(
    session: &mut crate::member_copy_kernel_v2::profile::session::NativeMemberReadSession,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    if !caller.is_member_copy() || caller.actor() != session.principal() {
        return Err(Error::copy_unavailable());
    }
    let mut args: ScanArgs = super::super::parse_args("scan", arguments)?;
    let (recent_window_days, high_degree_min, include_archived) = scan_bounds(&args)?;
    // A local member has no hosted context. The shared legacy selector's
    // is_host_owner check treats that absence as owner authority; the sealed
    // member session instead binds every explicit selector to its actor.
    if args
        .authored_by
        .as_deref()
        .is_some_and(|selector| selector != caller.credential())
    {
        return Err(Error::engine(
            "scan: authored_by may name only the current caller",
        ));
    }
    scan_authored_selector(caller, &args)?;
    if let Some(root) = args.scope.as_mut() {
        *root =
            super::super::lifecycle::native_member_resolve_reference(session, root, "scan").await?;
        if !crate::query::read::ordinary_record_read_eligible_native_member_in(
            session.transaction(),
            root,
        )
        .await?
        {
            return Err(Error::engine(format!(
                "scan: scope record {root} does not exist"
            )));
        }
        if crate::query::tree::native_member_subtree_ids_in(
            session.transaction(),
            root,
            include_archived,
        )
        .await?
        .is_empty()
        {
            return Err(Error::engine(format!(
                "scan: scope record {root} does not exist"
            )));
        }
    }
    let mut source = ScanReadSource::Native(session);
    // Native uses one request-consistent corpus for every served axis. The
    // canonical/v1 coordinator retains its original pool/subtree behavior.
    let (corpus_where, corpus_binds) =
        member_scan_predicate(&mut source, &args, include_archived).await?;
    let rows = source
        .rows(
            &format!("SELECT r.id FROM records r WHERE {corpus_where}"),
            &corpus_binds,
        )
        .await?;
    let ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let corpus_size = source.visible(caller, ids).await?.len() as i64;
    let mut census = member_scan_census_from_source(&mut source, &args, include_archived).await?;
    census.insert(
        "provenance".into(),
        member_unavailable_marker("scan.provenance"),
    );
    let mut axes = serde_json::Map::new();
    axes.insert(
        "authored_by".into(),
        member_unavailable_marker("scan.authored_by"),
    );
    if let Some(query) = args
        .query
        .as_deref()
        .filter(|query| !query.trim().is_empty())
    {
        let opts = FtsOptions {
            scope: args.scope.clone(),
            include_archived,
            limit: Some(SCAN_SAMPLE_LIMIT as i64),
            types: args.types.clone().unwrap_or_default(),
            member: true,
            exclude_predicate: None,
        };
        let ScanReadSource::Native(session) = &mut source else {
            return Err(Error::copy_unavailable());
        };
        let count = fts::native_member_pool_count(session, query, &opts).await?;
        let hits =
            fts::native_member_matches(session, query, &opts, fts::SearchMechanism::Strict).await?;
        axes.insert(
            "lexical".into(),
            AxisFacet {
                count,
                samples: hits
                    .iter()
                    .map(|hit| AxisSample {
                        id: hit.id.clone(),
                        record_type: hit.record_type.clone(),
                        name: hit.name.clone(),
                        evidence: vec![
                            ("score".into(), json!(hit.score)),
                            ("snippet".into(), json!(hit.snippet)),
                        ],
                    })
                    .collect(),
            }
            .to_json(corpus_size),
        );
    }
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(recent_window_days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let recent_sql=format!("SELECT r.id,r.type,r.name,r.last_activity_at FROM records r WHERE {corpus_where} AND r.last_activity_at>=? ORDER BY r.last_activity_at DESC,r.id");
    let mut recent_binds = corpus_binds.clone();
    recent_binds.push(cutoff.clone());
    axes.insert(
        "recent".into(),
        axis_from_source(
            &mut source,
            caller,
            &recent_sql,
            &recent_binds,
            Some(AxisMetricColumn {
                sql_alias: "last_activity_at",
                json_key: "last_activity_at",
                kind: AxisMetricKind::Text,
            }),
        )
        .await?
        .to_json(corpus_size),
    );
    axes.insert(
        "high_degree".into(),
        derived_relationship_axis_from_source(
            &mut source,
            caller,
            &corpus_where,
            &corpus_binds,
            DerivedAxisMetric::Degree,
            high_degree_min,
            true,
        )
        .await?
        .to_json(corpus_size),
    );
    axes.insert(
        "containers".into(),
        derived_relationship_axis_from_source(
            &mut source,
            caller,
            &corpus_where,
            &corpus_binds,
            DerivedAxisMetric::ChildCount,
            1,
            true,
        )
        .await?
        .to_json(corpus_size),
    );
    annotate_scan_axes_lifecycle_from_source(&mut source, caller, &mut axes).await?;
    annotate_scan_axes_record_paths_from_source(&mut source, caller, &mut axes).await?;
    annotate_scan_axes_superseded_from_source(&mut source, caller, &mut axes).await?;
    Ok(finish_scan(
        corpus_size,
        &args,
        census,
        axes,
        cutoff,
        (recent_window_days, high_degree_min),
        true,
    ))
}

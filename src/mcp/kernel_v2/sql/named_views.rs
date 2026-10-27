//! Caller-visible publications read on the same snapshot as their source rows.
use super::*;
#[cfg(test)]
use crate::kernel::named_views as carrier;
use crate::kernel::named_views::Binding;
use crate::mcp::tools::querying::SavedSqlDefinition;
use std::collections::BTreeMap;

#[cfg(test)]
tokio::task_local! { static CATALOG_STATIC_RESERVE: std::time::Duration; }
// Leave static staging time within the original outer deadline. This is a
// reserve, not a fresh deadline starting when registry discovery begins.
fn catalog_static_reserve() -> std::time::Duration {
    #[cfg(test)]
    if let Ok(budget) = CATALOG_STATIC_RESERVE.try_with(|budget| *budget) {
        return budget;
    }
    std::time::Duration::from_millis(500)
}

pub(super) fn map_setup_error(error: Error) -> Error {
    match error {
        Error::Sqlx(error) => guard::map_stream_error(error),
        error => error,
    }
}

pub(super) struct View {
    pub record: String,
    pub binding: Binding,
    pub revision: i64,
    pub definition: SavedSqlDefinition,
    pub description: String,
    pub detail: Option<Value>,
}
#[derive(Default)]
pub(super) struct Registry {
    pub views: BTreeMap<String, View>,
    pub invalid: BTreeMap<String, String>,
    pub validators: Option<guard::NamedViewValidators>,
    pub selected: BTreeSet<String>,
    overflow: bool,
    body_reads: BTreeSet<(String, String)>,
    pub retained: Option<crate::named_views::closure::Closure>,
    pub pins: BTreeMap<String, crate::named_views::Pin>,
    pub omission: Option<&'static str>,
}

pub(super) fn needed(
    preflight: &Result<(PreparedRead, BTreeSet<(String, String)>)>,
    args: &Value,
) -> bool {
    match preflight {
        Ok((_, reads)) => reads.iter().any(|(r, _)| {
            matches!(
                r.as_str(),
                "catalog_relations" | "catalog_columns" | "catalog_view_definitions"
            )
        }),
        Err(_) => args
            .get("sql")
            .and_then(Value::as_str)
            .filter(|sql| sql.len() <= contract::MAX_SQL_BYTES)
            .and_then(|sql| crate::query::turso_ast_rules::named_view_references(sql).ok())
            .is_some_and(|names| names.iter().any(|n| n.starts_with("view_"))),
    }
}

impl Registry {
    fn omitted(reason: &'static str) -> Self {
        Self {
            omission: Some(reason),
            ..Self::default()
        }
    }
    fn retained_view(
        name: &str,
        pin: &crate::named_views::Pin,
        node: &crate::named_views::closure::Node,
    ) -> View {
        View {
            record: pin
                .view_id
                .strip_prefix("native.named-view:")
                .unwrap()
                .into(),
            binding: Binding {
                v: 1,
                name: name.into(),
                definition_sha256: pin.definition_sha256.clone(),
                origin: "authored".into(),
            },
            revision: 0,
            definition: node.definition.query.static_shape(),
            description: node.definition.description.clone(),
            detail: Some(crate::named_views::details::summary(
                name,
                pin,
                &node.definition,
            )),
        }
    }
    pub(super) async fn load_retained(
        tx: &mut sqlx::SqliteConnection,
        actor: &str,
        args: &Value,
        pins: Option<BTreeMap<String, crate::named_views::Pin>>,
        deadline: Instant,
    ) -> Result<Self> {
        #[cfg(test)]
        let _ = STATS.try_with(|s| s.borrow_mut().named_registry_loads += 1);
        use crate::named_views::{self as retained, closure};
        let requested = crate::query::turso_ast_rules::named_view_references(
            args["sql"].as_str().unwrap_or_default(),
        )?;
        let catalog = requested.iter().any(|n| {
            matches!(
                n.as_str(),
                "catalog_relations" | "catalog_columns" | "catalog_view_definitions"
            )
        });
        let catalog_only = catalog && !requested.iter().any(|name| name.starts_with("view_"));
        let outer_deadline = deadline;
        let deadline = if catalog_only {
            deadline
                .checked_sub(catalog_static_reserve())
                .unwrap_or_else(Instant::now)
        } else {
            deadline
        };
        let incomplete = || {
            Self::omitted("Dynamic named-view catalog rows omitted: view_catalog_incomplete; retry on the hosted writer.")
        };
        let roots = if let Some(pins) = pins {
            pins
        } else {
            if catalog_only && !retained::storage::verify_index_on(tx).await? {
                // Continuity over freshness: static catalogs stay available
                // without scanning unrelated history. Dynamic rows require the
                // optional accelerator; explicit view reads retain fallback.
                return Ok(Self::omitted("Dynamic named-view catalog rows omitted: run prepare_named_views on the hosted writer."));
            }
            let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
                .fetch_one(&mut *tx)
                .await?;
            let state = match retained::storage::load_live(tx, head, deadline).await {
                Ok(state) => state,
                Err(error) if catalog_only => {
                    retained::storage::check_deadline(outer_deadline)?;
                    if matches!(error, Error::Sqlx(_)) {
                        return Err(error);
                    }
                    return Ok(incomplete());
                }
                Err(error) => return Err(error),
            };
            if state.legacy() {
                if catalog_only {
                    return Ok(Self::omitted("Dynamic named-view catalog rows omitted: legacy admissions need re-authoring as retained revisions."));
                }
                #[cfg(test)]
                return Self::load(tx, actor).await;
                #[cfg(not(test))]
                return Err(Error::engine(
                    "view_legacy_format: re-author the legacy admission as a retained revision",
                ));
            }
            state
                .bindings()
                .values()
                .filter_map(|b| b.active.as_ref())
                .filter(|(name, _)| catalog || requested.contains(name))
                .cloned()
                .collect()
        };
        if requested
            .iter()
            .any(|name| name.starts_with("view_") && !roots.contains_key(name))
        {
            return Err(Error::engine(retained::MISSING));
        }
        let mut registry = Self::default();
        let mut budget = closure::CertificationBudget::default();
        if roots.is_empty() {
            return Ok(registry);
        }
        let execution_roots: BTreeMap<_, _> = roots
            .iter()
            .filter(|(name, _)| requested.contains(*name))
            .map(|(n, p)| (n.clone(), p.clone()))
            .collect();
        if !execution_roots.is_empty() {
            let plan =
                closure::resolve_budgeted_on(tx, actor, &execution_roots, deadline, &mut budget)
                    .await?;
            // Executable roots are combined first. Only a failed combined
            // analysis pays for isolation; no partial result executes.
            match crate::query::sql::view_validation::analyze(&plan, deadline).await {
                Ok(reads) => registry.body_reads = reads,
                Err(error) => {
                    for (name, pin) in &execution_roots {
                        let isolated = closure::resolve_budgeted_on(
                            tx,
                            actor,
                            &BTreeMap::from([(name.clone(), pin.clone())]),
                            deadline,
                            &mut budget,
                        )
                        .await?;
                        crate::query::sql::view_validation::analyze(&isolated, deadline).await?;
                    }
                    return Err(error);
                }
            }
            for (name, pin) in &execution_roots {
                let node = plan.nodes.iter().find(|n| &n.pin == pin).unwrap();
                registry
                    .views
                    .insert(name.clone(), Self::retained_view(name, pin, node));
            }
            registry.pins = execution_roots;
            registry.retained = Some(plan);
        }
        if catalog {
            // A catalog-only read never constructs a combined validator.
            // Independent metadata candidates do not consume execution-union
            // staging budgets, and hidden/broken closures contribute no rows.
            let mut candidates = Vec::new();
            for (name, pin) in &roots {
                retained::storage::check_deadline(outer_deadline)?;
                if catalog_only && Instant::now() >= deadline {
                    return Ok(incomplete());
                }
                if registry.views.contains_key(name) {
                    continue;
                }
                let resolved = closure::resolve_budgeted_on(
                    tx,
                    actor,
                    &BTreeMap::from([(name.clone(), pin.clone())]),
                    deadline,
                    &mut budget,
                )
                .await;
                if resolved
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("view_revision_unavailable"))
                {
                    registry.omission = Some("Dynamic named-view catalog rows omitted: a retained revision is unavailable on this serving version.");
                }
                let resolved_budget_exhausted = resolved
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("view_budget_exceeded"));
                if let Err(Error::Sqlx(error)) = resolved {
                    return Err(Error::Sqlx(error));
                }
                if let Ok(plan) = resolved {
                    candidates.push((name, pin, plan));
                }
                retained::storage::check_deadline(outer_deadline)?;
                if catalog_only && Instant::now() >= deadline {
                    return Ok(incomplete());
                }
                if resolved_budget_exhausted {
                    // Retain already certified rows, with an honest partial-catalog notice.
                    registry.omission = incomplete().omission;
                    break;
                }
            }
            // At most eight independent candidates, sharing the existing
            // process-wide eight-worker limit. Serial worker waits spend the
            // catalog deadline repeatedly under concurrent read traffic. This
            // still constructs no combined catalog validator.
            let valid = futures::future::join_all(candidates.iter().map(|(_, _, plan)| async {
                crate::query::sql::view_validation::analyze(plan, deadline)
                    .await
                    .is_ok()
            }))
            .await;
            retained::storage::check_deadline(outer_deadline)?;
            if catalog_only && Instant::now() >= deadline {
                return Ok(incomplete());
            }
            for ((name, pin, plan), valid) in candidates.into_iter().zip(valid) {
                if valid {
                    let node = plan.nodes.iter().find(|n| &n.pin == pin).unwrap();
                    registry
                        .views
                        .insert(name.clone(), Self::retained_view(name, pin, node));
                }
            }
        }
        Ok(registry)
    }

    #[cfg(test)]
    pub(super) async fn load(tx: &mut sqlx::SqliteConnection, actor: &str) -> Result<Self> {
        // The canonical event witness prevents an imported/authored facet from
        // impersonating an engine admission. Cap candidates before decoding; the
        // optional preparation index avoids scanning unrelated history.
        let rows: Vec<(String, Option<String>, i64, String)> =
            sqlx::query_as(carrier::DISCOVER_SQL)
                .fetch_all(&mut *tx)
                .await?;
        if rows.len() as i64 > carrier::MAX_BINDINGS {
            // Only disclose registry overflow to a caller who can see a bearer.
            // Otherwise retain the ordinary missing-relation preflight error.
            let mut visible_bearer = false;
            for (record, _, _, _) in &rows {
                if kernel::read_record_on(tx, actor, record).await?.is_some() {
                    visible_bearer = true;
                    break;
                }
            }
            return Ok(Self {
                overflow: visible_bearer,
                ..Self::default()
            });
        }
        let mut registry = Self::default();
        for (record, raw, revision, witness) in rows {
            let Some(bearer) = kernel::read_record_on(tx, actor, &record).await? else {
                continue;
            };
            // The immutable witness supplies a diagnostic name even when the
            // current facet is malformed. It never grants access by itself.
            let witness_name = serde_json::from_str::<Value>(&witness)
                .ok()
                .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_owned));
            let parsed = (|| -> Result<Binding> {
                let raw = raw
                    .as_deref()
                    .ok_or_else(|| Error::engine("binding facet missing"))?;
                if raw.len() > carrier::MAX_CARRIER_BYTES {
                    return Err(Error::engine("invalid named view binding size"));
                }
                let binding: Binding = serde_json::from_str(raw)?;
                carrier::validate_name(&binding.name)?;
                if Some(binding.name.as_str()) != witness_name.as_deref() {
                    return Err(Error::engine("binding name differs from admission witness"));
                }
                Ok(binding)
            })();
            let binding = match parsed {
                Ok(binding) => binding,
                Err(error) => {
                    if let Some(name) = witness_name {
                        registry.views.remove(&name);
                        registry.invalid.insert(name, error.to_string());
                    }
                    continue;
                }
            };
            let definition_raw: Option<String> = sqlx::query_scalar(
                "SELECT value FROM main.kernel_facets WHERE record_id=? AND key='query'",
            )
            .bind(&record)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            let definition = (|| -> Result<SavedSqlDefinition> {
                let raw = definition_raw.ok_or_else(|| Error::engine("query facet missing"))?;
                if raw.len() > carrier::MAX_CARRIER_BYTES {
                    return Err(Error::engine("definition exceeds 256 KiB"));
                }
                let definition: SavedSqlDefinition = serde_json::from_str(&raw)?;
                carrier::validate_definition(&definition)?;
                if binding.v != 1
                    || binding.origin != "authored"
                    || carrier::digest(&definition)? != binding.definition_sha256
                {
                    return Err(Error::engine(
                        "admitted definition digest changed; named view unavailable",
                    ));
                }
                guard::NamedViewValidators::new(&[(binding.name.clone(), definition.sql.clone())])?;
                Ok(definition)
            })();
            match definition {
                Ok(definition) => {
                    let mut description = bearer
                        .fields
                        .get("summary")
                        .or_else(|| bearer.fields.get("v1_summary"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if description.len() > 4096 {
                        let mut end = 4096;
                        while !description.is_char_boundary(end) {
                            end -= 1;
                        }
                        description.truncate(end);
                    }
                    let name = binding.name.clone();
                    if registry.invalid.contains_key(&name) {
                        continue;
                    }
                    if registry
                        .views
                        .insert(
                            name.clone(),
                            View {
                                record,
                                binding,
                                revision,
                                definition,
                                description,
                                detail: None,
                            },
                        )
                        .is_some()
                    {
                        registry.views.remove(&name);
                        registry
                            .invalid
                            .insert(name, "duplicate named view publication".into());
                    }
                }
                Err(error) => {
                    registry.views.remove(&binding.name);
                    registry.invalid.insert(binding.name, error.to_string());
                }
            }
        }
        if !registry.views.is_empty() {
            registry.validators = Some(guard::NamedViewValidators::new(
                &registry
                    .views
                    .values()
                    .map(|v| (v.binding.name.clone(), v.definition.sql.clone()))
                    .collect::<Vec<_>>(),
            )?);
        }
        Ok(registry)
    }

    pub(super) fn expand(&mut self, reads: &mut BTreeSet<(String, String)>) -> Result<()> {
        self.selected = reads
            .iter()
            .filter_map(|(r, _)| self.views.contains_key(r).then_some(r.clone()))
            .collect();
        if let Some(plan) = &self.retained {
            // Every retained dependency is contractual, including one SQLite
            // prunes from an unused CTE or an outer projection.
            self.selected.extend(plan.roots.keys().cloned());
            reads.extend(self.body_reads.iter().cloned());
            reads.retain(|(r, _)| {
                !self.views.contains_key(r) && !plan.nodes.iter().any(|n| &n.alias == r)
            });
            return Ok(());
        }
        for name in &self.selected {
            // Observe the whole authored SELECT, not only columns retained by
            // SQLite's outer projection pruning (e.g. COUNT(*) or EXISTS).
            reads.extend(guard::public_reads_ad_hoc(
                &self.views[name].definition.sql,
            )?);
        }
        reads.retain(|(r, _)| !self.selected.contains(r));
        Ok(())
    }

    pub(super) async fn append_catalog(
        &mut self,
        tx: &mut sqlx::SqliteConnection,
        reads: &BTreeSet<(String, String)>,
    ) -> Result<()> {
        if !reads.iter().any(|(r, _)| {
            matches!(
                r.as_str(),
                "catalog_relations" | "catalog_columns" | "catalog_view_definitions"
            )
        }) {
            return Ok(());
        }
        for view in self.views.values() {
            if let Some(detail) = &view.detail {
                sqlx::query(
                    "INSERT INTO temp.catalog_view_definitions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                )
                .bind(&view.binding.name)
                .bind(detail["view_id"].as_str())
                .bind(detail["revision_id"].as_str())
                .bind(detail["definition_sha256"].as_str())
                .bind(detail["schema_sha256"].as_str())
                .bind(serde_json::to_string(&detail["origin"])?)
                .bind(detail["description"].as_str())
                .bind(serde_json::to_string(&detail["scope"])?)
                .bind(serde_json::to_string(&detail["source_pins"])?)
                .bind(serde_json::to_string(&detail["dependencies"])?)
                .bind(serde_json::to_string(&detail["columns"])?)
                .execute(&mut *tx)
                .await?;
            }
            let revision = view
                .detail
                .as_ref()
                .and_then(|d| d["revision_id"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| view.revision.to_string());
            let comment = format!(
                "{}; named view; revision {}; definition_sha256 {}",
                view.description, revision, view.binding.definition_sha256
            );
            sqlx::query("INSERT INTO temp.catalog_relations VALUES(?,?,1,1,'best_effort','sqlite-local-v2',?)")
                .bind(&view.binding.name).bind(format!("native.named-view:{}", view.record)).bind(comment).execute(&mut *tx).await?;
            for (position, column) in view.definition.output.columns.iter().enumerate() {
                sqlx::query("INSERT INTO temp.catalog_columns VALUES(?,?,?)")
                    .bind(&view.binding.name)
                    .bind(&column.name)
                    .bind(position as i64)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) async fn register(&mut self, tx: &mut sqlx::SqliteConnection) -> Result<()> {
        use sqlx::Executor;
        if self.selected.is_empty() {
            return Ok(());
        }
        if let Some(plan) = &self.retained {
            for node in &plan.nodes {
                let (body, _) = contract::rewrite_utc_date_label_calls(
                    contract::QuerySqlProfile::SqliteLocal,
                    &node.sql,
                    contract::UtcDateLabelEngine::Sqlite,
                )?;
                sqlx::query(&format!(
                    "CREATE TEMP VIEW \"{}\" AS {}",
                    node.alias,
                    body.trim().trim_end_matches(';')
                ))
                .persistent(false)
                .execute(&mut *tx)
                .await?;
                let described = (&mut *tx)
                    .describe(&format!("SELECT * FROM temp.\"{}\" WHERE 0", node.alias))
                    .await?;
                let actual: Vec<_> = described.columns().iter().map(|c| c.name()).collect();
                let expected: Vec<_> = node
                    .definition
                    .query
                    .output
                    .columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect();
                if actual != expected {
                    return Err(Error::engine("view_source_invalidated: prepared labels"));
                }
            }
            for (name, alias) in &plan.roots {
                sqlx::query(&format!(
                    "CREATE TEMP VIEW \"{name}\" AS SELECT * FROM \"{alias}\""
                ))
                .persistent(false)
                .execute(&mut *tx)
                .await?;
            }
            return Ok(());
        }

        for name in &self.selected {
            let view = &self.views[name];
            // This existing portable helper is lowered by ordinary query_sql.
            // View bodies also need that lowering; they are not part of the
            // outer statement's rewrite. Clock/principal binds are refused.
            let (definition_sql, _) = contract::rewrite_utc_date_label_calls(
                contract::QuerySqlProfile::SqliteLocal,
                &view.definition.sql,
                contract::UtcDateLabelEngine::Sqlite,
            )?;
            let sql = format!(
                r#"CREATE TEMP VIEW "{name}" AS {}"#,
                definition_sql.trim().trim_end_matches(';')
            );
            sqlx::query(&sql)
                .persistent(false)
                .execute(&mut *tx)
                .await?;
            let sql = format!(r#"SELECT * FROM temp."{name}" WHERE 0"#);
            let described = (&mut *tx).describe(&sql).await?;
            let labels: Vec<_> = described.columns().iter().map(|c| c.name()).collect();
            let expected: Vec<_> = view
                .definition
                .output
                .columns
                .iter()
                .map(|c| c.name.as_str())
                .collect();
            if labels != expected {
                return Err(contract::categorized_error(
                    contract::QuerySqlErrorCategory::SyntaxOrType,
                    format!("named view '{name}' compiled output does not match admitted columns"),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn unavailable(&self, args: &Value) -> Result<()> {
        let Some(sql) = args.get("sql").and_then(Value::as_str) else {
            return Ok(());
        };
        if let Ok(names) = crate::query::turso_ast_rules::named_view_references(sql) {
            for name in names {
                if self.overflow && name.starts_with("view_") {
                    return Err(contract::categorized_error(
                        contract::QuerySqlErrorCategory::UnauthorizedRelation,
                        "named view registry exceeds binding cap; named views unavailable",
                    ));
                }
                if let Some(error) = self.invalid.get(&name) {
                    return Err(contract::categorized_error(
                        contract::QuerySqlErrorCategory::UnauthorizedRelation,
                        format!("named view '{name}' unavailable: {error}"),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_view_registry_routing_preserves_static_reads() {
        for sql in [
            "SELECT id FROM records ORDER BY id LIMIT 1",
            "SELECT 'view_secret' AS label FROM records",
            "SELECT missing FROM records",
            "WITH view_local AS (SELECT missing FROM records) SELECT * FROM view_local",
            "WITH view_local AS (SELECT id FROM records) SELECT id FROM view_local",
        ] {
            let args = json!({"sql":sql});
            assert!(
                !needed(&prepare_read("caller", args.clone(), false), &args),
                "{sql}"
            );
        }
        for sql in [
            "SELECT * FROM catalog_columns",
            "SELECT id FROM view_notes",
            "SELECT v.id FROM records r JOIN view_notes v ON v.id=r.id",
        ] {
            let args = json!({"sql":sql});
            assert!(
                needed(&prepare_read("caller", args.clone(), false), &args),
                "{sql}"
            );
        }
    }
}

#[cfg(test)]
mod live_catalog_tests {
    use super::*;
    #[tokio::test]
    async fn named_view_catalog_child_expiry_keeps_static_rows_and_outer_timeout() {
        let (db, actor) =
            crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
                .await
                .unwrap();
        // This exercises the real registry + staging path, not a stand-in timer.
        let reply = CATALOG_STATIC_RESERVE
            .scope(
                std::time::Duration::from_secs(2),
                super::super::query_sql(
                    &db,
                    &actor,
                    json!({"sql":"SELECT relation_name FROM catalog_relations"}),
                ),
            )
            .await
            .unwrap();
        assert!(reply["row_count"].as_u64().unwrap() > 0);
        assert_eq!(reply["notices"][0]["code"], "view_catalog_incomplete");
        let mut tx = db.pool().begin().await.unwrap();
        let error = match Registry::load_retained(
            &mut tx,
            &actor,
            &json!({"sql":"SELECT * FROM catalog_relations"}),
            None,
            Instant::now(),
        )
        .await
        {
            Ok(_) => panic!("an expired outer deadline must propagate"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("deadline"), "{error}");
        tx.rollback().await.unwrap();
    }
}

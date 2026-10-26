//! Caller-scoped schema validators. Never installed in the thread-local caches.
use super::*;
use crate::Error;

/// Only Rule failures may survive beyond the request. Connection setup,
/// resource failures and worker errors are transient, even during preparation.
#[derive(Debug)]
pub(crate) enum SchemaFailure {
    Rule(Error),
    Infrastructure(Error),
}
impl SchemaFailure {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Rule(error) | Self::Infrastructure(error) => error,
        }
    }
}
impl From<Error> for SchemaFailure {
    fn from(error: Error) -> Self {
        Self::Rule(error)
    }
}

pub(crate) struct NamedViewValidators {
    frozen: rusqlite::Connection,
    strict: rusqlite::Connection,
    names: BTreeSet<String>,
}

impl NamedViewValidators {
    #[cfg(test)]
    pub(crate) fn new(definitions: &[(String, String)]) -> Result<Self> {
        Self::build(definitions, false)
    }

    // Engine-only aliases are accepted solely from an already bounded closure.
    #[allow(dead_code)] // PR 2b wires request validation.
    pub(crate) fn from_closure(closure: &crate::named_views::closure::Closure) -> Result<Self> {
        let mut definitions = closure
            .nodes
            .iter()
            .map(|n| (n.alias.clone(), n.sql.clone()))
            .collect::<Vec<_>>();
        definitions.extend(
            closure
                .roots
                .iter()
                .map(|(name, alias)| (name.clone(), format!("SELECT * FROM \"{alias}\""))),
        );
        Self::build(&definitions, true)
    }

    /// Resolve the author's relation names to the same exact tuples so SQLite
    /// can compare original and rewritten output labels.
    #[allow(dead_code)] // PR 2b wires request validation.
    pub(crate) fn for_original(
        closure: &crate::named_views::closure::Closure,
        node: &crate::named_views::closure::Node,
    ) -> Result<Self> {
        let mut definitions: Vec<_> = closure
            .nodes
            .iter()
            .map(|n| (n.alias.clone(), n.sql.clone()))
            .collect();
        for (name, dep) in &node.definition.query.relations {
            if let crate::named_views::contract::Dependency::View(pin) = dep {
                let child = closure
                    .nodes
                    .iter()
                    .find(|n| &n.pin == pin)
                    .ok_or_else(|| contract_violation("missing closure tuple"))?;
                definitions.push((name.clone(), format!("SELECT * FROM \"{}\"", child.alias)));
            }
        }
        Self::build(&definitions, true)
    }

    fn build(definitions: &[(String, String)], internal: bool) -> Result<Self> {
        let frozen = build_frozen_validator()?;
        let strict = build_strict_validator()?;
        configure_kernel_v2_bindings(&frozen, true)?;
        configure_kernel_v2_bindings(&strict, false)?;
        let mut names = BTreeSet::new();
        for (name, sql) in definitions {
            if internal && name.starts_with("_native_view_") {
                let suffix = name
                    .strip_prefix("_native_view_")
                    .ok_or_else(|| contract_violation("invalid internal alias"))?;
                if suffix.len() != 64
                    || !suffix
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return Err(contract_violation("invalid internal alias"));
                }
            } else {
                crate::kernel::named_views::validate_name(name)?;
            }
            sql_contract::classify_single_read_statement(
                sql_contract::QuerySqlProfile::SqliteLocal,
                sql,
            )?;
            crate::query::turso_ast_rules::validate_named_view_shape(sql)?;
            if !internal {
                validate_kernel_v2_ad_hoc(sql)?;
            }
            if !names.insert(name.clone()) {
                return Err(contract_violation("duplicate named view"));
            }
            let ddl = format!(
                "CREATE TEMP VIEW \"{name}\" AS {}",
                sql.trim().trim_end_matches(';')
            );
            for conn in [&frozen, &strict] {
                conn.execute_batch(&ddl)
                    .map_err(|e| contract_violation(e.to_string()))?;
            }
        }
        Ok(Self {
            frozen,
            strict,
            names,
        })
    }

    fn prepare(
        &self,
        conn: &rusqlite::Connection,
        statement: &str,
        expansion: bool,
        portable: bool,
    ) -> std::result::Result<KernelSqlInspection, SchemaFailure> {
        let names = self.names.clone();
        let reads = Arc::new(std::sync::Mutex::new(BTreeSet::new()));
        let observed = reads.clone();
        #[cfg(feature = "v2-kernel-probe")]
        let budget = super::view_validation::current();
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            #[cfg(feature = "v2-kernel-probe")]
            if budget.as_ref().is_some_and(|b| b.check().is_err()) {
                return Authorization::Deny;
            }
            // COUNT(*) can omit the direct Read(view) callback. SQLite still
            // reports expansion through the view's accessor; observe it without
            // granting that accessor any engine-only privileges.
            if let Some(accessor) = context.accessor.filter(|name| names.contains(*name)) {
                observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert((accessor.to_owned(), String::new()));
            }
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                if context.database_name == Some("temp") && names.contains(table_name) {
                    observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert((table_name.to_owned(), column_name.to_owned()));
                    return Authorization::Allow;
                }
                let relation = if strict_lifecycle_source_read(&context, table_name) {
                    "record_lifecycle_interpretations"
                } else if strict_reaction_source_read(&context, table_name) {
                    "message_reactions"
                } else {
                    table_name
                };
                if sql_contract::is_logical_relation(relation) {
                    observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert((relation.to_owned(), column_name.to_owned()));
                }
            }
            match (expansion, portable) {
                (true, true) => authorize_kernel_v2_portable_view_expansion(context),
                (true, false) => authorize_kernel_v2_view_expansion(context),
                (false, true) => authorize_strict(context),
                (false, false) => authorize_strict_ad_hoc(context),
            }
        }));
        let prepared = conn.prepare(statement);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        let prepared = prepared.map_err(|e| {
            use rusqlite::ffi::ErrorCode;
            let deterministic = matches!(
                e.sqlite_error_code(),
                Some(
                    ErrorCode::Unknown
                        | ErrorCode::AuthorizationForStatementDenied
                        | ErrorCode::TypeMismatch
                )
            );
            let error =
                sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, e.to_string());
            if deterministic {
                SchemaFailure::Rule(error)
            } else {
                SchemaFailure::Infrastructure(error)
            }
        })?;
        if !prepared.readonly() {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::UnsafeStatement,
                "read-only statement writes",
            )
            .into());
        }
        let labels = prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut unique = BTreeSet::new();
        if labels.iter().any(|s| !unique.insert(s)) {
            return Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::DuplicateColumns,
                "duplicate output labels",
            )
            .into());
        }
        let reads = reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Ok((reads, labels))
    }

    pub(crate) fn inspect(&self, sql: &str) -> Result<KernelSqlInspection> {
        self.inspect_with(sql, false)
            .map_err(SchemaFailure::into_error)
    }
    pub(crate) fn inspect_saved(&self, sql: &str) -> Result<KernelSqlInspection> {
        self.inspect_with(sql, true)
            .map_err(SchemaFailure::into_error)
    }
    pub(crate) fn inspect_classified(
        &self,
        sql: &str,
    ) -> std::result::Result<KernelSqlInspection, SchemaFailure> {
        self.inspect_with(sql, true)
    }
    fn inspect_with(
        &self,
        sql: &str,
        portable: bool,
    ) -> std::result::Result<KernelSqlInspection, SchemaFailure> {
        let statement = if portable {
            sql_contract::classify_single_read_statement(
                sql_contract::QuerySqlProfile::SqliteLocal,
                sql,
            )
        } else {
            sql_contract::classify_sqlite_ad_hoc_statement(sql)
        }
        .map_err(Error::from)?;
        super::super::turso_ast_rules::check_statement(&statement)?;
        self.prepare(&self.frozen, &statement, true, portable)?;
        self.prepare(&self.strict, &statement, false, portable)
    }

    pub(crate) fn default_order(
        &self,
        statement: &str,
    ) -> Result<(String, Option<sql_contract::AssumedOrder>)> {
        apply_ad_hoc_default_order_with(statement, |sql| {
            // Describe before enforcing LIMIT ordering, as on the static path.
            // inspect() validates the fully rewritten statement afterwards.
            let statement = sql_contract::classify_sqlite_ad_hoc_statement(sql)?;
            self.prepare(&self.frozen, &statement, true, false)
                .map_err(SchemaFailure::into_error)?;
            self.prepare(&self.strict, &statement, false, false)
                .map(|(_, labels)| labels)
                .map_err(SchemaFailure::into_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn validators() -> NamedViewValidators {
        NamedViewValidators::new(&[
            (
                "view_notes".into(),
                "SELECT id,name FROM records WHERE type='Document'".into(),
            ),
            ("view_ids".into(), "SELECT id FROM records".into()),
        ])
        .unwrap()
    }
    #[test]
    fn named_view_validators_resolve_columns_and_keep_both_gates() {
        let v = validators();
        let (ordered, assumed) = v
            .default_order("SELECT id FROM view_notes LIMIT 1")
            .unwrap();
        assert!(assumed.is_some());
        v.inspect(&ordered).unwrap();
        for sql in [
            "SELECT * FROM view_notes",
            "SELECT count(*) AS n FROM view_notes",
            "SELECT n.id FROM view_notes n JOIN records r ON r.id=n.id",
            "SELECT a.id AS a,b.id AS b FROM view_notes a JOIN view_ids b ON a.id=b.id",
        ] {
            let (reads, labels) = v.inspect(sql).unwrap();
            assert!(!labels.is_empty());
            assert!(reads.iter().any(|(r, _)| r == "view_notes"));
        }
        for sql in [
            "CREATE TEMP VIEW stolen AS SELECT * FROM records",
            "SELECT * FROM main.records",
            "SELECT load_extension('x') FROM view_notes",
            "SELECT * FROM _query_sql_visible_records",
            "SELECT missing FROM view_notes",
            "SELECT * FROM view_notes; DELETE FROM records",
        ] {
            assert!(v.inspect(sql).is_err(), "{sql}");
        }
        assert!(
            validate_kernel_v2_ad_hoc("SELECT * FROM view_notes").is_err(),
            "fresh views never enter cached validators"
        );
    }
    #[test]
    fn named_view_definition_shape_rejects_qualified_and_shadowed_relations() {
        use crate::query::turso_ast_rules::{named_view_references, validate_named_view_shape};
        assert!(named_view_references("WITH _native_view_hidden AS (SELECT id FROM records) SELECT id FROM _native_view_hidden").is_err());
        for sql in [
            "SELECT id FROM main.records",
            "WITH records AS (SELECT 1 AS id) SELECT id FROM records",
            "SELECT id FROM records WHERE EXISTS(SELECT 1 FROM temp.records)",
            "WITH view_notes AS (SELECT id FROM records) SELECT id FROM view_notes",
        ] {
            assert!(validate_named_view_shape(sql).is_err(), "{sql}");
        }
        validate_named_view_shape("SELECT r.id FROM records r WHERE EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id)").unwrap();
        assert_eq!(
            named_view_references("SELECT 'view_secret' FROM records -- view_other").unwrap(),
            BTreeSet::from(["records".into()])
        );
    }
    use super::super::view_validation::run;
    #[tokio::test]
    async fn named_view_fresh_validator_deadline_interrupts_sqlite_and_retires() {
        let finished = Arc::new(tokio::sync::Notify::new());
        let notify = finished.clone();
        let result=run(Instant::now()+Duration::from_millis(100),move || {
            struct Finish(Arc<tokio::sync::Notify>);
            impl Drop for Finish {fn drop(&mut self){self.0.notify_one();}}
            let _finished=Finish(notify);
            let conn=build_strict_validator()?;
            conn.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n",[],|row|row.get::<_,i64>(0)).map_err(|e|contract_violation(e.to_string()))?;
            Ok(())
        }).await;
        assert!(result.unwrap_err().to_string().contains("deadline"));
        tokio::time::timeout(Duration::from_secs(2), finished.notified())
            .await
            .unwrap();
        run(Instant::now() + Duration::from_secs(2), || {
            let conn = build_strict_validator()?;
            let _: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
            Ok(())
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn named_view_fresh_validator_cancellation_interrupts_and_joins() {
        let started = Arc::new(tokio::sync::Notify::new());
        let arrived = started.clone();
        let finished = Arc::new(tokio::sync::Notify::new());
        let notify = finished.clone();
        let task = tokio::spawn(run(Instant::now() + Duration::from_secs(2), move || {
            struct Finish(Arc<tokio::sync::Notify>);
            impl Drop for Finish {
                fn drop(&mut self) {
                    self.0.notify_one();
                }
            }
            let _finished = Finish(notify);
            let conn = build_strict_validator()?;
            arrived.notify_one();
            conn.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n",[],|r|r.get::<_,i64>(0)).map_err(|e|contract_violation(e.to_string()))?;
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), finished.notified())
            .await
            .unwrap();
    }
}

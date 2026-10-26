//! Versioned retained contracts. Structural replay checks never consult the live
//! catalog; current pins and SQLite preparation are separate admission/read work.
use super::*;
use crate::mcp::tools::querying::{
    SavedSqlBounds, SavedSqlColumnType, SavedSqlDefinition, SavedSqlOutput, SavedSqlProfile,
    SavedSqlRelationDependency,
};
use crate::query::sql_contract as sql;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Dependency {
    Static(SavedSqlRelationDependency),
    View(Pin),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlV12 {
    pub v: String,
    pub kind: String,
    pub profile: SavedSqlProfile,
    pub catalog_revision: u32,
    pub relations: BTreeMap<String, Dependency>,
    pub sql: String,
    #[serde(default)]
    pub parameters: Vec<sql::QuerySqlParameter>,
    pub output: SavedSqlOutput,
    pub bounds: SavedSqlBounds,
}
impl SavedSqlV12 {
    pub(crate) fn static_shape(&self) -> SavedSqlDefinition {
        SavedSqlDefinition {
            v: "1.1".into(),
            kind: self.kind.clone(),
            profile: self.profile.clone(),
            catalog_revision: self.catalog_revision,
            relations: self
                .relations
                .iter()
                .filter_map(|(n, p)| match p {
                    Dependency::Static(p) => Some((n.clone(), p.clone())),
                    _ => None,
                })
                .collect(),
            sql: self.sql.clone(),
            parameters: self.parameters.clone(),
            output: self.output.clone(),
            bounds: self.bounds.clone(),
        }
    }
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn roots(&self) -> BTreeMap<String, Pin> {
        self.relations
            .iter()
            .filter_map(|(n, p)| match p {
                Dependency::View(p) => Some((n.clone(), p.clone())),
                _ => None,
            })
            .collect()
    }
    pub(crate) fn validate_retained(&self) -> Result<()> {
        if self.v != "1.2"
            || self.kind != "governed_sql"
            || self.relations.is_empty()
            || self.relations.len() > 32
        {
            return Err(invalid("governed SQL v1.2 envelope/dependency bound"));
        }
        sql::QuerySqlRequest {
            sql: self.sql.clone(),
            parameters: self.parameters.clone(),
        }
        .validate()
        .map_err(Error::from)?;
        if self.output.columns.is_empty()
            || self.output.columns.len() > 64
            || !(1..=1000).contains(&self.bounds.rows)
        {
            return Err(invalid("output/bounds exceed retained contract"));
        }
        let mut labels = BTreeSet::new();
        for column in &self.output.columns {
            if !identifier(&column.name) || !labels.insert(column.name.as_str()) {
                return Err(invalid("duplicate/nonportable output label"));
            }
        }
        let digest = format!(
            "{:x}",
            Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
                &serde_json::to_value(&self.output.columns)?
            ))
        );
        if self.output.schema_sha256 != digest {
            return Err(invalid("output schema digest mismatch"));
        }
        if self.output.row_identity.len() != 1
            || self.output.order.is_empty()
            || self.output.order.last().map(|o| &o.column) != self.output.row_identity.last()
        {
            return Err(invalid(
                "one stable row identifier and total order required",
            ));
        }
        let identity = self
            .output
            .columns
            .iter()
            .find(|c| self.output.row_identity.contains(&c.name))
            .ok_or_else(|| invalid("row identity unavailable"))?;
        if identity.nullable
            || !matches!(identity.column_type, SavedSqlColumnType::Identifier)
            || self
                .output
                .order
                .iter()
                .any(|o| !labels.contains(o.column.as_str()))
        {
            return Err(invalid("row identity/order contract mismatch"));
        }
        for (name, pin) in &self.relations {
            if !identifier(name) || name != &name.to_ascii_lowercase() {
                return Err(invalid("nonportable relation token"));
            }
            if let Dependency::View(pin) = pin {
                validate_name(name)?;
                validate_pin(pin)?;
            } else if name.starts_with("view_") {
                return Err(invalid("named dependencies require exact revision pins"));
            }
        }
        Ok(())
    }
    #[allow(dead_code)] // Admission and request execution stay dark in PR 2a.
    pub(crate) fn validate_current(&self) -> Result<()> {
        self.validate_current_in(true)
    }
    pub(crate) fn validate_for_preparation(&self) -> Result<()> {
        self.validate_current_in(false)
    }
    fn validate_current_in(&self, prepare_static: bool) -> Result<()> {
        self.validate_retained()?;
        let active = sql::QuerySqlProfile::SqliteLocal.contract();
        if self.profile.id != active.id
            || self.profile.revision != active.revision
            || self.catalog_revision != sql::LOGICAL_CATALOG_REVISION
        {
            return Err(invalid("view_source_invalidated: profile/catalog pin"));
        }
        sql::classify_single_read_statement(sql::QuerySqlProfile::SqliteLocal, &self.sql)?;
        crate::query::turso_ast_rules::check_statement(&self.sql)?;
        sql::check_positional_arguments(
            sql::QuerySqlProfile::SqliteLocal,
            &self.sql,
            self.parameters.len(),
        )?;
        sql::validate_regexp_bound_patterns(
            sql::QuerySqlProfile::SqliteLocal,
            &self.sql,
            &self.parameters,
        )?;
        sql::validate_utc_date_label_bound_args(
            sql::QuerySqlProfile::SqliteLocal,
            &self.sql,
            &self.parameters,
        )?;
        let used = crate::query::turso_ast_rules::named_view_references(&self.sql)?;
        if used.contains("catalog_view_definitions") {
            return Err(invalid("saved governed SQL cannot read catalog_view_definitions: caller-relative detail rows require standalone hosted ad-hoc query_sql"));
        }
        if used.contains("catalog_operations") {
            return Err(invalid("saved governed SQL cannot read catalog_operations: serving catalogue rows require online ad-hoc query_sql"));
        }
        if used != self.relations.keys().cloned().collect() {
            return Err(invalid("exact SQL dependency map required"));
        }
        for (name, dep) in &self.relations {
            if let Dependency::Static(pin) = dep {
                let relation = sql::LOGICAL_RELATIONS
                    .iter()
                    .find(|r| r.name == name)
                    .ok_or_else(|| invalid("unsupported static dependency"))?;
                if relation.identity != pin.identity
                    || relation.semantic_version != pin.semantic_version
                {
                    return Err(invalid("view_source_invalidated: relation pin"));
                }
            }
        }
        // Reuse the complete existing v1.1 validator when the statement is static.
        if prepare_static
            && self
                .relations
                .values()
                .all(|p| matches!(p, Dependency::Static(_)))
        {
            crate::mcp::tools::querying::validate_saved_sql(&SavedSqlDefinition {
                v: "1.1".into(),
                kind: self.kind.clone(),
                profile: self.profile.clone(),
                catalog_revision: self.catalog_revision,
                relations: self
                    .relations
                    .iter()
                    .filter_map(|(n, p)| match p {
                        Dependency::Static(p) => Some((n.clone(), p.clone())),
                        _ => None,
                    })
                    .collect(),
                sql: self.sql.clone(),
                parameters: self.parameters.clone(),
                output: self.output.clone(),
                bounds: self.bounds.clone(),
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Origin {
    Authored,
    Generated {
        generator: String,
        version: String,
        source_identity: String,
        selector: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePin {
    pub record_id: String,
    pub revision_id: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FieldMeaning {
    pub meaning: String,
    pub source_mapping: String,
    pub vocabulary: Option<String>,
    pub unit: Option<String>,
    pub encoding: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub description: String,
    pub cardinality: String,
    pub default_inclusion: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    pub query: SavedSqlV12,
    pub origin: Origin,
    pub description: String,
    pub scope: Scope,
    pub columns: BTreeMap<String, FieldMeaning>,
    pub source_pins: Vec<SourcePin>,
}
impl Definition {
    pub(crate) fn validate_retained(&self) -> Result<()> {
        self.query.validate_retained()?;
        bounded_text(&self.description, 4096)?;
        bounded_text(&self.scope.description, 4096)?;
        bounded_text(&self.scope.cardinality, 512)?;
        bounded_text(&self.scope.default_inclusion, 4096)?;
        if self.source_pins.len() > 32 || !self.query.parameters.is_empty() {
            return Err(invalid("view parameter/source bound"));
        }
        for pin in &self.source_pins {
            if uuid::Uuid::parse_str(&pin.revision_id).is_err()
                || !sha256(&pin.sha256)
                || pin.record_id.len() > 128
            {
                return Err(invalid("invalid source pin"));
            }
        }
        let names: BTreeSet<_> = self
            .query
            .output
            .columns
            .iter()
            .map(|c| c.name.clone())
            .collect();
        if names != self.columns.keys().cloned().collect() {
            return Err(invalid("every output needs exact field metadata"));
        }
        for field in self.columns.values() {
            bounded_text(&field.meaning, 512)?;
            bounded_text(&field.source_mapping, 256)?;
            if serde_json::to_vec(field)?.len() > 1024 {
                return Err(invalid("field metadata exceeds 1 KiB"));
            }
        }
        if serde_json::to_vec(&self.columns)?.len() > 64 * 1024
            || serde_json::to_vec(self)?.len() > MAX_CARRIER_BYTES
        {
            return Err(invalid("metadata carrier bound"));
        }
        if let Origin::Generated {
            generator,
            version,
            source_identity,
            selector,
        } = &self.origin
        {
            for value in [generator, version, source_identity, selector] {
                bounded_text(value, 1024)?;
            }
        }
        Ok(())
    }
    #[allow(dead_code)] // Admission and request execution stay dark in PR 2a.
    pub(crate) fn validate_current(&self) -> Result<()> {
        self.validate_current_in(true)
    }
    pub(crate) fn validate_for_preparation(&self) -> Result<()> {
        self.validate_current_in(false)
    }
    fn validate_current_in(&self, prepare_static: bool) -> Result<()> {
        self.validate_retained()?;
        if prepare_static {
            self.query.validate_current()?;
        } else {
            self.query.validate_for_preparation()?;
        }
        crate::query::turso_ast_rules::validate_named_view_shape(&self.query.sql)?;
        if self
            .query
            .relations
            .keys()
            .any(|n| n.starts_with("catalog_"))
        {
            return Err(invalid("views cannot depend on catalogs"));
        }
        let profile = sql::QuerySqlProfile::SqliteLocal;
        if sql::rewrite_now_ms_calls(profile, &self.query.sql, "?1")?.1 > 0
            || sql::rewrite_current_principal_calls(profile, &self.query.sql, "?1")?.1 > 0
        {
            return Err(invalid("views cannot contain clock/principal binds"));
        }
        Ok(())
    }
}
pub(crate) fn validate_pin(pin: &Pin) -> Result<()> {
    if !pin.view_id.starts_with("native.named-view:")
        || pin.view_id.len() > 160
        || uuid::Uuid::parse_str(&pin.revision_id).is_err()
        || !sha256(&pin.definition_sha256)
        || !sha256(&pin.schema_sha256)
    {
        return Err(invalid("invalid exact revision pin"));
    }
    Ok(())
}
pub(super) fn sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn identifier(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=128).contains(&b.len())
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}
fn bounded_text(text: &str, cap: usize) -> Result<()> {
    if text.trim().is_empty() || text.len() > cap {
        Err(invalid("required metadata missing/oversized"))
    } else {
        Ok(())
    }
}
pub(crate) fn authored_name(name: &str) -> Result<()> {
    validate_name(name)?;
    if name.starts_with("view_gen_") {
        return Err(invalid("view_gen_ is reserved"));
    }
    Ok(())
}
#[allow(dead_code)] // Generated admission is wired by PR 2b.
pub(crate) fn generated_name(
    workspace: &str,
    generator: &str,
    source: &str,
    selector: &str,
) -> String {
    let seed = serde_json::json!([workspace, generator, source, selector]);
    format!(
        "view_gen_{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(&seed))
    )
}

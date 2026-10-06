//! Scoped typed reads, with no revision/head shortcut and no caller SQL.
use futures::future::BoxFuture;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    portable_sql::*,
};

pub(super) fn canonical(value: &Value) -> Vec<u8> {
    // serde_json's default Map is BTreeMap (preserve_order is not enabled).
    // Rebuild explicitly to make that property independent of feature changes.
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut pairs = m.iter().collect::<Vec<_>>();
                pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                let mut m = serde_json::Map::new();
                for (k, v) in pairs {
                    m.insert(k.clone(), sorted(v));
                }
                Value::Object(m)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).expect("Value serialization is infallible")
}
pub(super) fn hash(component: &str, value: &Value) -> String {
    let mut h = Sha256::new();
    h.update(format!("native.sql-selected.{component}.v1"));
    h.update([0]);
    h.update(canonical(value));
    format!("{:x}", h.finalize())
}

pub(super) fn scalar(v: &NormalizedValue) -> SqlResult<Value> {
    Ok(match v {
        NormalizedValue::Null => json!({"type":"null"}),
        NormalizedValue::Text(v) => json!({"type":"text","value":v}),
        NormalizedValue::Bool(v) => json!({"type":"boolean","value":v}),
        NormalizedValue::Integer(v) => json!({"type":"integer","value":v.to_string()}),
        _ => return Err(SqlError::contract("unsupported scoped result type")),
    })
}
fn bind(v: &BindValue) -> SqlResult<Value> {
    Ok(match v {
        BindValue::Null(t) => json!({"type":"null","logical_type":t}),
        BindValue::Text(v) => json!({"type":"text","value":v}),
        BindValue::Bool(v) => json!({"type":"boolean","value":v}),
        BindValue::Integer(v) => json!({"type":"integer","value":v.to_string()}),
        _ => return Err(SqlError::contract("unsupported scoped binding type")),
    })
}

#[derive(Clone, Copy)]
pub(super) enum Inventory {
    Capability,
    Kind,
    Facet,
}
fn family(sql: &str, inventory: Inventory) -> Option<&'static str> {
    let s = sql
        .replace('"', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    match (inventory,s.as_str()) {
        (Inventory::Capability,"SELECT type, kind, deleted_at, owner_id, policy_anchor_id FROM records WHERE id = ?1")=>Some("auth.record.v1"),
        (Inventory::Capability,"SELECT target_id FROM links WHERE source_id = ?1 AND relationship = 'part_of' ORDER BY target_id")=>Some("auth.derived-bearers.v1"),
        (Inventory::Capability,"SELECT authority_bearer_record_id FROM semantic_units WHERE unit_id = ?1")=>Some("auth.unit-bearer.v1"),
        (Inventory::Capability,"SELECT EXISTS(SELECT 1 FROM record_policies WHERE record_id = ?1) AS explicit")=>Some("auth.explicit-policy.v1"),
        (Inventory::Capability,"SELECT subject_kind, subject_id, effect, capability FROM policy_entries WHERE policy_anchor_id = ?1")=>Some("auth.policy-entries.v1"),
        (Inventory::Capability,"SELECT EXISTS(SELECT 1 FROM bindings WHERE record_id = ?1 AND system = 'account' AND identifier = ?2 AND is_canonical = 1) AS owns")=>Some("auth.owner-binding.v1"),
        (Inventory::Kind,"SELECT vv.id, vv.status, vv.metadata, vv.alias_of, canonical.id AS canonical_id, canonical.value AS canonical_value, canonical.status AS canonical_status, canonical.metadata AS canonical_metadata FROM vocabularies v JOIN vocabulary_values vv ON vv.vocabulary_id = v.id LEFT JOIN vocabulary_values canonical ON canonical.id = vv.alias_of WHERE v.name = ?1 AND vv.value = ?2")=>Some("eligibility.kind.v1"),
        (Inventory::Facet,"SELECT EXISTS(SELECT 1 FROM vocabularies WHERE id=?1) AS found")=>Some("facet.ref-exists.v1"),
        (Inventory::Facet,"SELECT id,name FROM vocabularies WHERE id = ?1 OR name = ?2 ORDER BY id LIMIT 1")=>Some("facet.vocabulary-identity.v1"),
        (Inventory::Facet,"SELECT candidate.id,candidate.status,candidate.alias_of,canonical.id AS canonical_id,canonical.value AS canonical_value FROM vocabulary_values candidate LEFT JOIN vocabulary_values canonical ON canonical.id=candidate.alias_of WHERE candidate.vocabulary_id=?1 AND candidate.value=?2 ORDER BY candidate.id LIMIT 1")=>Some("facet.token-resolution.v1"),
        // Only used to explain rejected values; that trace never enters a plan.
        (Inventory::Facet,"SELECT value FROM vocabulary_values WHERE vocabulary_id = ?1 AND status = 'active' ORDER BY ordinal, value, id LIMIT ?2")=>Some("facet.refusal-alternatives.v1"),
        _=>None,
    }
}

pub(super) struct Recorder<'a> {
    inner: BorrowedSqliteStatementExecutor<'a>,
    inventory: Inventory,
    pub reads: Vec<Value>,
    pub unsupported: bool,
}
impl<'a> Recorder<'a> {
    pub fn new(connection: &'a mut sqlx::SqliteConnection, inventory: Inventory) -> Self {
        Self {
            inner: BorrowedSqliteStatementExecutor::new(connection),
            inventory,
            reads: Vec::new(),
            unsupported: false,
        }
    }
}
impl DomainStatementExecutor for Recorder<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            let rendered = statement.render(Dialect::Sqlite)?;
            let Some(template_id) = family(&rendered.sql, self.inventory) else {
                self.unsupported = true;
                return Err(SqlError::contract("unsupported scoped dependency template"));
            };
            let rows = self.inner.fetch_all(statement, bindings, columns).await?;
            let mut encoded = rows
                .iter()
                .map(|r| {
                    columns
                        .iter()
                        .map(|c| {
                            r.get(&c.name)
                                .ok_or_else(|| SqlError::contract("missing scoped column"))
                                .and_then(scalar)
                        })
                        .collect::<SqlResult<Vec<_>>>()
                        .map(Value::Array)
                })
                .collect::<SqlResult<Vec<_>>>()?;
            if !rendered.sql.contains("ORDER BY") {
                encoded.sort_by_cached_key(canonical);
            }
            self.reads.push(json!({"template_id":template_id,"template_version":1,
                "statement":{"kind":statement.kind(),"relation":statement.relation(),"sql":rendered.sql},
                "bindings":bindings.iter().map(bind).collect::<SqlResult<Vec<_>>>()?,
                "columns":columns.iter().map(|c|json!({"name":c.name,"type":c.logical_type,"nullable":c.nullable})).collect::<Vec<_>>(),"rows":encoded}));
            Ok(rows)
        })
    }
}

/// Included evidence has two disjoint lanes: successful raw dependency
/// traces before hashing, and complete component/wrapper projections. Denied
/// scratch contributes neither. Fragment checks bound memory while streaming;
/// finish replaces that lower bound with the exact complete projection encoding.
#[derive(Default)]
pub(super) struct Budget {
    raw: usize,
    projected: usize,
    raw_count: usize,
}
impl Budget {
    fn check(&self) -> Result<()> {
        if self
            .raw
            .checked_add(self.projected)
            .is_none_or(|n| n > 8_388_608)
        {
            return Err(Error::conflict(
                "sql_write: visible evidence exceeds 8MiB; narrow scope",
            ));
        }
        Ok(())
    }
    pub fn include(&mut self, value: &Value) -> Result<()> {
        self.projected = self
            .projected
            .checked_add(canonical(value).len())
            .ok_or_else(|| Error::conflict("sql_write: visible evidence budget exceeded"))?;
        self.check()
    }
    pub fn include_raw(&mut self, component: &str, value: &Value) -> Result<()> {
        let size = canonical(
            &json!({"domain":format!("native.sql-selected.{component}.v1"),"evidence":value}),
        )
        .len();
        self.raw = self
            .raw
            .checked_add(size + usize::from(self.raw_count > 0))
            .ok_or_else(|| Error::conflict("sql_write: visible evidence budget exceeded"))?;
        self.raw_count += 1;
        self.check()
    }
    pub fn finish(&mut self, components: &Value) -> Result<()> {
        // Exact conceptual {raw_dependency_evidence:[...],components:{...}}.
        // The raw records were sized before hashing, with multiplicity retained.
        self.projected =
            canonical(components).len() + b"{\"raw_dependency_evidence\":[],\"components\":}".len();
        self.check()
    }
}

pub(super) fn checked<T>(result: Result<T>, unsupported: bool) -> Result<T> {
    if unsupported {
        return Err(Error::conflict(
            "sql_write: unsupported scoped dependency; use reviewed explicit-ID tools",
        ));
    }
    result.map_err(|_|Error::engine("sql_write: scoped evaluation could not complete; repair authoritative storage/state before retry"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_pre_hash_budget_has_exact_byte_boundary_and_typed_wrappers() {
        let wrapper = b"{\"raw_dependency_evidence\":[],\"components\":}".len();
        let mut budget = Budget::default();
        let components = json!("x".repeat(8_388_608 - wrapper - 2));
        budget.finish(&components).unwrap();
        assert!(budget
            .finish(&json!("x".repeat(8_388_608 - wrapper - 1)))
            .is_err());
        let mut budget = Budget::default();
        budget
            .include_raw(
                "capability-trace",
                &json!({"principal":{"account_id":"acct:x","is_member":false},"id":"visible"}),
            )
            .unwrap();
        assert!(budget.finish(&components).is_err());
        assert_ne!(hash("source", &json!("x")), hash("schema", &json!("x")));
        assert_ne!(
            scalar(&NormalizedValue::Text("1".into())).unwrap(),
            scalar(&NormalizedValue::Integer(1)).unwrap()
        );
    }
    #[test]
    fn admitted_public_token_template_includes_order_and_limit() {
        assert_eq!(family("SELECT candidate.id,candidate.status,candidate.alias_of,canonical.id AS canonical_id,canonical.value AS canonical_value FROM vocabulary_values candidate LEFT JOIN vocabulary_values canonical ON canonical.id=candidate.alias_of WHERE candidate.vocabulary_id=?1 AND candidate.value=?2 ORDER BY candidate.id LIMIT 1",Inventory::Facet),Some("facet.token-resolution.v1"));
    }
}

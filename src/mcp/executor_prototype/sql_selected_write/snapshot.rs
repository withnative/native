//! One workspace snapshot. Only admitted visible subjects retain dependency proof.
use super::{
    evidence::{self, Budget, Inventory, Recorder},
    predicate::Scalar,
};
use crate::{
    authorization::Capability,
    error::{Error, Result},
    mcp::Caller,
    portable_sql::BorrowedSqliteStatementExecutor,
};
use serde_json::{json, Value};
use sqlx::{Sqlite, Transaction};
use std::collections::BTreeMap;

pub(super) type Tx = Transaction<'static, Sqlite>;
pub(super) fn denial(message: &str) -> Error {
    Error::conflict(format!("sql_write: {message}"))
}

pub(super) struct Visible {
    pub capability: Capability,
    pub proof: Value,
    pub record_type: String,
    pub kind: Option<String>,
    pub canonical_kind: Option<String>,
}

async fn kind(
    tx: &mut Tx,
    record_type: &str,
    raw: Option<&str>,
    proof: &mut Vec<Value>,
) -> Result<(bool, bool, Option<String>)> {
    let Some(raw) = raw else {
        return Ok((false, false, None));
    };
    let designator = crate::meta::kind::kind_vocabulary_name(record_type);
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT id FROM vocabularies WHERE name=? ORDER BY id")
            .bind(&designator)
            .fetch_all(&mut **tx)
            .await?;
    if identities.len() > 1 {
        return Err(Error::engine("ambiguous governing kind vocabulary"));
    }
    proof.push(json!({"template":"eligibility.kind-vocabulary.v1","designator":designator,"identities":identities}));
    let mut recorder = Recorder::new(tx, Inventory::Kind);
    let result = crate::meta::kind::resolve_identity_with(&mut recorder, record_type, raw).await;
    let resolution = evidence::checked(result, recorder.unsupported)?;
    proof.push(json!({"type":record_type,"raw_kind":raw,"reads":recorder.reads}));
    use crate::generated::kinds::CoreKind;
    Ok((
        CoreKind::AnnotationAttribution.matches(&resolution),
        CoreKind::AnnotationComment.matches(&resolution),
        resolution.canonical_kind,
    ))
}

pub(super) async fn visible(
    tx: &mut Tx,
    caller: &Caller,
    id: &str,
    budget: &mut Budget,
) -> Result<Option<Visible>> {
    // Only explicit IDs need this absence probe; source IDs already exist in
    // the same snapshot. No raw predicate values are read before authorization.
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    if !live {
        return Ok(None);
    }
    let principal = crate::mcp::tools::principal(caller);
    let mut recorder = Recorder::new(tx, Inventory::Capability);
    let result =
        crate::authorization::effective_capability_with(&mut recorder, principal, id, false).await;
    let capability = evidence::checked(result, recorder.unsupported)?;
    if !capability.allows(Capability::View) {
        return Ok(None);
    }
    let auth = json!(recorder.reads);
    drop(recorder);
    let (record_type, raw_kind): (String, Option<String>) =
        sqlx::query_as("SELECT type,kind FROM records WHERE id=?")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    let mut eligibility = Vec::new();
    let (attribution, comment, canonical_kind) =
        kind(tx, &record_type, raw_kind.as_deref(), &mut eligibility).await?;
    if attribution {
        return Ok(None);
    }
    if comment {
        let mut consumed = Vec::new();
        if crate::comments::validate_stored_checked_on(tx, id, &mut consumed)
            .await?
            .is_err()
        {
            return Ok(None);
        }
        // Replay only the kind inputs actually consumed by the checked fold,
        // in this same snapshot. Early canonical exclusions never prewalk.
        for projection in &consumed {
            if projection["template"] == "eligibility.kind-input.v1" {
                kind(
                    tx,
                    projection["type"]
                        .as_str()
                        .ok_or_else(|| Error::engine("invalid eligibility type"))?,
                    projection["kind"].as_str(),
                    &mut eligibility,
                )
                .await?;
            }
        }
        eligibility.extend(consumed);
    }
    let eligibility =
        json!({"record_type":record_type,"kind":raw_kind,"live":true,"dependencies":eligibility});
    budget.include_raw("capability-trace", &auth)?;
    budget.include_raw("eligibility-trace", &eligibility)?;
    Ok(Some(Visible {
        capability,
        proof: json!({"id":id,"capability":capability,"capability_digest":evidence::hash("capability-trace",&auth),"eligibility_digest":evidence::hash("eligibility-trace",&eligibility)}),
        record_type,
        kind: raw_kind,
        canonical_kind,
    }))
}

pub(super) async fn raw(tx: &mut Tx, id: &str) -> Result<BTreeMap<String, Scalar>> {
    let (t,k,n,s,a):(String,Option<String>,String,Option<String>,bool)=sqlx::query_as(
        "SELECT type,kind,name,summary,EXISTS(SELECT 1 FROM facet_values WHERE record_id=records.id AND key='archived') FROM records WHERE id=?")
        .bind(id).fetch_one(&mut **tx).await?;
    Ok(BTreeMap::from([
        ("id".into(), Scalar::Text(id.into())),
        ("type".into(), Scalar::Text(t)),
        ("kind".into(), k.map(Scalar::Text).unwrap_or(Scalar::Null)),
        ("name".into(), Scalar::Text(n)),
        (
            "summary".into(),
            s.map(Scalar::Text).unwrap_or(Scalar::Null),
        ),
        ("archived".into(), Scalar::Boolean(a)),
    ]))
}

pub(super) async fn schemas(tx: &mut Tx) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    crate::query::cascade::global_schema_config_rows_with(
        &mut BorrowedSqliteStatementExecutor::new(tx),
    )
    .await
}

pub(super) fn shape(
    rows: &[crate::query::cascade::SchemaConfigRow],
    t: &str,
    k: Option<&str>,
    key: &str,
    validate: bool,
) -> Result<(Option<Value>, Value)> {
    for row in rows {
        if !row.data.is_object() {
            return Err(Error::engine("malformed global schema object"));
        }
        let Some(shapes) = row.data.get("shapes") else {
            continue;
        };
        if !shapes.is_object() {
            return Err(Error::engine("malformed schema shapes container"));
        }
        for slot in std::iter::once(t.to_string()).chain(k.map(|k| format!("{t}:{k}"))) {
            let Some(context) = shapes.get(&slot) else {
                continue;
            };
            if !context.is_object() || context.get("facets").is_some_and(|f| !f.is_object()) {
                return Err(Error::engine("malformed relevant facet schema container"));
            }
        }
    }
    let effective = crate::query::cascade::facets_for_record_context(rows, t, k, None)
        .get(key)
        .cloned();
    let mut declarations = Vec::new();
    for slot in std::iter::once(t.to_string()).chain(k.map(|k| format!("{t}:{k}"))) {
        for layer in ["pack", "user"] {
            for row in rows.iter().filter(|r| r.layer == layer) {
                if let Some(value) = row
                    .data
                    .get("shapes")
                    .and_then(|s| s.get(&slot))
                    .and_then(|s| s.get("facets"))
                    .and_then(|s| s.get(key))
                {
                    declarations.push(json!({"id":row.id,"layer":layer,"slot":slot,"shape":value}));
                }
            }
        }
    }
    if validate
        && effective.as_ref().is_some_and(|s| {
            !s.is_object()
                || s.get("type").is_some()
                || s.get("multi").is_some()
                || s.get("values").is_some_and(|v| {
                    !v.is_array()
                        || v.as_array()
                            .is_some_and(|a| a.iter().any(|v| !v.is_string()))
                })
                || s.get("vocab").is_some_and(|v| !v.is_string())
                || s.get("vocab_ref").is_some_and(|v| !v.is_string())
        })
    {
        return Err(denial(
            "referenced facet requires a valid scalar default-text shape",
        ));
    }
    let projection =
        json!({"type":t,"kind":k,"key":key,"effective":effective,"declarations":declarations});
    let mut pending = vec![&projection];
    while let Some(value) = pending.pop() {
        match value {
            Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
                return Err(denial("floating schema evidence is unsupported"));
            }
            Value::Array(a) => pending.extend(a),
            Value::Object(o) => pending.extend(o.values()),
            _ => {}
        }
    }
    Ok((effective, projection))
}

/// Resolve only this effective shape's governing designator, even when the
/// current facet is absent or the setter context is unselected. No token scan.
pub(super) async fn governing_identity(
    tx: &mut Tx,
    shape: Option<&Value>,
) -> Result<(Option<String>, Value)> {
    let governing = shape.and_then(|s| s.get("vocab").or_else(|| s.get("vocab_ref")));
    let Some(governing) = governing else {
        return Ok((None, Value::Null));
    };
    let raw = governing
        .as_str()
        .ok_or_else(|| denial("unsupported governing vocabulary designator"))?;
    let designator = crate::meta::resolve_vocab_ref(raw);
    let identities: Vec<(String, String)> =
        sqlx::query_as("SELECT id,name FROM vocabularies WHERE id=? OR name=? ORDER BY id")
            .bind(designator)
            .bind(designator)
            .fetch_all(&mut **tx)
            .await?;
    if identities.len() != 1 {
        return Err(denial("governing vocabulary is missing or ambiguous"));
    }
    Ok((
        Some(identities[0].0.clone()),
        json!({"designator":raw,"resolved_designator":designator,"identities":identities}),
    ))
}

#[derive(Clone)]
pub(super) struct Current {
    pub text: Option<String>,
    pub reference: Option<String>,
    pub present: bool,
}
pub(super) async fn current(tx: &mut Tx, id: &str, key: &str) -> Result<Current> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT value,vocab_ref FROM facet_values WHERE record_id=? AND key=?")
            .bind(id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await?;
    let timed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM facet_times WHERE record_id=? AND key=?)")
            .bind(id)
            .bind(key)
            .fetch_one(&mut **tx)
            .await?;
    if timed || row.as_ref().is_some_and(|r| r.0.is_none()) {
        return Err(denial(
            "referenced current facet has a time marker or malformed present NULL",
        ));
    }
    if row.as_ref().is_some_and(|r| {
        r.0.as_ref().is_some_and(|v| v.chars().count() > 1024)
            || r.1.as_ref().is_some_and(|v| v.chars().count() > 1024)
    }) {
        return Err(denial(
            "current facet value/reference exceeds 1024 characters",
        ));
    }
    Ok(match row {
        Some((text, reference)) => Current {
            text,
            reference,
            present: true,
        },
        None => Current {
            text: None,
            reference: None,
            present: false,
        },
    })
}

/// Public assessment supplies validation. This profile strengthens only canonical
/// token/ref admission, and preserves actual Err as infrastructure.
// Keep the audited public assessment inputs explicit at this checked seam.
#[allow(clippy::too_many_arguments)]
pub(super) async fn assess(
    tx: &mut Tx,
    t: &str,
    k: Option<&str>,
    key: &str,
    value: &str,
    reference: Option<&str>,
    shape: Option<&Value>,
    stored: bool,
    budget: &mut Budget,
) -> Result<(Option<String>, Value)> {
    let (governing, identity) = governing_identity(tx, shape).await?;
    let mut token = Value::Null;
    if let Some(vocabulary_id) = governing {
        let rows:Vec<(String,String,String,String,Option<String>)>=sqlx::query_as("SELECT vocabulary_id,id,value,status,alias_of FROM vocabulary_values WHERE vocabulary_id=? AND value=? ORDER BY id")
            .bind(&vocabulary_id).bind(value).fetch_all(&mut **tx).await?;
        if rows.len() != 1 || rows[0].3 != "active" || rows[0].4.is_some() {
            return Err(denial(
                "facet value must be an exact active nonalias vocabulary token",
            ));
        }
        if stored && reference != Some(format!("rec:{vocabulary_id}").as_str()) {
            return Err(denial(
                "governed current facet requires the exact canonical vocabulary reference",
            ));
        }
        token = json!({"identity":identity,"token":rows});
    }
    let facet = crate::domain_transaction::FacetWrite {
        key: key.into(),
        value: Value::String(value.into()),
        vocab_ref: reference.map(str::to_string),
        time_type: None,
    };
    let mut recorder = Recorder::new(tx, Inventory::Facet);
    let result = crate::domain_transaction::assess_facet_write(
        &mut recorder,
        shape,
        "sql_write",
        t,
        k,
        &facet,
    )
    .await;
    let assessment = evidence::checked(result, recorder.unsupported)?;
    if !assessment.accepted
        || assessment
            .value_resolution
            .as_ref()
            .is_some_and(|v| v.classification != "active_member")
    {
        return Err(denial(
            "facet value fails the public text/shape/canonical vocabulary assessment",
        ));
    }
    let after_ref = assessment
        .governing_vocabulary
        .as_ref()
        .map(|v| format!("rec:{}", v.id));
    if after_ref.as_ref().is_some_and(|v| v.chars().count() > 1024) {
        return Err(denial(
            "derived vocabulary reference exceeds 1024 characters",
        ));
    }
    let full = json!({"type":t,"kind":k,"key":key,"value":value,"reference":reference,"token":token,"reads":recorder.reads});
    budget.include_raw("schema", &full)?;
    Ok((
        after_ref,
        json!({"key":key,"validation_digest":evidence::hash("schema",&full)}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(data: Value) -> crate::query::cascade::SchemaConfigRow {
        crate::query::cascade::SchemaConfigRow {
            id: "schema-probe".into(),
            layer: "user".into(),
            name: None,
            data,
            applies_to_collection_id: None,
            version_lineage: None,
            created_at: "fixed".into(),
        }
    }
    #[test]
    fn relevant_container_absence_differs_from_malformed_without_global_hash() {
        assert!(shape(
            &[row(json!({"shapes":{"Document:note":{}}}))],
            "Document",
            Some("note"),
            "key",
            true
        )
        .unwrap()
        .0
        .is_none());
        for data in [
            json!([]),
            json!({"shapes":[]}),
            json!({"shapes":{"Document:note":[]}}),
            json!({"shapes":{"Document:note":{"facets":[]}}}),
            json!({"shapes":{"Document:note":{"facets":{"key":null}}}}),
        ] {
            assert!(shape(&[row(data)], "Document", Some("note"), "key", true).is_err());
        }
        let a = shape(
            &[row(
                json!({"shapes":{"Document:note":{"facets":{"key":{},"other":{"type":"number"}}}}}),
            )],
            "Document",
            Some("note"),
            "key",
            true,
        )
        .unwrap();
        let b=shape(&[row(json!({"shapes":{"Document:note":{"facets":{"key":{},"other":false}},"Unrelated":{"facets":[]}}}))],"Document",Some("note"),"key",true).unwrap();
        assert_eq!(a, b);
    }
    #[tokio::test]
    async fn minimal_kind_proof_binds_governing_identity_even_without_token() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut present = Vec::new();
        kind(&mut tx, "Document", Some("never-a-token"), &mut present)
            .await
            .unwrap();
        assert!(present[0]["identities"].as_array().unwrap().len() == 1);
        let mut absent = Vec::new();
        kind(&mut tx, "UnknownType", Some("never-a-token"), &mut absent)
            .await
            .unwrap();
        assert_eq!(absent[0]["identities"], json!([]));
        assert_ne!(
            evidence::hash("eligibility-trace", &json!(present)),
            evidence::hash("eligibility-trace", &json!(absent))
        );
        tx.rollback().await.unwrap();
    }
    #[test]
    fn losing_relevant_float_declarations_refuse_but_unrelated_floats_do_not() {
        let mut losing =
            row(json!({"shapes":{"Document:note":{"facets":{"key":{"description":1.5}}}}}));
        losing.layer = "pack".into();
        losing.id = "pack-losing".into();
        let winner = row(
            json!({"shapes":{"Document:note":{"facets":{"key":{},"other":{"description":1.5}}}}}),
        );
        assert!(shape(
            &[losing, winner.clone()],
            "Document",
            Some("note"),
            "key",
            false
        )
        .is_err());
        shape(&[winner], "Document", Some("note"), "key", true).unwrap();
    }
}

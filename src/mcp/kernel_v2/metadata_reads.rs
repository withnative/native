//! Read the sealed imported schema/vocabularies through kernel authorization.
use super::*;
use crate::query::cascade;
const GUARANTEE:&str="Imported schema declarations are read-only discoverability metadata. This response does not certify stored values or grant permission for a future write.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    record_id: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
    kind: Option<String>,
}
async fn context(
    db: &Db,
    actor: &str,
    args: Resolve,
) -> Result<(String, Option<String>, Option<String>, Option<Value>)> {
    match (args.record_id, args.typ) {
        (Some(id), None) => {
            let record = kernel::read_record_as(db, actor, &id)
                .await?
                .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
            let value = record_value(db, actor, &record).await?;
            Ok((
                value["type"].as_str().unwrap_or_default().to_owned(),
                value["kind"].as_str().map(str::to_owned),
                Some(id),
                Some(value),
            ))
        }
        (None, Some(typ)) => Ok((typ, args.kind, None, None)),
        _ => Err(Error::engine("takes exactly one of record_id or type")),
    }
}
pub(super) async fn schema(db: &Db, actor: &str) -> Result<Vec<cascade::SchemaConfigRow>> {
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let mut rows = kernel::v1_state::schema_rows_on(&mut tx, actor).await?;
    rows.sort_by(|a, b| {
        (a.layer != "pack", &a.created_at, &a.id).cmp(&(b.layer != "pack", &b.created_at, &b.id))
    });
    Ok(rows)
}
pub(super) async fn facet_values(
    db: &Db,
    actor: &str,
    id: &str,
) -> Result<Vec<(String, String, Option<String>, i64)>> {
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel::kernel_require(&mut tx, actor, id, crate::authorization::Capability::View).await?;
    let rows = sqlx::query_as("SELECT key,value,vocab_ref,event_seq FROM kernel_facets WHERE record_id=? AND value IS NOT NULL AND key!='archived' ORDER BY key").bind(id).fetch_all(&mut *tx).await?;
    Ok(rows)
}

pub(super) async fn resolve_facets(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Resolve = parse("resolve_facets", args)?;
    let (typ, kind, id, record) = context(db, actor, args).await?;
    let rows = schema(db, actor).await?;
    if let (Some(id), Some(record)) = (id, record) {
        let values = facet_values(db, actor, &id).await?;
        let values:Vec<Value>=values.into_iter().map(|(key,value,vocab_ref,seq)|json!({"key":key,"value":value,"vocab_ref":vocab_ref,"version":native_artifact_runtime::artifact_intents::FacetVersion::Observation{event_seq:seq}.encode()})).collect();
        Ok(
            json!({"record_id":id,"type":typ,"kind":kind,"bears_shape":cascade::bears_shape_from_rows(&rows,&id),"spine":{"lifecycle":record["lifecycle"],"owner":record["owner_id"],"persistence":record["persistence"],"maturity":record["maturity"]},"archived":record["archived"],"shape":cascade::facets_for_record_context(&rows,&typ,kind.as_deref(),Some(&id)),"pack_shape":cascade::pack_facets_for_record_context(&rows,&typ,kind.as_deref(),Some(&id)),"provenance":cascade::provenance_for_record_context(&rows,&typ,kind.as_deref(),Some(&id)),"values":values,"shape_guarantee":GUARANTEE}),
        )
    } else {
        let view = cascade::resolve_from_rows(&rows);
        let mut out = json!({"type":typ,"kind":kind,"spine":crate::schema::SPINE_FACET_KEYS,"shape":cascade::facets_for_type(&view.resolved,&typ,kind.as_deref()),"pack_shape":cascade::facets_for_type(&view.pack,&typ,kind.as_deref()),"provenance":cascade::provenance_for_type(&rows,&typ,kind.as_deref()),"shape_guarantee":GUARANTEE});
        if kind.is_none() {
            out["kind_shapes"] = json!(cascade::kind_shapes(&view.resolved, &typ));
        }
        Ok(out)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    action: String,
    vocabulary: String,
    status: Option<String>,
    resolve_aliases: Option<bool>,
}
async fn values(
    db: &Db,
    actor: &str,
    vocabulary: &str,
    status: Option<&str>,
    resolve: bool,
) -> Result<(Value, Vec<Value>)> {
    if status.is_some_and(|v| !["proposed", "active", "deprecated"].contains(&v)) {
        return Err(Error::engine("manage_vocabularies: invalid value status"));
    }
    let vocabulary = crate::meta::vocabulary::resolve_vocab_ref(vocabulary);
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let vocab = kernel::v1_state::rows_on(&mut tx, "vocabularies")
        .await?
        .into_iter()
        .find(|v| v["id"] == vocabulary || v["name"] == vocabulary)
        .ok_or_else(|| Error::engine("vocabulary does not exist"))?;
    let all = kernel::v1_state::rows_on(&mut tx, "vocabulary_values").await?;
    let mut out = Vec::new();
    for mut row in all
        .iter()
        .filter(|r| r["vocabulary_id"] == vocab["id"] && status.is_none_or(|s| r["status"] == s))
        .cloned()
    {
        if let Some(raw) = row["metadata"].as_str() {
            row["metadata"] = serde_json::from_str(raw)?;
        }
        if resolve {
            if let Some(alias) = row["alias_of"].as_str() {
                if let Some(target) = all
                    .iter()
                    .find(|t| t["id"] == alias && t["vocabulary_id"] == vocab["id"])
                {
                    row["canonical"] = json!({"id":target["id"],"value":target["value"]});
                }
            }
        }
        out.push(row);
    }
    out.sort_by(|a, b| {
        a["ordinal"]
            .as_f64()
            .unwrap_or_default()
            .total_cmp(&b["ordinal"].as_f64().unwrap_or_default())
            .then_with(|| a["value"].as_str().cmp(&b["value"].as_str()))
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    if out.len() > 10_000 {
        return Err(Error::engine(
            "vocabulary suggestion set exceeds 10000 rows",
        ));
    }
    Ok((json!({"id":vocab["id"],"name":vocab["name"]}), out))
}
pub(super) async fn list_values(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: List = parse("manage_vocabularies", args)?;
    if args.action != "list_values" {
        return Err(unsupported("manage_vocabularies", "action"));
    }
    let (vocab, values) = values(
        db,
        actor,
        &args.vocabulary,
        args.status.as_deref(),
        args.resolve_aliases.unwrap_or(true),
    )
    .await?;
    Ok(
        json!({"vocab_ref":format!("rec:{}",vocab["id"].as_str().unwrap_or_default()),"vocabulary":vocab,"status":args.status,"values":values}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Suggest {
    record_id: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
    kind: Option<String>,
    facet_key: String,
}
pub(super) async fn suggest(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Suggest = parse("suggest_facet_values", args)?;
    let (typ, kind, id, _) = context(
        db,
        actor,
        Resolve {
            record_id: args.record_id,
            typ: args.typ,
            kind: args.kind,
        },
    )
    .await?;
    let rows = schema(db, actor).await?;
    let shape = cascade::facets_for_record_context(&rows, &typ, kind.as_deref(), id.as_deref());
    let field = shape.get(&args.facet_key).cloned().unwrap_or(Value::Null);
    let (vocab, suggestions) = match field["vocab"]
        .as_str()
        .or_else(|| field["vocab_ref"].as_str())
    {
        Some(v) => values(db, actor, v, Some("active"), true).await?,
        None => (Value::Null, Vec::new()),
    };
    Ok(
        json!({"facet_key":args.facet_key,"type":typ,"kind":kind,"declared_type":field["type"],"vocabulary":vocab,"suggestions":suggestions,"shape_guarantee":GUARANTEE}),
    )
}

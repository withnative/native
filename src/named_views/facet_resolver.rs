//! Internal preparation only: trusted imported rows -> frozen candidate + owned
//! source proof. No operation, admission seam, execution or publication calls it.
use super::{source_proof, v2, Revision, MAX_CARRIER_BYTES};
use crate::{
    db::Db,
    query::{cascade::SchemaConfigRow, generated_facets as compiler},
    Error, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

pub(super) struct Request {
    pub record_type: String,
    pub kind: Option<String>,
    pub home: String,
    pub selection: compiler::Selection,
}
#[allow(dead_code)] // Prepared internally, deliberately no producer consumes it.
pub(super) struct Prepared {
    pub revision: Revision,
    pub name: String,
    pub proof: source_proof::Proof,
    /// Currently absent winning declaration/vocabulary rows will refuse future
    /// serving. Value and superseded/governance evidence is advisory instead.
    pub required_catalog_sources: BTreeSet<usize>,
}
fn invalid(why: impl std::fmt::Display) -> Error {
    Error::engine(format!("generated facet preparation: {why}"))
}
fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::conflict(
            "view_source_changed: source proof deadline exceeded; prepare again",
        ));
    }
    Ok(())
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing {field}")))
}
fn optional(v: &Value, field: &str) -> Result<Option<String>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(invalid(format!("invalid {field}"))),
    }
}
fn source(s: &source_proof::Source, anchor: Option<String>) -> Result<v2::Source> {
    let section = match s.section.as_str() {
        "schema_config" => v2::Section::SchemaConfig,
        "vocabularies" => v2::Section::Vocabularies,
        "vocabulary_values" => v2::Section::VocabularyValues,
        _ => return Err(invalid("unsupported source section")),
    };
    let ids: Vec<String> = serde_json::from_str(&s.source_id)?;
    Ok(v2::Source {
        section,
        source_id: s.source_id.clone(),
        origin: s.origin.clone(),
        row_id: ids[0].clone(),
        event_id: s.event_id.clone(),
        event_sha256: s.event_sha256.clone(),
        anchor,
    })
}
#[derive(Deserialize)]
struct SchemaRow {
    id: String,
    layer: String,
    name: Option<String>,
    data: String,
    applies_to_collection_id: Option<String>,
    version_lineage: Option<String>,
    created_at: String,
}

/// Shared declaration decoding, scope normalization and source ordering for
/// preparation and retained comparison. No SQL or vocabulary-map generation.
pub(super) struct ResolvedSources<'a> {
    pub rows: Vec<SchemaConfigRow>,
    pub schema_sources: BTreeMap<String, v2::Source>,
    pub raw: Vec<(&'a source_proof::Source, Value)>,
}
pub(super) fn resolve_sources<'a>(
    sources: &'a [source_proof::Source],
    home: &str,
    deadline: Instant,
) -> Result<ResolvedSources<'a>> {
    comparison_sources(sources, home, deadline).map_err(source_proof::ComparisonFailure::into_error)
}

pub(super) fn comparison_sources<'a>(
    sources: &'a [source_proof::Source],
    home: &str,
    deadline: Instant,
) -> source_proof::ComparisonResult<ResolvedSources<'a>> {
    let mut rows = Vec::new();
    let mut schema_sources = BTreeMap::new();
    let mut raw = Vec::new();
    for s in sources {
        check(deadline)?;
        // B already checked duplicates/outer identity and charged raw bytes.
        let value: Value = serde_json::from_str(&s.payload)?;
        if s.section == "schema_config" {
            let mut row: SchemaRow = serde_json::from_value(value)?;
            // Root alias is a logical scope, not a schema-row ACL. Do not turn
            // a folder's physical parent into its own governing collection.
            if row.applies_to_collection_id.as_deref() == Some(crate::events::KERNEL_ROOT_ID)
                && home == "native:root"
            {
                row.applies_to_collection_id = Some(home.to_owned());
            }
            if row
                .applies_to_collection_id
                .as_deref()
                .is_some_and(|h| h != home)
            {
                continue;
            }
            let data =
                serde_json::from_str::<crate::record_body::budgeted::UniqueJson>(&row.data)?.0;
            // Preserve pure compiler's whole-row validation and 128-row input
            // cap, including empty applicable metadata rows; never truncate.
            if rows.len() >= 128 {
                return Err(source_proof::ComparisonFailure::budget(invalid(
                    "applicable schema input exceeds 128 rows",
                )));
            }
            schema_sources.insert(
                row.id.clone(),
                source(s, row.applies_to_collection_id.clone())
                    .map_err(source_proof::ComparisonFailure::integrity)?,
            );
            rows.push(SchemaConfigRow {
                id: row.id,
                layer: row.layer,
                name: row.name,
                data,
                applies_to_collection_id: row.applies_to_collection_id,
                version_lineage: row.version_lineage,
                created_at: row.created_at,
            });
        } else {
            raw.push((s, value));
        }
    }
    rows.sort_by(|a, b| {
        (a.layer != "pack", &a.created_at, &a.id).cmp(&(b.layer != "pack", &b.created_at, &b.id))
    });
    Ok(ResolvedSources {
        rows,
        schema_sources,
        raw,
    })
}

/// `workspace` is the trusted host workspace namespace, not a selector or source
/// supplied by an agent. `bearer` is only the target identity; this preparation
/// proves View, not Edit/publication authority. Those remain later admission work.
#[allow(dead_code)] // No producer/API/admission/serving integration in this increment.
pub(super) async fn prepare(
    db: &Db,
    actor: &str,
    workspace: &str,
    bearer: &str,
    request: Request,
    deadline: Instant,
) -> Result<Prepared> {
    if [
        workspace,
        bearer,
        request.home.as_str(),
        request.record_type.as_str(),
    ]
    .iter()
    .any(|s| s.is_empty() || s.len() > 128 || s.contains('\0'))
        || request
            .kind
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 128 || s.contains('\0'))
    {
        return Err(invalid("context bound"));
    }
    let (snapshot, home, anchor) =
        source_proof::prepare_context(db, actor, bearer, &request.home, deadline).await?;
    prepare_snapshot(snapshot, actor, workspace, bearer, request, home, anchor).await
}
async fn prepare_snapshot(
    snapshot: source_proof::Snapshot,
    actor: &str,
    workspace: &str,
    bearer: &str,
    request: Request,
    home: String,
    anchor: String,
) -> Result<Prepared> {
    let deadline = snapshot.deadline();
    let ResolvedSources {
        rows,
        schema_sources,
        raw,
    } = resolve_sources(snapshot.sources(), &home, deadline)?;
    let effective = crate::query::cascade::facets_for_record_context(
        &rows,
        &request.record_type,
        request.kind.as_deref(),
        Some(&home),
    );
    let selected: BTreeSet<_> = match &request.selection {
        compiler::Selection::Keys(keys) => keys.clone(),
        compiler::Selection::All => effective
            .keys()
            .filter(|k| !crate::schema::SPINE_FACET_KEYS.contains(&k.as_str()))
            .cloned()
            .collect(),
    };
    if selected.is_empty() || selected.len() > 18 {
        return Err(invalid("selected columns bound"));
    }
    let mut references = BTreeSet::new();
    for key in &selected {
        check(deadline)?;
        let decl = effective
            .get(key)
            .ok_or_else(|| invalid("selected declaration absent"))?;
        if let Some(reference) = decl.get("vocab").or_else(|| decl.get("vocab_ref")) {
            references.insert(
                crate::meta::vocabulary::resolve_vocab_ref(
                    reference
                        .as_str()
                        .ok_or_else(|| invalid("vocabulary reference"))?,
                )
                .to_owned(),
            );
        }
    }
    let mut vocabs = Vec::new();
    let mut total = 0;
    for id in references {
        check(deadline)?;
        let matches: Vec<_> = raw
            .iter()
            .filter(|(s, v)| s.section == "vocabularies" && v["id"].as_str() == Some(&id))
            .collect();
        if matches.len() != 1 {
            return Err(invalid("required vocabulary unavailable"));
        }
        let (s, _) = matches[0];
        let mut values = Vec::new();
        for (s, v) in &raw {
            check(deadline)?;
            if s.section != "vocabulary_values" || v["vocabulary_id"].as_str() != Some(&id) {
                continue;
            }
            if values.len() >= 64 || total >= 256 {
                return Err(invalid("vocabulary value bound"));
            }
            values.push(compiler::VocabularyValue {
                source: source(s, None)?,
                id: text(v, "id")?.into(),
                value: text(v, "value")?.into(),
                status: text(v, "status")?.into(),
                alias_of: optional(v, "alias_of")?,
            });
            total += 1;
        }
        vocabs.push(compiler::Vocabulary {
            id: id.clone(),
            reference: id.clone(),
            source: source(s, None)?,
            values,
        });
    }
    let proposal = compiler::compile(
        compiler::Input {
            workspace,
            bearer,
            source_identity: &home,
            record_type: &request.record_type,
            kind: request.kind.as_deref(),
            home: &home,
            selection: request.selection,
            schema: &rows,
            schema_sources,
            vocabularies: &vocabs,
        },
        deadline,
    )
    .map_err(|e| match e {
        compiler::CompileError::Deadline => {
            Error::conflict("view_source_changed: source proof deadline exceeded; prepare again")
        }
        other => invalid(format!("{other:?}")),
    })?;
    let required_catalog_sources = required_sources(&proposal.manifest);
    // The public carrier stays exactly the already shipped closed Definition2.
    let definition: v2::Definition = serde_json::from_value(json!({
        "query":{"v":"1.2","kind":"governed_sql","profile":{"id":"sqlite-local","revision":1},"catalog_revision":crate::query::sql_contract::LOGICAL_CATALOG_REVISION,
        "relations":proposal.relations,"sql":proposal.sql,"parameters":[],"bounds":{"rows":100},"output":proposal.output},
        "origin":{"kind":"generated","generator":"native.declared-relational-defaults","version":"facet-1","source_identity":home,"selector":compiler::selector(&proposal.manifest)},
        "description":"Declared facets for visible direct members; frozen generated interpretation",
        "scope":{"description":format!("{} direct members",home),"cardinality":"one row per visible record","default_inclusion":"all matching visible records, including archived and superseded; unknown currentness stays NULL"},
        "columns":proposal.columns,"source_pins":[],"generated":proposal.manifest
    }))?;
    definition.validate()?; // Structural only. No SQL validators or workers.
    let selected = definition
        .generated
        .sources
        .iter()
        .map(|s| {
            snapshot
                .sources()
                .iter()
                .position(|r| {
                    r.source_id == s.source_id
                        && r.section
                            == match s.section {
                                v2::Section::SchemaConfig => "schema_config",
                                v2::Section::Vocabularies => "vocabularies",
                                v2::Section::VocabularyValues => "vocabulary_values",
                            }
                })
                .ok_or_else(|| invalid("retained evidence not from snapshot"))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut revision = Revision {
        v: 2,
        view_id: format!("native.named-view:{bearer}"),
        definition_sha256: String::new(),
        definition: serde_json::to_value(definition)?,
    };
    revision.definition_sha256 = revision.digest();
    compiler::size(&revision, MAX_CARRIER_BYTES)
        .map_err(|_| invalid("256 KiB revision carrier bound"))?;
    let anchors: Vec<_> = BTreeSet::from([anchor, bearer.into()])
        .into_iter()
        .collect();
    let proof = snapshot
        .seal_generated(actor, &selected, &anchors, bearer)
        .await?;
    Ok(Prepared {
        revision,
        name: proposal.name,
        proof,
        required_catalog_sources,
    })
}

pub(super) fn required_sources(manifest: &v2::Manifest) -> BTreeSet<usize> {
    let mut winners = BTreeMap::new();
    for f in manifest.slots.iter().flat_map(|s| &s.fragments) {
        winners.insert(&f.key, f.source);
    }
    winners
        .values()
        .copied()
        .chain(manifest.vocabularies.iter().map(|v| v.source))
        .collect()
}

/// Internal qualification artifact, never a retained revision or serving grant.
#[allow(dead_code)] // No public v2 producer/serving route consumes this checkpoint.
pub(super) struct Validated {
    pub definition: v2::Definition,
    pub reads: BTreeSet<(String, String)>,
}
impl Prepared {
    /// Full saved-SQL admission and both existing named security gates, outside
    /// any workspace/catalog writer. A typed manifest is not SQL certification.
    #[allow(dead_code)] // Internal checkpoint only.
    pub(super) async fn validate(&self, deadline: Instant) -> Result<Validated> {
        let revision = self.revision.clone();
        let name = self.name.clone();
        crate::query::sql::view_validation::run(deadline, move || {
            if revision.v != 2
                || revision.definition_sha256 != revision.digest()
                || revision.generated_name().as_deref() != Some(name.as_str())
            {
                return Err(invalid("candidate identity mismatch"));
            }
            let definition: v2::Definition = serde_json::from_value(revision.definition.clone())?;
            if serde_json::to_value(&definition)? != revision.definition {
                return Err(invalid("noncanonical candidate"));
            }
            compiler::size(&revision, MAX_CARRIER_BYTES)
                .map_err(|_| invalid("256 KiB revision carrier bound"))?;
            definition.validate()?;
            definition.common().validate_current()?;
            let validators = crate::query::sql::NamedViewValidators::new(&[(
                name,
                definition.query.sql.clone(),
            )])?;
            let (reads, labels) = validators.inspect_saved(&definition.query.sql)?;
            if labels
                != definition
                    .query
                    .output
                    .columns
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>()
            {
                return Err(invalid("candidate output labels mismatch"));
            }
            Ok(Validated { definition, reads })
        })
        .await
    }

    /// Future frozen interpretation check, scoped to this owned preparation.
    /// Present replacement refs are advisory; required absence and lost View
    /// refuse. The boolean reports retained-reference drift only: it cannot
    /// certify absence of new overrides/aliases. A fresh complete resolver
    /// snapshot proposes A2; strict commit `recheck_on` still catches additions.
    #[allow(dead_code)] // No serving route consumes this checkpoint.
    pub(super) async fn inspect_on(
        &self,
        db: &Db,
        conn: &mut sqlx::SqliteConnection,
        actor: &str,
        deadline: Instant,
    ) -> Result<bool> {
        self.proof
            .inspect_frozen_on(db, conn, actor, &self.required_catalog_sources, deadline)
            .await
    }
}

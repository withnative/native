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
/// Closed caller-facing profile selector. Omitted means facet-1; never an
/// automatic switch. The internal compiler profile is selected explicitly.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(super) enum Profile {
    #[default]
    #[serde(rename = "facet-1")]
    Facet1,
    #[serde(rename = "facet-global-1")]
    Global1,
}
impl Profile {
    pub(super) fn compiler(self) -> compiler::Profile {
        match self {
            Self::Facet1 => compiler::Profile::Facet1,
            Self::Global1 => compiler::Profile::Global1,
        }
    }
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
    prepare_profile(
        db,
        actor,
        workspace,
        bearer,
        request,
        compiler::Profile::Facet1,
        deadline,
    )
    .await
}
/// Explicit internal profile. Public proposal/export/admission still select
/// facet-1 and never dispatch here from a caller-supplied profile.
#[allow(dead_code)] // Global profile is private until STEP3.
#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_profile(
    db: &Db,
    actor: &str,
    workspace: &str,
    bearer: &str,
    request: Request,
    profile: compiler::Profile,
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
    prepare_snapshot(
        snapshot, actor, workspace, bearer, request, home, anchor, profile,
    )
    .await
}
/// Global-profile vocabulary binding against the complete bounded snapshot.
/// Literal `rec:` is ID-only and never guesses a canonical name. Any other
/// spelling resolves the union of vocabulary rows with `row.id == r OR
/// row.name == r`: exactly one distinct row must match (a row matching both
/// of its own columns counts once). A row whose own ID equals `r` binds that
/// exact ID; otherwise the row must carry the actual name `r` with ID
/// `voc:{r}` read from this same sealed snapshot row — that single row is the
/// only name evidence, never a live catalog lookup. Ambiguous, duplicate,
/// custom-ID name-mapping, and unknown references refuse, as does any budget
/// exhaustion (including the deadline): a cap refusal never proves absence
/// or uniqueness.
fn resolve_global_reference(
    raw: &[(&source_proof::Source, Value)],
    reference: &str,
    deadline: Instant,
) -> Result<(String, usize)> {
    if let Some(stripped) = reference.strip_prefix("rec:") {
        let mut found: Option<usize> = None;
        for (index, (s, v)) in raw.iter().enumerate() {
            check(deadline)?;
            if s.section != "vocabularies" || v["id"].as_str() != Some(stripped) {
                continue;
            }
            if found.is_some() {
                return Err(invalid("required vocabulary unavailable"));
            }
            found = Some(index);
        }
        let index = found.ok_or_else(|| invalid("required vocabulary unavailable"))?;
        let id = raw[index].1["id"]
            .as_str()
            .ok_or_else(|| invalid("vocabulary identity"))?
            .to_owned();
        return Ok((id, index));
    }
    let mut found: Option<usize> = None;
    for (index, (s, v)) in raw.iter().enumerate() {
        check(deadline)?;
        if s.section != "vocabularies" {
            continue;
        }
        if v["id"].as_str() != Some(reference) && v["name"].as_str() != Some(reference) {
            continue;
        }
        if found.is_some_and(|first| first != index) {
            return Err(invalid("ambiguous vocabulary reference"));
        }
        found = Some(index);
    }
    let index = found.ok_or_else(|| invalid("unknown vocabulary reference"))?;
    let id = raw[index].1["id"]
        .as_str()
        .ok_or_else(|| invalid("vocabulary identity"))?
        .to_owned();
    if id == reference {
        return Ok((id, index));
    }
    let name = raw[index].1["name"].as_str().unwrap_or_default();
    if name == reference && id == format!("voc:{reference}") {
        return Ok((id, index));
    }
    Err(invalid("unbound vocabulary name"))
}
#[allow(clippy::too_many_arguments)]
async fn prepare_snapshot(
    snapshot: source_proof::Snapshot,
    actor: &str,
    workspace: &str,
    bearer: &str,
    request: Request,
    home: String,
    anchor: String,
    profile: compiler::Profile,
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
    let global = profile == compiler::Profile::Global1;
    // Declared references in original spelling. Conflicting duals refuse on
    // the global path before any snapshot binding; facet-1 keeps its exact
    // historical extraction below.
    let mut declared: Vec<String> = Vec::new();
    for key in &selected {
        check(deadline)?;
        let decl = effective
            .get(key)
            .ok_or_else(|| invalid("selected declaration absent"))?;
        if global {
            let vocab = decl.get("vocab").and_then(|v| v.as_str());
            let vocab_ref = decl.get("vocab_ref").and_then(|v| v.as_str());
            if vocab.is_some_and(|a| vocab_ref.is_some_and(|b| a != b)) {
                return Err(invalid("conflicting vocabulary declaration"));
            }
        }
        if let Some(reference) = decl.get("vocab").or_else(|| decl.get("vocab_ref")) {
            declared.push(
                reference
                    .as_str()
                    .ok_or_else(|| invalid("vocabulary reference"))?
                    .to_owned(),
            );
        }
    }
    // Resolved (original reference, bound actual ID, snapshot row index).
    // Facet-1 keeps its exact historical ID-only binding; global resolves the
    // complete snapshot union with ambiguity and budget refusal.
    let mut resolved: Vec<(String, String, usize)> = Vec::new();
    if global {
        // Bind every spelling, then collapse to one vocabulary per bound ID
        // so fields sharing a vocabulary (same or mixed spellings) neither
        // refuse nor duplicate its source.
        let mut bound: Vec<(String, String, usize)> = Vec::new();
        for reference in &declared {
            check(deadline)?;
            let (id, index) = resolve_global_reference(&raw, reference, deadline)?;
            bound.push((reference.clone(), id, index));
        }
        let mut groups: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
        for (reference, id, index) in bound {
            check(deadline)?;
            if let Some((first, _)) = groups.get(&id) {
                if *first != index {
                    return Err(invalid("ambiguous vocabulary reference"));
                }
            }
            groups
                .entry(id)
                .or_insert((index, Vec::new()))
                .1
                .push(reference);
        }
        for (id, (index, spellings)) in groups {
            check(deadline)?;
            // The reference serves lookup for every declaring spelling: the
            // bare name when a field declares it (mixed spellings included),
            // otherwise the bound ID itself, so ID bindings never gain the
            // row's unrelated name.
            let name = raw[index].1["name"].as_str().filter(|n| !n.is_empty());
            let reference = match name {
                Some(name) if spellings.iter().any(|s| s == name) => name.to_owned(),
                _ => id.clone(),
            };
            resolved.push((reference, id, index));
        }
    } else {
        let mut references = BTreeSet::new();
        for reference in &declared {
            references.insert(crate::meta::vocabulary::resolve_vocab_ref(reference).to_owned());
        }
        for id in references {
            check(deadline)?;
            let matches: Vec<_> = raw
                .iter()
                .enumerate()
                .filter(|(_, (s, v))| {
                    s.section == "vocabularies" && v["id"].as_str() == Some(id.as_str())
                })
                .collect();
            if matches.len() != 1 {
                return Err(invalid("required vocabulary unavailable"));
            }
            let (index, _) = matches[0];
            resolved.push((id.clone(), id, index));
        }
    }
    let mut vocabs = Vec::new();
    let mut total = 0;
    for (reference, id, index) in resolved {
        check(deadline)?;
        let s = raw[index].0;
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
            reference,
            source: source(s, None)?,
            values,
        });
    }
    let input = compiler::Input {
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
    };
    // Keep a typed closed retained global manifest; the common input projection
    // below is only bookkeeping for selecting/sealing snapshot evidence.
    let (proposal, retained_manifest, selector) = match profile {
        compiler::Profile::Facet1 => compiler::compile(input, deadline).map(|p| {
            let value = serde_json::to_value(&p.manifest).expect("typed manifest");
            let selector = compiler::selector(&p.manifest);
            (p, value, selector)
        }),
        compiler::Profile::Global1 => compiler::compile_global(input, deadline).map(|p| {
            let value = serde_json::to_value(&p.manifest).expect("typed manifest");
            let selector =
                String::from_utf8(native_artifact_runtime::mdx_v2::canonical_json_bytes(
                    &json!({"context":p.manifest.context,"selection":p.manifest.selection}),
                ))
                .expect("canonical UTF-8");
            let common = compiler::Proposal {
                manifest: p.manifest.inputs(),
                manifest_sha256: p.manifest_sha256,
                name: p.name,
                sql: p.sql,
                output: p.output,
                columns: p.columns,
                relations: p.relations,
            };
            (common, value, selector)
        }),
    }
    .map_err(|e| match e {
        compiler::CompileError::Deadline => {
            Error::conflict("view_source_changed: source proof deadline exceeded; prepare again")
        }
        // Facet-1 remains the default and never auto-switches. Point at the
        // explicit global profile only after the View/existence checks above.
        compiler::CompileError::Invalid("home has no governing declaration")
            if profile == compiler::Profile::Facet1 =>
        {
            invalid("home has no governing declaration; retry with explicit profile=facet-global-1")
        }
        other => invalid(format!("{other:?}")),
    })?;
    let required_catalog_sources = required_sources(&proposal.manifest);
    // The public carrier stays exactly the already shipped closed Definition2.
    let definition = json!({
        "query":{"v":"1.2","kind":"governed_sql","profile":{"id":"sqlite-local","revision":1},"catalog_revision":crate::query::sql_contract::LOGICAL_CATALOG_REVISION,
        "relations":proposal.relations,"sql":proposal.sql,"parameters":[],"bounds":{"rows":100},"output":proposal.output},
        "origin":{"kind":"generated","generator":"native.declared-relational-defaults","version":profile.version(),"source_identity":home,"selector":selector},
        "description":if profile == compiler::Profile::Global1 {"Retained global declaration interpretation for visible direct members"} else {"Declared facets for visible direct members; frozen generated interpretation"},
        "scope":{"description":if profile == compiler::Profile::Global1 {format!("Retained global declaration interpretation for direct members of {}",home)} else {format!("{} direct members",home)},"cardinality":"one row per visible record","default_inclusion":"all matching visible records, including archived and superseded; unknown currentness stays NULL"},
        "columns":proposal.columns,"source_pins":[],"generated":retained_manifest
    });
    let definition = match profile {
        compiler::Profile::Facet1 => {
            serde_json::to_value(serde_json::from_value::<v2::Definition>(definition)?)?
        }
        compiler::Profile::Global1 => serde_json::to_value(serde_json::from_value::<
            v2::Definition<v2::GlobalManifest>,
        >(definition)?)?,
    };
    v2::validate_definition(&definition)?; // Structural only. No SQL validators or workers.
    let selected = proposal
        .manifest
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
        definition,
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
    pub definition: super::contract::Definition,
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
            // Typed dispatch by the closed profile; both carriers validate
            // structurally and return the common definition for the gates.
            let definition = v2::validate_definition(&revision.definition)
                .map_err(|_| invalid("noncanonical candidate"))?;
            compiler::size(&revision, MAX_CARRIER_BYTES)
                .map_err(|_| invalid("256 KiB revision carrier bound"))?;
            definition.validate_current()?;
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

//! Fixture-only adapter from a package-produced software projection to
//! ordinary kernel v2 writes (isolated database, no new operation or schema).
//!
//! The occurrence rows come from the committed output of the retained package
//! reference (`fixtures/software/reference-expected.json`); this module never
//! parses a tree. The coverage verdict (source integrity, structural and
//! semantic coverage, omissions, digests) is taken from the pure test oracle in
//! `software_occurrence` and is not production authority. Every record goes
//! through the ordinary `create_record` / `manage_links` tools, with a short
//! `software-attest:` idempotency key per role. See
//! `docs/named-views-software-occurrence-design.md`.

use super::software_occurrence::{self as oracle, Attestation, Declared, Scope};
use crate::Error;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub(super) const ADAPTER_VERSION: &str = "native.software-fixture-projection.v1";
pub(super) const RECORD_TYPE: &str = "Document";
pub(super) const KIND_VIEW: &str = "software_captured_view";
pub(super) const KIND_OCCURRENCE: &str = "software_occurrence";
pub(super) const KIND_GROUP: &str = "software_choice_group";
pub(super) const KIND_COVERAGE: &str = "software_coverage";
pub(super) const MEMBER: &str = "scope_member";

#[derive(Clone, Debug, Deserialize)]
pub(super) struct PackageNode {
    pub role: String,
    pub label: String,
    pub source_order: u32,
    pub parent: Option<usize>,
    pub depth: usize,
    pub bid: Option<String>,
    pub selected: Option<bool>,
    pub disabled: Option<bool>,
    pub line: u32,
    pub char_start: usize,
    pub char_end: usize,
    pub exact: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct PackageGroup {
    pub control: u32,
    pub options: Vec<u32>,
    pub boundary: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct PackageCoverage {
    pub parsed_nodes: u32,
}

/// One case of the committed package output.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Projection {
    pub schema: String,
    pub tree: String,
    pub tree_sha256: String,
    pub nodes: Vec<PackageNode>,
    pub groups: Vec<PackageGroup>,
    pub coverage: PackageCoverage,
}

pub(super) fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/software/reference-expected.json")).unwrap()
}

pub(super) fn load(case: &str) -> Projection {
    serde_json::from_value(reference()[case].clone()).unwrap()
}

/// Where a link end lives, resolved to a server-minted id at apply time.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum Role {
    View,
    Occurrence(usize),
    Group(usize),
    Coverage,
}

#[derive(Clone, Debug)]
pub(super) struct RecordSpec {
    pub role: Role,
    pub kind: &'static str,
    pub name: String,
    pub facets: Map<String, Value>,
    pub key: String,
}

#[derive(Clone, Debug)]
pub(super) struct LinkSpec {
    pub source: Role,
    pub target: Role,
    pub relationship: &'static str,
    pub key: String,
}

/// Records and links in write order: view, items, parent links, groups and
/// their option links, coverage, and only then the scope-membership links.
#[derive(Clone, Debug)]
pub(super) struct Plan {
    pub view: RecordSpec,
    pub occurrences: Vec<RecordSpec>,
    pub parent_links: Vec<LinkSpec>,
    pub groups: Vec<RecordSpec>,
    pub group_links: Vec<LinkSpec>,
    pub coverage: RecordSpec,
    pub coverage_links: Vec<LinkSpec>,
    pub member_links: Vec<LinkSpec>,
}

pub(super) struct Input<'a> {
    pub projection: &'a Projection,
    pub oracle: &'a Attestation,
    pub scope: &'a Scope,
    pub source_ref: &'a str,
    pub declared: &'a Declared,
    pub source_complete: Option<bool>,
    pub extractor_version: &'a str,
    pub caps: oracle::Caps,
}

fn tri(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn kind_of(role: &str) -> &'static str {
    match role {
        "option" => "option",
        "combobox" | "listbox" => "control",
        _ => "element",
    }
}

fn selector(node: &PackageNode) -> String {
    format!("line-{}", node.line)
}

/// Everything that can change a request, so a key never silently outlives a
/// different input: the full scope, declared source, manifest digest,
/// extractor, binding revision, requirements and output caps.
fn basis(input: &Input) -> String {
    let s = input.scope;
    let c = &input.caps;
    let id = &input.oracle.identity;
    let caps = format!(
        "{}/{}/{}/{}/{}/{}/{}/{}/{}",
        c.chunks, c.bytes, c.nodes, c.label, c.role, c.selector, c.bid, c.excerpt, c.diagnostics
    );
    oracle::digest(
        oracle::encode(&[
            ADAPTER_VERSION,
            &s.namespace,
            &s.trajectory,
            &s.state.to_string(),
            &s.view,
            &s.scope_selector,
            input.source_ref,
            &input.declared.sha256,
            &input.declared.len.to_string(),
            &input.declared.chunks.to_string(),
            &id.source_set_digest,
            &id.scope_digest,
            input.extractor_version,
            &id.binding_revision,
            &id.requirements_digest,
            &caps,
            &input.projection.tree_sha256,
        ])
        .as_bytes(),
    )
}

fn key(basis: &str, role: &str) -> String {
    format!(
        "software-attest:{}",
        oracle::digest(oracle::encode(&[basis, role]).as_bytes())
    )
}

fn put(facets: &mut Map<String, Value>, name: &str, value: impl Into<Value>) {
    facets.insert(name.to_owned(), value.into());
}

/// Refusals are typed: the plan is never built from inconsistent inputs.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    Schema,
    Digest,
    Count { package: u32, oracle: u32 },
}

pub(super) fn plan(input: &Input) -> Result<Plan, Refusal> {
    let p = input.projection;
    if p.schema != input.extractor_version {
        return Err(Refusal::Schema);
    }
    if p.tree_sha256 != input.declared.sha256 {
        return Err(Refusal::Digest);
    }
    let nodes = p.nodes.len() as u32;
    let expected = input.oracle.coverage.expected_item_count;
    if nodes != expected || p.coverage.parsed_nodes != expected {
        return Err(Refusal::Count {
            package: nodes,
            oracle: expected,
        });
    }
    let basis = basis(input);
    let id = &input.oracle.identity;
    let cov = &input.oracle.coverage;
    let selectors: Vec<String> = p.nodes.iter().map(selector).collect();

    let mut view = Map::new();
    put(&mut view, "namespace", input.scope.namespace.as_str());
    put(&mut view, "trajectory", input.scope.trajectory.as_str());
    put(&mut view, "state", input.scope.state);
    put(&mut view, "view", input.scope.view.as_str());
    put(
        &mut view,
        "scope_selector",
        input.scope.scope_selector.as_str(),
    );
    put(&mut view, "source_ref", input.source_ref);
    put(&mut view, "source_sha256", input.declared.sha256.as_str());
    put(&mut view, "declared_len", input.declared.len as u64);
    put(&mut view, "declared_chunks", input.declared.chunks as u64);
    put(&mut view, "source_complete", tri(input.source_complete));
    put(
        &mut view,
        "source_set_digest",
        id.source_set_digest.as_str(),
    );
    put(&mut view, "scope_digest", id.scope_digest.as_str());
    let view = RecordSpec {
        role: Role::View,
        kind: KIND_VIEW,
        name: format!("captured view {}", input.scope.view),
        facets: view,
        key: key(&basis, "view"),
    };

    let mut occurrences = Vec::new();
    let mut parent_links = Vec::new();
    for (i, node) in p.nodes.iter().enumerate() {
        let mut f = Map::new();
        put(&mut f, "occurrence_kind", kind_of(&node.role));
        put(&mut f, "raw_role", node.role.as_str());
        if !node.label.is_empty() {
            put(&mut f, "raw_label", node.label.as_str());
        }
        put(&mut f, "source_order", node.source_order);
        put(&mut f, "depth", node.depth as u64);
        put(&mut f, "source_selector", selectors[i].as_str());
        if let Some(parent) = node.parent {
            put(&mut f, "parent_selector", selectors[parent].as_str());
        }
        if let Some(bid) = &node.bid {
            put(&mut f, "source_bid", bid.as_str());
        }
        put(&mut f, "selected", tri(node.selected));
        put(&mut f, "disabled", tri(node.disabled));
        put(
            &mut f,
            "blank",
            if node.label.trim().is_empty() {
                "true"
            } else {
                "false"
            },
        );
        put(&mut f, "line", node.line);
        put(&mut f, "char_start", node.char_start as u64);
        put(&mut f, "char_end", node.char_end as u64);
        put(&mut f, "source_excerpt", node.exact.as_str());
        put(&mut f, "offset_unit", "unicode_codepoint");
        put(&mut f, "scope_digest", id.scope_digest.as_str());
        occurrences.push(RecordSpec {
            role: Role::Occurrence(i),
            kind: KIND_OCCURRENCE,
            name: format!("occurrence {}", selectors[i]),
            facets: f,
            key: key(&basis, &format!("occurrence:{}", selectors[i])),
        });
        if let Some(parent) = node.parent {
            parent_links.push(LinkSpec {
                source: Role::Occurrence(i),
                target: Role::Occurrence(parent),
                relationship: "part_of",
                key: key(&basis, &format!("parent:{}", selectors[i])),
            });
        }
    }

    let index_of = |order: u32| p.nodes.iter().position(|n| n.source_order == order);
    let mut groups = Vec::new();
    let mut group_links = Vec::new();
    for (g, group) in p.groups.iter().enumerate() {
        let control = index_of(group.control).expect("group control is a node");
        let mut f = Map::new();
        put(&mut f, "control_selector", selectors[control].as_str());
        put(&mut f, "boundary_method", group.boundary.as_str());
        put(&mut f, "ordering_basis", "source_order");
        put(&mut f, "binding_status", "bound");
        put(&mut f, "binding_revision", id.binding_revision.as_str());
        put(&mut f, "option_count", group.options.len() as u64);
        put(&mut f, "scope_digest", id.scope_digest.as_str());
        groups.push(RecordSpec {
            role: Role::Group(g),
            kind: KIND_GROUP,
            name: format!("choice group {}", selectors[control]),
            facets: f,
            key: key(&basis, &format!("group:{}", selectors[control])),
        });
        for option in &group.options {
            let o = index_of(*option).expect("group option is a node");
            group_links.push(LinkSpec {
                source: Role::Occurrence(o),
                target: Role::Group(g),
                relationship: "choice_member",
                key: key(&basis, &format!("choice:{}", selectors[o])),
            });
        }
    }

    let mut f = Map::new();
    put(&mut f, "coverage_schema", oracle::COVERAGE_SCHEMA);
    put(&mut f, "scope_digest", id.scope_digest.as_str());
    put(&mut f, "source_set_digest", id.source_set_digest.as_str());
    put(&mut f, "extractor_version", input.extractor_version);
    put(&mut f, "verdict_oracle_version", cov.extractor_version);
    put(&mut f, "binding_revision", id.binding_revision.as_str());
    put(
        &mut f,
        "requirements_digest",
        id.requirements_digest.as_str(),
    );
    fn word<T: serde::Serialize>(v: &T) -> Value {
        serde_json::to_value(v).unwrap()
    }
    put(&mut f, "source_integrity", word(&cov.source_integrity));
    put(
        &mut f,
        "structural_coverage",
        word(&cov.structural_coverage),
    );
    put(&mut f, "semantic_coverage", word(&cov.semantic_coverage));
    for code in &cov.omissions {
        put(&mut f, &format!("omission_{code}"), "true");
    }
    if let Some((ordinal, start)) = cov.continuation {
        put(&mut f, "continuation_ordinal", ordinal);
        put(&mut f, "continuation_char_start", start as u64);
    }
    // Counts every occurrence record of the scope (controls, options and
    // elements alike), never only options.
    put(&mut f, "expected_item_count", expected);
    let coverage = RecordSpec {
        role: Role::Coverage,
        kind: KIND_COVERAGE,
        name: format!("coverage {}", input.scope.view),
        facets: f,
        key: key(&basis, "coverage"),
    };
    let coverage_links = vec![LinkSpec {
        source: Role::Coverage,
        target: Role::View,
        relationship: "covers",
        key: key(&basis, "covers"),
    }];
    let member_links = (0..p.nodes.len())
        .map(|i| LinkSpec {
            source: Role::Occurrence(i),
            target: Role::Coverage,
            relationship: MEMBER,
            key: key(&basis, &format!("member:{}", selectors[i])),
        })
        .collect();
    Ok(Plan {
        view,
        occurrences,
        parent_links,
        groups,
        group_links,
        coverage,
        coverage_links,
        member_links,
    })
}

/// Stops the ordinary (non-atomic) write sequence early, as a crash would.
#[derive(Clone, Copy, Default)]
pub(super) struct Interrupt {
    /// Write at most this many scope-membership links.
    pub member_links: Option<usize>,
}

#[derive(Debug)]
pub(super) struct Applied {
    pub ids: BTreeMap<Role, String>,
}

pub(super) struct Writer<'a> {
    pub registry: &'a crate::mcp::registry::ToolRegistry,
    pub db: &'a crate::db::Db,
    pub credential: &'a str,
    pub home: &'a str,
}

impl Writer<'_> {
    async fn call(&self, tool: &str, args: Value) -> crate::Result<Value> {
        self.registry
            .call_engine(
                crate::mcp::registry::EngineHandle::KernelV2(self.db.clone()),
                crate::mcp::registry::Caller::authenticated(self.credential),
                tool,
                args,
            )
            .await
    }

    async fn create(&self, spec: &RecordSpec) -> crate::Result<String> {
        let receipt = self
            .call(
                "create_record",
                json!({
                    "type": RECORD_TYPE, "kind": spec.kind, "name": spec.name,
                    "home_id": self.home, "facets": spec.facets,
                    "idempotency_key": spec.key,
                }),
            )
            .await?;
        receipt["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::engine("create_record receipt carried no id"))
    }

    async fn link(&self, ids: &BTreeMap<Role, String>, spec: &LinkSpec) -> crate::Result<()> {
        self.call(
            "manage_links",
            json!({
                "action": "add", "source_id": ids[&spec.source],
                "target_id": ids[&spec.target], "relationship": spec.relationship,
                "idempotency_key": spec.key,
            }),
        )
        .await
        .map(|_| ())
    }

    /// Replays send the same request with no caller ids, so keyed receipts
    /// return the existing records and write nothing.
    pub(super) async fn apply(&self, plan: &Plan, stop: Interrupt) -> crate::Result<Applied> {
        let mut ids = BTreeMap::new();
        for spec in std::iter::once(&plan.view).chain(&plan.occurrences) {
            ids.insert(spec.role.clone(), self.create(spec).await?);
        }
        for link in &plan.parent_links {
            self.link(&ids, link).await?;
        }
        for spec in &plan.groups {
            ids.insert(spec.role.clone(), self.create(spec).await?);
        }
        for link in &plan.group_links {
            self.link(&ids, link).await?;
        }
        ids.insert(
            plan.coverage.role.clone(),
            self.create(&plan.coverage).await?,
        );
        for link in &plan.coverage_links {
            self.link(&ids, link).await?;
        }
        let allowed = stop.member_links.unwrap_or(usize::MAX);
        for link in plan.member_links.iter().take(allowed) {
            self.link(&ids, link).await?;
        }
        Ok(Applied { ids })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{definition_fixture, insert_retained_definition};
    use super::super::{closure, contract, Pin, Revision};
    use super::*;
    use crate::{events::KERNEL_ROOT_ID, kernel, mcp::registry::ToolRegistry};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    const OCCURRENCES: &str = "SELECT o.id AS id, sd.value AS scope_digest, CAST(so.value_num AS INTEGER) AS source_order, \
        ok.value AS occurrence_kind, rl.value AS raw_label, ss.value AS source_selector, \
        po.id AS parent_id, c.id AS coverage_id \
        FROM records o \
        JOIN facet_values sd ON sd.record_id = o.id AND sd.key = 'scope_digest' \
        JOIN facet_values so ON so.record_id = o.id AND so.key = 'source_order' \
        JOIN facet_values ok ON ok.record_id = o.id AND ok.key = 'occurrence_kind' \
        JOIN facet_values ss ON ss.record_id = o.id AND ss.key = 'source_selector' \
        LEFT JOIN facet_values rl ON rl.record_id = o.id AND rl.key = 'raw_label' \
        LEFT JOIN links pl ON pl.source_id = o.id AND pl.relationship = 'part_of' \
        LEFT JOIN records po ON po.id = pl.target_id AND po.type = 'Document' AND po.kind = 'software_occurrence' \
        LEFT JOIN links ml ON ml.source_id = o.id AND ml.relationship = 'scope_member' \
        LEFT JOIN records c ON c.id = ml.target_id AND c.type = 'Document' AND c.kind = 'software_coverage' \
        WHERE o.type = 'Document' AND o.kind = 'software_occurrence'";
    const OCCURRENCE_COLUMNS: [(&str, &str, bool); 8] = [
        ("id", "identifier", false),
        ("scope_digest", "text", false),
        ("source_order", "integer", false),
        ("occurrence_kind", "text", false),
        ("raw_label", "text", true),
        ("source_selector", "text", false),
        ("parent_id", "identifier", true),
        ("coverage_id", "identifier", true),
    ];
    // Starts from the coverage record and counts the occurrence rows the
    // caller can see (`o.id`, never `m.source_id`): items are never the
    // verdict, and a hidden or missing item cannot be counted or inferred.
    const COVERAGE: &str = "SELECT c.id AS id, sd.value AS scope_digest, si.value AS source_integrity, \
        sc.value AS structural_coverage, se.value AS semantic_coverage, \
        CAST(ec.value_num AS INTEGER) AS expected_item_count, COUNT(o.id) AS item_rows, COUNT(ok.id) AS option_rows, \
        CASE WHEN ec.value_num = COUNT(o.id) THEN 'matches' ELSE 'count_gap' END AS count_guard, \
        CASE WHEN ec.value_num <> COUNT(o.id) THEN 'incomplete' \
             WHEN si.value = 'verified' AND sc.value = 'complete' AND se.value = 'established' THEN 'complete' \
             ELSE 'partial' END AS reading \
        FROM records c \
        JOIN facet_values cs ON cs.record_id = c.id AND cs.key = 'coverage_schema' \
            AND cs.value = 'native.software-fixture-coverage.v1' \
        JOIN facet_values sd ON sd.record_id = c.id AND sd.key = 'scope_digest' \
        JOIN facet_values si ON si.record_id = c.id AND si.key = 'source_integrity' \
        JOIN facet_values sc ON sc.record_id = c.id AND sc.key = 'structural_coverage' \
        JOIN facet_values se ON se.record_id = c.id AND se.key = 'semantic_coverage' \
        JOIN facet_values ec ON ec.record_id = c.id AND ec.key = 'expected_item_count' \
        LEFT JOIN links m ON m.target_id = c.id AND m.relationship = 'scope_member' \
        LEFT JOIN records o ON o.id = m.source_id AND o.type = 'Document' AND o.kind = 'software_occurrence' \
        LEFT JOIN facet_values ok ON ok.record_id = o.id AND ok.key = 'occurrence_kind' AND ok.value = 'option' \
        WHERE c.type = 'Document' AND c.kind = 'software_coverage' \
        GROUP BY c.id, sd.value, si.value, sc.value, se.value, ec.value_num";
    const COVERAGE_COLUMNS: [(&str, &str, bool); 10] = [
        ("id", "identifier", false),
        ("scope_digest", "text", false),
        ("source_integrity", "text", false),
        ("structural_coverage", "text", false),
        ("semantic_coverage", "text", false),
        ("expected_item_count", "integer", false),
        ("item_rows", "integer", false),
        ("option_rows", "integer", false),
        ("count_guard", "text", false),
        ("reading", "text", false),
    ];

    fn authored(
        record: &str,
        sql: &str,
        columns: &[(&str, &str, bool)],
        order: &[&str],
        statics: &[&str],
        views: &[(&str, &Pin)],
    ) -> (Pin, contract::Definition) {
        let mut definition = definition_fixture();
        let output: Vec<Value> = columns
            .iter()
            .map(|(name, kind, nullable)| json!({"name": name, "type": kind, "nullable": nullable}))
            .collect();
        let schema = format!(
            "{:x}",
            Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
                &json!(output)
            ))
        );
        let mut relations = Map::new();
        for name in statics {
            let r = crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|r| r.name == *name)
                .unwrap();
            relations.insert(
                (*name).into(),
                json!({"identity": r.identity, "semantic_version": r.semantic_version}),
            );
        }
        for (name, pin) in views {
            relations.insert((*name).into(), serde_json::to_value(pin).unwrap());
        }
        let query = &mut definition["query"];
        query["sql"] = json!(sql);
        query["relations"] = Value::Object(relations);
        query["output"] = json!({
            "columns": output, "schema_sha256": schema, "row_identity": ["id"],
            "order": order.iter().map(|c| json!({"column": c, "direction": "asc"})).collect::<Vec<_>>(),
        });
        query["bounds"] = json!({"rows": 1000});
        definition["columns"] = Value::Object(
            columns
                .iter()
                .map(|(name, ..)| {
                    ((*name).to_owned(), json!({"meaning": format!("software projection {name}"),
                        "source_mapping": "records, facet_values and links", "vocabulary": null, "unit": null, "encoding": null}))
                })
                .collect(),
        );
        let definition: contract::Definition = serde_json::from_value(definition).unwrap();
        let revision = Revision {
            v: 1,
            view_id: format!("native.named-view:{record}"),
            definition_sha256: String::new(),
            definition: serde_json::to_value(&definition).unwrap(),
        };
        let pin = Pin {
            view_id: revision.view_id.clone(),
            revision_id: uuid::Uuid::new_v4().to_string(),
            definition_sha256: revision.digest(),
            schema_sha256: schema,
        };
        (pin, definition)
    }

    struct Views {
        occurrences: Pin,
        coverage: Pin,
    }

    struct World {
        db: crate::db::Db,
        registry: ToolRegistry,
        scope_home: String,
        views: Views,
        admin: String,
        viewer: String,
    }

    /// An isolated database: one scope home (admin only, plus `viewer_sees`
    /// on request) and a separate home holding the two view bearers, which
    /// the viewer can always read.
    async fn world(viewer_sees_scope: bool) -> World {
        let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
            .await
            .unwrap();
        let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
            .await
            .unwrap();
        // The existing v1 compat carrier: any (type, kind) pair rides it.
        let carrier = crate::v2_standard::v1_compat::package();
        let identity = carrier.identity().unwrap();
        kernel::install_package_as(&db, &admin, &carrier)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &carrier,
            Some(&identity),
            &carrier.declared_reads,
        )
        .await
        .unwrap();
        let mut scope_grants = vec![(admin.as_str(), "manage")];
        if viewer_sees_scope {
            scope_grants.push((viewer.as_str(), "view"));
        }
        let scope_home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&scope_grants), &admin)
            .await
            .unwrap();
        let views_home = kernel::create_home(
            &db,
            KERNEL_ROOT_ID,
            Some(&[(admin.as_str(), "manage"), (viewer.as_str(), "view")]),
            &admin,
        )
        .await
        .unwrap();
        let occ_record = kernel::create_record_as(&db, &admin, &views_home)
            .await
            .unwrap();
        let cov_record = kernel::create_record_as(&db, &admin, &views_home)
            .await
            .unwrap();
        let (occurrences, occ_def) = authored(
            &occ_record,
            OCCURRENCES,
            &OCCURRENCE_COLUMNS,
            &["scope_digest", "source_order", "id"],
            &["records", "facet_values", "links"],
            &[],
        );
        let (coverage, cov_def) = authored(
            &cov_record,
            COVERAGE,
            &COVERAGE_COLUMNS,
            &["scope_digest", "id"],
            &["records", "facet_values", "links"],
            &[],
        );
        // The named validators run on both authored definitions.
        for definition in [&occ_def, &cov_def] {
            definition.validate_retained().unwrap();
        }
        let roots = BTreeMap::from([
            ("view_software_occurrences".to_owned(), occurrences.clone()),
            ("view_software_coverage".to_owned(), coverage.clone()),
        ]);
        closure::build(
            &roots,
            &BTreeMap::from([
                (occurrences.clone(), occ_def.clone()),
                (coverage.clone(), cov_def.clone()),
            ]),
        )
        .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        insert_retained_definition(&mut tx, &occurrences, &occ_def, None).await;
        insert_retained_definition(&mut tx, &coverage, &cov_def, None).await;
        tx.commit().await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        World {
            db,
            registry,
            scope_home,
            views: Views {
                occurrences,
                coverage,
            },
            admin,
            viewer,
        }
    }

    impl World {
        fn writer(&self) -> Writer<'_> {
            Writer {
                registry: &self.registry,
                db: &self.db,
                credential: "acct:admin",
                home: &self.scope_home,
            }
        }

        /// Reads one authored view through the pinned SavedSQL 1.2 route.
        async fn read(&self, actor: &str, coverage: bool) -> Value {
            let (pin, columns, order) = if coverage {
                (
                    &self.views.coverage,
                    &COVERAGE_COLUMNS[..],
                    vec!["scope_digest", "id"],
                )
            } else {
                (
                    &self.views.occurrences,
                    &OCCURRENCE_COLUMNS[..],
                    vec!["scope_digest", "source_order", "id"],
                )
            };
            let select = columns.iter().map(|c| c.0).collect::<Vec<_>>().join(", ");
            let (_, outer) = authored(
                "query",
                &format!("SELECT {select} FROM view_under_read"),
                columns,
                &order,
                &[],
                &[("view_under_read", pin)],
            );
            crate::mcp::kernel_v2::query_pinned_saved_sql(&self.db, actor, &outer.query)
                .await
                .unwrap()
        }

        async fn events(&self) -> i64 {
            sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(self.db.pool())
                .await
                .unwrap()
        }
    }

    struct Fixture {
        projection: Projection,
        request: oracle::Request,
        attestation: Attestation,
    }

    fn fixture(case: &str, binding: &str) -> Fixture {
        let projection = load(case);
        let len = projection.tree.len();
        let request = oracle::Request {
            scope: Scope {
                namespace: "synthetic.software".into(),
                trajectory: "traj-1".into(),
                state: 0,
                view: format!("view-{case}"),
                scope_selector: "root".into(),
            },
            source_ref: format!("fixture:{case}"),
            source_complete: Some(true),
            tree: projection.tree.clone(),
            // Declared metadata is fixture-provided: the package's own digest
            // of the tree, a single whole-source chunk. Not external proof.
            declared: Declared {
                sha256: projection.tree_sha256.clone(),
                len,
                chunks: 1,
            },
            chunks: vec![oracle::Chunk {
                ordinal: 0,
                byte_start: 0,
                byte_end: len,
                sha256: oracle::digest(projection.tree.as_bytes()),
            }],
            binding_revision: binding.into(),
            requirements: ["flags", "options", "parents"].map(str::to_owned).into(),
        };
        let attestation = oracle::attest(&request, oracle::Caps::default());
        Fixture {
            projection,
            request,
            attestation,
        }
    }

    impl Fixture {
        fn plan(&self) -> Plan {
            plan(&Input {
                projection: &self.projection,
                oracle: &self.attestation,
                scope: &self.request.scope,
                source_ref: &self.request.source_ref,
                declared: &self.request.declared,
                source_complete: self.request.source_complete,
                extractor_version: "native.software-observations/0.1",
                caps: oracle::Caps::default(),
            })
            .unwrap()
        }
    }

    fn row_for<'a>(rows: &'a Value, scope_digest: &str) -> &'a Value {
        rows["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["scope_digest"] == scope_digest)
            .unwrap_or_else(|| panic!("no coverage row for {scope_digest}"))
    }

    #[tokio::test]
    async fn positive_and_zero_option_scopes_project_through_ordinary_writes() {
        let w = world(false).await;
        let mut applied = BTreeMap::new();
        let cases = ["positive", "groups_end_of_source", "zero_option"];
        for case in cases {
            let f = fixture(case, "binding-1");
            let a = w
                .writer()
                .apply(&f.plan(), Interrupt::default())
                .await
                .unwrap();
            applied.insert(case, (f, a));
        }
        let occurrences = w.read(&w.admin, false).await;
        let coverage = w.read(&w.admin, true).await;
        assert_eq!(coverage["rows"].as_array().unwrap().len(), 3);

        // Positive scope: every node is a row, in source order, with the
        // part_of parent composition and membership of its own coverage.
        let (f, a) = &applied["positive"];
        let digest = &f.attestation.identity.scope_digest;
        let rows: Vec<&Value> = occurrences["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["scope_digest"] == digest.as_str())
            .collect();
        let labels: Vec<_> = rows
            .iter()
            .map(|r| r["raw_label"].as_str().unwrap())
            .collect();
        assert_eq!(labels, ["Priority", "High", "Low", "Area"]);
        let kinds: Vec<_> = rows
            .iter()
            .map(|r| r["occurrence_kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["control", "option", "option", "control"]);
        let control = a.ids[&Role::Occurrence(0)].as_str();
        assert!(rows[0]["parent_id"].is_null() && rows[3]["parent_id"].is_null());
        assert_eq!(rows[1]["parent_id"], control);
        assert_eq!(rows[2]["parent_id"], control);
        let coverage_id = a.ids[&Role::Coverage].as_str();
        assert!(rows.iter().all(|r| r["coverage_id"] == coverage_id));

        // Counts are all occurrence nodes; options are reported separately.
        let positive = row_for(&coverage, digest);
        assert_eq!(positive["expected_item_count"], 4);
        assert_eq!(positive["item_rows"], 4);
        assert_eq!(positive["option_rows"], 2);
        assert_eq!(positive["count_guard"], "matches");
        // "Area" has no option children, so even this scope is only partial.
        assert_eq!(positive["semantic_coverage"], "partial");
        assert_eq!(positive["reading"], "partial");

        let whole = &applied["groups_end_of_source"]
            .0
            .attestation
            .identity
            .scope_digest;
        let whole = row_for(&coverage, whole);
        assert_eq!(
            (whole["item_rows"].as_i64(), whole["option_rows"].as_i64()),
            (Some(3), Some(2))
        );
        assert_eq!(whole["reading"], "complete");

        // Zero options: the coverage row still exists, is independent of the
        // option rows, and is not an empty-complete claim.
        let (f, a) = &applied["zero_option"];
        let zero = row_for(&coverage, &f.attestation.identity.scope_digest);
        assert_eq!(zero["option_rows"], 0);
        assert_eq!(zero["item_rows"], 1);
        assert_eq!(zero["expected_item_count"], 1);
        assert_eq!(zero["count_guard"], "matches");
        assert_eq!(zero["structural_coverage"], "complete");
        assert_eq!(zero["semantic_coverage"], "partial");
        assert_eq!(zero["reading"], "partial");
        let omission: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM kernel_facets WHERE record_id=? AND key='omission_no_observed_option_children' AND value='true'",
        )
        .bind(&a.ids[&Role::Coverage])
        .fetch_one(w.db.pool())
        .await
        .unwrap();
        assert_eq!(omission, 1);

        // One home holds every record of every scope; nothing else exists.
        let homes: Vec<(String, i64)> = sqlx::query_as(
            "SELECT home_id, count(*) FROM kernel_records WHERE id IN (SELECT record_id FROM kernel_facets WHERE key='scope_digest' OR key='namespace') GROUP BY home_id",
        )
        .fetch_all(w.db.pool())
        .await
        .unwrap();
        assert_eq!(homes.len(), 1, "{homes:?}");
        assert_eq!(homes[0].0, w.scope_home);
    }

    #[tokio::test]
    async fn interrupted_membership_reads_as_count_gap_never_complete_zero() {
        let w = world(false).await;
        let f = fixture("groups_end_of_source", "binding-1");
        let plan = f.plan();
        let digest = f.attestation.identity.scope_digest.clone();
        // A crash between the coverage record and its membership links, with
        // none, then only some of the links written.
        for written in [0usize, 2] {
            let stop = Interrupt {
                member_links: Some(written),
            };
            w.writer().apply(&plan, stop).await.unwrap();
            let coverage = w.read(&w.admin, true).await;
            let row = row_for(&coverage, &digest);
            assert_eq!(row["expected_item_count"], 3);
            assert_eq!(row["item_rows"], written as i64);
            assert_eq!(row["count_guard"], "count_gap");
            assert_eq!(row["reading"], "incomplete", "{row}");
            // The coverage record's own verdict is still reported; the gap
            // is what stops it being read as complete.
            assert_eq!(row["structural_coverage"], "complete");
        }
        // Replaying the same plan completes only the missing links.
        let before = w.events().await;
        let before_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let completed = w.writer().apply(&plan, Interrupt::default()).await.unwrap();
        assert_eq!(
            w.events().await,
            before + 2,
            "one missing membership link and one canonical private receipt fact"
        );
        let key = &plan.member_links[2].key;
        let facts: Vec<(i64, i64, String)> = sqlx::query_as(
            "SELECT seq,act,payload FROM content_events WHERE seq>? AND record_id='kernel:mcp-write-receipts' \
             AND type='kernel.mcp_write_receipt_recorded.v1' AND actor=? \
             AND json_extract(payload,'$.operation')='manage_links' \
             AND json_extract(payload,'$.operation_key')=?"
        ).bind(before_seq).bind(&w.admin).bind(key).fetch_all(w.db.pool()).await.unwrap();
        assert_eq!(
            facts.len(),
            1,
            "only the previously missing membership key commits a recovery fact"
        );
        let (fact_seq, fact_act, raw) = &facts[0];
        assert!(*fact_act > 0);
        let fact: Value = serde_json::from_str(raw).unwrap();
        let ledger: String = sqlx::query_scalar("SELECT receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='manage_links' AND operation_key=?")
            .bind(&w.admin).bind(key).fetch_one(w.db.pool()).await.unwrap();
        assert_eq!(
            fact["receipt_json"].as_str().unwrap(),
            ledger,
            "carriage preserves the exact complete response bytes"
        );
        let receipt: Value = serde_json::from_str(&ledger).unwrap();
        let links: Vec<(i64, String, i64)> = sqlx::query_as(
            "SELECT seq,record_id,act FROM content_events WHERE seq>? AND type='kernel.generic_link_added.v1'"
        ).bind(before_seq).fetch_all(w.db.pool()).await.unwrap();
        assert_eq!(
            links.len(),
            1,
            "completing the plan appends only its missing business link"
        );
        let (link_seq, source, link_act) = &links[0];
        assert_eq!(source, &completed.ids[&plan.member_links[2].source]);
        assert_eq!(
            receipt["link"]["target_id"],
            completed.ids[&plan.member_links[2].target]
        );
        assert_eq!(
            receipt["link"]["relationship"],
            plan.member_links[2].relationship
        );
        assert_eq!(receipt["write_receipt"]["event"]["seq"], *link_seq);
        assert_eq!(
            link_act, fact_act,
            "membership effect and receipt fact share one act"
        );
        assert!(*fact_seq > *link_seq);
        let coverage = w.read(&w.admin, true).await;
        let row = row_for(&coverage, &digest);
        assert_eq!(
            (row["item_rows"].as_i64(), row["count_guard"].as_str()),
            (Some(3), Some("matches"))
        );
        assert_eq!(row["reading"], "complete");
    }

    #[tokio::test]
    async fn replay_is_effect_free_and_a_changed_request_conflicts_on_the_same_key() {
        let w = world(false).await;
        let f = fixture("positive", "binding-1");
        let plan = f.plan();
        let first = w.writer().apply(&plan, Interrupt::default()).await.unwrap();
        let after_first = w.events().await;

        // Keys are short, prefixed and distinct per role.
        let keys: Vec<&String> = std::iter::once(&plan.view.key)
            .chain(plan.occurrences.iter().map(|r| &r.key))
            .chain(plan.groups.iter().map(|r| &r.key))
            .chain(std::iter::once(&plan.coverage.key))
            .chain(plan.parent_links.iter().map(|l| &l.key))
            .chain(plan.group_links.iter().map(|l| &l.key))
            .chain(plan.coverage_links.iter().map(|l| &l.key))
            .chain(plan.member_links.iter().map(|l| &l.key))
            .collect();
        assert!(keys
            .iter()
            .all(|k| k.starts_with("software-attest:") && k.len() <= 200));
        assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), keys.len());

        // Same plan again: same ids, no events, no caller ids sent.
        let again = w.writer().apply(&plan, Interrupt::default()).await.unwrap();
        assert_eq!(again.ids, first.ids);
        assert_eq!(w.events().await, after_first);

        // Same key, different request: a typed conflict and no effect.
        let mut changed = plan.clone();
        changed.occurrences[1]
            .facets
            .insert("raw_label".into(), json!("Changed"));
        let error = w
            .writer()
            .apply(&changed, Interrupt::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::Conflict(m) if m.contains("idempotency_key reused for different request")),
            "{error:?}"
        );
        assert_eq!(w.events().await, after_first);

        // A new binding revision is a new attestation: every key differs and
        // the first attestation is untouched.
        let second = fixture("positive", "binding-2");
        let other = second.plan();
        assert!(other.view.key != plan.view.key && other.coverage.key != plan.coverage.key);
        assert!(other
            .member_links
            .iter()
            .zip(&plan.member_links)
            .all(|(a, b)| a.key != b.key));
        w.writer()
            .apply(&other, Interrupt::default())
            .await
            .unwrap();
        let coverage = w.read(&w.admin, true).await;
        let rows = coverage["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|r| r["count_guard"] == "matches" && r["item_rows"] == 4));
        assert!(rows
            .iter()
            .any(|r| r["id"] == first.ids[&Role::Coverage].as_str()));

        // The plan is refused, not repaired, when its inputs disagree.
        let mut tampered = fixture("positive", "binding-1");
        tampered.request.declared.sha256 = "0".repeat(64);
        let refusal = super::plan(&Input {
            projection: &tampered.projection,
            oracle: &tampered.attestation,
            scope: &tampered.request.scope,
            source_ref: &tampered.request.source_ref,
            declared: &tampered.request.declared,
            source_complete: Some(true),
            extractor_version: "native.software-observations/0.1",
            caps: oracle::Caps::default(),
        });
        assert_eq!(refusal.unwrap_err(), Refusal::Digest);
    }

    #[tokio::test]
    async fn caller_without_view_on_the_scope_home_sees_the_same_as_an_absent_scope() {
        let hidden = world(false).await;
        hidden
            .writer()
            .apply(
                &fixture("positive", "binding-1").plan(),
                Interrupt::default(),
            )
            .await
            .unwrap();
        let absent = world(false).await;
        for coverage in [false, true] {
            let seen = hidden.read(&hidden.viewer, coverage).await;
            let none = absent.read(&absent.viewer, coverage).await;
            assert_eq!(seen["rows"], json!([]));
            assert_eq!(seen["rows"], none["rows"]);
            assert_eq!(seen["columns"], none["columns"]);
        }
        let counted = crate::mcp::kernel_v2::sql::query_sql(
            &hidden.db,
            &hidden.viewer,
            json!({"sql": "SELECT count(*) AS n FROM records WHERE kind LIKE 'software_%'"}),
        )
        .await
        .unwrap();
        assert_eq!(counted["rows"], json!([{"n": 0}]));

        // The same data is readable once the home itself grants View, so the
        // empty result above is permissions and not a vacuous view.
        let shared = world(true).await;
        shared
            .writer()
            .apply(
                &fixture("positive", "binding-1").plan(),
                Interrupt::default(),
            )
            .await
            .unwrap();
        let rows = shared.read(&shared.viewer, false).await;
        assert_eq!(rows["rows"].as_array().unwrap().len(), 4);
        let coverage = shared.read(&shared.viewer, true).await;
        assert_eq!(coverage["rows"][0]["item_rows"], 4);
    }
}

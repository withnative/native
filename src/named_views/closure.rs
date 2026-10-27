//! Exact tuple-scoped closure planning. This does not stage or execute user SQL.
use super::*;
use contract::{Definition, Dependency};
use std::collections::BTreeSet;

#[derive(Clone)]
#[cfg_attr(not(feature = "v2-kernel-probe"), allow(dead_code))]
pub(crate) struct Node {
    pub pin: Pin,
    pub definition: Definition,
    pub alias: String,
    pub sql: String,
}
#[derive(Clone)]
#[cfg_attr(not(feature = "v2-kernel-probe"), allow(dead_code))]
pub(crate) struct Closure {
    pub nodes: Vec<Node>,
    #[allow(dead_code)] // Consumed by the PR 2b execution surface.
    pub roots: BTreeMap<String, String>,
    #[allow(dead_code)] // Consumed by the PR 2b validation cache.
    pub digest: String,
}
#[allow(dead_code)] // Tuple aliases are consumed by the dormant closure builder.
fn alias(pin: &Pin) -> Result<String> {
    Ok(format!(
        "_native_view_{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::to_value(pin)?
        ))
    ))
}
#[allow(dead_code)] // Admission remains closed until PR 2b.
struct Builder<'a> {
    definitions: &'a BTreeMap<Pin, Definition>,
    nodes: Vec<Node>,
    heights: BTreeMap<Pin, usize>,
    descendants: BTreeMap<Pin, BTreeSet<String>>,
    ancestors: BTreeSet<String>,
    edges: usize,
    bytes: usize,
    sql_bytes: usize,
    expanded_bytes: usize,
}
impl Builder<'_> {
    #[allow(dead_code)] // Admission remains closed until PR 2b.
    fn visit(&mut self, pin: &Pin, depth: usize) -> Result<usize> {
        if self.ancestors.contains(&pin.view_id) {
            return Err(invalid("view_cycle"));
        }
        if depth > 4 {
            return Err(invalid("view_budget_exceeded: depth"));
        }
        if let Some(height) = self.heights.get(pin) {
            if !self.descendants[pin].is_disjoint(&self.ancestors) {
                return Err(invalid("view_cycle"));
            }
            if depth + height - 1 > 4 {
                return Err(invalid("view_budget_exceeded: shared subtree depth"));
            }
            return Ok(*height);
        }
        if self.nodes.len() + self.ancestors.len() >= 16 {
            return Err(invalid("view_budget_exceeded: nodes"));
        }
        let def = self
            .definitions
            .get(pin)
            .ok_or_else(|| invalid("view_revision_unavailable"))?
            .clone();
        def.validate_for_preparation()?;
        if def.query.output.schema_sha256 != pin.schema_sha256 {
            return Err(invalid("view_source_invalidated: schema digest"));
        }
        let revision = Revision {
            v: 1,
            view_id: pin.view_id.clone(),
            definition_sha256: pin.definition_sha256.clone(),
            definition: serde_json::to_value(&def)?,
        };
        if revision.digest() != pin.definition_sha256 {
            return Err(invalid("view_source_invalidated: definition digest"));
        }
        self.bytes += serde_json::to_vec(&revision)?.len();
        self.sql_bytes += def.query.sql.len();
        if self.bytes > 512 * 1024 || self.sql_bytes > 256 * 1024 {
            return Err(invalid("view_budget_exceeded: closure bytes"));
        }
        self.ancestors.insert(pin.view_id.clone());
        let mut bindings = BTreeMap::new();
        let mut height = 1;
        let mut descendants = BTreeSet::new();
        for (name, dep) in &def.query.relations {
            if let Dependency::View(child) = dep {
                self.edges += 1;
                if self.edges > 32 {
                    return Err(invalid("view_budget_exceeded: edges"));
                }
                height = height.max(1 + self.visit(child, depth + 1)?);
                descendants.insert(child.view_id.clone());
                descendants.extend(self.descendants[child].iter().cloned());
                bindings.insert(name.clone(), alias(child)?);
            }
        }
        self.ancestors.remove(&pin.view_id);
        let sql = if bindings.is_empty() {
            def.query.sql.clone()
        } else {
            crate::query::turso_ast_rules::rebind_definition(&def.query.sql, &bindings)?
        };
        self.expanded_bytes += sql.len();
        if sql.len() > 64 * 1024 || self.expanded_bytes > 256 * 1024 {
            return Err(invalid("view_budget_exceeded: expanded SQL bytes"));
        }
        self.nodes.push(Node {
            pin: pin.clone(),
            definition: def,
            alias: alias(pin)?,
            sql,
        });
        self.descendants.insert(pin.clone(), descendants);
        self.heights.insert(pin.clone(), height);
        Ok(height)
    }
}
#[allow(dead_code)] // Admission is intentionally closed until PR 2b.
pub(crate) fn build(
    roots: &BTreeMap<String, Pin>,
    definitions: &BTreeMap<Pin, Definition>,
) -> Result<Closure> {
    if roots.len() > 8 {
        return Err(invalid("view_budget_exceeded: roots"));
    }
    let mut builder = Builder {
        definitions,
        nodes: Vec::new(),
        heights: BTreeMap::new(),
        descendants: BTreeMap::new(),
        ancestors: BTreeSet::new(),
        edges: 0,
        bytes: 0,
        sql_bytes: 0,
        expanded_bytes: 0,
    };
    let mut bound_roots = BTreeMap::new();
    for (name, pin) in roots {
        validate_name(name)?;
        contract::validate_pin(pin)?;
        builder.visit(pin, 1)?;
        bound_roots.insert(name.clone(), alias(pin)?);
    }
    let tuples: Vec<_> = builder.nodes.iter().map(|n| &n.pin).collect();
    let digest = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::to_value(tuples)?
        ))
    );
    Ok(Closure {
        nodes: builder.nodes,
        roots: bound_roots,
        digest,
    })
}

/// Shared request work cap for catalog certification, charged before payloads
/// are fetched. Exact references are reused only within this read snapshot.
#[cfg(feature = "v2-kernel-probe")]
#[derive(Default)]
pub(crate) struct CertificationBudget {
    nodes: usize,
    bytes: usize,
    certified: BTreeMap<Pin, Definition>,
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn resolve_budgeted_on(
    tx: &mut SqliteConnection,
    actor: &str,
    roots: &BTreeMap<String, Pin>,
    deadline: Instant,
    budget: &mut CertificationBudget,
) -> Result<Closure> {
    let inspected = inspect_on(tx, actor, roots, deadline, None, true, budget).await?;
    storage::check_deadline(deadline)?;
    let plan = build(roots, &inspected.definitions)?;
    storage::check_deadline(deadline)?;
    Ok(plan)
}

#[cfg(feature = "v2-kernel-probe")]
#[allow(dead_code)] // Snapshot execution is wired by PR 2b.
pub(crate) async fn resolve_on(
    tx: &mut SqliteConnection,
    actor: &str,
    roots: &BTreeMap<String, Pin>,
    deadline: Instant,
) -> Result<Closure> {
    let inspected = inspect_on(
        tx,
        actor,
        roots,
        deadline,
        None,
        true,
        &mut CertificationBudget::default(),
    )
    .await?;
    build(roots, &inspected.definitions)
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn resolve_candidate_on(
    tx: &mut SqliteConnection,
    actor: &str,
    pin: Pin,
    definition: Definition,
    deadline: Instant,
) -> Result<Closure> {
    let roots = BTreeMap::from([("view_candidate".into(), pin.clone())]);
    let inspected = inspect_on(
        tx,
        actor,
        &roots,
        deadline,
        Some((pin, definition)),
        true,
        &mut CertificationBudget::default(),
    )
    .await?;
    build(&roots, &inspected.definitions)
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct Inspection {
    pub definitions: BTreeMap<Pin, Definition>,
    pub drifted: bool,
}

/// Commit-time visibility and strict current-source checks. The SQL/graph
/// contract was certified outside the writer on these immutable event bodies.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn inspect_executable_on(
    tx: &mut SqliteConnection,
    actor: &str,
    roots: &BTreeMap<String, Pin>,
    deadline: Instant,
    candidate: Option<(Pin, Definition)>,
) -> Result<Inspection> {
    inspect_on(
        tx,
        actor,
        roots,
        deadline,
        candidate,
        true,
        &mut CertificationBudget::default(),
    )
    .await
}

/// Authorize every retained bearer and source before returning immutable SQL.
/// Current source/schema validity is an execution property, not read authority.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn inspect_metadata_on(
    tx: &mut SqliteConnection,
    actor: &str,
    roots: &BTreeMap<String, Pin>,
    deadline: Instant,
) -> Result<Inspection> {
    inspect_on(
        tx,
        actor,
        roots,
        deadline,
        None,
        false,
        &mut CertificationBudget::default(),
    )
    .await
}
#[cfg(feature = "v2-kernel-probe")]
async fn inspect_on(
    tx: &mut SqliteConnection,
    actor: &str,
    roots: &BTreeMap<String, Pin>,
    deadline: Instant,
    candidate: Option<(Pin, Definition)>,
    executable: bool,
    budget: &mut CertificationBudget,
) -> Result<Inspection> {
    if roots.len() > 8 {
        return Err(invalid("view_budget_exceeded: roots"));
    }
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    // Exact event-id lookups use content_events.id, independent of the optional
    // lifecycle accelerator and of the total workspace log length.
    let mut visible_bearers = BTreeSet::new();
    let mut definitions = BTreeMap::new();
    let mut pending: Vec<_> = roots.values().cloned().collect();
    let mut bytes = 0;
    let mut drifted = false;
    while let Some(pin) = pending.pop() {
        storage::check_deadline(deadline)?;
        contract::validate_pin(&pin)?;
        if definitions.contains_key(&pin) {
            continue;
        }
        let record = pin
            .view_id
            .strip_prefix("native.named-view:")
            .ok_or_else(|| invalid("view_missing"))?;
        require_accessible_bearer_on(tx, actor, record, &mut visible_bearers, executable).await?;
        if !executable {
            let archived: bool = sqlx::query_scalar(
                "SELECT coalesce((SELECT archived FROM kernel_lifecycle WHERE record_id=?),0)",
            )
            .bind(record)
            .fetch_one(&mut *tx)
            .await?;
            drifted |= archived;
        }
        let budget_pins = || std::iter::once(&pin).chain(pending.iter());
        if definitions.len() >= 16 || (budget.nodes >= 16 && !budget.certified.contains_key(&pin)) {
            return Err(budget_error_on(
                tx,
                actor,
                budget_pins(),
                &mut visible_bearers,
                deadline,
                executable,
                "view_budget_exceeded: nodes",
            )
            .await?);
        }
        // SQLite measures retained bytes without returning the payload to Rust.
        // Count before allocating either the EventRow payload or decoded JSON.
        let def = if let Some((_, definition)) = candidate.as_ref().filter(|(p, _)| p == &pin) {
            let len = serde_json::to_vec(definition)?.len() + 256;
            if len > MAX_CARRIER_BYTES
                || len > 512 * 1024 - bytes
                || len > 512 * 1024 - budget.bytes
            {
                return Err(budget_error_on(
                    tx,
                    actor,
                    budget_pins(),
                    &mut visible_bearers,
                    deadline,
                    executable,
                    "view_budget_exceeded: closure bytes",
                )
                .await?);
            }
            bytes += len;
            budget.nodes += 1;
            budget.bytes += len;
            definition.clone()
        } else if let Some(definition) = budget.certified.get(&pin) {
            let len = serde_json::to_vec(definition)?.len() + 256;
            if len > 512 * 1024 - bytes {
                return Err(invalid("view_budget_exceeded: closure bytes"));
            }
            bytes += len;
            definition.clone()
        } else {
            let header: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT record_id,type,coalesce(length(CAST(payload AS BLOB)),0) FROM content_events WHERE id=? AND seq<=?")
            .bind(&pin.revision_id).bind(head).fetch_optional(&mut *tx).await?;
            let (event_record, kind, payload_bytes) =
                header.ok_or_else(|| invalid("view_revision_unavailable"))?;
            if kind != REVISION || event_record != record {
                return Err(invalid("view_revision_unavailable"));
            }
            let payload_bytes =
                usize::try_from(payload_bytes).map_err(|_| invalid("invalid revision length"))?;
            if payload_bytes > MAX_CARRIER_BYTES
                || payload_bytes > 512 * 1024 - bytes
                || payload_bytes > 512 * 1024 - budget.bytes
            {
                return Err(budget_error_on(
                    tx,
                    actor,
                    budget_pins(),
                    &mut visible_bearers,
                    deadline,
                    executable,
                    "view_budget_exceeded: closure bytes",
                )
                .await?);
            }
            bytes += payload_bytes;
            budget.nodes += 1;
            budget.bytes += payload_bytes;
            let event = read_event(tx, &pin.revision_id, head).await?;
            let revision: Revision = decode(&event, MAX_CARRIER_BYTES)?;
            let def = revision.validate(&event)?;
            if revision.definition_sha256 != pin.definition_sha256 {
                return Err(invalid("view_revision_unavailable"));
            }

            def
        };

        for source in &def.source_pins {
            require_accessible_bearer_on(
                tx,
                actor,
                &source.record_id,
                &mut visible_bearers,
                executable,
            )
            .await?;
            let current: i64 = sqlx::query_scalar(
                "SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=?",
            )
            .bind(&source.record_id)
            .fetch_one(&mut *tx)
            .await?;
            let valid = match read_event(tx, &source.revision_id, head).await {
                Ok(e) => {
                    e.record_id == source.record_id
                        && e.local_seq == current
                        && source_digest(&e)? == source.sha256
                }
                Err(error) if executable => return Err(error),
                Err(_) => false,
            };
            if !valid {
                if executable {
                    return Err(invalid("view_source_invalidated"));
                }
                drifted = true;
            }
        }
        pending.extend(def.query.relations.values().filter_map(|dep| match dep {
            Dependency::View(pin) => Some(pin.clone()),
            _ => None,
        }));
        budget.certified.insert(pin.clone(), def.clone());
        definitions.insert(pin, def);
    }
    storage::check_deadline(deadline)?;
    Ok(Inspection {
        definitions,
        drifted,
    })
}

/// Visibility only: never hydrate record bodies, fields or event payloads.
#[cfg(feature = "v2-kernel-probe")]
pub(super) async fn require_accessible_bearer_on(
    conn: &mut SqliteConnection,
    actor: &str,
    record: &str,
    checked: &mut BTreeSet<String>,
    executable: bool,
) -> Result<()> {
    if checked.contains(record) {
        return Ok(());
    }
    let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r LEFT JOIN kernel_lifecycle l ON l.record_id=r.id WHERE r.id=? AND (?=0 OR coalesce(l.archived,0)=0))")
        .bind(record).bind(executable).fetch_one(&mut *conn).await?;
    if !live
        || !crate::kernel::kernel_effective_capability_on(conn, actor, record)
            .await?
            .allows(crate::authorization::Capability::View)
    {
        return Err(invalid("view_missing"));
    }
    checked.insert(record.to_owned());
    Ok(())
}

/// At most eight roots plus 16 loaded definitions' bounded dependency maps
/// can contribute pending pins. Inspect only these discovered bearers; do not
/// load more definitions or walk an unseen closure after exhausting the budget.
#[cfg(feature = "v2-kernel-probe")]
async fn budget_error_on<'a>(
    conn: &mut SqliteConnection,
    actor: &str,
    pins: impl Iterator<Item = &'a Pin>,
    checked: &mut BTreeSet<String>,
    deadline: Instant,
    executable: bool,
    reason: &str,
) -> Result<Error> {
    for pin in pins {
        storage::check_deadline(deadline)?;
        let record = pin
            .view_id
            .strip_prefix("native.named-view:")
            .ok_or_else(|| invalid("view_missing"))?;
        require_accessible_bearer_on(conn, actor, record, checked, executable).await?;
    }
    Ok(invalid(reason))
}

/// Source pins identify the current record revision's retained event contract,
/// independent of event sequence translation or present-day record formatting.
pub(crate) fn source_digest(event: &EventRow) -> Result<String> {
    let payload: serde_json::Value = serde_json::from_str(
        event
            .payload
            .as_deref()
            .ok_or_else(|| invalid("missing source contract"))?,
    )?;
    Ok(format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::json!([event.event_type, event.record_id, payload])
        ))
    ))
}

#[cfg(feature = "v2-kernel-probe")]
impl Closure {
    /// Both SQLite security gates observe every whole body, even columns the
    /// outer query might prune. Data staging/execution is deliberately PR 2b.
    #[allow(dead_code)] // Request validation is wired by PR 2b.
    pub(crate) fn validate_schema(&self) -> Result<BTreeSet<(String, String)>> {
        self.analyze_schema()
            .map_err(crate::query::sql::named_views::SchemaFailure::into_error)
    }
    pub(crate) fn analyze_schema(
        &self,
    ) -> std::result::Result<
        BTreeSet<(String, String)>,
        crate::query::sql::named_views::SchemaFailure,
    > {
        use crate::query::sql::named_views::SchemaFailure;
        let validators = crate::query::sql::NamedViewValidators::from_closure(self)
            .map_err(SchemaFailure::Infrastructure)?;
        let mut union = BTreeSet::new();
        for node in &self.nodes {
            let (reads, labels) = validators.inspect_classified(&node.sql)?;
            if node
                .definition
                .query
                .relations
                .values()
                .any(|d| matches!(d, Dependency::View(_)))
            {
                let original = crate::query::sql::NamedViewValidators::for_original(self, node)
                    .map_err(SchemaFailure::Infrastructure)?;
                let (_, original_labels) =
                    original.inspect_classified(&node.definition.query.sql)?;
                if labels != original_labels {
                    return Err(invalid("view_source_invalidated: rebinding changed labels").into());
                }
            }
            if labels
                != node
                    .definition
                    .query
                    .output
                    .columns
                    .iter()
                    .map(|c| c.name.clone())
                    .collect::<Vec<_>>()
            {
                return Err(invalid("view_source_invalidated: prepared labels").into());
            }
            for (relation, column) in reads {
                if self.nodes.iter().any(|n| n.alias == relation) {
                    continue;
                }
                let columns = crate::mcp::kernel_v2::sql::columns(&relation)
                    .ok_or_else(|| invalid("view_profile_unsupported"))?;
                if !column.is_empty() && !columns.contains(&column.as_str()) {
                    return Err(invalid("view_source_invalidated: static column").into());
                }
                union.insert((relation, column));
            }
        }
        Ok(union)
    }
}

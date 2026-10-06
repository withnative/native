//! Gated v2 dependency-safety enforcement (task e2bfaf5, Increment 2).
//!
//! Shared prospective-transaction preflight plus the public attributed
//! consumer wrappers. No mapping, no upcast, no re-pin, no identity
//! changes: incompatible changes refuse atomically, nothing is migrated.
//!
//! Rules shared by execute and preview (identical auth on both):
//! - traversal-domain first: View on every home in the affected domain is
//!   proven BEFORE any consumer or data row is read, independent of whether
//!   such rows exist, so success/refusal cannot leak hidden presence;
//! - per-requirement non-worsening: only requirements satisfied before AND
//!   broken after block; already-unsatisfied (legacy displaced) consumers
//!   are reported explicitly and never freeze a change;
//! - retained history stays valid: ordinary disable never blocks on
//!   version-pinned rows; only candidate surface exclusion does (package
//!   replacement path, workspace-global row coverage);
//! - every projection/event disagreement fails closed, never reads as
//!   absent; exact retries run the same preflight, never bless state.

use serde::Serialize;
use sqlx::SqliteConnection;

use crate::authorization::Capability;
use crate::error::{Error, Result};
use crate::events::KERNEL_ROOT_ID;
use crate::meta::definition_artifact::RevisionIdentity;

const MAX_TRAVERSAL_DEPTH: usize = 100;

/// Uniform refusal for any impact evaluation that touches hidden, missing,
/// or corrupt dependency state. Missing and hidden are indistinguishable.
pub const DEPENDENCY_REFUSAL: &str = "dependency impact hidden or unreadable; refusing";

/// Oracle-uniform answer for a bad scope, principal, or capability on the
/// wrappers, matching the kernel's existing target discipline.
pub(crate) const TARGET_HIDDEN: &str = "kernel target missing or hidden";

/// A prospective family-pin change at one tier. Package adopt/disable
/// translates to one scoped change per embedded family; direct definition
/// adoption is a single change; the root meta API is the global change.
/// Root global fallback stays distinct from root scoped overrides: the
/// prospective effective adoption applies scoped rows first and only then
/// the global fallback (mirroring `resolve_effective_adoption`).
/// Prospective package selection pin (immutable revision identity only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProspectivePackagePin {
    pub version: u32,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProspectiveChange {
    ScopedFamily {
        scope_home: String,
        family: String,
        pin: Option<RevisionIdentity>,
    },
    GlobalFamily {
        family: String,
        pin: Option<RevisionIdentity>,
    },
    /// The package selection row written at exactly `scope_home`
    /// (`None` = tombstone). Derived package-surface requirements evaluate
    /// against this candidate selection state, not the current rows — so a
    /// change never counts its own deactivated/replaced requirements as
    /// breakage, while descendants overriding the selection keep theirs.
    PackageSelection {
        scope_home: String,
        namespace: String,
        name: String,
        selected: Option<ProspectivePackagePin>,
    },
}

/// One impacted requirement in a preview or refusal: what it needed, what
/// the change would leave, and who declared it (actor redacted per the
/// history rule unless the viewer may see it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactedRequirement {
    pub scope_home: String,
    pub consumer_kind: String,
    pub consumer_namespace: String,
    pub consumer_name: String,
    pub family: String,
    pub required_version: u32,
    pub required_digest: String,
    pub prospective_version: Option<u32>,
    pub prospective_digest: Option<String>,
    pub actor: Option<String>,
    pub already_unsatisfied: bool,
}

/// Typed preview/execution impact: newly broken requirements refuse;
/// already-unsatisfied ones are reported explicitly and never block.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DependencyImpact {
    pub broken: Vec<ImpactedRequirement>,
    pub already_unsatisfied: Vec<ImpactedRequirement>,
}

impl DependencyImpact {
    pub fn refuses(&self) -> bool {
        !self.broken.is_empty()
    }
}

/// Public attributed requirement view. `actor` follows the history rule:
/// disclosed iff the viewer is the actor or holds View on the workspace
/// root, else redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsumerRequirementView {
    pub scope_home: String,
    pub consumer_kind: String,
    pub consumer_namespace: String,
    pub consumer_name: String,
    pub family: String,
    pub version: u32,
    pub digest: String,
    pub active: bool,
    pub event_seq: i64,
    pub actor: Option<String>,
}

pub(crate) async fn scope_exists(conn: &mut SqliteConnection, scope_home: &str) -> Result<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
        .bind(scope_home)
        .fetch_one(&mut *conn)
        .await
        .map_err(crate::error::Error::from)
}

pub(crate) async fn principal_exists(
    conn: &mut SqliteConnection,
    principal_id: &str,
) -> Result<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)")
        .bind(principal_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(crate::error::Error::from)
}

/// Ancestor chain from `scope` up to the root, scope first. Fail closed on
/// depth overflow or a dangling parent link.
pub(crate) async fn ancestor_chain(
    conn: &mut SqliteConnection,
    scope_home: &str,
) -> Result<Vec<String>> {
    let mut chain = vec![scope_home.to_string()];
    let mut scope = scope_home.to_string();
    for _ in 0..MAX_TRAVERSAL_DEPTH {
        let row: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
                .bind(&scope)
                .fetch_optional(&mut *conn)
                .await?;
        match row {
            // The home row vanished mid-walk: fail closed, never treat a
            // dangling link as the root.
            None => return Err(Error::engine(DEPENDENCY_REFUSAL)),
            // Genuine root: NULL parent terminates the chain.
            Some(None) => return Ok(chain),
            Some(Some(parent)) => {
                scope = parent.clone();
                chain.push(parent);
            }
        }
    }
    Err(Error::engine(DEPENDENCY_REFUSAL))
}

/// Scope plus all descendant homes (transitive). The recursion cap is a
/// fail-closed tripwire, not a silent truncation: hitting it (pathological
/// depth or a parent cycle) refuses instead of partially evaluating.
pub(crate) async fn subtree_homes(
    conn: &mut SqliteConnection,
    scope_home: &str,
) -> Result<Vec<String>> {
    let homes: Vec<(String, i64)> = sqlx::query_as(
        "WITH RECURSIVE subtree(root_id, depth) AS (
           SELECT ?, 0 UNION ALL
           SELECT r.root_id, s.depth + 1 FROM kernel_roots r
             JOIN subtree s ON r.parent_id = s.root_id
            WHERE s.depth < 100
         ) SELECT root_id, depth FROM subtree",
    )
    .bind(scope_home)
    .fetch_all(&mut *conn)
    .await?;
    if homes.iter().any(|(_, depth)| *depth >= 100) {
        return Err(Error::engine(DEPENDENCY_REFUSAL));
    }
    Ok(homes.into_iter().map(|(h, _)| h).collect())
}

/// Prove View on every home in `homes` before any consumer or data row is
/// read. Presence-independent: the domain is enumerated first, so the same
/// inaccessible domain refuses identically with or without consumers.
async fn require_view_on_all(
    conn: &mut SqliteConnection,
    viewer: &str,
    homes: &[String],
) -> Result<()> {
    for home in homes {
        let allows = crate::kernel::kernel_effective_capability_on(conn, viewer, home)
            .await
            .map(|c| c.allows(Capability::View))
            .unwrap_or(false);
        if !allows {
            return Err(Error::engine(DEPENDENCY_REFUSAL));
        }
    }
    Ok(())
}

async fn require_manage_on(
    conn: &mut SqliteConnection,
    actor: &str,
    scope_home: &str,
) -> Result<()> {
    let allows = crate::kernel::kernel_effective_capability_on(conn, actor, scope_home)
        .await
        .map(|c| c.allows(Capability::Manage))
        .unwrap_or(false);
    if !allows {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    Ok(())
}

/// Other packages effectively selected at `scope_home` (nearest row per
/// package along the ancestor chain, tombstones suppress) with their
/// verified immutable manifests. Excludes `exclude` package. Every
/// projection/event disagreement fails closed via the verified reads.
async fn effective_selected_packages(
    conn: &mut SqliteConnection,
    scope_home: &str,
    exclude: Option<(&str, &str)>,
) -> Result<
    Vec<(
        crate::kernel::StoredPackageSelection,
        crate::package_manifest::PackageManifest,
    )>,
> {
    let chain = ancestor_chain(conn, scope_home).await?;
    let mut candidates = std::collections::HashSet::new();
    // Projection UNION log subjects: a package with adoption events but no
    // projection row is corruption, and enumerating the projection alone
    // would skip it silently. Candidate keys come from both; the verified
    // read below refuses a missing row that has log subjects.
    let placeholders = chain.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let mut logged: Vec<(String, String)> = Vec::new();
    if !chain.is_empty() {
        let sql = format!(
            "SELECT DISTINCT json_extract(payload, '$.namespace'), json_extract(payload, '$.name') \
               FROM content_events WHERE type = ? AND record_id IN ({placeholders}) \
                 AND json_extract(payload, '$.namespace') IS NOT NULL \
                 AND json_extract(payload, '$.name') IS NOT NULL"
        );
        let mut q = sqlx::query_as::<_, (String, String)>(&sql)
            .bind(crate::kernel::KERNEL_PACKAGE_ADOPTED_EVENT);
        for scope in &chain {
            q = q.bind(scope);
        }
        logged = q.fetch_all(&mut *conn).await?;
    }
    let mut logged_set = std::collections::HashSet::new();
    for (ns, name) in &logged {
        logged_set.insert((ns.clone(), name.clone()));
        candidates.insert((ns.clone(), name.clone()));
    }
    for scope in &chain {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT DISTINCT namespace, name FROM kernel_package_selections WHERE scope_home = ?",
        )
        .bind(scope)
        .fetch_all(&mut *conn)
        .await?;
        for (ns, name) in rows {
            candidates.insert((ns, name));
        }
    }
    let mut out = Vec::new();
    for (ns, name) in candidates {
        if Some((ns.as_str(), name.as_str())) == exclude {
            continue;
        }
        // Nearest verified row on the chain wins; a tombstone suppresses
        // the subtree. A key with log subjects but no row anywhere on the
        // chain refuses instead of reading as absent.
        let mut winning = None;
        for scope in &chain {
            if let Some(stored) =
                crate::kernel::read_package_selection_in(conn, scope, &ns, &name).await?
            {
                winning = Some(stored);
                break;
            }
        }
        let Some(winning) = winning else {
            if logged_set.contains(&(ns.clone(), name.clone())) {
                return Err(Error::engine(DEPENDENCY_REFUSAL));
            }
            continue;
        };
        let Some(sel) = &winning.selected else {
            continue;
        };
        let manifest = crate::meta::package::read_package_in(
            conn,
            &sel.namespace,
            &sel.name,
            sel.version,
            &sel.digest,
        )
        .await?
        .ok_or_else(|| Error::engine(DEPENDENCY_REFUSAL))?
        .manifest;
        out.push((winning, manifest));
    }
    Ok(out)
}

/// Whether another effectively selected package at `scope_home` (same scope,
/// ancestors, or inherited — the falsifier case: root selects A and B, child
/// disables A while inheriting B) embeds the same family pin. Disabling must
/// consult effective selections, not same-scope rows alone, so a shared pin
/// is preserved instead of tombstoned and refused.
pub(crate) async fn scope_effectively_shares_family_pin(
    conn: &mut SqliteConnection,
    scope_home: &str,
    exclude_namespace: &str,
    exclude_name: &str,
    family: &str,
    version: u32,
    digest: &str,
) -> Result<bool> {
    for (_, manifest) in
        effective_selected_packages(conn, scope_home, Some((exclude_namespace, exclude_name)))
            .await?
    {
        if manifest
            .definitions
            .iter()
            .any(|e| e.family == family && e.version == version && e.digest == digest)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Prospective effective adoption for one (home, family) under `changes`.
/// Scoped changes replace the row at exactly their scope (nearer actual rows
/// still win); the global change replaces only the workspace-wide fallback.
async fn prospective_effective(
    conn: &mut SqliteConnection,
    home: &str,
    family: &str,
    changes: &[ProspectiveChange],
) -> Result<Option<crate::kernel::ScopedAdoption>> {
    let chain = ancestor_chain(conn, home).await?;
    for scope in &chain {
        let mut overridden = None;
        for change in changes {
            if let ProspectiveChange::ScopedFamily {
                scope_home,
                family: f,
                pin,
            } = change
            {
                if scope_home == scope && f == family {
                    overridden = Some(pin.clone());
                    break;
                }
            }
        }
        if let Some(pin) = overridden {
            // An overriding pin must itself be retained: a corrupt change
            // pin fails here even when no consumer watches this family.
            // Validated against the DECLARED family, never the pin's own
            // (which would be tautological and admit alien-family pins).
            if let Some(pin) = &pin {
                crate::kernel::verify_installed_pin_for_dependency(conn, family, pin).await?;
            }
            return Ok(pin.map(crate::kernel::ScopedAdoption::Adopted));
        }
        match crate::kernel::read_scoped_adoption_verified(conn, scope, family).await? {
            Some((Some(pin), _)) => {
                crate::kernel::verify_installed_pin_for_dependency(conn, family, &pin).await?;
                return Ok(Some(crate::kernel::ScopedAdoption::Adopted(pin)));
            }
            Some((None, _)) => return Ok(Some(crate::kernel::ScopedAdoption::Disabled)),
            None => {}
        }
    }
    for change in changes {
        if let ProspectiveChange::GlobalFamily { family: f, pin } = change {
            if f == family {
                if let Some(pin) = pin {
                    crate::kernel::verify_installed_pin_for_dependency(conn, &pin.family, pin)
                        .await?;
                }
                return Ok(pin.clone().map(crate::kernel::ScopedAdoption::Adopted));
            }
        }
    }
    // No scoped row on the path and no global change: the prospective state
    // equals the actual state, so the verified resolver answers directly.
    crate::kernel::resolve_effective_adoption_verified(conn, family, home).await
}

/// One collected dependency: a generic registered requirement or a package
/// surface derived from an immutable selected manifest (never a stored
/// `package-surface` row — that key stays reserved).
struct CollectedRequirement {
    scope_home: String,
    consumer_kind: String,
    consumer_namespace: String,
    consumer_name: String,
    family: String,
    version: u32,
    digest: String,
    actor: String,
}

/// Generic active requirements plus package-surface dependencies derived
/// directly from the immutable selected manifests effective in `subtree`.
/// Retired generic rows impose nothing and are skipped. Derived requirements
/// of a package whose effective selection `changes` deactivates or replaces
/// at their home are excluded — a change never counts its own removed
/// requirements as breakage — while descendants overriding the changed
/// selection keep theirs (their effective selection is unchanged).
async fn collect_requirements(
    conn: &mut SqliteConnection,
    subtree: &[String],
    changes: &[ProspectiveChange],
) -> Result<Vec<CollectedRequirement>> {
    let changed_pkgs = changed_packages(changes);
    let mut out = Vec::new();
    for home in subtree {
        for stored in crate::meta::consumer::list_consumers_in(conn, home).await? {
            if !stored.active {
                continue;
            }
            // `package-surface` is a derived-only key: the collector derives
            // its requirements from the live selected manifests below, so a
            // stored row of that reserved kind (forgery or legacy residue) is
            // never authoritative and must not block.
            if stored.consumer_kind == crate::meta::consumer::PACKAGE_SURFACE_KIND {
                continue;
            }
            out.push(CollectedRequirement {
                scope_home: stored.scope_home,
                consumer_kind: stored.consumer_kind,
                consumer_namespace: stored.consumer_namespace,
                consumer_name: stored.consumer_name,
                family: stored.family,
                version: stored.version,
                digest: stored.digest,
                actor: stored.actor,
            });
        }
        // Rule-derived definition pins from the latest verified ACTIVE
        // snapshots in this home (S2b): one collected requirement per explicit
        // pin, keyed as consumer `rule`. Disabled installations and pin-free
        // rules contribute nothing. The scope-indexed census verifies every
        // row against its authorizing event; corrupt rows fail the whole
        // preflight closed. Single enforcer: comparison below is unchanged.
        for stored in
            crate::meta::rule_installation::list_installations_in_scope(conn, home).await?
        {
            if !stored.active {
                continue;
            }
            for pin in &stored.revision.definition_pins {
                out.push(CollectedRequirement {
                    scope_home: stored.scope_home.clone(),
                    consumer_kind: crate::meta::rule_installation::RULE_CONSUMER_KIND.to_string(),
                    consumer_namespace: stored.namespace.clone(),
                    consumer_name: stored.name.clone(),
                    family: pin.family.clone(),
                    version: pin.version,
                    digest: pin.digest.clone(),
                    actor: stored.actor.clone(),
                });
            }
        }
        for (selection, manifest) in effective_selected_packages(conn, home, None).await? {
            let Some(sel) = &selection.selected else {
                continue;
            };
            if changed_pkgs.contains(&(sel.namespace.clone(), sel.name.clone())) {
                let before = Some(ProspectivePackagePin {
                    version: sel.version,
                    digest: sel.digest.clone(),
                });
                let after =
                    prospective_selection(conn, home, &sel.namespace, &sel.name, changes).await?;
                if before != after {
                    continue;
                }
            }
            let Some(sel) = &selection.selected else {
                continue;
            };
            // A definitions-only package (K5) supplies no behaviour or
            // surface, so it derives no `package-surface` requirement: there
            // is no surface whose definition pins must stay live. Its
            // revisions are recomputed from the live manifest each preflight,
            // so a stale requirement can never linger.
            if !manifest.declares_surface() {
                continue;
            }
            for entry in &manifest.definitions {
                out.push(CollectedRequirement {
                    scope_home: home.clone(),
                    consumer_kind: crate::meta::consumer::PACKAGE_SURFACE_KIND.to_string(),
                    consumer_namespace: sel.namespace.clone(),
                    consumer_name: sel.name.clone(),
                    family: entry.family.clone(),
                    version: entry.version,
                    digest: entry.digest.clone(),
                    actor: selection.ack_actor.clone(),
                });
            }
        }
    }
    Ok(out)
}

/// Package triples carrying a `PackageSelection` change.
fn changed_packages(changes: &[ProspectiveChange]) -> std::collections::HashSet<(String, String)> {
    let mut set = std::collections::HashSet::new();
    for change in changes {
        if let ProspectiveChange::PackageSelection {
            namespace, name, ..
        } = change
        {
            set.insert((namespace.clone(), name.clone()));
        }
    }
    set
}

/// A surface requirement introduced or moved by the change itself, derived
/// from the prospective (candidate) selection state.
struct AfterDerived {
    scope_home: String,
    namespace: String,
    name: String,
    family: String,
    version: u32,
    digest: String,
}

/// Derived requirements of changed packages under their AFTER selections.
/// A deactivated package contributes none (its surface is gone by design);
/// every selected pin is verified against its immutable manifest.
async fn collect_after_derived(
    conn: &mut SqliteConnection,
    subtree: &[String],
    changes: &[ProspectiveChange],
) -> Result<Vec<AfterDerived>> {
    let changed_pkgs = changed_packages(changes);
    let mut out = Vec::new();
    for home in subtree {
        for (ns, name) in &changed_pkgs {
            let after = prospective_selection(conn, home, ns, name, changes).await?;
            let Some(after) = after else { continue };
            let manifest =
                crate::meta::package::read_package_in(conn, ns, name, after.version, &after.digest)
                    .await?
                    .ok_or_else(|| Error::engine(DEPENDENCY_REFUSAL))?
                    .manifest;
            // Mirrors `collect_requirements`: a definitions-only after-state
            // derives no package-surface requirement.
            if !manifest.declares_surface() {
                continue;
            }
            for entry in &manifest.definitions {
                out.push(AfterDerived {
                    scope_home: home.clone(),
                    namespace: ns.clone(),
                    name: name.clone(),
                    family: entry.family.clone(),
                    version: entry.version,
                    digest: entry.digest.clone(),
                });
            }
        }
    }
    Ok(out)
}

fn pin_satisfies(
    effective: &Option<crate::kernel::ScopedAdoption>,
    family: &str,
    version: u32,
    digest: &str,
) -> bool {
    matches!(effective,
        Some(crate::kernel::ScopedAdoption::Adopted(pin))
        if pin.family == family && pin.version == version && pin.digest == digest)
}

/// Before/after non-worsening comparison for one requirement. Only
/// satisfied-before AND broken-after blocks; already-unsatisfied
/// requirements (legacy displacement included) are reported explicitly and
/// never freeze the change. Verified reads fail closed via propagation.
async fn compare_requirement(
    conn: &mut SqliteConnection,
    req: &CollectedRequirement,
    changes: &[ProspectiveChange],
    viewer: &str,
    impact: &mut DependencyImpact,
) -> Result<()> {
    let before =
        crate::kernel::resolve_effective_adoption_verified(conn, &req.family, &req.scope_home)
            .await?;
    let after = prospective_effective(conn, &req.scope_home, &req.family, changes).await?;
    let satisfied_before = pin_satisfies(&before, &req.family, req.version, &req.digest);
    let satisfies_after = pin_satisfies(&after, &req.family, req.version, &req.digest);
    let (after_version, after_digest) = match &after {
        Some(crate::kernel::ScopedAdoption::Adopted(pin)) => {
            (Some(pin.version), Some(pin.digest.clone()))
        }
        _ => (None, None),
    };
    let entry = ImpactedRequirement {
        scope_home: req.scope_home.clone(),
        consumer_kind: req.consumer_kind.clone(),
        consumer_namespace: req.consumer_namespace.clone(),
        consumer_name: req.consumer_name.clone(),
        family: req.family.clone(),
        required_version: req.version,
        required_digest: req.digest.clone(),
        prospective_version: after_version,
        prospective_digest: after_digest,
        actor: disclose_actor(conn, viewer, &req.actor).await?,
        already_unsatisfied: !satisfied_before,
    };
    if satisfied_before && !satisfies_after {
        impact.broken.push(entry);
    } else if !satisfied_before {
        impact.already_unsatisfied.push(entry);
    }
    Ok(())
}

/// Per-family-key non-worsening for a newly introduced or moved surface
/// requirement: satisfied-after is fine; unsatisfied-after refuses unless
/// the same package already carried an unsatisfied requirement for this
/// family before (legacy displacement — reported, never freezing).
/// Entirely new package/family keys unsatisfied after refuse
/// (broken-at-birth is never created); a satisfied-before counterpart that
/// the new pin leaves unsatisfied refuses too. Verified reads fail closed.
async fn compare_after_derived(
    conn: &mut SqliteConnection,
    req: &AfterDerived,
    changes: &[ProspectiveChange],
    caller: &str,
    impact: &mut DependencyImpact,
) -> Result<()> {
    let after = prospective_effective(conn, &req.scope_home, &req.family, changes).await?;
    if pin_satisfies(&after, &req.family, req.version, &req.digest) {
        return Ok(());
    }
    let (after_version, after_digest) = match &after {
        Some(crate::kernel::ScopedAdoption::Adopted(pin)) => {
            (Some(pin.version), Some(pin.digest.clone()))
        }
        _ => (None, None),
    };
    // Counterpart: what this package served here before the change, from
    // the verified effective row (which also carries the real attributor).
    let before_stored = crate::kernel::resolve_effective_package_selection(
        conn,
        &req.scope_home,
        &req.namespace,
        &req.name,
    )
    .await?;
    let before_sel = before_stored
        .as_ref()
        .and_then(|stored| stored.selected.as_ref());
    // The after-derived requirement comes from the prospective selection,
    // so "newly adopted" means no counterpart pin or a moved pin.
    let after_sel =
        prospective_selection(conn, &req.scope_home, &req.namespace, &req.name, changes).await?;
    let is_new = match (before_sel, after_sel.as_ref()) {
        (Some(before), Some(after)) => {
            before.version != after.version || before.digest != after.digest
        }
        _ => true,
    };
    let mut legacy_unsatisfied = false;
    if let Some(b) = before_sel {
        let manifest = crate::meta::package::read_package_in(
            conn,
            &req.namespace,
            &req.name,
            b.version,
            &b.digest,
        )
        .await?
        .ok_or_else(|| Error::engine(DEPENDENCY_REFUSAL))?
        .manifest;
        if let Some(old) = manifest.definitions.iter().find(|e| e.family == req.family) {
            let before = crate::kernel::resolve_effective_adoption_verified(
                conn,
                &req.family,
                &req.scope_home,
            )
            .await?;
            legacy_unsatisfied = !pin_satisfies(&before, &req.family, old.version, &old.digest);
        }
    }
    // Unchanged selections keep their real attributor under the history
    // disclosure rule; only a genuinely newly adopted selection attributes
    // to the caller making the change.
    let actor = if is_new {
        Some(caller.to_string())
    } else {
        disclose_actor(
            conn,
            caller,
            &before_stored
                .as_ref()
                .map(|stored| stored.ack_actor.clone())
                .unwrap_or_default(),
        )
        .await?
    };
    let entry = ImpactedRequirement {
        scope_home: req.scope_home.clone(),
        consumer_kind: crate::meta::consumer::PACKAGE_SURFACE_KIND.to_string(),
        consumer_namespace: req.namespace.clone(),
        consumer_name: req.name.clone(),
        family: req.family.clone(),
        required_version: req.version,
        required_digest: req.digest.clone(),
        prospective_version: after_version,
        prospective_digest: after_digest,
        actor,
        already_unsatisfied: legacy_unsatisfied,
    };
    if legacy_unsatisfied {
        impact.already_unsatisfied.push(entry);
    } else {
        impact.broken.push(entry);
    }
    Ok(())
}

/// Replacement retained-data check (package path only; ordinary disable
/// never consults pinned rows). Every old-manifest pin not served
/// identically by the candidate must have zero workspace-global rows:
/// families dropped entirely and changed pins alike. The caller proves View
/// on ALL workspace homes first, independent of row presence.
async fn check_retained_data(
    conn: &mut SqliteConnection,
    old: &crate::package_manifest::PackageManifest,
    candidate: &crate::package_manifest::PackageManifest,
    viewer: &str,
    target_scope: &str,
    impact: &mut DependencyImpact,
) -> Result<()> {
    // Only old pins excluded by the candidate require a global coverage
    // scan. This is decided from verified manifests, never row presence:
    // exact retries and unchanged pins need no unrelated-home authority.
    let excluded: Vec<_> = old
        .definitions
        .iter()
        .filter(|entry| {
            !candidate.definitions.iter().any(|e| {
                e.family == entry.family && e.version == entry.version && e.digest == entry.digest
            })
        })
        .collect();
    if excluded.is_empty() {
        return Ok(());
    }
    let all_homes: Vec<(String,)> = sqlx::query_as("SELECT root_id FROM kernel_roots")
        .fetch_all(&mut *conn)
        .await?;
    let all: Vec<String> = all_homes.into_iter().map(|(h,)| h).collect();
    require_view_on_all(conn, viewer, &all).await?;
    for entry in excluded {
        let stranded: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_records
              WHERE pin_family = ? AND pin_version = ? AND pin_digest = ?)",
        )
        .bind(&entry.family)
        .bind(entry.version as i64)
        .bind(&entry.digest)
        .fetch_one(&mut *conn)
        .await?;
        if !stranded {
            continue;
        }
        let new_pin = candidate
            .definitions
            .iter()
            .find(|e| e.family == entry.family)
            .map(|e| (e.version, e.digest.clone()));
        impact.broken.push(ImpactedRequirement {
            scope_home: target_scope.to_string(),
            consumer_kind: "retained-data".to_string(),
            consumer_namespace: old.namespace.clone(),
            consumer_name: old.name.clone(),
            family: entry.family.clone(),
            required_version: entry.version,
            required_digest: entry.digest.clone(),
            prospective_version: new_pin.as_ref().map(|(v, _)| *v),
            prospective_digest: new_pin.as_ref().map(|(_, d)| d.clone()),
            actor: None,
            already_unsatisfied: false,
        });
    }
    Ok(())
}

/// Optional replacement retained-data check for the package-adopt path:
/// the replaced revision against the candidate. `None` disables it
/// (ordinary disable, direct definition changes).
pub(crate) struct RetainedCheck<'a> {
    pub old: &'a crate::package_manifest::PackageManifest,
    pub candidate: &'a crate::package_manifest::PackageManifest,
}

/// Shared prospective-transaction preflight: read-only over the caller's
/// snapshot. Callers run it inside the writer tx before any append (execute)
/// or over a read snapshot (preview, same auth). Returns the typed impact;
/// execute paths refuse with [`DEPENDENCY_REFUSAL`] when `refuses()`.
pub(crate) async fn preflight(
    conn: &mut SqliteConnection,
    caller: &str,
    target_scope: &str,
    changes: &[ProspectiveChange],
    retained: Option<RetainedCheck<'_>>,
) -> Result<DependencyImpact> {
    if !scope_exists(conn, target_scope).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    // Traversal domain first, independent of consumer presence — and before
    // the baseline verification below, so a hidden domain refuses uniformly
    // before any baseline corruption or pin reads are touched.
    let subtree = subtree_homes(conn, target_scope).await?;
    require_view_on_all(conn, caller, &subtree).await?;
    // Every change reads its verified PRIOR baseline before any override is
    // evaluated — even with zero consumers watching, so a tampered old row
    // can never be silently overwritten through an empty impact set. New
    // pins must additionally name retained bytes.
    for change in changes {
        match change {
            ProspectiveChange::ScopedFamily {
                scope_home,
                family,
                pin,
            } => {
                // Scope row plus the inherited baseline it overrides.
                let _ =
                    crate::kernel::resolve_effective_adoption_verified(conn, family, scope_home)
                        .await?;
                if let Some(pin) = pin {
                    crate::kernel::verify_installed_pin_for_dependency(conn, family, pin).await?;
                }
            }
            ProspectiveChange::GlobalFamily { family, pin } => {
                // Verified global choice regardless of any root scoped
                // override: the effective resolver may early-return a scoped
                // root row and skip global corruption, so read it explicitly
                // (missing row with prior log refuses inside).
                let _ = crate::kernel::read_global_adoption_verified(conn, family).await?;
                if let Some(pin) = pin {
                    crate::kernel::verify_installed_pin_for_dependency(conn, family, pin).await?;
                }
            }
            ProspectiveChange::PackageSelection { .. } => {}
        }
    }
    let mut impact = DependencyImpact::default();
    for req in collect_requirements(conn, &subtree, changes).await? {
        compare_requirement(conn, &req, changes, caller, &mut impact).await?;
    }
    for req in collect_after_derived(conn, &subtree, changes).await? {
        compare_after_derived(conn, &req, changes, caller, &mut impact).await?;
    }
    if let Some(check) = retained {
        check_retained_data(
            conn,
            check.old,
            check.candidate,
            caller,
            target_scope,
            &mut impact,
        )
        .await?;
    }
    Ok(impact)
}

/// Prospective changes for adopting a package revision at `scope_home`: one
/// scoped pin per embedded definition, plus the selection row itself so
/// derived requirements evaluate against the candidate selection state.
pub(crate) fn prospective_for_package_adopt(
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
    digest: &str,
) -> Vec<ProspectiveChange> {
    let mut changes: Vec<ProspectiveChange> = manifest
        .definitions
        .iter()
        .map(|e| ProspectiveChange::ScopedFamily {
            scope_home: scope_home.to_string(),
            family: e.family.clone(),
            pin: Some(RevisionIdentity {
                family: e.family.clone(),
                version: e.version,
                digest: e.digest.clone(),
            }),
        })
        .collect();
    changes.push(ProspectiveChange::PackageSelection {
        scope_home: scope_home.to_string(),
        namespace: manifest.namespace.clone(),
        name: manifest.name.clone(),
        selected: Some(ProspectivePackagePin {
            version: manifest.version,
            digest: digest.to_string(),
        }),
    });
    changes
}

/// Prospective changes for disabling a package at `scope_home`: only the
/// family pins the write path would actually clear (effective pin matches
/// and no other effective package shares it). Mirrors the clearing decision
/// exactly so preflight evaluates what the write produces.
pub(crate) async fn prospective_for_package_disable(
    conn: &mut SqliteConnection,
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<Vec<ProspectiveChange>> {
    let mut changes = Vec::new();
    for entry in &manifest.definitions {
        let pinned_here = matches!(
            crate::kernel::resolve_effective_adoption_verified(conn, &entry.family, scope_home)
                .await?,
            Some(crate::kernel::ScopedAdoption::Adopted(pin))
                if pin.version == entry.version && pin.digest == entry.digest
        );
        if !pinned_here {
            continue;
        }
        if scope_effectively_shares_family_pin(
            conn,
            scope_home,
            &manifest.namespace,
            &manifest.name,
            &entry.family,
            entry.version,
            &entry.digest,
        )
        .await?
        {
            continue;
        }
        changes.push(ProspectiveChange::ScopedFamily {
            scope_home: scope_home.to_string(),
            family: entry.family.clone(),
            pin: None,
        });
    }
    changes.push(ProspectiveChange::PackageSelection {
        scope_home: scope_home.to_string(),
        namespace: manifest.namespace.clone(),
        name: manifest.name.clone(),
        selected: None,
    });
    Ok(changes)
}

/// Prospective effective selection of one package at `home`: the nearest
/// row on the ancestor chain, with a `PackageSelection` change at the row's
/// scope replacing that scope's actual row. Tombstones suppress; no row on
/// the path (and no change) is absence. Verified reads fail closed.
async fn prospective_selection(
    conn: &mut SqliteConnection,
    home: &str,
    namespace: &str,
    name: &str,
    changes: &[ProspectiveChange],
) -> Result<Option<ProspectivePackagePin>> {
    let chain = ancestor_chain(conn, home).await?;
    for scope in &chain {
        let mut overridden: Option<Option<ProspectivePackagePin>> = None;
        for change in changes {
            if let ProspectiveChange::PackageSelection {
                scope_home,
                namespace: ns,
                name: n,
                selected,
            } = change
            {
                if scope_home == scope && ns == namespace && n == name {
                    overridden = Some(selected.clone());
                    break;
                }
            }
        }
        if let Some(selected) = overridden {
            return Ok(selected);
        }
        if let Some(stored) =
            crate::kernel::read_package_selection_in(conn, scope, namespace, name).await?
        {
            return Ok(stored.selected.map(|sel| ProspectivePackagePin {
                version: sel.version,
                digest: sel.digest,
            }));
        }
    }
    Ok(None)
}

/// History-rule actor disclosure for wrapper outputs.
pub(crate) async fn disclose_actor(
    conn: &mut SqliteConnection,
    viewer: &str,
    actor: &str,
) -> Result<Option<String>> {
    if actor == viewer {
        return Ok(Some(actor.to_string()));
    }
    let root_view = crate::kernel::kernel_effective_capability_on(conn, viewer, KERNEL_ROOT_ID)
        .await
        .map(|c| c.allows(Capability::View))
        .unwrap_or(false);
    Ok(if root_view {
        Some(actor.to_string())
    } else {
        None
    })
}

fn to_view(
    stored: &crate::meta::consumer::StoredConsumer,
    actor: Option<String>,
) -> ConsumerRequirementView {
    ConsumerRequirementView {
        scope_home: stored.scope_home.clone(),
        consumer_kind: stored.consumer_kind.clone(),
        consumer_namespace: stored.consumer_namespace.clone(),
        consumer_name: stored.consumer_name.clone(),
        family: stored.family.clone(),
        version: stored.version,
        digest: stored.digest.clone(),
        active: stored.active,
        event_seq: stored.event_seq,
        actor,
    }
}

/// Register one generic requirement. Manage on the scope; the scope must
/// exist as a kernel home and the actor must be a valid principal (the
/// storage seam's phantom scopes are test-only, never public permission).
/// The pin must be satisfiable at the scope — equal to the family's
/// effective adoption pin there — so meaningless requirements cannot be
/// stockpiled. Atomic: check and append share one writer tx.
#[allow(clippy::too_many_arguments)]
pub async fn register_consumer_at(
    db: &crate::db::Db,
    actor_principal_id: &str,
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
    version: u32,
    digest: &str,
    expected_seq: crate::meta::consumer::ExpectedSeq,
) -> Result<ConsumerRequirementView> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if !scope_exists(&mut tx, scope_home).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    if !principal_exists(&mut tx, actor_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    require_manage_on(&mut tx, actor_principal_id, scope_home).await?;
    let effective =
        crate::kernel::resolve_effective_adoption_verified(&mut tx, family, scope_home).await?;
    let satisfiable = matches!(&effective,
        Some(crate::kernel::ScopedAdoption::Adopted(pin))
        if pin.version == version && pin.digest == digest);
    if !satisfiable {
        return Err(Error::engine(
            "consumer requirement is not satisfiable at this scope",
        ));
    }
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = crate::meta::consumer::register_consumer_in(
        &mut tx,
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
        version,
        digest,
        expected_seq,
        Some(actor_principal_id),
        &mut alloc,
    )
    .await;
    let stored = match outcome {
        Ok(outcome) => outcome.stored,
        Err(e) => {
            tx.rollback().await?;
            return Err(e);
        }
    };
    let actor = disclose_actor(&mut tx, actor_principal_id, &stored.actor).await?;
    tx.commit().await?;
    Ok(to_view(&stored, actor))
}

/// Retire one generic requirement. Manage on the scope; scope, principal,
/// and seq preconditions mirror registration. Atomic in one writer tx.
#[allow(clippy::too_many_arguments)]
pub async fn retire_consumer_at(
    db: &crate::db::Db,
    actor_principal_id: &str,
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
    expected_seq: crate::meta::consumer::ExpectedSeq,
) -> Result<ConsumerRequirementView> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if !scope_exists(&mut tx, scope_home).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    if !principal_exists(&mut tx, actor_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    require_manage_on(&mut tx, actor_principal_id, scope_home).await?;
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = crate::meta::consumer::retire_consumer_in(
        &mut tx,
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
        expected_seq,
        Some(actor_principal_id),
        &mut alloc,
    )
    .await;
    let stored = match outcome {
        Ok(outcome) => outcome.stored,
        Err(e) => {
            tx.rollback().await?;
            return Err(e);
        }
    };
    let actor = disclose_actor(&mut tx, actor_principal_id, &stored.actor).await?;
    tx.commit().await?;
    Ok(to_view(&stored, actor))
}

/// List one scope's requirements. View on the scope; actors redacted per the
/// history rule. Read-only snapshot, no writer lock held.
pub async fn list_consumers_as(
    db: &crate::db::Db,
    viewer_principal_id: &str,
    scope_home: &str,
) -> Result<Vec<ConsumerRequirementView>> {
    // ONE explicit read transaction for auth, list, and redaction: a pool
    // connection would snapshot each statement separately.
    let mut tx = db.write_pool().begin().await?;
    if !scope_exists(&mut tx, scope_home).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    if !principal_exists(&mut tx, viewer_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    let allows =
        crate::kernel::kernel_effective_capability_on(&mut tx, viewer_principal_id, scope_home)
            .await
            .map(|c| c.allows(Capability::View))
            .unwrap_or(false);
    if !allows {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    let mut out = Vec::new();
    for stored in crate::meta::consumer::list_consumers_in(&mut tx, scope_home).await? {
        let actor = disclose_actor(&mut tx, viewer_principal_id, &stored.actor).await?;
        out.push(to_view(&stored, actor));
    }
    tx.rollback().await?;
    Ok(out)
}

/// Typed preview of adopting a package revision: same auth as execute
/// (Manage on the scope plus the traversal/global gates inside preflight).
/// Includes the replacement retained-data check against the currently
/// effective revision, if any.
pub async fn preview_package_adopt(
    db: &crate::db::Db,
    caller_principal_id: &str,
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<DependencyImpact> {
    manifest.validate()?;
    let identity = manifest.identity()?;
    // ONE read snapshot from the first auth check through the retained scan;
    // explicit rollback after the result. No second connection.
    let mut tx = db.write_pool().begin().await?;
    if !scope_exists(&mut tx, scope_home).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    if !principal_exists(&mut tx, caller_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    require_manage_on(&mut tx, caller_principal_id, scope_home).await?;
    // Installed-candidate parity with execute: previewing an uninstalled
    // revision refuses exactly as adoption would.
    let installed = crate::meta::package::read_package_in(
        &mut tx,
        &manifest.namespace,
        &manifest.name,
        manifest.version,
        &identity.digest,
    )
    .await?;
    if installed.is_none() {
        return Err(Error::engine(
            "package adoption selects a missing package revision",
        ));
    }
    let changes = prospective_for_package_adopt(scope_home, manifest, &identity.digest);
    let old = current_selected_manifest(&mut tx, scope_home, manifest).await?;
    let retained = old.as_ref().map(|old| RetainedCheck {
        old,
        candidate: manifest,
    });
    let impact = preflight(&mut tx, caller_principal_id, scope_home, &changes, retained).await;
    tx.rollback().await?;
    impact
}

/// Currently effective selected manifest for the same package triple, if
/// any. Verified reads throughout: disagreement fails closed, never reads
/// as "no prior revision" (which would skip the retained-data check).
async fn current_selected_manifest(
    conn: &mut SqliteConnection,
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<Option<crate::package_manifest::PackageManifest>> {
    let stored = crate::kernel::resolve_effective_package_selection(
        conn,
        scope_home,
        &manifest.namespace,
        &manifest.name,
    )
    .await?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let Some(sel) = stored.selected else {
        return Ok(None);
    };
    Ok(Some(
        crate::meta::package::read_package_in(
            conn,
            &sel.namespace,
            &sel.name,
            sel.version,
            &sel.digest,
        )
        .await?
        .ok_or_else(|| Error::engine(DEPENDENCY_REFUSAL))?
        .manifest,
    ))
}

/// Typed preview of disabling a package revision: same auth as execute.
/// Retained rows never block a disable; only registered and derived
/// requirements do.
pub async fn preview_package_disable(
    db: &crate::db::Db,
    caller_principal_id: &str,
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<DependencyImpact> {
    manifest.validate()?;
    let identity = manifest.identity()?;
    // ONE read snapshot for auth, staleness, prospect, and impact alike.
    let mut tx = db.write_pool().begin().await?;
    if !scope_exists(&mut tx, scope_home).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    if !principal_exists(&mut tx, caller_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    require_manage_on(&mut tx, caller_principal_id, scope_home).await?;
    // Stale-disable parity with execute: previewing against a moved or
    // absent selection refuses exactly as the disable would.
    let effective = crate::kernel::resolve_effective_package_selection(
        &mut tx,
        scope_home,
        &manifest.namespace,
        &manifest.name,
    )
    .await?;
    match effective {
        Some(stored) => match stored.selected {
            Some(current)
                if current.version == manifest.version && current.digest == identity.digest => {}
            Some(_) => {
                return Err(Error::engine(
                    "stale package disable: the scope selection moved to another revision",
                ));
            }
            None => {
                return Err(Error::engine("no active package selection to disable"));
            }
        },
        None => {
            return Err(Error::engine("no active package selection to disable"));
        }
    }
    // Execute re-derives the same map inside its writer tx, so the
    // evaluated prospect matches the write.
    let changes = prospective_for_package_disable(&mut tx, scope_home, manifest).await?;
    let impact = preflight(&mut tx, caller_principal_id, scope_home, &changes, None).await;
    tx.rollback().await?;
    impact
}

/// Typed preview of a direct definition change: `scope_home = None` targets
/// the workspace-wide (root meta) choice, `Some` a scoped home — except
/// `Some(KERNEL_ROOT_ID)`, which normalizes to the global change, mirroring
/// `adopt_definition_at`'s delegation to `adopt_definition_as` at the root.
/// Without this, a root scoped-package override could make preview refuse
/// while the actual global change succeeds. Same auth as execute either way.
pub async fn preview_definition_change(
    db: &crate::db::Db,
    caller_principal_id: &str,
    scope_home: Option<&str>,
    family: &str,
    pin: Option<&RevisionIdentity>,
) -> Result<DependencyImpact> {
    // ONE read snapshot from auth through impact; explicit rollback after.
    let mut tx = db.write_pool().begin().await?;
    if !principal_exists(&mut tx, caller_principal_id).await? {
        return Err(Error::engine(TARGET_HIDDEN));
    }
    let global = scope_home.is_none() || scope_home.is_some_and(|s| s == KERNEL_ROOT_ID);
    let (target_scope, change) = match scope_home {
        Some(scope) if !global => {
            if !scope_exists(&mut tx, scope).await? {
                return Err(Error::engine(TARGET_HIDDEN));
            }
            require_manage_on(&mut tx, caller_principal_id, scope).await?;
            (
                scope.to_string(),
                ProspectiveChange::ScopedFamily {
                    scope_home: scope.to_string(),
                    family: family.to_string(),
                    pin: pin.cloned(),
                },
            )
        }
        _ => {
            require_manage_on(&mut tx, caller_principal_id, KERNEL_ROOT_ID).await?;
            (
                KERNEL_ROOT_ID.to_string(),
                ProspectiveChange::GlobalFamily {
                    family: family.to_string(),
                    pin: pin.cloned(),
                },
            )
        }
    };
    let impact = preflight(&mut tx, caller_principal_id, &target_scope, &[change], None).await;
    tx.rollback().await?;
    impact
}

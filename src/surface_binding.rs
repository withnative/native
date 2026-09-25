//! Surface bindings — the general K3 resolver (design `6e2acbd` §3, task
//! `441844b`).
//!
//! A binding points a *surface* at a *target* for a *who* under a *mode*. Home
//! is simply the first binding row (`who: principal`, `subject: environment`),
//! not a special registry.
//!
//! This module is the pure resolution core: types plus a function over
//! already-authorized bindings and a viewer, so precedence and the
//! skip-with-reason path are testable without a host, a database, or a request.
//! Storage and the MCP family live elsewhere and call [`resolve`].
//!
//! `who: group` and `mode: trusted` are carried as fields and deliberately not
//! resolved in this slice (design §3.1, §3.6). They are present so the shape is
//! right; nothing here interprets them.

/// The reserved link relationship that carries a surface binding.
///
/// One edge from the binding's `who` record — a member's person record for a
/// personal override, or the workspace root `native:root` for the default — to
/// the bound artifact. Surface, subject, and mode travel in the link note as
/// `native.surface-binding.v1`, which is also where the K1 consent fields
/// (`declaration_digest`, `consented_declaration`, `consented_source_revision`)
/// will be added later.
///
/// This follows the `manage_renderer_binding` precedent: a reserved
/// relationship, validated on write and authority-checked on read, with an
/// explicit repair path when the target goes missing or unauthorized. It is
/// deliberately not `renders`, and `manage_renderer_binding` is not overloaded.
pub const SURFACE_BINDING_RELATIONSHIP: &str = "surface_binding";

/// The wire version of the link-note descriptor.
pub const SURFACE_BINDING_NOTE_VERSION: &str = "native.surface-binding.v1";

/// Whether `relationship` is the reserved surface-binding relationship.
///
/// Every generic link-writing surface — `manage_links`, `manage_canvas`
/// `promote`, `manage_canvas` `assert_connector` — must refuse it, because
/// generic link authority is `Edit` on the source and `View` on the target,
/// which is weaker than the `Manage` the official workspace-default path
/// demands. Centralised here, beside the relationship it protects, so a new
/// link writer calls one function rather than re-deriving the rule.
pub fn is_reserved_relationship(relationship: &str) -> bool {
    relationship == SURFACE_BINDING_RELATIONSHIP
}

/// Refuse the reserved surface-binding relationship on a generic link writer.
///
/// `surface_binding` is reserved to `manage_surface_bindings`. Without this, an
/// `Edit`-but-not-`Manage` holder could write `native:root -> artifact` and set
/// the workspace Home by a path that never demands `Manage` on the root.
pub fn refuse_reserved_surface_binding(tool: &str, relationship: &str) -> crate::Result<()> {
    if is_reserved_relationship(relationship) {
        return Err(crate::Error::engine(format!(
            "{tool}: '{SURFACE_BINDING_RELATIONSHIP}' is a reserved surface binding; \
             use manage_surface_bindings to set or reset it"
        )));
    }
    Ok(())
}

/// Who a binding is scoped to.
///
/// `Group` is carried but not resolved in this slice: there is no group model
/// to resolve against, and a group binding raises authorization questions the
/// design leaves open. `Principal` and `Workspace` are the live cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Who {
    Principal,
    Group,
    Workspace,
}

/// What a binding targets.
///
/// Only `Environment` is exercised in this slice; the rest are present so the
/// resolver's ordering is written against the finished vocabulary rather than
/// a Home-only subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    Environment,
    Slot,
    Kind,
    Collection,
    Record,
}

/// How a bound target is presented. `Trusted` is carried but not exercised:
/// only `Isolated` (the iframe path) is built in this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    Trusted,
    Isolated,
}

/// A registered surface. The registry holds exactly one surface in this slice;
/// the enum, not a string, keeps the set closed and the resolver total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    Home,
}

/// The subject half of a binding: what the binding applies to.
///
/// The variant is also the specificity rank (see [`Subject`], whose variant
/// order is least to most specific). Payloads are opaque identifiers compared
/// for equality; how a request's ancestors are supplied is the host's job.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectPattern {
    Environment,
    Slot(String),
    Kind(String),
    Collection(String),
    Record(String),
}

impl SubjectPattern {
    /// The specificity rank of this pattern. Sorting descending on it puts the
    /// most specific binding first.
    pub fn specificity(&self) -> Subject {
        match self {
            SubjectPattern::Environment => Subject::Environment,
            SubjectPattern::Slot(_) => Subject::Slot,
            SubjectPattern::Kind(_) => Subject::Kind,
            SubjectPattern::Collection(_) => Subject::Collection,
            SubjectPattern::Record(_) => Subject::Record,
        }
    }
}

/// A request for a surface to be rendered for a concrete subject.
///
/// The ancestor fields are what let a less specific binding match: a request
/// for `record r1` also matches a `Kind`, `Collection`, `Slot`, or
/// `Environment` binding when the host has supplied those facts. Environment —
/// the Home case — carries none of them and matches only `Environment`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SurfaceRequest {
    pub slot: Option<String>,
    pub record_type: Option<String>,
    pub kind: Option<String>,
    pub collection: Option<String>,
    pub record: Option<String>,
}

impl SurfaceRequest {
    /// The environment request. Home is exactly this.
    pub fn environment() -> Self {
        Self::default()
    }

    fn matches(&self, pattern: &SubjectPattern) -> bool {
        match pattern {
            SubjectPattern::Environment => true,
            SubjectPattern::Slot(slot) => self.slot.as_deref() == Some(slot.as_str()),
            SubjectPattern::Kind(kind) => self.kind.as_deref() == Some(kind.as_str()),
            SubjectPattern::Collection(collection) => {
                self.collection.as_deref() == Some(collection.as_str())
            }
            SubjectPattern::Record(record) => self.record.as_deref() == Some(record.as_str()),
        }
    }
}

/// One binding as the resolver sees it: identity, where it came from, what it
/// points at, and whether that target is currently usable.
///
/// The host fills this in, computing [`TargetStatus`] against the viewer before
/// resolution. The resolver itself therefore needs no database and no viewer
/// object — it only orders and skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceBinding {
    /// The binding's own record, for revision and provenance in the result.
    pub binding_id: String,
    pub who: Who,
    pub subject: SubjectPattern,
    pub surface: Surface,
    pub mode: Mode,
    /// The target record, when one is set at all.
    pub target: Option<String>,
    /// Whether that target is currently usable for this viewer.
    pub status: TargetStatus,
}

/// Why a binding could or could not be used, determined by the host.
///
/// The variants are the reasons a person can be told when a binding is skipped
/// (acceptance 5): a missing, archived, unauthorized, wrong-typed, or
/// unrenderable target each degrade to the fallback with its own explanation,
/// never silently and never to a blank surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    /// A live, accepted-type record the viewer may view.
    Resolvable,
    /// No target is set on the binding at all.
    Unbound,
    /// The target record does not exist or is tombstoned.
    Missing,
    /// The target exists but is archived.
    Archived,
    /// The viewer lacks view authority on the target now.
    Unauthorized,
    /// The target is the wrong kind of record for this surface.
    WrongRecordType,
    /// The target is the right shape but currently fails to render.
    NotRenderable,
}

impl TargetStatus {
    /// Whether a binding carrying this status can serve the surface.
    pub fn is_resolvable(self) -> bool {
        matches!(self, TargetStatus::Resolvable)
    }

    /// The recorded reason a skipped binding was skipped; `None` when the
    /// binding was usable and therefore never skipped.
    pub fn skip_reason(self) -> Option<SkipReason> {
        match self {
            TargetStatus::Resolvable => None,
            TargetStatus::Unbound => Some(SkipReason::Unbound),
            TargetStatus::Missing => Some(SkipReason::Missing),
            TargetStatus::Archived => Some(SkipReason::Archived),
            TargetStatus::Unauthorized => Some(SkipReason::Unauthorized),
            TargetStatus::WrongRecordType => Some(SkipReason::WrongRecordType),
            TargetStatus::NotRenderable => Some(SkipReason::NotRenderable),
        }
    }
}

/// The recorded, honest reason a binding was not used.
///
/// These are stable vocabulary: the fallback surface and any caller can name
/// why the person is not looking at what they bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The binding carries no target at all.
    Unbound,
    /// The target record does not exist or is tombstoned.
    Missing,
    /// The target exists but is archived.
    Archived,
    /// The viewer lacks view authority on the target now.
    Unauthorized,
    /// The target is the wrong kind of record for this surface.
    WrongRecordType,
    /// The target is the right shape but currently fails to render.
    NotRenderable,
    /// The binding asks for `mode: trusted`, which is carried but not
    /// exercised in this slice.
    TrustedModeUnsupported,
}

/// Where a resolved surface came from, in precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BindingSource {
    Principal,
    Group,
    Workspace,
    /// The shipped, app-owned surface. Not a binding and never absent.
    AppFallback,
}

impl BindingSource {
    fn of(who: Who) -> Self {
        match who {
            Who::Principal => BindingSource::Principal,
            Who::Group => BindingSource::Group,
            Who::Workspace => BindingSource::Workspace,
        }
    }

    /// The precedence rank within one specificity: personal, then shared
    /// (group), then workspace. `AppFallback` sorts last.
    fn rank(self) -> u8 {
        match self {
            BindingSource::Principal => 0,
            BindingSource::Group => 1,
            BindingSource::Workspace => 2,
            BindingSource::AppFallback => 3,
        }
    }
}

/// A binding that matched but was not used, with the reason recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedBinding {
    pub binding_id: String,
    pub who: Who,
    pub subject: SubjectPattern,
    pub target: Option<String>,
    pub reason: SkipReason,
}

/// The outcome of resolution. Always present: when nothing resolves, the
/// app-owned fallback is the answer, so a surface is never blank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub surface: Surface,
    /// The winning source. `AppFallback` when no binding resolved.
    pub source: BindingSource,
    /// The target record to render; `None` for the app fallback.
    pub target: Option<String>,
    /// The winning binding's record, or `None` for the app fallback.
    pub binding_id: Option<String>,
    /// The winning binding's presentation mode; `None` for the app fallback.
    pub mode: Option<Mode>,
    /// Every matching binding that was skipped, in precedence order.
    pub skipped: Vec<SkippedBinding>,
}

impl Resolution {
    /// Whether this resolution is the app-owned fallback rather than a binding.
    pub fn is_fallback(&self) -> bool {
        self.source == BindingSource::AppFallback
    }
}

/// Resolve which binding serves `request` for `surface`.
///
/// Pure: it orders the supplied bindings and skips unusable ones, recording
/// each skip's reason. It never returns nothing — if no binding resolves, the
/// result is the app-owned fallback.
///
/// Order is most-specific subject first, then personal → shared → workspace,
/// then binding id for determinism.
pub fn resolve(
    surface: Surface,
    request: &SurfaceRequest,
    bindings: &[SurfaceBinding],
) -> Resolution {
    let mut matching: Vec<&SurfaceBinding> = bindings
        .iter()
        .filter(|binding| binding.surface == surface && request.matches(&binding.subject))
        .collect();
    matching.sort_by(|a, b| {
        b.subject
            .specificity()
            .cmp(&a.subject.specificity())
            .then_with(|| {
                BindingSource::of(a.who)
                    .rank()
                    .cmp(&BindingSource::of(b.who).rank())
            })
            .then_with(|| a.binding_id.cmp(&b.binding_id))
    });

    let mut skipped = Vec::new();
    for binding in matching {
        // A resolvable status with no target is impossible from a correct host,
        // but the resolver refuses to trust it: no target means no surface.
        // Only the isolated mode is exercised in this slice: a `trusted`
        // binding is carried in the vocabulary but never resolved, so it is
        // skipped with its own reason rather than handed to the isolated host.
        let usable = binding.status.is_resolvable()
            && binding.target.is_some()
            && binding.mode == Mode::Isolated;
        if usable {
            return Resolution {
                surface,
                source: BindingSource::of(binding.who),
                target: binding.target.clone(),
                binding_id: Some(binding.binding_id.clone()),
                mode: Some(binding.mode),
                skipped,
            };
        }
        let reason = if binding.mode != Mode::Isolated {
            SkipReason::TrustedModeUnsupported
        } else if binding.target.is_none() {
            SkipReason::Unbound
        } else {
            binding.status.skip_reason().unwrap_or(SkipReason::Unbound)
        };
        skipped.push(SkippedBinding {
            binding_id: binding.binding_id.clone(),
            who: binding.who,
            subject: binding.subject.clone(),
            target: binding.target.clone(),
            reason,
        });
    }

    Resolution {
        surface,
        source: BindingSource::AppFallback,
        target: None,
        binding_id: None,
        mode: None,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(
        id: &str,
        who: Who,
        subject: SubjectPattern,
        target: &str,
        status: TargetStatus,
    ) -> SurfaceBinding {
        SurfaceBinding {
            binding_id: id.into(),
            who,
            subject,
            surface: Surface::Home,
            mode: Mode::Isolated,
            target: Some(target.into()),
            status,
        }
    }

    fn home_environment(id: &str, who: Who, target: &str, status: TargetStatus) -> SurfaceBinding {
        binding(id, who, SubjectPattern::Environment, target, status)
    }

    #[test]
    fn environment_binding_resolves_to_its_target() {
        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[home_environment(
                "b1",
                Who::Principal,
                "artifact-1",
                TargetStatus::Resolvable,
            )],
        );
        assert_eq!(result.source, BindingSource::Principal);
        assert_eq!(result.target.as_deref(), Some("artifact-1"));
        assert_eq!(result.binding_id.as_deref(), Some("b1"));
        assert_eq!(result.mode, Some(Mode::Isolated));
        assert!(result.skipped.is_empty());
        assert!(!result.is_fallback());
    }

    #[test]
    fn no_bindings_resolves_to_the_fallback_never_to_nothing() {
        let result = resolve(Surface::Home, &SurfaceRequest::environment(), &[]);
        assert!(result.is_fallback());
        assert_eq!(result.source, BindingSource::AppFallback);
        assert_eq!(result.target, None);
        assert_eq!(result.binding_id, None);
        assert_eq!(result.mode, None);
    }

    #[test]
    fn personal_beats_workspace_at_equal_specificity() {
        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[
                home_environment(
                    "workspace",
                    Who::Workspace,
                    "artifact-shared",
                    TargetStatus::Resolvable,
                ),
                home_environment(
                    "personal",
                    Who::Principal,
                    "artifact-mine",
                    TargetStatus::Resolvable,
                ),
            ],
        );
        assert_eq!(result.source, BindingSource::Principal);
        assert_eq!(result.target.as_deref(), Some("artifact-mine"));
    }

    #[test]
    fn shared_beats_workspace_and_personal_beats_shared() {
        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[
                home_environment(
                    "workspace",
                    Who::Workspace,
                    "artifact-w",
                    TargetStatus::Resolvable,
                ),
                home_environment("group", Who::Group, "artifact-g", TargetStatus::Resolvable),
            ],
        );
        assert_eq!(result.source, BindingSource::Group);
        assert_eq!(result.target.as_deref(), Some("artifact-g"));

        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[
                home_environment("group", Who::Group, "artifact-g", TargetStatus::Resolvable),
                home_environment(
                    "personal",
                    Who::Principal,
                    "artifact-p",
                    TargetStatus::Resolvable,
                ),
            ],
        );
        assert_eq!(result.source, BindingSource::Principal);
        assert_eq!(result.target.as_deref(), Some("artifact-p"));
    }

    #[test]
    fn more_specific_subject_beats_environment() {
        let request = SurfaceRequest {
            record: Some("r1".into()),
            kind: Some("note".into()),
            ..Default::default()
        };
        let result = resolve(
            Surface::Home,
            &request,
            &[
                home_environment(
                    "env",
                    Who::Principal,
                    "artifact-env",
                    TargetStatus::Resolvable,
                ),
                binding(
                    "rec",
                    Who::Principal,
                    SubjectPattern::Record("r1".into()),
                    "artifact-rec",
                    TargetStatus::Resolvable,
                ),
                binding(
                    "kind",
                    Who::Principal,
                    SubjectPattern::Kind("note".into()),
                    "artifact-kind",
                    TargetStatus::Resolvable,
                ),
            ],
        );
        assert_eq!(result.target.as_deref(), Some("artifact-rec"));
        assert_eq!(result.binding_id.as_deref(), Some("rec"));
    }

    #[test]
    fn kind_beats_environment_but_record_beats_kind() {
        let request = SurfaceRequest {
            record: Some("r1".into()),
            kind: Some("note".into()),
            ..Default::default()
        };
        let result = resolve(
            Surface::Home,
            &request,
            &[
                home_environment(
                    "env",
                    Who::Principal,
                    "artifact-env",
                    TargetStatus::Resolvable,
                ),
                binding(
                    "kind",
                    Who::Principal,
                    SubjectPattern::Kind("note".into()),
                    "artifact-kind",
                    TargetStatus::Resolvable,
                ),
            ],
        );
        assert_eq!(result.target.as_deref(), Some("artifact-kind"));
    }

    #[test]
    fn a_non_matching_subject_is_not_considered() {
        let request = SurfaceRequest {
            record: Some("r1".into()),
            ..Default::default()
        };
        let result = resolve(
            Surface::Home,
            &request,
            &[binding(
                "other",
                Who::Principal,
                SubjectPattern::Record("r2".into()),
                "artifact-r2",
                TargetStatus::Resolvable,
            )],
        );
        assert!(result.is_fallback());
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn invalid_personal_binding_is_skipped_with_reason_and_workspace_wins() {
        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[
                home_environment(
                    "personal",
                    Who::Principal,
                    "artifact-mine",
                    TargetStatus::Unauthorized,
                ),
                home_environment(
                    "workspace",
                    Who::Workspace,
                    "artifact-shared",
                    TargetStatus::Resolvable,
                ),
            ],
        );
        assert_eq!(result.source, BindingSource::Workspace);
        assert_eq!(result.target.as_deref(), Some("artifact-shared"));
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].binding_id, "personal");
        assert_eq!(result.skipped[0].reason, SkipReason::Unauthorized);
    }

    #[test]
    fn a_trusted_mode_binding_is_never_resolved() {
        let mut trusted = home_environment(
            "trusted",
            Who::Principal,
            "artifact-1",
            TargetStatus::Resolvable,
        );
        trusted.mode = Mode::Trusted;
        let result = resolve(Surface::Home, &SurfaceRequest::environment(), &[trusted]);
        assert!(result.is_fallback());
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].reason, SkipReason::TrustedModeUnsupported);
    }

    #[test]
    fn every_unusable_status_maps_to_its_own_skip_reason() {
        for (status, expected) in [
            (TargetStatus::Unbound, SkipReason::Unbound),
            (TargetStatus::Missing, SkipReason::Missing),
            (TargetStatus::Archived, SkipReason::Archived),
            (TargetStatus::Unauthorized, SkipReason::Unauthorized),
            (TargetStatus::WrongRecordType, SkipReason::WrongRecordType),
            (TargetStatus::NotRenderable, SkipReason::NotRenderable),
        ] {
            let result = resolve(
                Surface::Home,
                &SurfaceRequest::environment(),
                &[home_environment("b", Who::Principal, "artifact-1", status)],
            );
            assert!(result.is_fallback(), "status {status:?} should not resolve");
            assert_eq!(result.skipped.len(), 1);
            assert_eq!(result.skipped[0].reason, expected);
            assert_eq!(result.skipped[0].target.as_deref(), Some("artifact-1"));
        }
    }

    #[test]
    fn resolvable_without_a_target_is_treated_as_unbound() {
        let mut b = home_environment("b", Who::Principal, "artifact-1", TargetStatus::Resolvable);
        b.target = None;
        let result = resolve(Surface::Home, &SurfaceRequest::environment(), &[b]);
        assert!(result.is_fallback());
        assert_eq!(result.skipped[0].reason, SkipReason::Unbound);
    }

    #[test]
    fn skips_are_recorded_in_precedence_order() {
        let result = resolve(
            Surface::Home,
            &SurfaceRequest::environment(),
            &[
                home_environment(
                    "workspace",
                    Who::Workspace,
                    "artifact-w",
                    TargetStatus::Missing,
                ),
                home_environment(
                    "personal",
                    Who::Principal,
                    "artifact-p",
                    TargetStatus::NotRenderable,
                ),
                home_environment("group", Who::Group, "artifact-g", TargetStatus::Archived),
            ],
        );
        assert!(result.is_fallback());
        let order: Vec<&str> = result
            .skipped
            .iter()
            .map(|s| s.binding_id.as_str())
            .collect();
        assert_eq!(order, vec!["personal", "group", "workspace"]);
    }
}

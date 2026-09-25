//! The action-evidence carve-out of the interaction log.
//!
//! Native builds collective intelligence from **acts**, not from attention:
//! the shared world contains only what was done to it (ratified 20 Sep 2026).
//! The interaction log's attention tier — who looked at what — is therefore
//! foldable: it can be summarised, aggregated, or dropped without losing
//! anything the shared world is made of.
//!
//! A small part of that log is **not** attention. Some captured calls are
//! evidence *about an act*: they record that an agent released a claim,
//! coordinated over disclosed overlap, or did material work on a record that
//! someone else had disclosed an interest in. That evidence has a shipped
//! reader — the work-overlap outcome evaluation in `get_run_activity`
//! (`src/mcp/tools/history.rs`) — which reaches conclusions no folded
//! form can support.
//!
//! This module is the single authority for which calls those are, so that a
//! later capture change that folds the attention tier cannot quietly take the
//! action evidence with it. What that authority actually buys, precisely:
//!
//! * **Derived by production code.** `get_run_activity` reads
//!   [`is_material_mutation_surface`] instead of keeping its own list, names
//!   the three surfaces it inspects by shape through [`START_WORK`],
//!   [`MANAGE_LINKS`] and [`CREATE_RECORD`], and `work_overlap_result_annotation`
//!   refuses to annotate any kind outside [`ANNOTATION_SURFACES`].
//! * **Enforced by test.** Everything else — that the set has not been
//!   narrowed, that capture keeps these calls' arguments verbatim, that
//!   exactly the annotation surfaces retain a notice — is asserted in
//!   `action_evidence_tests` below and in `tests/tools/action_evidence.rs`,
//!   not structurally guaranteed. [`is_action_evidence`] and
//!   [`action_evidence_surfaces`] exist for those pins and for the capture
//!   change this slice protects against; no production caller reads them yet.
//!
//! # What `ToolKind` does and does not guarantee
//!
//! The lists below name [`ToolKind`] variants, not strings, so **retiring**
//! a tool breaks this module at compile time rather than leaving an entry
//! that nothing answers to. **Renaming** is a different matter: changing
//! `ToolKind::ManageLinks => "manage_links"` in `src/mcp/interactions.rs`
//! compiles cleanly here and silently retargets the carve-out, at which point
//! every historical `read_log_calls` row written under the old name stops
//! matching and settled verdicts change. Captured rows hold the *name*. This
//! module carries no historical aliases today; if a shipped tool is ever
//! renamed, the rename has to bring one with it.
//!
//! # What the evaluator actually needs, per call
//!
//! The evaluator does not ask "was this record mutated somewhere in this
//! episode". It asks "did *this* action mutate an eligible record", and it
//! reads the shape of the action to decide. That requires, **co-located on
//! one raw row**:
//!
//! * the `tool`;
//! * **verbatim `arguments`** — it inspects their structure: `start_work`
//!   with `action=release`, `manage_links` with `action=add`,
//!   `create_record` with `type=Document, kind=handoff` and a `links[]`
//!   entry whose `target_id` matches an eligible touch;
//! * that call's **own** touches, with the `mutated` interaction preserved;
//! * intra-episode **ordering** (`ORDER BY ended_at, seq`) — the *first*
//!   qualifying action decides the verdict, so `released` / `coordinated` /
//!   `proceeded` all change if calls are reordered or merged;
//! * run parentage, walked recursively through `read_log_calls.parent_key`;
//! * a retained `result_annotation`, keyed by `(actor, ended_at, seq)`.
//!
//! # Boundary note for the next slice
//!
//! A later slice may stop storing verbatim `arguments` for **pure reads** —
//! nothing reads those. It must not do so for the surfaces named here:
//! verbatim arguments have a live reader on exactly this set, and dropping
//! them silently turns `coordinated` into `proceeded`. `captured_arguments`
//! in `src/mcp/interactions.rs` is the one place that decides what an
//! argument row contains; the pin in `action_evidence_tests` below asserts it
//! stays verbatim for every surface in this set.

use super::interactions::ToolKind;

/// Surfaces whose calls the coordination reading of the evaluator inspects
/// directly, beyond the material-mutation set. `start_work` (release),
/// `manage_links` (add) and `create_record` (linked handoff) are read by
/// `is_explicit_coordination` and the release check; `set_intent` is one of
/// the three surfaces that emits a retained overlap notice, so its own row is
/// the anchor the evaluation starts from.
/// The coordination surfaces by captured name, individually, because the
/// evaluator reads each one's arguments differently. `get_run_activity`
/// matches on these rather than on its own string literals.
///
/// **They must stay `const`.** They are used as match patterns; a `const`
/// pattern compares, but a `let` binding of the same name would be an
/// irrefutable pattern that matches every tool, turning
/// `is_explicit_coordination` into "always true" with no compile error.
pub const START_WORK: &str = ToolKind::StartWork.name();
/// See [`START_WORK`] — the same `const`-pattern requirement applies.
pub const MANAGE_LINKS: &str = ToolKind::ManageLinks.name();
/// See [`START_WORK`] — the same `const`-pattern requirement applies.
pub const CREATE_RECORD: &str = ToolKind::CreateRecord.name();
/// See [`START_WORK`] — the same `const`-pattern requirement applies.
pub const SET_INTENT: &str = ToolKind::SetIntent.name();

pub const COORDINATION_SURFACES: &[ToolKind] = &[
    ToolKind::CreateRecord,
    ToolKind::ManageLinks,
    ToolKind::SetIntent,
    ToolKind::StartWork,
];

/// Successful calls whose extracted `mutated` touch represents material work
/// on an existing record. The list is intentionally explicit: adding a new
/// mutation surface does not silently change the evaluation instrument.
///
/// Typed as [`ToolKind`] rather than strings so that renaming or retiring a
/// tool breaks this list at compile time instead of turning one of its
/// entries into a name nothing answers to.
pub const MATERIAL_MUTATION_SURFACES: &[ToolKind] = &[
    ToolKind::ArchiveRecord,
    ToolKind::AttachFromUrl,
    ToolKind::AttachText,
    ToolKind::BatchWrite,
    ToolKind::ClaimUnownedRecord,
    ToolKind::CorrectRecordType,
    ToolKind::CreateAttribution,
    ToolKind::DeleteRecord,
    ToolKind::InvokeArtifactInteraction,
    ToolKind::ManageArtifactInputs,
    ToolKind::ManageAttachments,
    ToolKind::ManageAttributions,
    ToolKind::ManageCanvas,
    ToolKind::ManageCitations,
    ToolKind::ManageChangeSummaries,
    ToolKind::ManageFacetObservations,
    ToolKind::ManageInterventions,
    ToolKind::ManageLinks,
    ToolKind::ManageMdxModules,
    ToolKind::ManageMessages,
    ToolKind::ManageRelationships,
    ToolKind::ResolveExternal,
    ToolKind::ResolveSuggestions,
    ToolKind::StartWork,
    ToolKind::UpdateRecord,
];

/// The three surfaces that can carry a work-overlap `result_annotation`.
/// A call carrying an annotation is action evidence whatever its tool, but
/// only these can produce one; `work_overlap_result_annotation` in
/// `src/mcp/interactions.rs` must agree with this list.
pub const ANNOTATION_SURFACES: &[ToolKind] = &[
    ToolKind::StartWork,
    ToolKind::CreateRecord,
    ToolKind::SetIntent,
];

/// True when a call on this surface is evidence about an act rather than
/// about attention, and so must survive any folding of the attention tier
/// with its tool, verbatim arguments, own touches and ordering intact.
#[must_use]
pub fn is_action_evidence_surface_kind(kind: ToolKind) -> bool {
    COORDINATION_SURFACES
        .iter()
        .chain(MATERIAL_MUTATION_SURFACES)
        .any(|surface| *surface == kind)
}

/// The material-mutation reading, by captured tool name. `get_run_activity`
/// reads this rather than keeping its own copy of the list.
#[must_use]
pub fn is_material_mutation_surface(tool: &str) -> bool {
    MATERIAL_MUTATION_SURFACES
        .iter()
        .any(|kind| kind.name() == tool)
}

/// Every tool name in the action-evidence set, sorted and deduplicated.
///
/// Public so that out-of-crate tests can pin the carve-out without restating
/// it; a caller that wants to *decide* something should use
/// [`is_action_evidence_surface`] instead.
#[must_use]
pub fn action_evidence_surfaces() -> Vec<&'static str> {
    let mut names = COORDINATION_SURFACES
        .iter()
        .chain(MATERIAL_MUTATION_SURFACES)
        .map(|kind| kind.name())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    names
}

/// True when a captured call is action evidence: it carries a work-overlap
/// `result_annotation`, or it is a call on one of the action-evidence
/// surfaces. Everything else the interaction log holds is attention.
#[must_use]
pub fn is_action_evidence(tool: &str, has_result_annotation: bool) -> bool {
    has_result_annotation || is_action_evidence_surface(tool)
}

/// True when this captured tool name is one of the action-evidence surfaces.
#[must_use]
pub fn is_action_evidence_surface(tool: &str) -> bool {
    COORDINATION_SURFACES
        .iter()
        .chain(MATERIAL_MUTATION_SURFACES)
        .any(|kind| kind.name() == tool)
}

#[cfg(test)]
mod action_evidence_tests {
    use super::*;
    use crate::mcp::interactions::{captured_arguments, work_overlap_result_annotation, Extractor};
    use serde_json::json;

    /// An independent restatement of the whole carve-out. It is deliberately
    /// a literal, not derived: narrowing the set in source without an
    /// argued-for change here fails this test.
    const PINNED: &[&str] = &[
        "archive_record",
        "attach_from_url",
        "attach_text",
        "batch_write",
        "claim_unowned_record",
        "correct_record_type",
        "create_attribution",
        "create_record",
        "delete_record",
        "invoke_artifact_interaction",
        "manage_artifact_inputs",
        "manage_attachments",
        "manage_attributions",
        "manage_canvas",
        "manage_change_summaries",
        "manage_citations",
        "manage_facet_observations",
        "manage_interventions",
        "manage_links",
        "manage_mdx_modules",
        "manage_messages",
        "manage_relationships",
        "resolve_external",
        "resolve_suggestions",
        "set_intent",
        "start_work",
        "update_record",
    ];

    /// The material-mutation reading, restated separately and in list order.
    ///
    /// [`PINNED`] alone cannot protect this: it is the *union* of the two
    /// lists, so moving a tool from the material set into the coordination
    /// set leaves the union untouched while
    /// [`is_material_mutation_surface`] silently starts returning `false`
    /// for it — and `get_run_activity` stops returning `proceeded` for a
    /// surface that still does material work. Before the split there was one
    /// list and that reshuffle was impossible; this literal is what replaces
    /// that impossibility.
    const PINNED_MATERIAL: &[&str] = &[
        "archive_record",
        "attach_from_url",
        "attach_text",
        "batch_write",
        "claim_unowned_record",
        "correct_record_type",
        "create_attribution",
        "delete_record",
        "invoke_artifact_interaction",
        "manage_artifact_inputs",
        "manage_attachments",
        "manage_attributions",
        "manage_canvas",
        "manage_citations",
        "manage_change_summaries",
        "manage_facet_observations",
        "manage_interventions",
        "manage_links",
        "manage_mdx_modules",
        "manage_messages",
        "manage_relationships",
        "resolve_external",
        "resolve_suggestions",
        "start_work",
        "update_record",
    ];

    #[test]
    fn the_action_evidence_set_is_exactly_the_pinned_surfaces() {
        assert_eq!(action_evidence_surfaces(), PINNED);
        for tool in PINNED {
            assert!(
                is_action_evidence(tool, false),
                "{tool} dropped out of the action-evidence carve-out"
            );
        }
        // A call carrying a retained overlap notice is action evidence even
        // when its tool is not itself one of the surfaces.
        assert!(is_action_evidence("get_record", true));
        assert!(!is_action_evidence("get_record", false));
    }

    #[test]
    fn the_material_mutation_reading_is_exactly_the_pinned_material_surfaces() {
        let material = MATERIAL_MUTATION_SURFACES
            .iter()
            .map(|kind| kind.name())
            .collect::<Vec<_>>();
        assert_eq!(
            material, PINNED_MATERIAL,
            "the material-mutation reading changed: get_run_activity's \
             `proceeded` verdict is decided by exactly this list"
        );
        for tool in PINNED_MATERIAL {
            assert!(
                is_material_mutation_surface(tool),
                "{tool} no longer reads as material mutation"
            );
        }
        // Coordination-only surfaces. These are in the carve-out, and the
        // evaluator must *not* read them as material work: `create_record`
        // and `set_intent` are notice surfaces, and reading either as
        // `proceeded` would pre-empt the `coordinated` verdict.
        for tool in [CREATE_RECORD, SET_INTENT] {
            assert!(
                is_action_evidence_surface(tool),
                "{tool} must stay in the carve-out"
            );
            assert!(
                !is_material_mutation_surface(tool),
                "{tool} must not read as material mutation"
            );
        }
    }

    #[test]
    fn the_named_coordination_surfaces_are_the_coordination_list() {
        let mut named = vec![START_WORK, MANAGE_LINKS, CREATE_RECORD, SET_INTENT];
        named.sort_unstable();
        let mut listed = COORDINATION_SURFACES
            .iter()
            .map(|kind| kind.name())
            .collect::<Vec<_>>();
        listed.sort_unstable();
        assert_eq!(named, listed);
    }

    #[test]
    fn every_action_evidence_surface_keeps_its_arguments_verbatim() {
        // The structure the evaluator inspects, exaggerated: if capture ever
        // shapes, truncates or redacts arguments on these surfaces, the
        // round trip stops being an identity.
        let original = json!({
            "action": "release",
            "type": "Document",
            "kind": "handoff",
            "record_id": "01234567-89ab-4def-8abc-0123456789ab",
            "links": [{
                "target_id": "01234567-89ab-4def-8abc-0123456789ab",
                "relationship": "relates_to",
            }],
            "nested": {"deep": ["a", 1, true, null]},
        });
        for kind in COORDINATION_SURFACES
            .iter()
            .chain(MATERIAL_MUTATION_SURFACES)
        {
            assert!(is_action_evidence_surface_kind(*kind));
            assert_eq!(
                captured_arguments(Extractor::Shipped(*kind), &original),
                original,
                "{} lost its verbatim arguments at capture",
                kind.name()
            );
        }
    }

    /// The retention half of the carve-out. A result shaped to qualify under
    /// all three notice readings is offered to every shipped tool: exactly
    /// the annotation surfaces may keep one, and each of those is carved
    /// out. If a capture change stops one of them retaining, this fails.
    #[test]
    fn exactly_the_annotation_surfaces_retain_a_disclosed_notice() {
        let anchor = "01234567-89ab-4def-8abc-0123456789ab";
        let other = "01234567-89ab-4def-8abc-0123456789ac";
        let overlap = json!({
            "items": [{"record_id": other}],
            "total_count": 1,
            "truncated": false,
        });
        let result = json!({
            "action": "claim",
            "record_id": anchor,
            "id": anchor,
            "work_overlap": overlap,
            "briefing": {"overlapping_claims": {"items": [
                {"record_id": anchor, "overlap": overlap}
            ]}},
        });
        for kind in ToolKind::ALL {
            let retained = work_overlap_result_annotation(kind, &result).is_some();
            assert_eq!(
                retained,
                ANNOTATION_SURFACES.contains(&kind),
                "{} retention disagrees with the annotation surfaces",
                kind.name()
            );
            if retained {
                assert!(
                    is_action_evidence_surface_kind(kind),
                    "{} retains evidence but is not carved out",
                    kind.name()
                );
            }
        }
    }

    #[test]
    fn annotation_surfaces_are_part_of_the_carve_out() {
        for kind in ANNOTATION_SURFACES {
            assert!(
                is_action_evidence_surface_kind(*kind),
                "{} emits retained evidence but is not carved out",
                kind.name()
            );
        }
    }
}

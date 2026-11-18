//! How a write shows while it waits for hosted to accept it.
//!
//! Every write goes into the local buffer first, and hosted Native re-checks
//! authorization when it accepts each one, so governance does not need the
//! local copy to refuse a tool. What differs between writes is how they show
//! while they wait, and this module is the one place that says which, as
//! [`ACCEPTANCE_TABLE`]. The operation catalogue projects it as
//! `catalog_operations.requires_acceptance`.
//!
//! - **Local-first** (`requires_acceptance = false`): shown as done straight
//!   away. If hosted later refuses it, it becomes a visible draft with undo.
//!   This suits edits, renames, moves, creates, archiving and changes of
//!   owner, because only the caller sees their own local copy.
//! - **Required** (`requires_acceptance = true`): queued and shown as waiting,
//!   not applied to the local copy. This is for effects on other people or the
//!   outside world that cannot be taken back: sends, publication,
//!   invitations, external import, artifact execution, changes to other
//!   people's access or membership, and schema or guidance administration.
//!
//! # What the declaration does and does not do
//!
//! It is a declaration, not a gate. It changes no behaviour: the writes the
//! node actually holds while hosted is away are still the hand-kept
//! `HOLDABLE` list in `src/node/hold.rs`, and the hosted outbox keeps its own
//! allowlist (`ingress::source_call`). Tests tie those lists to this table so
//! they cannot drift apart unnoticed: see `node::hold::tests`.
//!
//! # Defaults, and how a new operation gets declared
//!
//! Per the local-first decision (Native 2aacbb7) an operation is local-first
//! unless it declares otherwise, so an undeclared pair answers `false`.
//! "Undeclared" must still never happen for a write, though: a test requires
//! every operation the catalogue serves as a mutation to have a row here.
//! Adding a write operation therefore fails the build until the author has
//! chosen [`Acceptance::LocalFirst`] or [`Acceptance::Required`] with a
//! [`Reason`].
//!
//! Reads are never listed and always answer `false`: a read has nothing to
//! queue or show, so the question does not apply.
//!
//! # Choosing
//!
//! Ask whether the write can be taken back if hosted refuses it, and who else
//! sees it before then. If only the caller sees their own local copy and the
//! change can be undone, choose `LocalFirst`. If it reaches other people or
//! the outside world, or cannot be undone, choose `Required` with the reason.
//! When unsure, choose `Required(Reason::Unreviewed)`: it keeps the write
//! queued and marks the operation for review.

/// Why a write is queued and shown as waiting instead of applied locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reason {
    /// It reaches other people or the outside world and cannot be taken back:
    /// sends, publication, invitations, artifact execution, import.
    OutsideEffect,
    /// It changes access, membership, identity, schema or guidance in a way
    /// that affects other people.
    Admin,
    /// It removes something and there is no restore, so it cannot be undone.
    Delete,
    /// It claims or mints something other people see and race over, which a
    /// local copy cannot settle.
    Exclusive,
    /// Replaying it creates its records again. Declared for `create_many`;
    /// proven by the replay conformance test for `observe_external`.
    ReplayDuplicates,
    /// Replaying it is refused or reports a conflict for a write that already
    /// applied, so a host would take a write that stuck for a failure. Proven
    /// by the replay conformance test.
    ReplayRefused,
    /// It is gated behind a prepared plan, which hosted must preview and bind.
    PlanGated,
    /// Not yet decided on its merits. Treated as `Required` until reviewed.
    Unreviewed,
}

/// One operation's declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Acceptance {
    /// Shown as done straight away; if hosted refuses it, it becomes a visible
    /// draft with undo.
    LocalFirst,
    /// Queued and shown as waiting until hosted accepts it, not applied to the
    /// local copy. Hosted re-checks every write either way.
    Required(Reason),
}

use Acceptance::{LocalFirst as Local, Required as Needs};

/// Every write operation, once, by executor and operation, in the audit's
/// names. `archive_record` also restores (`archived: false`), so it is
/// local-first; `delete_record` is a soft delete that freezes the record with
/// no restore, so it stays required. Reads are absent: that includes `artifacts_execute`
/// `manage_alpha_tabs.launch`, `open_collection` and `render_artifact`, which the audit files
/// under writes but the registry classifies as reads, so they project `false`.
/// The opposite case, an audit read the registry classifies as a write, is
/// declared (see the entries near the end). Checked against the
/// frozen audit and the served catalogue by the tests in `acceptance_tests.rs`.
// One row per line keeps the table scannable and diffs small.
#[rustfmt::skip]
pub(super) const ACCEPTANCE_TABLE: &[(&str, &str, Acceptance)] = &[
    ("access_admin", "manage_artifact_module_grants.grant", Needs(Reason::Admin)),
    ("access_admin", "manage_artifact_module_grants.revoke", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.grant", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.replace", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.restore_inheritance", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.revoke", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.set_many", Needs(Reason::Admin)),
    ("access_admin", "manage_record_policy.set_members_baseline", Needs(Reason::Admin)),
    ("artifacts_execute", "invoke_artifact_interaction", Needs(Reason::OutsideEffect)),
    ("artifacts_write", "advance_artifact_port_pin", Local),
    ("artifacts_write", "instantiate_artifact", Local),
    ("artifacts_write", "manage_alpha_tabs.adopt", Needs(Reason::Unreviewed)),
    ("artifacts_write", "manage_alpha_tabs.adopt_authored", Needs(Reason::Unreviewed)),
    ("artifacts_write", "manage_alpha_tabs.disable", Local),
    ("artifacts_write", "manage_alpha_tabs.install", Needs(Reason::Admin)),
    ("artifacts_write", "manage_alpha_tabs.live_unsubscribe", Local),
    ("artifacts_write", "manage_alpha_tabs.materialize_catalog_update", Needs(Reason::Admin)),
    ("artifacts_write", "manage_alpha_tabs.publish_catalog_update", Needs(Reason::OutsideEffect)),
    ("artifacts_write", "manage_alpha_tabs.remove", Local),
    ("artifacts_write", "manage_alpha_tabs.reorder", Local),
    ("artifacts_write", "manage_alpha_tabs.restore", Local),
    ("artifacts_write", "manage_alpha_tabs.set_scope", Needs(Reason::Unreviewed)),
    ("artifacts_write", "manage_alpha_tabs.shelf_add", Needs(Reason::Admin)),
    ("artifacts_write", "manage_alpha_tabs.shelf_remove", Needs(Reason::Admin)),
    ("artifacts_write", "manage_alpha_tabs.update", Needs(Reason::Unreviewed)),
    ("artifacts_write", "manage_artifact_inputs.bind", Local),
    ("artifacts_write", "manage_artifact_inputs.bind_many", Local),
    ("artifacts_write", "manage_artifact_inputs.unbind", Local),
    ("artifacts_write", "manage_change_summaries.confirm", Local),
    ("artifacts_write", "manage_change_summaries.create_or_reuse", Local),
    ("artifacts_write", "manage_change_summaries.derive", Needs(Reason::Unreviewed)),
    ("artifacts_write", "manage_change_summaries.revoke", Local),
    ("artifacts_write", "manage_mdx_modules.deprecate", Needs(Reason::OutsideEffect)),
    ("artifacts_write", "manage_mdx_modules.publish", Needs(Reason::OutsideEffect)),
    ("artifacts_write", "manage_mdx_modules.withdraw", Needs(Reason::OutsideEffect)),
    ("artifacts_write", "manage_renderer_binding.bind", Local),
    ("artifacts_write", "manage_renderer_binding.unbind", Local),
    ("artifacts_write", "manage_surface_bindings.reset", Local),
    ("artifacts_write", "manage_surface_bindings.set", Local),
    ("canvas_write", "manage_canvas.assert_connector", Local),
    ("canvas_write", "manage_canvas.commit_batch", Local),
    ("canvas_write", "manage_canvas.promote", Needs(Reason::PlanGated)),
    ("coordination_write", "close_run", Local),
    ("coordination_write", "set_intent", Local),
    ("coordination_write", "start_work.claim", Local),
    ("coordination_write", "start_work.release", Needs(Reason::ReplayRefused)),
    ("experimental_freshness", "experimental_freshness_agent_intent.assess_exact_change", Needs(Reason::Unreviewed)),
    ("experimental_freshness", "experimental_freshness_agent_intent.bind_exact_expression", Needs(Reason::Unreviewed)),
    ("experimental_freshness", "experimental_freshness_agent_intent.declare_sources", Needs(Reason::Unreviewed)),
    ("experimental_freshness", "experimental_freshness_agent_intent.promote_exact_expression", Needs(Reason::Unreviewed)),
    ("experimental_freshness", "experimental_freshness_agent_intent.reconcile_affected_output", Needs(Reason::Unreviewed)),
    ("experimental_freshness", "experimental_freshness_agent_intent.revise_exact_expression", Needs(Reason::Unreviewed)),
    ("export", "authority_act_delta", Needs(Reason::Admin)),
    ("export", "authority_act_head", Needs(Reason::Admin)),
    ("export", "export_snapshot", Needs(Reason::Admin)),
    ("external_import", "attach_from_url", Needs(Reason::OutsideEffect)),
    ("guidance_admin", "manage_instructions.apply_seeded_default", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.create_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.disable_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.enable_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.remove_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.reorder_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.reset_seeded_default", Needs(Reason::Admin)),
    ("guidance_admin", "manage_instructions.retarget_binding", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.add_source", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.change_source", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.configure_programme", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.create_programme", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.publish_generation", Needs(Reason::OutsideEffect)),
    ("guidance_admin", "manage_onboarding.record_progress", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.remove_source", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.reopen_obligation", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.reorder_source", Needs(Reason::Admin)),
    ("guidance_admin", "manage_onboarding.resolve_obligation", Needs(Reason::Admin)),
    ("identity_admin", "manage_bindings.add", Needs(Reason::Admin)),
    ("identity_admin", "manage_bindings.canonicalize", Needs(Reason::Admin)),
    ("identity_admin", "manage_bindings.reconcile", Needs(Reason::Admin)),
    ("identity_admin", "manage_bindings.remove", Needs(Reason::Admin)),
    ("identity_resolve", "materialize_record", Needs(Reason::Exclusive)),
    ("identity_resolve", "observe_external", Needs(Reason::ReplayDuplicates)),
    ("identity_resolve", "resolve_external", Local),
    ("membership_admin", "manage_memberships.create_guest_link", Needs(Reason::Admin)),
    ("membership_admin", "manage_memberships.invitations_copy_link", Needs(Reason::Admin)),
    ("membership_admin", "manage_memberships.invitations_create", Needs(Reason::Admin)),
    ("membership_admin", "manage_memberships.invitations_revoke", Needs(Reason::Admin)),
    ("membership_admin", "manage_memberships.invitations_send", Needs(Reason::OutsideEffect)),
    ("membership_admin", "manage_memberships.revoke_guest_link", Needs(Reason::Admin)),
    ("membership_admin", "manage_memberships.set_role", Needs(Reason::Admin)),
    ("membership_remove", "manage_memberships.remove", Needs(Reason::Delete)),
    ("messaging_write", "manage_interventions.cancel", Needs(Reason::OutsideEffect)),
    ("messaging_write", "manage_interventions.resume_delivery", Needs(Reason::OutsideEffect)),
    ("messaging_write", "manage_messages.add_reaction", Local),
    ("messaging_write", "manage_messages.classify", Local),
    ("messaging_write", "manage_messages.delete", Needs(Reason::Delete)),
    ("messaging_write", "manage_messages.edit", Local),
    ("messaging_write", "manage_messages.mark_no_longer_relevant", Local),
    ("messaging_write", "manage_messages.move", Local),
    ("messaging_write", "manage_messages.mutate_human_awareness", Needs(Reason::Unreviewed)),
    ("messaging_write", "manage_messages.remove_reaction", Local),
    ("messaging_write", "manage_messages.satisfy_acknowledgement_expectation_with_reaction", Local),
    ("messaging_write", "manage_messages.send", Needs(Reason::OutsideEffect)),
    ("messaging_write", "manage_messages.set_agent_disposition", Local),
    ("messaging_write", "manage_messages.set_destination", Local),
    ("messaging_write", "manage_messages.set_notification_preference", Local),
    ("messaging_write", "manage_messages.set_preference", Local),
    ("messaging_write", "manage_messages.set_routing", Local),
    ("messaging_write", "manage_messages.share_history", Needs(Reason::OutsideEffect)),
    ("messaging_write", "manage_messages.unclassify", Local),
    ("messaging_write", "manage_messages.unmark_no_longer_relevant", Local),
    ("messaging_write", "manage_participants.register_persona", Needs(Reason::Admin)),
    ("messaging_write", "manage_participants.retire_persona", Needs(Reason::Admin)),
    ("reach_connect", "connect_source", Needs(Reason::OutsideEffect)),
    ("records_delete", "delete_record", Needs(Reason::Delete)),
    ("records_delete", "manage_attachments.detach", Needs(Reason::Delete)),
    ("records_delete", "manage_citations.remove", Needs(Reason::Delete)),
    ("records_lifecycle", "archive_record", Local),
    ("records_write", "activate_view", Needs(Reason::OutsideEffect)),
    ("records_write", "attach_text", Local),
    ("records_write", "batch_write", Local),
    ("records_write", "claim_unowned_record", Local),
    ("records_write", "correct_record_type", Needs(Reason::PlanGated)),
    ("records_write", "create_attribution", Local),
    ("records_write", "create_exploration", Local),
    // `create_many` without its key mints every record again, so it stays
    // queued as waiting. A keyed multi-record call replays safely on both
    // engines (proven by the conformance suite), but the node still excludes
    // it from automatic retry: a historical keyed call timed out and
    // duplicated on retry (see `automatic_replay_safe` in src/node/gate.rs).
    ("records_write", "create_many", Needs(Reason::ReplayDuplicates)),
    ("records_write", "create_record", Local),
    ("records_write", "manage_account_config.ensure", Local),
    ("records_write", "manage_account_config.replace", Local),
    ("records_write", "manage_attributions.add_evidence", Local),
    ("records_write", "manage_attributions.retract", Local),
    ("records_write", "manage_citations.reanchor", Local),
    ("records_write", "manage_facet_observations.set", Local),
    ("records_write", "manage_facet_observations.unset", Local),
    ("records_write", "manage_links.add", Local),
    ("records_write", "manage_links.remove", Local),
    ("records_write", "manage_relationships.add_evidence", Local),
    ("records_write", "manage_relationships.assert", Local),
    ("records_write", "manage_relationships.contest", Local),
    ("records_write", "manage_relationships.retract", Local),
    ("records_write", "manage_saved_tabs.create", Local),
    ("records_write", "manage_saved_tabs.rename", Local),
    ("records_write", "manage_saved_tabs.retire", Local),
    ("records_write", "merge_body", Local),
    ("records_write", "prepare_named_views", Local),
    ("records_write", "record_view_revision", Local),
    ("records_write", "resolve_suggestions.accept", Local),
    ("records_write", "resolve_suggestions.reject", Local),
    ("records_write", "save_account", Local),
    ("records_write", "unpublish_view", Needs(Reason::OutsideEffect)),
    ("records_write", "update_record", Local),
    ("schema_admin", "manage_schema_config.write", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.alias_value", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.create_vocabulary", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.deprecate_value", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.promote_value", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.propose_value", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.reorder_value", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.set_gloss", Needs(Reason::Admin)),
    ("schema_admin", "manage_vocabularies.set_metadata", Needs(Reason::Admin)),
    ("schema_delete", "manage_vocabularies.delete_value", Needs(Reason::Delete)),
    ("schema_delete", "manage_vocabularies.delete_vocabulary", Needs(Reason::Delete)),
    ("sql_write", "sql_write", Needs(Reason::PlanGated)),
    // Filed under reads in the audit, but the registry classifies them as
    // writes (they record something when called), so they are declared.
    ("artifacts_read", "manage_alpha_tabs.admit_reveal_target", Local),
    ("guidance_read", "quickstart", Local),
    ("messaging_read", "manage_messages.get_notification_preference", Local),
    // Composed only in some builds, so not in the frozen audit.
    ("records_write", "manage_publication.publish", Needs(Reason::OutsideEffect)),
    ("records_write", "manage_publication.unpublish", Needs(Reason::OutsideEffect)),
];

/// The declaration for a pair, if it has one.
pub(super) fn declaration(executor: &str, operation: &str) -> Option<Acceptance> {
    ACCEPTANCE_TABLE
        .iter()
        .find(|(table_executor, table_operation, _)| {
            *table_executor == executor && *table_operation == operation
        })
        .map(|(_, _, acceptance)| *acceptance)
}

/// Whether the operation must wait for hosted acceptance. Reads and
/// undeclared pairs are `false`; see the module docs for why that is safe.
pub(super) fn requires_acceptance(executor: &str, operation: &str) -> bool {
    matches!(
        declaration(executor, operation),
        Some(Acceptance::Required(_))
    )
}

# SQLite authorization coverage contract

This is the review index for Native CE's observable record authorization. The
machine-readable source is
[`tests/fixtures/authorization-contract.json`](../tests/fixtures/authorization-contract.json);
CI compares every `(tool, action)` row with the production `ToolKind::ALL`
registry and registered input schemas. `$tool` is the action key for a tool
without a top-level action discriminator.

## Current operation census

- **90 registered tools / 247 operations**.
- **13 ordinary, 87 high-risk, and 147 specialized operations**.
- **105 read-only and 142 mutating operations**.
- **242 operations carry a non-disclosure obligation**.
- All **142 mutating operations** carry an explicit no-write-on-deny obligation
  and named negative evidence.
- **5 read operations** have justified `negative_evidence: not_applicable`:
  `ping.$tool`, `engine_info.$tool`, `quickstart.$tool`, `read_guide.$tool`, and
  `manage_vocabularies.list_values`. They have no authorization threshold;
  each still has positive executable evidence.
- Complete-coverage claim: **SQLite local**, exercised by
  `sqlite-reference-ci`. Postgres and Turso contract profiles do not inherit
  this claim. Named-view rows separately qualify hosted-v2 success and
  ordinary-SQLite refusal; they do not claim local success.

Each operation independently declares its production disposition, risk tier,
fixture owner, expected threshold, read/mutation nature, non-disclosure and
no-write obligations, and separate positive and negative evidence claims. A
single named test can own several operations only when every operation row
cites that test and states the side-specific claim it owns. A side of one
operation may cite several tests when its conjunction threshold is proven by
separate focused tests. CI verifies that a Rust citation is an exact
`fn`/`async fn` declaration and a Playwright citation is an exact named
`test(...)`, rather than accepting an arbitrary substring.

CI fails when:

- a production `(tool, action)` is missing, duplicated, or replaced by an
  unshipped operation;
- a schema gains, removes, or renames an action;
- an operation's disposition differs from production;
- a sensitive operation drops its non-disclosure obligation;
- an operation declared mutating is marked `no_write_on_deny: false` or lacks
  negative test evidence;
- a protected read lacks negative test evidence;
- an evidence citation does not resolve to an exact test declaration; or
- specialized behavior lacks a rationale.

The validator has explicit negative controls for a newly shipped schema
action, a mutation with missing negative evidence, a mutation with
`no_write_on_deny: false`, and a citation that is only a source substring.

## Proof layers

1. `authorization_contract::ordinary_dispatch_matrix_keeps_allow_and_deny_adjacent`
   drives the production MCP registry across inherited/explicit and
   narrow-parent/broad-child topologies. It pairs positive and negative view,
   edit, manage, query, and search assertions and checks denied writes append
   no content, policy, or metadata events.
2. `authorization_contract::vocabulary_operation_matrix_proves_each_host_owner_boundary`
   executes all eleven `manage_vocabularies` actions. It proves the ten mutations
   require host ownership and write nothing on denial, while `list_values` is
   deliberately callable without that role.
3. Focused suites named per operation own expensive or specialized evidence:
   temporal reads, policy and identity mutation, links, messaging,
   interventions, artifacts, attachments, citations, instructions,
   onboarding, suggestions, and change summaries.
4. The real-server Workbench acceptance suite owns authenticated account/token
   binding; per-action membership list/set-role/remove allow and deny cases;
   immediate grant/revoke/baseline effects; non-disclosing read/search
   behavior; and a denied mutation with unchanged content and policy revisions.

The manifest is an exact review and ownership index; its lightweight citation
parser does not infer test semantics. The stated side-specific claims remain
reviewable assertions owned by the cited suites. The contract intentionally
does not claim canonical allow/deny execution for every action in this one
test binary, and it does not replace differential predicate parity or
property-generated policy trees. Those remain separate proof obligations.

Alpha-tab update retains the shared numeric X.Y.Z version format and imposes
no version ordering; equal versions and rollback are allowed.

Alpha-tab `prepare_install` requires View on the live artifact and reads current
install state only for the authenticated caller account. Its positive and
negative evidence is `prepare_install_authorization_requires_view_and_scopes_install_to_caller`
in `tests/tools/alpha_tabs_prepare_install.rs`: it proves non-disclosing refusal
without View and independent current-install pins for two accounts sharing a
package. Preparation is read-only and grants no installation or adoption.

The main-Native-only `read_hcp_audit.$tool` operation is owned by
`hcp_audit_non_owner_reads_only_own_events_and_refuses_foreign_cursors` in
`tests/tools/counter_guard.rs`. A non-owner reads only its caller-derived sealed
state/read aggregates, even across interleaved account activity. Pagination uses
opaque event identities from that same snapshot. Foreign, unknown and malformed
cursors receive a uniform refusal; payloads cannot select another account. This
JSON-only audit is unavailable offline, where a partial workspace history cannot
establish a complete personal audit.

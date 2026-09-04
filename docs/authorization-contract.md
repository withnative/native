# SQLite authorization coverage contract

This is the review index for Native CE's observable record authorization. The
machine-readable source is
[`tests/fixtures/authorization-contract.json`](../tests/fixtures/authorization-contract.json);
CI compares every `(tool, action)` row with the production `ToolKind::ALL`
registry and registered input schemas. `$tool` is the action key for a tool
without a top-level action discriminator.

## Current operation census

- **74 registered tools / 185 operations**.
- **13 ordinary, 70 high-risk, and 102 specialized operations**.
- **74 read-only and 111 mutating operations**.
- **180 operations carry a non-disclosure obligation**.
- All **111 mutating operations** carry an explicit no-write-on-deny obligation
  and named negative evidence.
- **5 read operations** have justified `negative_evidence: not_applicable`:
  `ping.$tool`, `engine_info.$tool`, `quickstart.$tool`, `read_guide.$tool`, and
  `manage_vocabularies.list_values`. They have no authorization threshold;
  each still has positive executable evidence.
- Complete-coverage claim: **SQLite local**, exercised by
  `sqlite-reference-ci`. Postgres and Turso contract profiles do not inherit
  this claim.

Each operation independently declares its production disposition, risk tier,
fixture owner, expected threshold, read/mutation nature, non-disclosure and
no-write obligations, and separate positive and negative evidence claims. A
single named test can own several operations only when every operation row
cites that test and states the side-specific claim it owns. CI verifies that a
Rust citation is an exact `fn`/`async fn` declaration and a Playwright citation
is an exact named `test(...)`, rather than accepting an arbitrary substring.

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

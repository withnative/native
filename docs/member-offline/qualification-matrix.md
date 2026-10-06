# Member-offline qualification matrix (independent, Q1)

Contract: Native record c323277 rev 7 (`/tmp/mo/c323277-rev7.md`;
body digest `86b18563...9a432`). Base: `8a486471f` (origin/main).
Worker: Q1 independent qualifier, branch `member-offline/q1-qualification`.

Method: the qualifier does not trust the implementation's own tests.
E(m) is the engine's online evaluator (`workspace_visible_set`,
`QueryPrincipal::authenticated(m, true)`); each differential check
compares E(m) against what an online member-scoped read path actually
returns for m. A disagreement is a FINDING, recorded, never fixed here.

Columns: threat | evidence required (`raw-scan` = raw-file byte scan;
`differential` = online-as-m vs E(m); `race` = interleaved fence steps;
`crash` = kill-and-resume) | existing coverage on main (`file:test`)
| gap | planned fixture | blocked-on (`none`, producer `766ede6`,
consumer `da0a471`, lifecycle `4207bbb`).

Fixture worlds (read-only): `src/member_offline_fixtures.rs`
(`two_caller`, `hidden_change`, `prefix_gate`, `counter_scan_tests`).

## Rows A–C: visibility core

| Area (§7.2) | Threat | Evidence | Existing coverage on main | Gap | Planned fixture (this branch) | Blocked-on |
|---|---|---|---|---|---|---|
| A. Owner floor (§7.2.3; §3.2 records row) | A member-owned record under a restrictive policy leaks to another member, or is wrongly withheld from its owner. | differential | `member_offline_fixtures.rs:two_caller::world_is_what_it_claims` pins `A_OWNED` in E(A) only; `assert_evaluator_agreement` checks both evaluators agree. | Online side CLOSED (round 1 fixture 1: records-view equality + hidden-membership pins). Remaining: artifact raw-scan. | 1 (done) | none (artifact raw-scan: producer 766ede6) |
| B. Bearer changes (§7.2.1, §7.2.3; §3.3 rule 3) | A Unit bearer change moves records in/out of E(m) unnoticed; a restricted-bearer attachment's bytes reach the wrong member. | differential + raw-scan | `two_caller::world_is_what_it_claims` pins `ATT_A` visible to A only; `hidden_change` notes the Unit-bearer delta as deliberately unbuilt (Units excluded from v1). | Online side CLOSED (round 1 fixture 1: single-record absence + blob reachability follow the bearer). Remaining: Unit-bearer (excluded v1); bearer grant-change sequences; artifact raw-scan. | 1 (done) | none (Unit-bearer + raw-scan: producer 766ede6) |
| C. Hidden parents/endpoints (§7.2.3, §7.2.6; §3.3 rules 1–2, 4) | Hidden parent id/title leaks via child; visible→hidden link leaks target; hidden mention target resolves for the wrong caller. | differential | `two_caller::world_is_what_it_claims` pins raw `home_id` intact plus governed-NULL for B (`query_sql` one-shot), and the authored-text exception list. | Online side CLOSED (fixture 2 + round-2 group 8: containment walk subset, tool-path `containment_path_visible`, links-view endpoints, visible→hidden edge absence, mention `unresolved`-for-B / resolved-for-A). Remaining: offline answers. | 2 + 8 (done) | none (offline answers: consumer da0a471) |

## Rows D–E: caller-specific state and derived values

| Area (§7.2) | Threat | Evidence | Existing coverage on main | Gap | Planned fixture (this branch) | Blocked-on |
|---|---|---|---|---|---|---|
| D. Caller bindings / awareness / identity (§7.2.3, §7.2.4; §3.2 caller-bound) | Instruction bindings, awareness evidence, or person/account bindings of A appear in B's derived set; database-scope binding with hidden source ships. | differential | `two_caller::world_is_what_it_claims` pins `MSG_A` audience row present and E(B)-excluded. Caller-confined instruction resolution is also covered on main by `tests/tools/bootstrap_instructions.rs:260 manage_instructions_resolve_hides_other_member_sources` and `tests/tools/instruction_controls.rs`. | Instruction content CLOSED (round-2 group 7: hidden id/title/body/digest absent from B's `resolve_for_account` and the `manage_instructions.resolve` tool path). OPEN: finding Q2 — hidden-sourced binding is distinguishable from no binding (`invalid/instruction_source_unreadable` vs `ready`), pinned as a passing trip-wire test (`hidden_binding_oracle_pinned_for_product_fix`; `#[ignore]` is forbidden by the gate's `EXPECTED_IGNORED_TESTS` policy, so the pin asserts current behavior and trips on any product change). OPEN (gap, F2): awareness evidence — `awareness_event_evidence` has no member-facing read (write-side only, `src/awareness.rs:909`; member message reads refused offline per §2.3b); the online `manage_messages` projection of evidence is unaudited. | 3 + 7 (done; Q2 ignored) | none (offline answers: consumer da0a471; Q2 fix: product owner) |
| E. Counts and derived state (§7.2.1b, §7.2.4; §2.4 items 1–7) | `superseded_by.total_count` counts invisible successors (known carve-out, pending e5f171c); child/link/mention counts include hidden rows; search scores order on hidden corpus. | differential | `hidden_change::hidden_only_changes_move_nothing_for_b` pins E(B) equal across hidden deltas and attributes the VIS_H timestamp move (§2.4 item 3). | Online side CLOSED (fixture 4: `superseded_by` carve-out pin, `child_count` 2-for-A/1-for-B, `links_in` sources in E(B), search-hit subsets + B_ONLY visibility). Executed mutation M2 (round 2): deleting the `child_count` fold makes B read 2 and fails the test; restored. Remaining: offline recomputation. | 4 (done) | none (offline recomputation: consumer da0a471) |

## Rows F–I: revocation, identity, crash

| Area (§7.2) | Threat | Evidence | Existing coverage on main | Gap | Planned fixture (this branch) | Blocked-on |
|---|---|---|---|---|---|---|
| F. Download revocation races (§7.2.5; §4.3 steps 6–7) | Membership removed / binding re-bound / epoch bumped between C1 and C2 still serves bytes; E(m) narrowing mid-download is served, not restarted. | race | None on main (no producer; `replica_generation.rs` is sibling-owned). | All §7.2.5 race fixtures. | none (out of scope) | producer 766ede6 + lifecycle 4207bbb |
| G. Membership/session withdrawal (§7.2.5; §4.3 step 7, §6) | Demotion member→guest keeps the copy; revoked session reads as `current`; expired-while-offline locks locally instead of at reconnect. | race + differential | None on main. | Reconnect-answer fixtures (`revoked{role_changed}`, offline-expiry readability, same-account unlock without re-download). | none (out of scope) | producer 766ede6 + lifecycle 4207bbb |
| H. Account switch (§7.2.5; §1.5) | Re-added member's old `scope_ref` resolves to `current`; different-account sign-in keeps old files. | race | None on main. | `scope_ref` rotation fixture (remove/re-add, binding re-reconcile equality). | none (out of scope) | producer 766ede6 |
| I. Interrupted migration (§7.2.5–6; §7.1 consumer, §6) | Crash mid-promote leaves older generation/WAL/SHM/index/cache; partial download counts as retained; `deletion` never reaches `complete`. | crash | None on main. | Kill-and-resume fixtures for staging promote-by-pointer and the 4207bbb cleanup barrier. | none (out of scope) | lifecycle 4207bbb |

## Rows J–K: measurements and §7.2 items 1–8

| Area (§7.2) | Threat | Evidence | Existing coverage on main | Gap | Planned fixture (this branch) | Blocked-on |
|---|---|---|---|---|---|---|
| J. Measurements (c25df88: group/slice sizes, generation time, peak memory, download/rebuild time, invalidation frequency) | Refresh cost unknown: hidden-touch timestamp moves (§2.4 item 3) force re-downloads at unknown frequency; F-e counter churn cost unmeasured. | measurement | None (needs the producer). | Out of scope for Q1 by brief. | none (out of scope) | producer 766ede6 |
| §7.2.1 hidden-only change | Hidden identity/content/count reaches the artifact. | raw-scan + differential | `hidden_change::hidden_only_changes_move_nothing_for_b` (E(B) equality, raw-row attribution, evaluator agreement). | Producer-side raw-scan of the artifact; online-side attribution covered here by Q1 fixtures 1–2. | 1 + 2 (done) | artifact raw-scan: producer 766ede6 |
| §7.2.2 prefix gate (N1) | Short reference resolves against hidden records; gate outcome depends on hidden prefix existence. | differential | `prefix_gate::short_reference_ships_verbatim_in_both_worlds` (verbatim row, E(B) equality). | Consumer gate behavior; online-side verbatim check extended here. | — (fixtures own it) | consumer gate: producer 766ede6 + consumer da0a471 |
| §7.2.3 two callers | Cross-member private bytes in either artifact. | raw-scan + differential | `two_caller::world_is_what_it_claims` (E(A)/E(B) pins, governed-NULL, evaluator agreement). | Producer raw-scan; read-path differentials here (Q1 fixtures 1–4, 7–9). | 1–4, 7–9 (done) | artifact raw-scan: producer 766ede6 |
| §7.2.4 differential parity | A §2.3(a) surface disagrees with online-as-m; a §2.3(b) surface answers instead of typed `UnavailableOffline`. | differential | `query_sql` governed-NULL one-shot inside `world_is_what_it_claims`; `counter_scan_tests` pins the item-8 scanner only. | All surface differentials except those closed today. | 1–9 (done, online side) | offline answers: consumer da0a471 |
| §7.2.5 fence races | See rows F–I. | race | None. | All. | none (out of scope) | producer 766ede6 + lifecycle 4207bbb |
| §7.2.6 folders/collections | Hidden children counted; hidden `member_of` sources listed; hidden artifact in renderers; hidden-collection scoped-schema divergence answered silently. | differential | None on main. | Online half CLOSED (round-2 group 9: visible-folder walk, `member_of` selection parity, plain + `as_of` query collections — `as_of` fails closed at parse online, typed refusal offline). OPEN (gap): renderer lists with hidden artifacts; offline answers. | 5 + 9 (done, online half) | online half: none; offline half: producer 766ede6 + consumer da0a471 |
| §7.2.7 trigger coverage (F-A…F-e) | Evaluator reads a column no counter watches; Unit `unit_id` gap ships. | differential (authorizer-callback test) | None on main. | Owned by producer 766ede6 (must resolve before it merges). | none (out of scope) | producer 766ede6 |
| §7.2.8 no omitted field (R5) | `act`/`seq`/`rec:`/`obs:` tokens in a member response or refusal payload. | raw-scan (JSON walk) | `counter_scan_tests` (17 tests: 16 rejections + 1 clean shape). | Member envelopes still producer-owned. | 6 (done, online side) | member envelopes: producer 766ede6 |

## Planned Q1 fixtures (this branch) and blocking

| # | Planned fixture (`src/member_offline_qualification.rs`) | Closes | Blocked-on |
|---|---|---|---|
| 1 | Owner-floor + bearer differentials (get_record-as-m, query_sql records-view-as-m vs E(m)) | A, B, §7.2.3 (online side) | none |
| 2 | Hidden-parent/link/mention differentials (descendants_as, query_sql links view, mentions sections) | C, §7.2.3 (online side) | none |
| 3 | Caller-bindings/awareness/identity differentials (instruction stacks, bindings view, message audience) | D, §7.2.3 (online side) | none |
| 4 | Counts/derived-state differentials (superseded_by carve-out pin, child counts, search-as-m) | E, §7.2.1b/§7.2.4 (online side) | none |
| 5 | Folder/collection online-side differentials (hidden children, member_of, saved-query refusal shape) | §7.2.6 (online side) | online half: none; offline half: producer 766ede6 + consumer da0a471 |
| 6 | Item-8 scanner over live online-as-m responses | §7.2.8 (online side) | none (member envelopes: producer 766ede6) |
| 7 | Instruction differentials with hidden-sourced database binding + private account binding (`resolve_for_account` and `manage_instructions.resolve` tool path); hidden-binding oracle pinned as a passing trip-wire (finding Q2) | D, §7.2.3 (online side) | none (Q2 fix: product owner) |
| 8 | Mention resolution via tool path (`unresolved`-for-B / resolved-for-A) | C, §7.2.3 (online side) | none |
| 9 | Selection + query-collection online halves (`member_of` parity, plain + `as_of` saved queries) | §7.2.6 (online side) | online half: none; offline half: producer 766ede6 + consumer da0a471 |

## Executed mutation evidence (round 2, M2)

`cargo test --lib member_offline_qualification::child_counts` with the
`record.child_count = authorized_children.len()` fold deleted fails with
B reading `child_count` 2 instead of 1; with the fold restored it passes.
Note: the fold exists twice — `:4738`
(`filter_enriched_record_with_auth_in_pools`) and `:4908`
(`filter_enriched_record_in`). Deleting only `:4738` does NOT fail the
test (the `get_record` tool path folds at `:4908`); deleting `:4908`
does. The mutation was reverted with `git checkout` and never committed.

Deliberately left for later: rows F–I races/crashes, row J measurements,
producer raw-scans, consumer offline answers, lifecycle barrier.

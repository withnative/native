# Inspectable authoring and reuse

This workflow preserves declared source use when an agent writes an ordinary
account and prepares bounded context for later reuse. Declaring a source does
not establish that the account correctly represents it.

The supported operations are `records_write.save_account` and
`records_read.get_reuse_context`. The former records the output body and its
exact declared basis through the existing Receipt aggregate; the latter
combines the current account, revision coverage, direct concerns, recorded
treatment and inherited uncertainty. Neither operation runs a model.

Create a new ordinary note through `create_record` first, then use
`save_account` for its authored text and basis. Record creation and the first
basis save are separate operations; a failed save leaves the initial document
without a new basis claim. Subsequent authored saves use the same guarded
operation. The supported save does not accept executable artifacts.

Read the account and proposed Document sources with `get_reuse_context` to
obtain their current `record.revision.revision_event_id`. The packet also identifies
body revisions for its visible comments. Then declare the exact revisions
used, with a role and reason for each source:

```json
{
  "operation": "save_account",
  "arguments": {
    "record_id": "<account id>",
    "expected_revision_event_id": "<account body event id>",
    "body": "Friday remains conditional on the reviewed Engineering plan.",
    "sources": [{
      "record_id": "<source id>",
      "revision_event_id": "<source body event id>",
      "role": "Engineering plan",
      "reason": "Establishes the conditional target date."
    }],
    "idempotency_key": "sales-draft-1",
    "reason": "Give Sales a reusable account of the stated condition."
  }
}
```

This envelope goes to `records_write`. The matching read goes to
`records_read` with `operation: "get_reuse_context"` and
`arguments: {"record_id": "<account id>"}`. Event identifiers are exact;
they are not record abbreviations.

## Revision coverage

A declaration covers one exact output body revision. An ordinary body edit
does not renew it. The previous declaration remains inspectable as historical
evidence, and reuse must disclose that the current body has no matching basis.
Unchanged wording alone is not permission to attach an old declaration to a
different revision.

Selected source revisions must be explicit. Saving must never silently replace
the selected source with newer text. Retrying the same write must recover its
original result, while changing the request under the same idempotency key
must fail. Authorization is checked again on reads and retries.

The first slice selects source body heads at context assembly. A supplied
revision that is already historical is refused; recover the current source
and reconsider the draft. This does not remove the historical evidence of a
previous successful save.

When a previous declared source has changed, the save preserves that change
as unresolved uncertainty. It does not judge the change immaterial or assert
that the earlier conclusion remains valid. Existing inherited uncertainty
and visibility limits continue into the new receipt.

## Concern and treatment boundaries

The first slice uses recorded direct comment relationships. It does not infer
that two concerns mean the same thing or search the workspace for related
disputes. Separate comment roots represent independently resolvable issues:
correcting commitment wording must not resolve a separate QA question.

Resolved roots belong in treatment history. A later reuse should distinguish
their recorded resolution from still-open questions, and an earlier
derivative retains the evidence that existed when it was authored. Resolving a
comment does not retroactively correct a derivative or establish a release
approval.

Source declarations bind body revisions. A comment's resolution summary and
lifecycle have separate metadata revisions in the reuse packet; declaring its
body as a source does not bind that treatment metadata. When a later draft
depends on a recorded outcome, include the outcome's source document in its
declared basis, as the acceptance journey does for QA evidence.

Completeness is relative to an identified selection: declared basis, direct
concern windows, reply windows and treatment windows. Truncation and withheld
context cannot become a claim that no other evidence or concerns exist.
Continuation calls read live state rather than a pinned snapshot. Compare
receipt identifiers before combining basis pages; comment windows may change
between calls.

A general Receipt may record provenance without a semantic dependency role;
the reader returns `role: null` in that case. Choose a role for the new draft
after inspecting the source; do not invent a historical role.

## Drafting contract

The reuse packet includes a versioned instruction requiring uncertainty to
remain scoped in the reusable prose itself. In particular, “not established
by the supplied material” must not become “pending”, “not approved”, or an
organisation-wide absence without an explicit record of that operational
state. A separate provenance note is insufficient if the standalone draft
overstates the evidence.

The instruction also distinguishes an original concern from its later
recorded resolution. It requires the reusable prose to preserve the scoped
resolution outcome and to distinguish earlier statements from later
treatment, without treating one resolved concern as unrelated approval.

Deterministic tests verify packet contents and persistence. Fresh-model
evaluations separately test whether a model follows the instruction. Passing
structural tests does not establish model reliability.

## Scope

This is a SQLite authoring workflow over the existing record, comment and
Receipt authorities. It does not add scheduling, notifications, semantic
matching, automatic correctness judgements, publishing or launch decisions.
The experimental Unit and Receipt grammars remain internal to their existing
development surfaces.

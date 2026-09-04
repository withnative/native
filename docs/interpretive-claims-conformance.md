# Interpretive claims conformance proof

This proof records what the interpretive-claims contract establishes, and what it deliberately does not establish. The composed scenarios live in `tests/records/interpretive_claims.rs`; the existing focused attribution, provenance, authorization, renderer, and generic-read suites remain the deeper witnesses for each primitive.

## Acceptance map

| Acceptance domain | Composed proof |
| --- | --- |
| Existing content with no claim | A legacy task is read through the dedicated, generic get, generic query, and record-render surfaces as `status: none`, with zero caller-visible claims and no invented interpretation. |
| Decisions, recommendations, comments, suggestions, standing guidance, and an external-facing draft | Each record kind carries a bounded assessment, and every read surface returns the same typed projection and group headlines. |
| Agent paraphrase, selection, summary, synthesis, and opinion | The domain matrix preserves the declared transformation and classifies agent claims as `agent_opinion`; it never upgrades them to human endorsement. |
| Mixed authorship | Distinct passage/revision claims for a person and an agent remain distinct groups. This proves mixed stance attribution, not an unsupported `authored_by` relation. |
| Direct human declaration and later confirmation | Only the authenticated person's exact structured gesture creates `direct_declaration` with receiver-local confirmation. A credential-only call fails closed; an earlier agent interpretation remains an assessment. |
| Conflict, retraction, successors, and historical replay | Opposing frontier claims stay conflicted, retracted claims remain historical, successor identity is explicit, and an earlier event boundary reconstructs the earlier assessment-only view. |
| Passage relocation and ambiguity | A passage target moves from `relocated` to `conflict` without silently re-anchoring or becoming historical. |
| Hidden and sealed evidence | A caller who can see the bearer but not the evidence sees incomplete/withheld state, no hidden cardinality or identifier, and only a boolean that sealed evidence was recorded. |
| Imported and invalidated evidence | Import removes receiver-local trust and current invalidation remains fail-closed; neither can produce confirmation. |
| Atomic failure and deterministic replay | An injected attestation failure leaves no partial claim or membership while preserving the prior committed claim; rebuilding derived state remains equal. |
| Machine and human presentations | Dedicated interpretation JSON, opt-in generic get/query JSON, structured record rendering, and their human-readable headlines agree for the same caller authority. |

## Authority boundary

Interpretive claims describe attributed stance over exact content. They do not grant behavioural authority. In particular:

- delegation does not establish endorsement;
- confidence does not establish truth;
- claim counts do not establish consensus;
- a standing-guidance record is interpretable content, not an instruction binding;
- an external-facing draft does not authorize publication or sending;
- ownership of a credential does not manufacture a declaration; and
- imported, invalidated, hidden, or sealed evidence never becomes receiver-local confirmation by omission.

The current public target vocabulary is whole-revision or passage selection, and the public relation vocabulary is `expresses_view` or `endorses`. Field/proposition targets and an `authored_by` relation are therefore outside this proof. Comments and suggestions are independently attributable records; the evidence model cites their action attestations rather than pretending an annotation record is itself evidence.

## Determinism and bounds

The stress corpus uses fixed record identities and stance times, keeps each generic projection window below its public cap, and makes no assertion about generated identifiers or wall-clock timestamps. Each narrative uses one in-memory authority, bounded claim/evidence sets, explicit historical boundaries, and a final rebuild comparison. Test-only SQL is limited to the existing seams needed to demonstrate sealed-reference non-disclosure, current invalidation, and transactional rollback; no production schema or behaviour is changed by this proof.

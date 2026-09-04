# Adopting interpretive claims

Use interpretive claims selectively where attributed stance needs to survive the session: decisions and recommendations, passages combining person and agent analysis, confirmed summaries, comments or suggestions used as evidence, and material intended for external review. The conformance proof is in `docs/interpretive-claims-conformance.md`; the callable operating guide is `read_guide {"topic":"interpretive-claims"}`.

## Rollout without invented history

1. Leave existing content in the explicit no-claim state. There is no inferred or bulk backfill from authorship, credentials, wording, links, or legacy metadata.
2. Start with new high-value decisions or with a person deliberately confirming one exact existing revision. Record assessments when the attribution is interpretive; reserve declarations for the trusted exact human gesture.
3. Keep the content, authored attribution, and Native-issued action attestations separate. Retain returned attestation identifiers only when they are genuinely useful as bounded basis or counterevidence.
4. Enable `include_interpretation` only for a view that needs it. Default reads remain unchanged and do no attribution/provenance work. Use dedicated `read_attributions` for raw claims or an authorized Why chain.
5. Monitor unavailable/incomplete projections as a signal to narrow the authorized window or page the dedicated reader—not as permission to infer counts or bypass privacy.

## Standing guidance and public material

A claim can preserve who expressed or endorsed a rule, recommendation, or external-facing draft. It cannot make the rule binding or authorize publication, sending, representation, or execution. Any later behavioural-policy integration requires its own governed decision and implementation; it is intentionally outside the present contract.

## Operational invariants

- Never upgrade delegation, confidence, or repetition into endorsement, truth, or consensus.
- Never treat imported, invalidated, hidden, sealed, or foreign evidence as receiver-local confirmation.
- Never mutate a target or assertion. Retract, append evidence, or create an explicit successor.
- Never erase conflict or historical claims when presenting a concise headline.
- Never disclose inaccessible evidence identifiers, sealed references, or hidden cardinality through retries, errors, paging, or alternate read surfaces.

If a workflow cannot preserve these invariants, keep interpretation disabled and use ordinary content plus the existing authorization and approval mechanisms.

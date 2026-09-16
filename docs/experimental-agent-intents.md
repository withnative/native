# Experimental freshness agent-intent seam

Ordinary builds include one experimental tool,
`experimental_freshness_agent_intent`, in the hosted and stdio MCP binaries.
The implementation remains gated by the `experimental-agent-intents` Cargo
feature, which is now a default feature for staging. This changes build
availability, not the tool's stability status: it remains deliberately absent
from the generated stable tool inventory and is advertised only in the
`complete` MCP tool profile so the focused startup descriptor remains within
its byte budget. Exact-name dispatch remains available in either profile.

The tool is one tagged dispatcher for six intentions:

- `promote_exact_expression` promotes an exact artefact expression into a Unit
  and returns the Unit, immutable revision, Occurrence, and current anchor
  resolution;
- `bind_exact_expression` binds an existing Unit revision into another record
  as a new Occurrence and returns the Unit, bound Occurrence, and current
  anchor resolution;
- `revise_exact_expression` records a new revision of a Unit behind its exact
  expected current revision and returns the previous and new revisions with
  the Unit;
- `declare_sources` assembles context and commits a durable output whose exact
  selected sources all support one bounded conclusion;
- `assess_exact_change` assembles the current context, seals one assessment for
  every exact comparison, derives explicit uncertainty lineage when required,
  and commits the replacement output;
- `reconcile_affected_output` records reconciliation through the runtime and
  returns the historical Receipt explanation containing that evidence.

Every path calls the existing freshness kernel/runtime. The seam does not write
projection tables directly. Authorization, current authorization revision,
idempotency, exact revision verification, dependency budgets, temporal
high-water checks, withheld-context propagation, execution/disclosure policy,
and explanation redaction therefore remain the runtime's rules. Results carry
the experimental contract version, an observed high-water, provenance
completeness, and exact semantic evidence rather than a success string.

The `declare_sources` and `assess_exact_change` intentions each cover one
`AffectedConclusion`. Every selected source must be declared exactly once. A
change assessment must bind the complete sealed `RevisionRef` (not merely an
event identifier), and every comparison must come from a dependency carrying
that same bounded conclusion. Idempotent replay re-authorizes all exact Receipt
evidence before returning it. Reconciliation validates that the requested
Receipt owns the dependency before the runtime records anything.

A source or dependency discovered transitively from prior Receipt evidence is
not returned when it is hidden: the resulting Receipt carries withheld context
and the response reports `ProvenanceCompleteness::Withheld` without disclosing
the hidden identity or count. Directly requesting an unreadable record instead
fails authorization.

## Running the staging probe

An ordinary build includes the tool. Select the `complete` profile to discover
it through `tools/list`:

```console
NATIVE_CE_MCP_TOOL_PROFILE=complete cargo run --bin mcp-stdio -- <database>
```

## Executor-surface opt-in

The executor MCP surface does not advertise this seam by default: its
catalogue admits only `stable` audit rows. Setting the deployment-level,
off-by-default allowlist

```console
NATIVE_CE_EXPERIMENTAL_EXECUTORS=experimental_freshness
```

admits the audited `experimental_freshness` executor (six operations:
`experimental_freshness_agent_intent.promote_exact_expression`,
`.bind_exact_expression`, `.revise_exact_expression`, `.declare_sources`,
`.assess_exact_change`, and
`.reconcile_affected_output`) on both the ordinary and lens catalogues, served
through `describe_operation` and dispatched to the unchanged legacy handler.
Unset or empty means the stable-only surface, byte-identical to before. Any
other name fails process startup naming the variable and the offending value.
This advertises the seam where an operator asks for it; it is not a promotion
out of experimental, and the seam's limitations below apply unchanged.

For a build that must omit the experiment entirely, disable default features:

```console
cargo build --no-default-features
```

Cargo features are additive, so the opt-out is deliberately the standard
`--no-default-features` mechanism rather than a competing negative feature.
Explicitly adding `--features experimental-agent-intents` enables the seam
again. Default-on staging availability is not production promotion: production
deployment remains a separate, explicit release decision.

## Deliberate limitations

- This is not a stable public API or a compatibility commitment.
- It does not decide when an idea should be promoted or extract ideas
  automatically.
- It does not supply prompts, materiality judgments, thresholds, or calibration.
- It does not create a primitive-per-command tool surface.
- It does not run background repair, propagation, or workspace cleanup.
- It accepts a completed output body; it is not a streaming generation protocol.
- As an experimental extension, its calls are not classified by the stable
  shipped-tool read-log extractor. The real semantic events still retain the
  authenticated actor and asserted run context.
- The seam exercises SQLite's candidate runtime only; it makes no backend
  portability promise.

Held-out calibration and the final architecture/positioning verdict remain
outside this snapshot. No selected calibration evidence has run, so the
positioning remains provisional.

# Storage portability protocol — research draft v1

This directory defines the machine-readable storage-target model. A profile
identifies an engine, SQL frontend, connection mode, topology, logical
contracts, and capabilities independently. Sharing a dialect does not make two
engines the same target.

These fixtures are research evidence, not a support announcement:

- `sqlite-local` is the current reference implementation.
- `postgres-server` describes the bounded reviewed contract spike.
- `turso-local` describes the deterministic, test-only `TursoHarness` slice.
- `turso-remote` and `turso-embedded-sync` keep network and synchronization
  claims separate from local evidence. They remain research profiles, not
  shipped production routes.

`backend-contract-classifications.json` is the reviewed operation-level
qualification source. It explicitly covers every registered MCP tool, the
exhaustive federated-read/destination-pass-through/unsupported-read lens policy,
cross-cutting request wrappers, and the authoritative
storage/backup operator command inventory. An operated upstream process outside
this snapshot joins it to the live registries and emits stable JSON and
Markdown evidence. Classification is release evidence, not runtime capability
negotiation.

The compact reviewed codes expand in generated output: `F` = required/full
proof, `P` = required/partial proof, `N` = required/no proof, `C` =
convertible/partial proof, `V` = convertible/no proof, `U` = intentionally
unsupported, and `A` = not applicable. Every non-none proof appends a reviewed operation-specific evidence
identifier after `|`; there is no generated default evidence claim. This keeps
intended support separate from current evidence. Generated profile identities
come directly from the compiled profile catalog and pin driver, engine version,
topology, connection mode, and a canonical profile digest.

Each evidence identifier must resolve through the executable, test-owned
`backend_contract_evidence` registry to one exact profile, dedicated CI
entrypoint, and explicit operation set. The classifications file cannot add an
evidence scenario. The generator verifies that the CI job invokes the exact
entrypoint and rejects missing, extra, duplicate, or ungoverned claims.

Profile revisions are immutable once used by a released migrator. Before that
first release, a research candidate's claims may be corrected in place because
no compatibility identity has shipped. Afterwards, a changed capability claim
creates a new revision. The migration preflight resolves exact
source and target revisions and the selected connection mode. For a capability
with `mode_support`, preflight uses the selected mode's value; the top-level
`partial` is only a conservative summary and never authorizes an unsupported or
planned mode. It then intersects capabilities whose effective support is `full`
or `partial` and whose portability is `portable` or `convertible`, and refuses
undeclared, planned, unsupported, or blocking state before quiescing writes.

The top-level capability `support` is conservative across every connection mode
declared by the profile. When support differs by mode, it is `partial` and
`mode_support` records the exact status for every declared mode. An omitted
`mode_support` means the top-level status applies uniformly.

## Strict enforcement

Strict portability is an explicit, per-database opt-in. Its durable policy pins
the active source profile, every target profile's exact revision and connection
mode, the compiled profile-set digest, and the small set of conversions the
operator has deliberately accepted. Admission uses the intersection across all
targets. Strict admission requires `full` support for the exact operation-scoped
capability; aggregate `partial` claims remain useful audit evidence but never
authorize an operation by themselves. `portable` is direct, `convertible`
additionally requires its capability in `allow_conversions`, and all other
states fail closed. Shipped tools without a proven operation scope retain the
aggregate `native.domain-mcp.v1` label and are therefore rejected by partial
targets.

The removable interaction tap is separately scoped as
`native.interaction-log.v1`. Targets that do not materialize
`read_log_calls` and `read_log_touches` suppress that best-effort tap instead
of silently persisting target-specific rows after an otherwise portable call.

Policy updates use a compare-and-set revision. A target revision floor is
monotonic and survives switching enforcement off, so a later strict policy
cannot silently downgrade a previously selected target. Strict configuration
also requires `native.guarded-write.v1` in the intersection because policy-safe
engine reconciliation and every admitted mutation depend on that portable
write primitive. Unknown profiles,
changed compiled fixtures, stale policy revisions, unclassified requests, and
unclassified writes are rejected in strict mode. With no policy row, or with
`enforcement: off`, existing non-strict behavior remains unchanged.

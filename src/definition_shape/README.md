# Gated definition shape spike

`crate::definition_shape` is available only under `cfg(test)` or
`v2-kernel-probe`. Nothing exposes these tools through hosted MCP.

`TypedShape::from_bytes(bytes, kind)` validates the definition, derives its
pin from the exact bytes, and retains native field types alongside JSON types.
The IR contains no JSON Schema nodes. Refinement remains metadata; fields are
never inherited and versions are never mapped.

The schema emitters cover `{home, fields}` create inputs, `{id,
expected_revision, fields}` revision patches, scalar equality/link/pagination
query inputs, and record outputs containing the retained pin. Patches replace
nested values rather than deep-merging them. Top-level optional nulls mean
absence; nested nulls are refused. Legacy unknown null fields remain accepted.

The IR names the rules that require kernel validation:

- `scope_adoption`: adoption and permission depend on current workspace state.
- `identity_uniqueness`: uniqueness is workspace-wide per family and kind.
- `revise_state`: identity immutability, merged-field validation, CAS and the
  record's retained pin require record state.
- `integer_spelling`: JSON Schema accepts integral decimals/exponents, while
  the kernel requires an i64/u64 representation. The schema still emits the
  representable numeric bounds.
- `temporal_grammar`: `native-time` and `native-date` are format annotations,
  not assertions. Chrono's RFC3339 parser (and exact calendar-date round trips)
  remain authoritative rather than substituting a different format checker.
- `value_budget`: JSON Schema cannot count UTF-8 bytes, normalized encoded
  bytes or aggregate value nodes. The kernel also checks value depth.
- `raw_json`: duplicate keys, numeric precision and raw byte limits must be
  checked before JSON values exist.

The compiler emits the frozen `/6` text formats as patterns and `max_length`
as Unicode code-point `maxLength`. Required blank-text rules are patterns too.
Definition prose does not become extra validation (for example, Outcome
magnitude pairs and date-window ordering are not kernel rules).

`typed_tools_for(db, principal, scope)` uses `describe_world_as` adoption groups.
`scope: Some(home)` restricts discovery to that exact visible home; `None`
uses all visible homes. Create homes are the corresponding Edit subset.
Version suffixes appear when multiple adopted pins of a family remain in the
selected discovery set. Disabled families retain only query tools. Names are
sanitized for tools; an ambiguous sanitized-name collision fails explicitly.

`dispatch_typed_tool` resolves the tools again, validates input and calls the
existing kernel paths. Creation rechecks the advertised pin in the same write
transaction as creation. Revision loads the record's own definition before
validating the patch, and reports `validated_pin`, `tool_pin` and
`used_record_pin`. Published revise fields accept the union of per-pin patch
schemas for every caller-visible retained version containing the kind. Dispatch still checks
the precise record pin. Query filters include scalar fields from currently
visible adoptions and retained pins of caller-visible records, with alternatives
for differing field types. Unknown field names accept scalar values without
advertising hidden names. Other scalar comparisons remain accepted, as in the
kernel, even when they match nothing. Original structured field bytes reach the
kernel, preserving its duplicate-key, precision and byte checks. Queries use
`query_as`, span versions and visible homes, and enrich hits with authorized
record reads for
`pin` and `revision` (these are not supplied by the kernel query hit itself).
Those record reads use separate snapshots from the query page: returned fields
and revision come from the authorized record read, while cursor membership comes
from the original query. A future atomic query receipt needs a kernel API change.
Kernel errors propagate without rewriting.

Tool descriptions include declared link targets, directions and cardinalities,
and incoming links from other visible kinds. Query predicate enums are hints in
an `anyOf` with a string fallback: `query_as` accepts arbitrary predicate strings,
including ones with no matching edges. Incoming queries use `direction: in`;
`either` permits outgoing admission and does not create symmetry. Cardinalities
remain declaration metadata. `/1` link metadata is opaque and is not emitted;
unrecognized `/1` kind entries are skipped as in generic describe.
Legacy `/2` and `/3` targets use only
`primary_type` and `kind`; newer target-selector extensions are ignored.
Linking stays on the generic `link` subcommand.

`tools` returns `{"rules": [...], "tools": [...]}`. Shared rules appear once in
`rules` (exported as `TYPED_TOOL_RULES` for Rust consumers). Each tool description
starts with the definition and kind prose, then field descriptions, identity
rules and compact link phrases. Only applicable shape limitations follow;
revise includes limitations from every visible pin in its patch union. When
identity rules differ across that union, revise describes each pin
(`family@version#digest`) separately; the current pin's field identity does not
make that field immutable on older records with record identity. Query
filters do not acquire create/patch field restrictions. `typed_tools_for` still
returns the descriptor vector; Rust callers pair it with `TYPED_TOOL_RULES`.

Build `examples/v2_contract.rs` with `v2-kernel-probe`. The harness adds:

```sh
v2_contract --db world.db tools --as acct:alice
v2_contract --db world.db call create_lab_Specimen --as acct:alice \
  '{"home":"HOME_ID","fields":{"accession":"S-105","site":"North Ridge","collected_at":"2026-10-18T12:00:00Z"}}'
```

`call` also supports `--json <file|->`; both commands accept `--scope <home>`.
Existing generic commands keep their syntax.

The differential test loads all standard definitions and all four Slice 2
ontologies, plus synthetic witnesses for every retained language and `/6`
format. It compares the create schema to the existing `validate_record_fields`
through a test-only observation helper. Only schema acceptance paired with
kernel rejection can be excepted, with a concrete spelling, temporal-grammar
or budget witness and a corresponding IR rule. All other disagreements fail.

SQL emission, hosted exposure, v1 changes and the fresh-agent comparison trial
are outside this four-increment implementation.

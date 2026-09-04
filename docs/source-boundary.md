# Native source boundary v2

The private upstream and public target carry different views of the versioned
source boundary. The upstream selection authority declares canonical `source`
paths and optional public `target` paths. Publication deterministically derives
`native-boundary.json`, a target-native receipt containing only paths that
exist in the public repository. Globs are unsupported and selectors are unique
and non-overlapping.

Validate this generated candidate as an exact clean target:

```sh
python3 scripts/release/validate_source_boundary.py \
  --manifest native-boundary.json --repo . --mode target \
  --emit-selection /tmp/native-selected-source.json
```

Keep emitted evidence outside the candidate. Each row records `source_path`,
`target_path`, mode, and SHA-256 digest in bytewise target-path order. Target
mode inventories every local file other than `.git`, validates projected target
paths and bytes, and refuses undeclared output.

Maintainers preparing a candidate use `--mode upstream` in the private source
checkout. Upstream mode permits only the exact fingerprinted transition edges in the
manifest. Each edge binds its source and target components and paths, detector
kind and evidence, successor task, and reason. A stale edge or one new edge is
a refusal. The digest is asserted both by the manifest and the v2 validator,
so recomputing the manifest field cannot grow the reviewed set. Every public
source selector must match a tracked regular or executable Git blob. Symlinks,
submodules, unresolved index stages, and unsupported dynamic Rust compile-time
includes fail closed. Every exclusion must also match a tracked entry. Upstream
validation refuses any index/working-tree content or mode mismatch before it
reads source, so staged dependency edges cannot be masked by safer unstaged
bytes. Cargo explicit and implicit build scripts, path dependencies, patches,
replacements, workspace membership/default membership, targets, and
target-specific dependency tables are parser-backed inputs to the edge graph.

`target` mode is the clean-root authority. Its manifest has the canonical empty
debt array/digest and no upstream exclusions. Component reasons, source-to-target
mappings and upstream-only execution references are also omitted rather than
made visible at the publication boundary. It inventories the actual
filesystem with `lstat`, including ignored and untracked files, while excluding
only `.git`; undeclared files, symlinks, and other non-regular entries are
refused. The extraction and publisher successor tasks are responsible for
reaching and invoking that mode. Materialisation copies selected source bytes
to target paths with recorded modes and no textual rewriting, except that it
replaces the private selection authority with the deterministically derived
public receipt. A mapped source path that leaks into the receipt is refused.

The local candidate preparer retains two operational mode labels over the same
complete wrapper inputs. `public-release` additionally requires the root
governance documents and runs the public candidate checker. Neither mode
patches repository identity strings. Both pass target, held-path, credential,
mode, and digest checks.

`runtime_services` is the intended public composition. A binary service's ID
and entrypoint must exactly match a `[[bin]]` in the selected public Cargo
workspace; declared features must exist in the root Cargo feature surface. The
current hosted `serve`/`operator` Docker composition,
provider adapters, and Docker/entrypoint files are held, so the manifest makes
no claim that today's container is public.
Public dependency permissions are an exact versioned matrix and can name only
public components.

`web/generated` is public tier-1 source: `kinds.ts` and `tools.d.ts` are
committed products of the public generators `src/bin/kind_types.rs` and
`src/bin/tool_types.rs`. A public generator may not write into a held tree.
Held consumers may read these public outputs, which needs no debt edge.

`src/mcp/executor_prototype/candidate-audit.public.generated.json` is the same
shape in the other direction. The public executor prototype needs the audited
candidate descriptors and the seven audit-row fields it deserializes, but the
full audit at `docs/evals/mcp-executors/candidate-audit.generated.json` is held
operated evidence, so the public source cannot compile it in. The committed
public file is a projection of exactly the fields the Rust structs read, with
the `descriptors` arrays copied verbatim in source key order because the
runtime re-asserts `serde_json::to_vec(&descriptors).len()` against the audited
`descriptor_bytes`. Its producer and input are held upstream provenance; they
are not runnable from this candidate. The resulting selected include is
intra-component.

The optional MCP Apps exception contains exactly two committed, self-contained
HTML bundles. Both record `npm run build` as producer and drift command. The
upstream authority governs execution evidence; the public receipt records only
the reproducible command and exact artifact set. No other `web/mcp-apps/dist`
file is selectable.

Run the mutation fixtures without a Rust build:

```sh
python3 -m unittest scripts.release.test_source_boundary
```

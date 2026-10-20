# Core delivery acceptance

`fixtures/core-source.html` is a test-only plain HTML/JS source. Its tests use
`web/apps/src/apps/template/declaration.json`'s existing param-less
`records.recent` snapshot, without React, a renderer, imports or new grants.
Reusable source-template registration is separate.

From the repository root:

```sh
mkdir -p .review
NATIVE_KIT_DELIVERY_EVIDENCE_DIR="$PWD/.review" cargo test -p native-artifact-html --lib kit_delivery
node --test packages/alpha-tab-kit/test/core-delivery.test.mjs packages/alpha-tab-kit/test/presentation-bridge.test.mjs
NATIVE_KIT_DELIVERY_REAL_HTML="$PWD/.review/real-core-delivery.html" node packages/alpha-tab-kit/test/core-delivery-browser.mjs
```

The required `test` job in `.github/workflows/ci.yml` runs artifact-html unit
tests after root dependency compilation, emits fresh custody evidence, installs
Playwright from the workbench lockfile and its Chromium, then runs the standalone
proof. The test-gate verifier checks ordering and refuses conditional/soft-fail
steps, missing evidence wiring, or compile/list substitutions. Node-only fixture
jobs do not invoke Cargo.

The explicit browser proof requires Playwright and Chromium. A cached install
can be selected with `ALPHA_TAB_KIT_PLAYWRIGHT` (directory containing
`node_modules/playwright`) and `ALPHA_TAB_KIT_CHROMIUM` (executable path). Use the
normal system library search path, or `LD_LIBRARY_PATH` for a cached sysroot.
The proof fails if its browser or Rust evidence is unavailable; it never skips.

The emitted evidence is actual legacy ticket custody HTML. The browser proof
first compares it byte-for-byte with fake injection, then executes it in a
sandboxed child with the real MessagePort bootstrap. This proves composition
and bridge behavior, not a deployed hosted-service/held-runtime acceptance.

Production retains only admitted 1.0.0. Test-only A/B ownership fixtures derive
an independent B factory identity in memory, rehash its manifest/catalog, and
never rewrite canonical releases or mirrors. They prove selection, pending
custody, new-session updates, rollback and source restoration independently of
author history; they do not claim an admitted production 1.0.1 exists.

Real API: `KitDelivery::from_selector` accepts the closed
`native.app-kit.selector.v1` shape `{schema, selections: [{major, version}]}`;
`LaunchDelivery::with_kit(config, delivery)` supplies immutable host ownership.
`with_kit_selection` creates another immutable owner while retaining the same
ticket/Body stores, so updates and rollback preserve pending custody.
Legacy constructors/free launches share the admitted default. `Launch` and
`VerificationHarness` carry optional `kit_release`; `PreparedLaunch::kit_release`
returns the retained metadata. Producer preview includes
`preview.launch.kit_release` only when selected. All use the exact kit release
shape: version, major, layer, factory, bridge, js_sha256, types_sha256.

Fake API: `createKitDelivery(inventory, selector)` admits a copied immutable
owner; `injectBridge(source, origin, delivery?)` and `startFakeHost({kitDelivery})`
use it. The Node-only returned host can select another admitted owner for the
next session. `/frame?session=N` retains prepared bytes and performs no lookup;
`reload()` requests a new session and logs its exact selected metadata. The
bounded fake session inventory retains at most 32 sessions. No factory or
lifecycle disposal is installed on the browser global.

Source-only starter acceptance uses the HTML blocks extracted directly from
`src/mcp/guides/app-builder-1.0.0.md`, including their declarations. Run:

```sh
NATIVE_KIT_DELIVERY_EVIDENCE_DIR="$PWD/.review" cargo test -p native-artifact-html --lib source_starter_guide_bytes
NATIVE_STARTER_REAL_HTML="$PWD/.review/real-starter-0.html" node packages/alpha-tab-kit/test/source-starters-browser.mjs
```

The explicit proof requires Chromium, runs both starters in the fake host, and
executes the reader through fresh Rust ticket custody. It is not the live
MCP-only author acceptance, which remains a separate human-assisted run.

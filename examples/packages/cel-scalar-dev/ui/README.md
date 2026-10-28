# Installed local package reader proof

This plain HTML app invokes the existing server operations through the real
`window.native` bridge. It contains no evaluator and declares no effects. It is
outside the shipping app catalog. The host must explicitly opt into
`package-cel-dev`; this is local development under interim P1, not hosted
activation or guest containment.

The development server's authenticated app-list response carries the closed
`native.package-cel-dev.reads/1` contract only with `package-cel-dev` enabled.
The parent shell uses that current server fact to admit exactly
`describe_package_operations` and `call_package_operation` as reads. App messages
cannot opt in. Shipping `APP_CALL_TOOL_NAMES` and `APP_EARLY_READS` are unchanged;
the driver waits for ordinary workspace verification before calling. The
installed browser driver exercises discovery, compute, disable refusal,
retained data/history and an explicit retry after re-enable. Independent fresh
agent acceptance is a separate proof; the writer's stdio diagnostic is not it.

Version 0.2.0 accepts only a record ID. **Discover for record** calls
`describe_package_operations` with `{record_id}`; the user chooses an operation
from the returned canonical namespace/package identities and explicitly clicks
Compute. No namespace is inferred from a family, and discovery never computes.
The server requires record/home View and current authenticated app admission.
It resolves the nearest verified package selections, including inherited
selections and tombstones, and filters by exact record pin/kind, available pure
provider, and declared plus acknowledged reads. It rechecks the record revision,
selection events, membership, authority and app consent/source before delivery.
Drift discards metadata and requires an explicit retry.

Discovery returns a complete deterministic list or refuses atomically. The
development bounds are 32 candidate package identities before manifest loads,
the kernel's 100-level ancestor bound, and 64 KiB of serialized discovery data.
It accepts no executable/evidence and reads no operation source field. These
are discovery bounds, not changes to CEL/P1 admission. The existing exact
`{scope_home,namespace,name}` describe selector and response remain supported.
The descriptor is metadata, not lasting authority to call; each call performs
its own checks and returns its current server receipt.

The installed browser proof requires operator-supplied matching development
`serve` and `v2-browser-fixture` binaries, embedded workbench/shell/catalog assets,
and private fixture infrastructure from the same source revision, explicitly
built with `package-cel-dev`. This public snapshot does not provide a
self-contained build of that host. With those prerequisites available, build
the public stdio/CLI tools and prepare the local proof:

```sh
cargo build -p native-ce --features package-cel-dev --bin mcp-stdio --example v2_contract
node web/workbench/scripts/check-playwright.mjs
node examples/packages/cel-scalar-dev/ui/prepare.mjs
node examples/packages/cel-scalar-dev/ui/host.mjs
```

A changed HTML bundle requires a **new disposable fixture** and real consent
on both sides of the verified import. Preserve an earlier accepted fixture and
its receipts; do not resume it to replace its installed bytes with version 0.2.

The prebuilt host must expose the explicit development capability; supplying
binaries does not activate it in shipping builds. The host script fails on
occupied ports (default4495/4496). All state is synthetic,
under an owned `/tmp/native-v2-browser-package-ui-*/fixture`. It never accepts a
source workspace database or touches the running Native node.

When the host prints `v1-preview-adopt`, run in another terminal:

```sh
node examples/packages/cel-scalar-dev/ui/browser.mjs target/package-ui-live v1
```

This signs in normally and clicks the actual shell Preview and Adopt controls.
The fixture then closes the v1 server, completes/verifies the frozen import and
activates the verified app source. No adoption SQL is used in this proof path.
It creates an ordinary, explicitly shared proof home: root-wide package
adoption correctly refuses dependency traversal across unrelated private homes.
When the host prints `v2-ready`:

```sh
node examples/packages/cel-scalar-dev/ui/browser.mjs target/package-ui-live v2
```

A different member performs an ordinary pending install and real Preview →
Adopt against that frozen source. The app describes and calls through its own
bridge. The curator CLI disables the computation package, the next browser
call refuses, data/history remain readable, and a new selection plus explicit
click succeeds. This does not claim browser coverage of mid-computation races.

The driver saves bounded screenshots, selected source/install pins and server
receipts. Files named `*.private.*`, connection state, cookies and raw server
logs are local credentials/diagnostics: do not publish them. Share only reviewed
receipt fields/screenshots. The host stays alive for a separately commissioned
fresh consumer; parent owns its eventual stop and cleanup.
`host.mjs <output> --resume` verifies and reopens only this proof's retained
ready disposable fixture. It preserves consent and data and does not rerun a
computation. After a controlled host restart, `browser.mjs <output> v2
--existing-consent` checks the retained real Preview → Adopt evidence against
the current install generation and source/declaration pins before reusing it.
The local debug host uses the existing browser harness's 64 MiB
worker-stack setting; this is not a change to P1 or a containment claim.

The browser receipt retains bounded console diagnostics, including shell CSP
and sign-in notices. The workflow asserts HTTP results/refusals, exactly three
computation requests for three explicit clicks, and no uncaught page exceptions.

The consumer can connect its MCP client through:

```sh
node examples/packages/cel-scalar-dev/ui/agent.mjs target/package-ui-live/connection.private.json
```

That wrapper supplies connection/authentication only and no operation-specific
instructions. It requires Linux with `prlimit` from util-linux and launches only
its stdio child with a fixed 64 MiB soft and hard process stack limit. This local
debug binary uses a current-thread Tokio runtime. The first independent consumer
attempt fatally overflowed the main thread in ordinary `get_record`, before
computation. A controlled disposable database snapshot reproduced that failure
with an 8 MiB process stack; the unchanged binary completed the same record read
and ordinary catalog query with the explicit 64 MiB process limit.
`RUST_MIN_STACK` was unset in both controls: it affects spawned Rust threads,
not the existing main thread. The exact deep frame contributor is unqualified;
the wrapper refuses if it cannot establish that configuration. It does not retry
failed requests or change the retained host's limits. This is a required local
development launch configuration, not a production runtime fix or safety claim.

A script client is a transport check, not independent fresh-agent acceptance.
The first consumer failure remains an acceptance gap until a separate fresh
attempt succeeds. Preserve the UI receipt's exact record revision/package/source
identity for the parent to compare with that agent's receipt.

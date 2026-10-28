# Local package CEL development proof

Start with the [complete authoring guide and copyable template](AUTHORING.md),
including numeric versions, embedded-definition bytes/digest and the full
new-home record-discovery lifecycle. All linked sample files are explicitly
available as structural authoring references in a checkout.

These two ordinary package manifests supply their own CEL logic.
[Quote](quote.package.json) computes a discounted integer amount;
[Dispatch](dispatch.package.json) checks a prepaid parcel's eligibility.
Neither requires a package-specific Rust provider. The JSON files are
package-authored fixtures, including exact definition bytes and their SHA-256;
they are not independent-author acceptance.

This is an explicitly opted-in local development proof. Its generic MCP and
installed-v2-app read routes are available only with `package-cel-dev`. It adds
no hosted activation, production validator or production resource guarantee.
The development runtime uses an import-free checked CEL Wasm guest; its targeted
containment proof is not production qualification.
The explicit `package-cel-dev` feature is required; `v2-kernel-probe` alone
never admits, executes or advertises this provider. P1 remains interim. The
parked general callable/advisory rules work remains parked; the language and P1
are unchanged. See the [guest build/runtime notes](../../../crates/package-cel-host/README.md).

## Run

From the repository root, build the trusted guest before the generic CLI.
The explicit guest step has no Native/host dependency and uses the root lock:

```sh
rustup target add wasm32-unknown-unknown
python3 scripts/build-package-cel-guest.py
cargo build -p native-ce --example v2_contract --features package-cel-dev
target/debug/examples/v2_contract --db target/cel-demo.db init --label Admin --binding demo:admin
target/debug/examples/v2_contract --db target/cel-demo.db --as demo:admin package-install --json examples/packages/cel-scalar-dev/quote.package.json
target/debug/examples/v2_contract --db target/cel-demo.db --as demo:admin package-adopt --scope kernel:root --ack-reads '["record:view"]' --json examples/packages/cel-scalar-dev/quote.package.json
target/debug/examples/v2_contract --db target/cel-demo.db --as demo:admin describe
target/debug/examples/v2_contract --db target/cel-demo.db --as demo:admin create --family example.sales.quote --kind quote --home kernel:root --json examples/packages/cel-scalar-dev/quote.record.json
```

Save the returned record id in a JSON file, for example
`target/cel-call.json` containing `{"record_id":"<returned id>"}`, then:

```sh
target/debug/examples/v2_contract --db target/cel-demo.db --as demo:admin package-call --namespace example.sales --name quote --operation compute --json target/cel-call.json
```

The result's value is 900. Repeat install/adopt/create/call for
[dispatch.package.json](dispatch.package.json), [dispatch.record.json](dispatch.record.json), namespace `example.shipping`,
family `example.shipping.dispatch` and kind/package `dispatch`; its value is true.
The CLI smoke test performs both flows against a fresh disposable database.

## Development transport

A development KernelV2 registry registers `describe_package_operations` and
`call_package_operation`, also exposed as read operations under `records_read`
and in the request-local executor catalog. Both routes are absent in an ordinary
`v2-kernel-probe` build and unavailable on the ordinary SQLite engine. They
accept identifiers only. Record-only discovery avoids guessing a package
identity from its record family (choose the returned canonical package/operation):

```json
{"executor":"records_read","operation":"describe_package_operations","arguments":{"record_id":"<record id>"},"format":"json"}
```

The existing exact home/package selector remains supported:

```json
{"executor":"records_read","operation":"describe_package_operations","arguments":{"scope_home":"kernel:root","namespace":"example.sales","name":"quote"},"format":"json"}
```

```json
{"executor":"records_read","operation":"call_package_operation","arguments":{"namespace":"example.sales","name":"quote","package_operation":"compute","record_id":"<record id>"},"format":"json"}
```

The transport resolves the authenticated credential; no actor, executable,
validation receipt or app identity is accepted in these argument objects.
Existing installed `native.app.v2` apps can use the same read route through their
host bridge. The host supplies package/version/install attribution and live
consent/source admission; the route grants no app installation/adoption or
lifecycle management. An installed UI demonstration remains a separate proof.

## Author contract

An operation using `host.cel-scalar-dev/1` carries an `executable` object with
`language: "cel-subset@1"`, `profile: "native.cel-scalar-dev/1"`, an exact
`expression` string, and a list of `{"name": "...", "type": "..."}` bindings.
Types are `int`, `double`, `bool` and `string`; no nullable or untyped bindings.
The existing text source field holds a JSON object matching those names and
types exactly. Duplicate/extra/missing keys, nested values and null bindings
refuse. The declaration and its ordering are digest-covered; expression
whitespace is significant.

The host-owned development profile limits:

- At most 16 bindings; unique ASCII identifiers, at most 64 bytes each.
- Expression at most 1,024 UTF-8 bytes; source JSON at most 16,384 bytes.
- Strings at most 1,024 UTF-8 bytes. Numbers are finite and within
  ±9,007,199,254,740,991; integer bindings require JSON integers.
- Checked expanded AST depth at most 16 and at most 128 nodes; no
  comprehensions. These checks use the existing engine's parsed measures.
- Output is a JSON scalar (including null), with the same numeric/string caps
  and at most 8,192 serialized bytes. Lists, maps, bytes and time values refuse.
- Unmodified P1 checking/evaluation budgets still apply. Admission and
  invocation share two process-local blocking-worker slots; excess requests
  receive a retryable busy message without joining a waiting queue. Cancellation
  retains the slot until its blocking work ends.

These are additional restrictions for this development profile, not changes to
general CEL or rule admission. Bounded inputs and metered evaluation do not
establish a production parser-memory or native-process isolation guarantee.

Source/binding errors return `invalid_bindings`; evaluation errors return
`evaluation_failed`; inadmissible results return `invalid_result`, all under
`result.error` with a bounded message. Successful output has `result.value`
and `result.error: null`. Authority, activation, definition pins, invalid
declarations and worker failures remain outer call refusals.

There are two source-size boundaries. Once the generic package-call path has
loaded the source, the 16 KiB development binding cap returns
`invalid_bindings` with a receipt. Before loading or hashing, the existing
generic 256 KiB materialization guard checks the stored JSON representation's
byte count (including string quotes and escaping). Crossing that guard is an
outer refusal with no receipt. The development profile does not widen it.

The optional receipt `execution` identifies the checked guest development
adapter, actual P1 policy/interim flag, language/profile and expression digest.
Its `guest` metadata pins actual ABI/module/source/build digests, Wasmtime
runtime/configuration/limits, consumed fuel and phase. On binding failure it
does not claim evaluation occurred. Legacy providers omit execution metadata.
The ABI request is capped32KiB after encoding; oversized/heavily escaped frames
refuse outside the result/receipt envelope, independently of the16KiB binding
and256KiB outer materialization guards. Compilation/native host allocation is
outside guest caps. No native fallback or automatic retry is available.

## Upgrade and disable

To change logic, increment the package version, change its executable expression
and explicitly install/adopt the new manifest. Keep the embedded definition bytes
unchanged for this milestone: existing records retain their definition pin and
compute under the newly selected package logic. Changed definition pins refuse
rather than silently reinterpret old records. The receipt identifies each call's
selected package and source revision.

`package-disable --scope kernel:root --json <selected manifest>` stops calls.
Ordinary record reads and history remain available. Calls release their initial
read transaction before computation. Before delivery the server rechecks current
membership, credential binding, View on record and home, definition pin,
package version/digest and selection event, acknowledged reads, and record
revision/input digest. Disable followed by re-enable still changes the selection
event. Installed apps also recheck their host-asserted installation generation,
source/declaration pin, frozen source witness and consent epoch. Existing installs
keep their frozen source: editing the artifact head alone does not select new app
bytes. Any admission failure or drift discards the result
with `result discarded; explicitly retry`; the server never automatically reruns.
These are delivery-snapshot checks, not a lease over subsequent network delivery.

## Focused checks

The named development CI workflow runs the shipping refusal and explicitly
opted-in scalar/CLI subsets. Default and supported-product feature closures
remain unchanged. Inert declarations and canonical package identity stay
readable without the runtime; retained definitions, data and history can still
be inspected, replayed and disabled.

```sh
cargo test -p native-ce --features v2-kernel-probe --lib package_cel_dev::shipping_tests::
python3 scripts/build-package-cel-guest.py
cargo test -p native-package-cel-wire -p native-package-cel-guest -p native-package-cel-host --lib
cargo test -p native-ce --features package-cel-dev --lib package_cel_dev::runtime::tests::
cargo test -p native-ce --features package-cel-dev --lib development_package_
cargo build -p native-ce --example v2_contract --features package-cel-dev
cargo test -p native-ce --features package-cel-dev --test kernel v2_contract_smoke_cel_scalar_packages
```

Adding the optional executable field requires explicit absent-field initializers
in three retained relationship sources. Their pre-extension source snapshots,
source checksums, provider pins and manifest bytes are retained. A compatibility
test checks that the absent initializer is the only source difference.

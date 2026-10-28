# Optional checked-CEL guest development runtime

Root `package-cel-dev` is the only opt-in. Default and ordinary v2 builds do
not compile this host, require a Wasm target/artifact, or run a guest verifier.
The host normal/build dependency graph excludes CEL. The wire crate contains
only closed serialization and shape/byte checks; CEL is in the guest and native
parity tests. The older standalone stages remain historical reviewed evidence.
No hosted activation, effects, user Wasm upload, new language or P1 change.

From repository root, read `AGENTS.md` before Cargo. Use two jobs, disable
incremental and retain the12GiB guard. These commands do not build held assets:

```bash
rustup target add wasm32-unknown-unknown
python3 scripts/package-cel-guest-guard.py guest-build python3 scripts/build-package-cel-guest.py
python3 scripts/build-package-cel-guest.py --verify-only
python3 scripts/package-cel-guest-guard.py guest-tests cargo test -p native-package-cel-wire -p native-package-cel-guest -p native-package-cel-host --lib --locked
RUST_MIN_STACK=67108864 python3 scripts/package-cel-guest-guard.py package-tests cargo test -p native-ce --features package-cel-dev --lib package_cel_dev::runtime::tests:: --locked
```

The prescribed build uses `cargo rustc -p native-package-cel-guest --lib
--crate-type cdylib --target wasm32-unknown-unknown --locked`. The guest's normal
library target gives native tests an ordinary Cargo owner. It does not depend
on Native or the optional host. No host build script invokes Cargo: the
explicit guest build must finish before compiling the optional host. All
integrated packages resolve through the root lock; no older standalone module
is substituted. Guest compilation does not activate Native's development
feature or create an artifact dependency cycle.

`target/package-cel-guest/build.json` pins all guest/wire/CEL crate source files,
root manifest/lock, toolchain/configuration, exact target/flags/crate type, ABI,
module digest and import/export inventory. The builder selects the Wasm artifact
from Cargo's actual compiler-artifact message, checks unchanged inputs across
the build, and refuses imports/unexpected exports. The host build verifier
refuses missing/stale pins or changed module bytes and embeds the verified byte
buffer as a read-only native data object inside a target-aware static archive.
No generated Rust source or dynamic include macro is used. Build pins become
small `cargo:rustc-env` constants; the fixed-size extern array has the verified
module length. A single local unsafe reference relies on the strong, uniquely
prefixed static symbol and build-time object readback of exact bytes, extent,
alignment and target. Startup rehashes the linked bytes against the verified
module pin and checks the ABI/source/root-lock/build identity bundle before
compiling. This is consistency of trusted compiled pins, not runtime source
attestation or defense against a substituted compiler/linker. Source/lock
freshness is checked at build time, not by reading mutable files at runtime.
ELF/Linux, Mach-O/macOS and COFF/Windows encodings are supported for little-endian
x86_64/aarch64 only; unsupported targets fail explicitly. Encoding/readback tests
cover all six combinations; actual execution/linking here is Linux x86_64 only.
Runtime validation additionally checks exact
export types, ABI version and actual stack-first layout before use. There is
no opaque committed artifact or runtime module path. Cross-machine byte
reproducibility is unqualified; receipts identify the actual compiled module.

Build record v2 resolves a concrete compiler once: explicit `--compiler` (host
build.rs supplies Cargo's `RUSTC`), then `RUSTC`/`CARGO_BUILD_RUSTC`, otherwise
rustup's selected compiler. That same executable is queried with `-Vv` and bound
to guest Cargo via environment and explicit `build.rustc` override. Guest-only
wrapper settings are disabled; parent host Clippy/cache wrappers remain separate.
Prescribed extra target flags use `CARGO_ENCODED_RUSTFLAGS`, overriding inherited
extra flags. Applicable Cargo config file hashes are recorded and checked;
configuration includes, compilation-control `[env]` entries, bootstrap and guest dev-profile
environment overrides refuse rather than guess. Cargo-generated profile/target
arguments are not represented as an exhaustive rustc argv record. These are
trusted-build consistency checks, not compiler/linker attestation or protection
against mutable/hostile tools. Fresh CI guest build/verification remains required.

The verifier reads each manifest into one byte buffer, parses/validates it, and
carries that buffer's digest together with verified module bytes into embedding
and receipt generation. Concurrent mismatched manifest/module replacement may
refuse, but cannot associate a later unvalidated manifest hash with prior bytes.

ABI `native.cel-scalar-guest/2` keeps four typed exports and the checked unsigned
32KiB-input/8192-byte-output boundary. Explicit Check takes declarations only:
no default/invented values and no evaluation. Evaluate carries the same
immutable declaration and raw source JSON, preserving duplicate keys for guest
refusal. The guest enforces byte/count/name/type/range/string restrictions,
checked CEL parsing, parsed AST restrictions, closed binding JSON and scalar
results. Host checks are structural/byte/resource checks, never native CEL.
The existing16KiB source development cap remains enforced inside the guest.
An encoded request exceeding32KiB refuses outside the result/receipt envelope;
this can include large or heavily escaped source, even below the generic
256KiB stored-field guard. Nothing automatically retries or falls back native.

Two fixed8MiB workers have immediate nonqueued admission. A bounded oneshot
reply owns its cancellation ticket: dropping the awaiting future cancels but
cannot free the job's slot before decoding and actual Store drop. Each Store
gets fuel, memory/table limits and epoch callback before instantiation. The
10ms ticker remains alive until worker shutdown joins, then is joined. The
1000ms monotonic deadline starts at slot admission, with checks after Store
drop and before reply delivery. A scoped Host supports explicit shutdown; the
Native application singleton owns one compile/startup and lives for the
process. Concurrent initial startup refuses Busy; cancellation of the first
waiter does not abandon/repeat compilation. Initialization failure has no
native fallback. Compilation and other native allocations are outside guest
resource caps; no whole-process allocation or hard native wall-time claim.

Kernel Manage preflight/writer recheck and call delivery fences remain in
place. The guest receives only a declaration/source, no DB, caller credentials,
clock/network or host callback. New execution receipt metadata records actual
ABI/module/source/build pins, runtime/configuration/limits/fuel/phase and actual
P1 policy/interim flags. Canonical package declaration bytes remain unchanged;
legacy providers still omit execution metadata. The development workflow
builds a fresh guest before host tests and reconciles all new package tests
against source; shipping feature-off read/replay/refusal stays separate.

Evidence remains targeted development evidence. Parity compares all fields of
the REDUCED protocol report (status, mode, policy/interim, scalar value/error),
excluding checked API caps/load cost/budget scope/cost/input cost. It is not full
checked-report accounting, parser-memory qualification, a full local gate pass
or production containment qualification. Existing UI/fresh-consumer acceptance
belongs to its original pins; it is not a new UI proof for this runtime.

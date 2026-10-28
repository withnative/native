# Author a local scalar CEL package

This is the complete **copyable scalar-template path**, not a schema for every
Native definition language or package provider. It uses unchanged interim P1
and requires an explicitly opted-in `package-cel-dev` development binary. It
adds no shipping/hosted activation or production safety claim.

All links below are relative **checked-out source** references. They do not
promise that a private upstream commit, raw GitHub URL or hosted public snapshot
is accessible. A source distributor must supply these files together.

The following samples are explicitly allowed to copy for **structure**; a new
author should choose its own identity, use case, bindings, expression and data:

- [Complete package](template/sample.package.json), [exact standalone definition](template/sample.definition.json), [record input](template/sample.record.json).
- Other complete package-authored fixtures: [quote package](quote.package.json), [quote record](quote.record.json), [dispatch package](dispatch.package.json), [dispatch record](dispatch.record.json).
- [Provider limits and refusals](README.md#author-contract), [guest build/runtime](../../../crates/package-cel-host/README.md), [installed-app/stdio launch notes](ui/README.md).
- [Generic public CLI usage](../../../examples/v2_contract.rs) (leading documentation comment).

The quote/dispatch fixtures are not independent-author acceptance. The separately
commissioned greenhouse author proof supplies that provenance; UI and fresh-agent
proofs establish consumption separately. Copying a template proves neither.

## Complete envelope and identity rules

Use ordinary UTF-8 JSON, with no duplicate object keys. The actual canonical
loader is authoritative; this guide deliberately provides a valid narrow shape
rather than a partial machine-readable schema advertised as universal.

| Location | Required fields for this scalar path |
| --- | --- |
| Package object | `format: "native.package-manifest@1"`, `namespace`, `name`, numeric `version`, nonempty `definitions`, `declared_reads: ["record:view"]`, nonempty `operations`. Omit `behaviour` and `surface` entirely. |
| Each definition entry | `family`, numeric `version`, `artifact_bytes` (a **string** containing the whole definition JSON text), `digest` (lowercase hex SHA-256 of that string's exact UTF-8 bytes). |
| Each operation | `name`, nonblank `description`, `provider: "host.cel-scalar-dev/1"`, `family`, `kind`, `source_field`, `reads: ["record:view"]`, `effects: []`, `executable`. |
| Executable | `language: "cel-subset@1"`, `profile: "native.cel-scalar-dev/1"`, exact `expression` string, `bindings` array of objects with exactly `name` and `type`. |
| Binding | Unique ASCII identifier (first character letter/underscore; later letters/digits/underscore), `type` one of `int`, `double`, `bool`, `string`. No default, nullable, nested or untyped binding. |

Every version here is a JSON **integer from 0 through 4294967295 (u32)**,
including the version inside the definition text. Use `1`, then `2` for a
logic-only package upgrade, **not** `"1.0.0"`, `"2"`, or a fractional number.
Package version and definition version are independent.

Namespace, package name and operation name are 1..128 ASCII bytes from
`[A-Za-z0-9._-]`, starting/ending with an alphanumeric. Use that same restricted
shape for the example's family, kind and field names. The operation's family must
match an embedded definition family, kind an entry's `token`, and source_field
that kind's declared `text` field. A package holds 1..16 definitions, at most one
revision per family, and 1..8 uniquely named operations for this path. Descriptions
are nonblank and at most1024 UTF-8 bytes. These bounds do not invite other
providers or any-record targets into the scalar template.

The canonical loader rejects extra package-envelope/operation/executable keys, noncanonical array
ordering or altered shapes rather than silently dropping them. Sort definition
entries by `(family,version,digest)`, operations by `name`, and declared reads
lexically; do not add duplicates. The executable binding order is retained and
digest-covered. JSON object-key order/outer formatting is immaterial to the
package's SHA-256-over-JCS digest. Expression bytes, binding order and the exact
embedded definition string **are** material. Do not compute the package digest
by hashing a pretty-printed file; use the identity returned by install/describe.
Same `(namespace,name,version)` with changed content is a collision: use a new
numeric package version.

## Complete embedded definition and source mapping

[The standalone sample](template/sample.definition.json) is a real `native.defn/3`
definition, with this entire shape:

```json
{
  "family": "example.scalar.sample",
  "version": 1,
  "interpreter": "native.defn/3",
  "primary_type": "ScalarSample",
  "kinds": [{
    "token": "sample",
    "description": "Copyable scalar source record structure.",
    "maturity": "current",
    "identity": {"mode": "record"},
    "fields": [{
      "name": "inputs_json", "type": "text", "required": true,
      "description": "JSON object encoded as text, matching executable bindings."
    }],
    "links": []
  }]
}
```

Keep these keys/values for this supported structural path, changing the family,
primary type label, kind token, descriptions and field name consistently as
needed. `primary_type` is a nonblank label; kind identity is per-record, not a
binding-field value. `fields` declares the required **text** source field; `links`
is empty. Other definition grammars/field types are outside this guide. The
standalone sample's actual whitespace differs from this display: hash the file,
not this fenced block. JSON escaping in `artifact_bytes` is the outer encoding
of a string, not base64, a filename or an embedded JSON object.

The package definition entry's family/version must equal the embedded envelope.
Its digest includes every UTF-8 byte, whitespace and trailing newline. After any
definition edit, re-embed and rehash the same bytes before installation (commands
below). A record created by `create --family ... --kind ... --home ...` receives
the currently selected definition revision pin from that home's adoption. Do
not put a guessed definition pin in record fields. Calls and discovery require
that exact pin/kind; a logic-only upgrade retains definition bytes/version/digest.
Changing definition bytes is a separate migration problem and refuses old pins.

The [record sample](template/sample.record.json) is `{"inputs_json":"{\"value\":7}"}`:
the outer object supplies a text field; the text decodes to a JSON object with
exactly the executable binding names/types. Supplying `{"inputs_json":{"value":7}}`
is wrong for this definition. `int` needs a JSON integer, `double` a JSON number,
`bool` an actual boolean, `string` a string; duplicate/extra/missing keys, null and
nested values refuse. Do not confuse the source field name with a binding name.

Operation `reads` is exactly `["record:view"]`; package `declared_reads` covers it.
Normal adoption separately acknowledges it with `--ack-reads '["record:view"]'`.
Declaration is not authority: caller needs ordinary membership/View on record
and home and adoption needs Manage. A descriptor is not a lasting call grant.

## Run the complete lifecycle with public tools

Run these Bash blocks **in order from the repository root, in the same shell**.
Requirements: Python3, Linux util-linux `prlimit`, and matching opted-in CLI/stdio
binaries. Either an operator supplies them (prebuilt onboarding) or build the
trusted guest and public targets using the [build instructions](README.md#run).
This flow needs no private held host, server, browser assets, SQL or fixture
infrastructure. Do not point it at any real or retained database.

```bash
set -euo pipefail
umask 077
CLI="${CEL_PREBUILT_CLI:-$PWD/target/debug/examples/v2_contract}"
STDIO="${CEL_PREBUILT_STDIO:-$PWD/target/debug/mcp-stdio}"
mkdir -p target
RUN="$(mktemp -d "$PWD/target/cel-author-XXXXXXXX")"
export RUN
DB="$RUN/synthetic.db"
BINDING="local:scalar-author"
cp examples/packages/cel-scalar-dev/template/sample.definition.json "$RUN/definition.json"
cp examples/packages/cel-scalar-dev/template/sample.package.json "$RUN/package-v1.json"
cp examples/packages/cel-scalar-dev/template/sample.record.json "$RUN/record.json"
# Authors may edit these NEW copies; keep all identity/source mappings consistent.
# Embed and hash exact bytes without text-mode newline normalization.
python3 - <<'PY'
import hashlib, json, os, pathlib
r = pathlib.Path(os.environ["RUN"])
p = json.loads((r / "package-v1.json").read_text())
b = (r / "definition.json").read_bytes()
d = json.loads(b)
p["definitions"] = [{"family": d["family"], "version": d["version"],
                     "artifact_bytes": b.decode("utf-8"), "digest": hashlib.sha256(b).hexdigest()}]
(r / "package-v1.json").write_text(json.dumps(p, indent=2) + "\n")
PY
"$CLI" --db "$DB" init --label ScalarAuthor --binding "$BINDING" > "$RUN/init.json"
cli() { "$CLI" --db "$DB" --as "$BINDING" "$@"; }
cli home --parent kernel:root > "$RUN/home.json"
HOME_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["home_id"])' "$RUN/home.json")"
cli package-install --json "$RUN/package-v1.json" > "$RUN/install-v1.json"
cli package-adopt --scope "$HOME_ID" --ack-reads '["record:view"]' --json "$RUN/package-v1.json" > "$RUN/adopt-v1.json"
cli create --family example.scalar.sample --kind sample --home "$HOME_ID" --json "$RUN/record.json" > "$RUN/create.json"
RECORD_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$RUN/create.json")"
printf '{"record_id":"%s"}\n' "$RECORD_ID" > "$RUN/record-selector.json"
```

The next block creates a local generic MCP client. Bootstrap **once** for this
synthetic logical author session, requesting the public `run_key: "new"` mint
sentinel with `format: "json"`. Save the actual returned
`structuredContent.run.run_key` and carry it on every later MCP tool call, reads
included, even across one-request child launches. MCP initialize/notifications
are transport messages, not bootstrap or tool calls. Do not bootstrap each
child, invent a key, or reuse a connected Native/other fixture session key.
The helper refuses absent/mismatched context before launching a child and refuses
a second bootstrap. It selects no package/formula, retries nothing and closes
only its own child. The bootstrap launch also captures the actual public
`tools/list` schemas; subsequent calls use the same returned key. Linux's64MiB
**process** stack is required for the current debug stdio request path;
`RUST_MIN_STACK` alone does not resize the existing main thread. Keep stderr and
receipts private. MCP initialization/tool calls do not replace CLI DB creation.

```bash
cat > "$RUN/mcp-call.py" <<'PY'
import json, pathlib, subprocess, sys
binary, db, binding, tool, arguments, context = sys.argv[1:]
context = pathlib.Path(context)
with open(arguments) as f:
    args = json.load(f)
identity = {"db": str(pathlib.Path(db).resolve()), "binding": binding}
if tool == "bootstrap":
    if context.exists():
        sys.exit("session already bootstrapped; retain its key, do not bootstrap again")
    if args != {"run_key": "new", "format": "json"}:
        sys.exit('bootstrap requires exactly {"run_key":"new","format":"json"}')
else:
    if not context.is_file():
        sys.exit("missing session context; run the explicit bootstrap block ONCE first")
    session = json.loads(context.read_text())
    if any(session.get(k) != v for k, v in identity.items()):
        sys.exit("session context belongs to another DB/binding")
    key = session.get("run_key")
    if not isinstance(key, str) or not key or key == "new" or key.startswith("new:"):
        sys.exit("session context lacks an issued run_key")
    if "run_key" in args:
        sys.exit("the helper carries run_key from context; do not override it")
    args = {**args, "run_key": key, "format": "json"}
p = subprocess.Popen(["prlimit", "--stack=67108864:67108864", "--", binary,
                      "--kernel-v2", "--account", binding, db],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(message):
    with context.with_name("mcp-requests.jsonl").open("a") as log:
        log.write(json.dumps(message) + "\n")
    p.stdin.write(json.dumps(message) + "\n")
    p.stdin.flush()
def response(request_id):
    for line in p.stdout:
        message = json.loads(line)
        if message.get("id") == request_id:
            if "error" in message:
                raise RuntimeError(message["error"])
            return message["result"]
    raise RuntimeError("stdio EOF before response")
try:
    send({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
        "protocolVersion":"2024-11-05", "capabilities":{},
        "clientInfo":{"name":"scalar-author-guide", "version":"1"}}})
    response(1)
    send({"jsonrpc":"2.0", "method":"notifications/initialized"})
    if tool == "bootstrap":
        send({"jsonrpc":"2.0", "id":2, "method":"tools/list"})
        schemas = response(2)
        context.with_name("tools-list.json").write_text(json.dumps(schemas, indent=2) + "\n")
    send({"jsonrpc":"2.0", "id":3, "method":"tools/call",
          "params":{"name":tool, "arguments":args}})
    result = response(3)
    print(json.dumps(result, indent=2))
    if result.get("isError"):
        sys.exit(1)
    if tool == "bootstrap":
        # format=json exposes the exact public structuredContent envelope.
        payload = result["structuredContent"]
        key = payload["run"]["run_key"]
        if not isinstance(key, str) or not key or key == "new" or key.startswith("new:"):
            raise RuntimeError("bootstrap returned no issued run_key; stop, do not invent one")
        context.write_text(json.dumps({**identity, "run_key": key}) + "\n")
finally:
    p.stdin.close()
    p.wait(timeout=15)
PY
mcp() { python3 "$RUN/mcp-call.py" "$STDIO" "$DB" "$BINDING" "$@" "$RUN/session.json"; }
printf '{"run_key":"new","format":"json"}\n' > "$RUN/bootstrap-arguments.json"
mcp bootstrap "$RUN/bootstrap-arguments.json" > "$RUN/bootstrap.json"
mcp describe_package_operations "$RUN/record-selector.json" > "$RUN/discovery-v1.json"
cat "$RUN/discovery-v1.json"
```

Choose the returned canonical package and operation explicitly. The following
block reads the MCP text-content JSON envelope and selects the **sole** sample
operation; it refuses an ambiguous list. For your own package, inspect the list
and choose the desired entry. Never derive namespace/name from a record family.

```bash
python3 - <<'PY'
import json, os, pathlib
r = pathlib.Path(os.environ["RUN"])
wire = json.loads((r / "discovery-v1.json").read_text())
# The current public tool returns the discovery object as JSON text content.
d = json.loads(next(x["text"] for x in wire["content"] if x["type"] == "text"))
choices = [(p, op) for p in d["packages"] for op in p["operations"]]
assert d["complete"] and len(choices) == 1, "choose one returned operation explicitly"
p, op = choices[0]
request = {"record_id": d["record_id"], "namespace": p["namespace"],
           "name": p["name"], "package_operation": op["name"]}
(r / "call-selector.json").write_text(json.dumps(request) + "\n")
PY
```

```bash
mcp call_package_operation "$RUN/call-selector.json" > "$RUN/call-v1.json"
cat "$RUN/call-v1.json"
# Make a logic-only numeric-version upgrade. Definition bytes remain untouched.
python3 - <<'PY'
import json, os, pathlib
r = pathlib.Path(os.environ["RUN"])
p = json.loads((r / "package-v1.json").read_text())
p["version"] = 2
p["operations"][0]["executable"]["expression"] = "value + 1"
(r / "package-v2.json").write_text(json.dumps(p, indent=2) + "\n")
PY
cli package-install --json "$RUN/package-v2.json" > "$RUN/install-v2.json"
cli package-adopt --scope "$HOME_ID" --ack-reads '["record:view"]' --json "$RUN/package-v2.json" > "$RUN/adopt-v2.json"
mcp describe_package_operations "$RUN/record-selector.json" > "$RUN/discovery-v2.json"
mcp call_package_operation "$RUN/call-selector.json" > "$RUN/call-v2.json"
cat "$RUN/call-v2.json"
cli package-disable --scope "$HOME_ID" --json "$RUN/package-v2.json" > "$RUN/disable.json"
# One explicit request; failure is expected. Inspect its outer refusal.
if mcp call_package_operation "$RUN/call-selector.json" > "$RUN/disabled-call.json"; then
  echo 'Expected disabled call to refuse' >&2
  exit 1
fi
cat "$RUN/disabled-call.json"
cli read --id "$RECORD_ID" > "$RUN/retained-read.json"
cli history --id "$RECORD_ID" > "$RUN/retained-history.json"
printf '{"ids":["%s"]}\n' "$RECORD_ID" > "$RUN/read-selector.json"
mcp get_record "$RUN/read-selector.json" > "$RUN/retained-mcp-read.json"
mcp get_history "$RUN/record-selector.json" > "$RUN/retained-mcp-history.json"
# An optional re-enable needs a new normal acknowledgement and explicit call:
cli package-adopt --scope "$HOME_ID" --ack-reads '["record:view"]' --json "$RUN/package-v2.json" > "$RUN/reenable.json"
mcp call_package_operation "$RUN/call-selector.json" > "$RUN/explicit-retry.json"
printf 'Retained synthetic author evidence: %s\n' "$RUN"
```

Compare `call-v1.json` and `call-v2.json`: successful tool text contains `result`
with `value` and `error: null`, plus a receipt identifying the actual selected
package version/digest, input/revision, expression and guest execution. The
record/definition pin is retained, while package logic/selection changes.
Disable changes selection, not record/history bytes. Do not interpret an MCP
`isError`/outer refusal as a result-domain success. Any authority/selection/input
or app-consent drift before delivery discards output and requires an explicit
retry; neither this client nor the server automatically recomputes.

## Limits, refusals and evidence boundaries

The development profile admits at most16 bindings, names up to64bytes,
1024 UTF-8 expression bytes,16384 source-text bytes,1024 UTF-8 bytes per binding
or result string; finite numbers within ±9007199254740991. Expanded checked AST
is at most128nodes/depth16, without comprehensions. Results are JSON scalars
(including null), not lists/maps/bytes/time values, at most8192 serialized bytes.
Unmodified P1 checked budgets apply. See the [full runtime limits and native
allocation exclusions](../../../crates/package-cel-host/README.md).

Malformed binding JSON, key/type/range/string errors become `invalid_bindings`;
checked evaluation errors become `evaluation_failed`; an inadmissible scalar
result becomes `invalid_result`. These domain results carry a receipt (binding
failure does not claim evaluation). Canonical manifest/digest/language/profile/
expression admission, authority, unavailable feature/provider, definition pin,
disabled selection, delivery drift, Busy and guest/resource/codec failures are
outer refusals. Invalid installation returns CLI error/nonzero, no call receipt.
The generic256KiB stored-source materialization guard applies before loading/
hashing, counting the stored JSON representation including quotes/escaping;
exceeding it refuses without receipt. The inner16KiB source limit is distinct.
Encoded guest requests above32KiB also refuse outside the result/receipt,
even if heavily escaped source is below16KiB. Do not widen any bound to make an
example work or conflate these three size boundaries.

Shipping feature-off builds preserve metadata/data/history reads but refuse new
CEL activation/execution/discovery. Installed apps additionally need normal
host-authenticated install/source/consent; this CLI/stdio walkthrough claims no
app installation or public hosted endpoint. Guest receipt identity and bounded
runtime evidence do not establish whole-process/native allocation bounds,
production qualification, external human acceptance or fresh public compilation.
A prebuilt operator run validates these commands/loaders only for its recorded
binary and guest pins.

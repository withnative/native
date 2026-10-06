# CEL subset corpus

Each `*.json` file is a JSON array of test cases.

```json
{"name": "...", "expr": "CEL expression", "bindings": {"varname": <Value>},
 "expect": {"value": <Value>} | {"error": true, "note": "..."},
 "spec": "langdef section (optional)", "note": "... (optional)"}
```

`Value` is a tagged encoding that preserves CEL's numeric types (plain JSON
numbers cannot distinguish int / uint / double, and cannot carry a full int64):

| tag | example | meaning |
|---|---|---|
| `{"int":"42"}` | decimal string | `int` (i64) |
| `{"uint":"42"}` | decimal string | `uint` (u64) |
| `{"double":1.5}` | number | `double` (f64), finite non-zero |
| `{"double":"NaN"}` | string | `double` NaN (not representable in JSON) |
| `{"double":"+Inf"}` | string | `double` +Infinity |
| `{"double":"-Inf"}` | string | `double` -Infinity |
| `{"double":"-0"}` | string | `double` negative zero |
| `{"string":"hi"}` | string | `string` |
| `{"bool":true}` | bool | `bool` |
| `{"null":true}` | - | `null` |
| `{"list":[<Value>,...]}` | - | list |
| `{"map":[[<Value>,<Value>],...]}` | - | map (entries are key/value pairs) |

Special doubles are tagged as strings because JSON has no syntax for NaN,
Infinity or negative zero (`JSON.stringify` maps all of them to `null`/`0`).
Finite non-zero doubles stay plain numbers. Both runners and `tools/compare.py`
normalise the two forms, so `{"double":4.0}` and `{"double":4}` are equal.

`expect.error` is one of the cel-spec error **categories** below (or `"any"`
when the language definition names no category), not merely a boolean. The
runners classify each engine's actual message into the same vocabulary and
record both the raw `message` and the `category`. `expect.probe` marks a case
whose value is recorded and cross-checked between runtimes but not asserted
(the language definition is ambiguous — e.g. lossy int/double comparison).

| category | spec source |
|---|---|
| `no_matching_overload` | langdef "Runtime Errors", "Functions" |
| `no_such_field` | langdef "Runtime Errors", "Field Selection" |
| `no_such_key` | conformance `fields.textproto` (map key); langdef "Field Selection" step 3 |
| `division_by_zero` | langdef "Standard Definitions", "Division (/)" |
| `modulus_by_zero` | langdef "Standard Definitions", "Modulus (%)" |
| `overflow` | langdef "Numeric Values", "Overflow"; conformance "return error for overflow" |
| `invalid_argument` | conformance `lists.textproto` (OOB / bad index type); langdef "Field Selection" step 4 |
| `bad_key_type` | conformance `fields.textproto` ("unsupported key type"); langdef "Aggregate Values" |
| `parse_error` | langdef "String and Bytes Values" (invalid escapes); conformance `parse.textproto` |

Expectations are derived from the CEL language definition
(github.com/google/cel-spec `doc/langdef.md`) and the conformance corpus under
`tests/simple/testdata/`. Cases with a non-obvious expectation carry a `spec`
citation.

// RFC 8785 JSON Canonicalization Scheme, for the value shapes an alpha-tab
// digest ever hashes (objects, arrays, strings, integers, booleans, null).
// Mirrors `src/canonical_json.rs` (`serde_jcs::to_vec`): array order is
// preserved, so callers sort semantically unordered arrays first.

export function canonicalJson(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("JCS cannot encode a non-finite number");
      return JSON.stringify(value);
    case "object": {
      // JCS orders members by UTF-16 code units, which is what the default
      // Array#sort comparison does for strings.
      const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`JCS cannot encode a ${typeof value}`);
  }
}

// Rust sorts `Vec<String>` by UTF-8 bytes. That differs from JavaScript's
// UTF-16 order only for code points above U+FFFF against U+E000..U+FFFF, but
// the digest must match byte-exactly, so compare the way Rust does.
const encoder = new TextEncoder();
export function compareUtf8(left, right) {
  if (left === right) return 0;
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

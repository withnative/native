import { compareUtf8 } from "./jcs.mjs";

// Immutable26f5 Rust alpha_tab_sessions structural grammar and tuple order.
// Shared by digest and opt-in author planning; never session admission.
const sessionFields = ["session", "key", "scope", "mode", "presence"];
const scopeFields = ["type", "kind"];
// Rust str::trim uses Unicode White_Space: unlike JS trim, U+0085 is blank
// and U+FEFF is not. Keep the baseline set explicit rather than using JS trim.
const rustBlank = /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;
export const isRustBlank = (value) => rustBlank.test(value);
function sessionObject(value, fields) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return Reflect.ownKeys(descriptors).length === fields.length && fields.every((key) =>
    Object.hasOwn(descriptors, key) && descriptors[key].enumerable
    && Object.hasOwn(descriptors[key], "value"));
}
function sessionString(value) {
  return typeof value === "string" && !rustBlank.test(value)
    // Rust JSON strings contain scalars; JS can also hold lone surrogates.
    && [...value].every((char) => {
      const point = char.codePointAt(0);
      return point < 0xd800 || point > 0xdfff;
    });
}
export function canonicalSessionsIn(declaration) {
  const member = Object.getOwnPropertyDescriptor(declaration ?? {}, "sessions");
  if (!member) return undefined;
  const fail = (where) => { throw new Error(`${where} must match the closed baseline session.body.v1 shape [invalid_session]`); };
  if (!Object.hasOwn(member, "value") || !Array.isArray(member.value)) fail("sessions");
  const sessions = Array.from(member.value, (entry, index) => {
    const where = `sessions[${index}]`;
    if (!sessionObject(entry, sessionFields) || entry.session !== "session.body.v1"
      || !sessionString(entry.key) || !sessionObject(entry.scope, scopeFields)
      || !sessionString(entry.scope.type) || !sessionString(entry.scope.kind)
      || !["edit", "view"].includes(entry.mode) || typeof entry.presence !== "boolean") fail(where);
    return { session: "session.body.v1", key: entry.key,
      scope: { type: entry.scope.type, kind: entry.scope.kind },
      mode: entry.mode, presence: entry.presence };
  });
  // No count/string-length cap or deduplication exists in this baseline.
  return sessions.sort((left, right) => compareUtf8(left.key, right.key)
    || compareUtf8(left.scope.type, right.scope.type) || compareUtf8(left.scope.kind, right.scope.kind)
    || compareUtf8(left.mode, right.mode) || Number(left.presence) - Number(right.presence));
}

// Qualified frozen commitment path; session-only inputs do not require a descriptor.
// No ordinary evolving parser, admission or digest-version change.
// alpha-tab-digest.v1, mirroring src/mcp/tools/alpha_tabs.rs:
//   alpha_tab_bundle_digest            (line 720)
//   alpha_tab_canonical_declaration    (line 770)
//   alpha_tab_declaration_digest       (line 840)
//   alpha_tab_digest                   (line 851)
// and src/canonical_json.rs (RFC 8785 JCS + SHA-256).
import { createHash } from "node:crypto";
import { canonicalJson, compareUtf8 } from "./jcs.mjs";
import { parseCommentCreateBound, parseFacetSetBound, parseMessageReactBound, classifyDeclarationNeed, bodyReadDescriptorIn, BODY_READ_NEED, BODY_READ_SCOPE, parseTitleSetBound } from "./body-feature-grammar.mjs";

import { canonicalSessionsIn } from "./session-structure.mjs";



const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

function canonicalParams(params) {
  // Declared order is consent (it defines `?N`), so it is kept.
  return params.map((param) => param.type === "text"
    ? { name: param.name, type: param.type, max_len: param.max_len, required: param.required }
    : { name: param.name, type: param.type, required: param.required });
}

/**
 * The canonical declaration. Fails closed, as Rust does, on a non-string
 * `needs` entry that is not a well-formed SQL need or inert body descriptor.
 * Digest support is not public install/adoption permission.
 */
export function canonicalBodyFeatureDeclaration(declaration) {
  const sessions = canonicalSessionsIn(declaration);
  const names = (key) => (Array.isArray(declaration?.[key]) ? declaration[key] : [])
    .filter((value) => typeof value === "string")
    .sort(compareUtf8);
  const bodyRead = bodyReadDescriptorIn(declaration);
  if (bodyRead.error) throw Object.assign(new Error(bodyRead.error.message), { finding: bodyRead.error });
  const sqlNeeds = [];
  for (const entry of Array.isArray(declaration?.needs) ? declaration.needs : []) {
    if (typeof entry === "string") continue;
    const parsed = classifyDeclarationNeed(entry);
    if (parsed.error) {
      const error = new Error(`${parsed.error.message} [invalid_sql_need]`);
      error.finding = parsed.error;
      throw error;
    }
    if (parsed.kind !== "sql") continue;
    const { key, label, sql, params } = parsed.need;
    sqlNeeds.push(params.length
      ? { key, label, need: "sql.snapshot.v1", sql, params: canonicalParams(params) }
      : { key, label, need: "sql.snapshot.v1", sql });
  }
  sqlNeeds.sort((left, right) => compareUtf8(left.key, right.key) || compareUtf8(left.sql, right.sql));
  // Facet-set, comment.create, message.react and title-set objects
  // canonicalize with their full bounds together, ordered by the hex of
  // their JCS SHA-256 — exactly how Rust sorts by `digest_json` output
  // (hex order preserves byte order, so `compareUtf8` on the hex is
  // exact, not raw-JSON order). Strings keep their historical sorted
  // order, so a string-only declaration digests byte-identically. With
  // no comment, react or title objects the facet group keeps its exact
  // historical order. Invalid objects throw: they never digest as absent.
  const effectObjects = [];
  for (const entry of Array.isArray(declaration?.effects) ? declaration.effects : []) {
    if (typeof entry === "string") continue;
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.effect === "comment.create.v1") {
      const parsed = parseCommentCreateBound(entry, "effects[]");
      if (parsed.error) {
        const error = new Error(`${parsed.error.message} [invalid_effect]`);
        error.finding = parsed.error;
        throw error;
      }
      const { positions, max_body_bytes, need } = parsed.bound;
      effectObjects.push({
        object: { effect: "comment.create.v1", positions: [...positions], target: { need }, max_body_bytes },
      });
      continue;
    }
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.effect === "message.react.v1") {
      const parsed = parseMessageReactBound(entry, "effects[]");
      if (parsed.error) {
        const error = new Error(`${parsed.error.message} [invalid_effect]`);
        error.finding = parsed.error;
        throw error;
      }
      const { emoji, need } = parsed.bound;
      effectObjects.push({
        object: { effect: "message.react.v1", emoji: [...emoji], target: { need } },
      });
      continue;
    }
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.effect === "records.title-set.v1") {
      const parsed = parseTitleSetBound(entry, "effects[]");
      if (parsed.error) {
        const error = new Error(`${parsed.error.message} [invalid_effect]`);
        error.finding = parsed.error;
        throw error;
      }
      const { need } = parsed.bound;
      effectObjects.push({
        object: { effect: "records.title-set.v1", target: { need } },
      });
      continue;
    }
    const parsed = parseFacetSetBound(entry, "effects[]");
    if (parsed.error) {
      const error = new Error(`${parsed.error.message} [invalid_effect]`);
      error.finding = parsed.error;
      throw error;
    }
    const { key, values, need } = parsed.bound;
    effectObjects.push({
      object: { effect: "records.facet-set.v1", key, target: { need }, values: [...values] },
    });
  }
  effectObjects.sort((left, right) => compareUtf8(
    sha256Hex(Buffer.from(canonicalJson(left.object), "utf8")),
    sha256Hex(Buffer.from(canonicalJson(right.object), "utf8")),
  ));
  const canonical = { needs: names("needs"), effects: [...names("effects"), ...effectObjects.map((row) => row.object)] };
  if (sqlNeeds.length) canonical.sql_needs = sqlNeeds;
  if (bodyRead.present) canonical.body_read_needs = [{ need: BODY_READ_NEED, scope: BODY_READ_SCOPE }];
  if (sessions !== undefined) canonical.sessions = sessions;
  return canonical;
}


import { canonicalBodyFeatureDeclaration } from "./body-feature-digest.mjs";
// alpha-tab-digest.v1, mirroring src/mcp/tools/alpha_tabs.rs:
//   alpha_tab_bundle_digest            (line 720)
//   alpha_tab_canonical_declaration    (line 770)
//   alpha_tab_declaration_digest       (line 840)
//   alpha_tab_digest                   (line 851)
// and src/canonical_json.rs (RFC 8785 JCS + SHA-256).
import { createHash } from "node:crypto";
import { canonicalJson, compareUtf8 } from "./jcs.mjs";
import { BODY_SET_EFFECT, parseBodySetBounds, parseCommentCreateBound, parseFacetSetBound, parseMessageReactBound, parseSqlNeedEntry, parseTitleSetBound } from "./declaration.mjs";
import { LIMITS } from "./limits.mjs";

export const DIGEST_VERSION = LIMITS.digest.version;

const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Lowercase hex SHA-256 over the exact source body bytes. */
export function bundleSha256(body) {
  return sha256Hex(typeof body === "string" ? Buffer.from(body, "utf8") : body);
}

function canonicalParams(params) {
  // Declared order is consent (it defines `?N`), so it is kept.
  return params.map((param) => param.type === "text"
    ? { name: param.name, type: param.type, max_len: param.max_len, required: param.required }
    : { name: param.name, type: param.type, required: param.required });
}

/**
 * The canonical declaration. Fails closed, as Rust does, on a non-string
 * `needs` entry that is not a well-formed sql.snapshot.v1 object — so a
 * malformed SQL cannot digest as absent. Dormant BodySet is a proposed
 * canonical shape only: current engine install/write parity is unqualified.
 */
export function canonicalDeclaration(declaration) {
  const sessions = Object.getOwnPropertyDescriptor(declaration ?? {}, "sessions");
  const attemptedDescriptor = Array.isArray(declaration?.needs) && declaration.needs.some(entry =>
    entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.need === "records.body.read.v1");
  if (sessions || attemptedDescriptor) return canonicalBodyFeatureDeclaration(declaration);
  return canonicalOrdinaryDeclaration(declaration);
}

// Main269 ordinary/dormant BodySet canonicalization remains unchanged.
function canonicalOrdinaryDeclaration(declaration) {
  // Dormant S2 shape, not Rust parity/write admission. Validate the WHOLE
  // BodySet list before canonicalizing: duplicate/undeclared bounds must
  // not receive a digest even when parseDeclaration was bypassed. Keep
  // legacy no-Body canonical behavior (including bare older families).
  // Inspect an explicit non-array BodySet BEFORE the legacy [] fallback:
  // malformed object/bare-family envelopes must refuse, not hash as absent.
  const entries = Array.isArray(declaration?.effects) ? declaration.effects : [declaration?.effects];
  let bodyBounds = [];
  if (entries.some((entry) => entry === BODY_SET_EFFECT || entry?.effect === BODY_SET_EFFECT)) {
    const parsed = parseBodySetBounds(declaration);
    if (parsed.error) {
      const error = new Error(`${parsed.error.message}${parsed.error.rule.startsWith("sql-") ? " [invalid_sql_need]" : ""}`);
      error.finding = parsed.error;
      throw error;
    }
    bodyBounds = parsed.bounds;
  }
  const names = (key) => (Array.isArray(declaration?.[key]) ? declaration[key] : [])
    .filter((value) => typeof value === "string")
    .sort(compareUtf8);
  const sqlNeeds = [];
  for (const entry of Array.isArray(declaration?.needs) ? declaration.needs : []) {
    if (typeof entry === "string") continue;
    const parsed = parseSqlNeedEntry(entry);
    if (parsed.error) {
      const error = new Error(`${parsed.error.message} [invalid_sql_need]`);
      error.finding = parsed.error;
      throw error;
    }
    const { key, label, sql, params } = parsed.need;
    sqlNeeds.push(params.length
      ? { key, label, need: LIMITS.declaration.sql_snapshot_need, sql, params: canonicalParams(params) }
      : { key, label, need: LIMITS.declaration.sql_snapshot_need, sql });
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
    if (entry !== null && typeof entry === "object" && !Array.isArray(entry) && entry.effect === BODY_SET_EFFECT) {
      const { need, max_body_bytes } = bodyBounds[0];
      effectObjects.push({ object: { effect: BODY_SET_EFFECT, max_body_bytes, target: { need } } });
      continue;
    }
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
  return canonical;
}

/** Hex SHA-256 over the JCS bytes of the canonical declaration (no prefix). */
export function declarationDigest(declaration) {
  return sha256Hex(Buffer.from(canonicalJson(canonicalDeclaration(declaration)), "utf8"));
}

/** `sha256:` + hex SHA-256 over JCS({bundle_sha256, declaration_digest, runtime}). */
export function installDigest(bundleSha256Hex, declarationDigestHex, runtime) {
  const input = { bundle_sha256: bundleSha256Hex, declaration_digest: declarationDigestHex, runtime };
  return `sha256:${sha256Hex(Buffer.from(canonicalJson(input), "utf8"))}`;
}

/** All three digests for one package. */
export function computeDigests(body, declaration, runtime = LIMITS.install.runtime) {
  const bundle_sha256 = bundleSha256(body);
  const declaration_digest = declarationDigest(declaration);
  return {
    digest_version: DIGEST_VERSION,
    bundle_sha256,
    declaration_digest,
    digest: installDigest(bundle_sha256, declaration_digest, runtime),
  };
}

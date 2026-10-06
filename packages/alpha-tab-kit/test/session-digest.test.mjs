import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { canonicalDeclaration, declarationDigest, installDigest } from "../src/digest.mjs";
import { canonicalJson } from "../src/jcs.mjs";
import { parseDeclaration, splitNeeds } from "../src/declaration.mjs";
import { planInstall } from "../src/install.mjs";
import { startFakeHost } from "../src/fake-host/server.mjs";

// Immutable qualified Rust commitments plus independent Python expectations;
// never derive an expected digest using the JS implementation under test.
const vectors = JSON.parse(readFileSync(new URL("vectors/session-digest-vectors.json", import.meta.url), "utf8"));
const qualifiedPath = new URL("../../../tests/fixtures/alpha-tab-body-admission-v1/vectors.json", import.meta.url);
const session = (patch = {}) => ({ session: "session.body.v1", key: "doc",
  scope: { type: "Document", kind: "note" }, mode: "edit", presence: true, ...patch });
const declaration = (sessions) => ({ needs: [], effects: [], sessions });
const errors = (parsed) => parsed.findings.filter((f) => f.severity === "error");

function assertVector(item) {
  assert.deepEqual(canonicalDeclaration(item.declaration), item.canonical, item.name);
  assert.equal(canonicalJson(canonicalDeclaration(item.declaration)), item.canonical_bytes, item.name);
  assert.equal(declarationDigest(item.declaration), item.declaration_digest, item.name);
  assert.equal(installDigest(vectors.bundle_sha256, declarationDigest(item.declaration), vectors.runtime),
    item.install_digest, item.name);
}

test("copied expectations match all eight qualified Rust vectors when inside native-ce", {
  skip: !existsSync(qualifiedPath) && "qualified Rust source fixture unavailable outside native-ce",
}, () => {
  const rust = JSON.parse(readFileSync(qualifiedPath, "utf8"));
  assert.deepEqual(vectors.rust_qualified.map(({ install_digest, ...rest }) => rest), rust.vectors);
});

test("exact canonical object, JCS, declaration and install digests match qualified Rust", () => {
  for (const item of vectors.rust_qualified) assertVector(item);
});

test("session absence, explicit empty and duplicates retain different fixed commitments", () => {
  const absent = vectors.rust_qualified.find((v) => v.name === "historical empty");
  const empty = vectors.extra.find((v) => v.name === "explicit empty sessions");
  const duplicate = vectors.extra.find((v) => v.name === "duplicates remain commitment material");
  for (const item of [absent, empty, duplicate]) assertVector(item);
  assert.equal(Object.hasOwn(canonicalDeclaration(absent.declaration), "sessions"), false);
  assert.notEqual(declarationDigest(absent.declaration), declarationDigest(empty.declaration));
  assert.notEqual(declarationDigest(declaration([session()])), duplicate.declaration_digest);
  assert.equal(canonicalDeclaration(duplicate.declaration).sessions.length, 2);
});

test("UTF8 tuple ordering covers key, scope type, scope kind, mode and presence", () => {
  const item = vectors.extra.find((v) => v.name === "UTF8 tuple fields and false before true");
  assertVector(item);
  const reversed = declaration([...item.declaration.sessions].reverse());
  assertVector({ ...item, declaration: reversed });
  assert.deepEqual(item.canonical.sessions.slice(-2).map((s) => s.key), ["\ue000", "\u{10000}"]);
});

test("member order is irrelevant, canonicalization does not mutate source strings or arrays", () => {
  const item = vectors.rust_qualified.find((v) => v.name === "baseline SQL params effects sessions");
  const input = structuredClone(item.declaration);
  input.sessions.reverse();
  input.sessions = input.sessions.map((s) => ({ presence: s.presence, mode: s.mode,
    scope: { kind: s.scope.kind, type: s.scope.type }, key: s.key, session: s.session }));
  const before = structuredClone(input);
  assertVector({ ...item, declaration: input });
  assert.deepEqual(input, before);
  const whitespace = session({ key: " doc ", scope: { type: " Document ", kind: " * " } });
  assert.deepEqual(canonicalDeclaration(declaration([whitespace])).sessions, [whitespace]);
});

test("sessions impose no new count, length, uniqueness or scope vocabulary cap", () => {
  const long = session({ key: "k".repeat(4096), scope: { type: "Unknown", kind: "*" } });
  const input = declaration(Array.from({ length: 129 }, () => long));
  const canonical = canonicalDeclaration(input);
  assert.equal(canonical.sessions.length, 129);
  assert.ok(canonical.sessions.every((s) => s.key === long.key && s.scope.kind === "*"));
});

test("all malformed session shapes refuse standalone canonicalization and digest", () => {
  const good = session();
  const malformed = [null, undefined, "no", {}, 1, false, [null], [1], [[]], Array(1),
    [{ ...good, session: "session.body.v2" }], [{ ...good, session: null }],
    [{ ...good, mode: "write" }], [{ ...good, mode: false }],
    [{ ...good, presence: 0 }], [{ ...good, presence: "true" }], [{ ...good, extra: true }],
    [{ ...good, key: "" }], [{ ...good, key: " \t\r\n" }], [{ ...good, key: 7 }],
    [{ ...good, key: "\ud800" }], [{ ...good, key: "\udc00" }],
    [{ ...good, scope: null }], [{ ...good, scope: [] }],
    [{ ...good, scope: { type: "Document" } }],
    [{ ...good, scope: { type: "Document", kind: "note", extra: true } }],
    [{ ...good, scope: { type: "", kind: "note" } }],
    [{ ...good, scope: { type: "Document", kind: false } }],
    [{ ...good, scope: { type: "Document", kind: "\ud800" } }],
  ];
  for (const field of ["session", "key", "scope", "mode", "presence"]) {
    const missing = { ...good };
    delete missing[field];
    malformed.push([missing]);
  }
  for (const sessions of malformed) {
    assert.throws(() => canonicalDeclaration(declaration(sessions)), /invalid_session/);
    assert.throws(() => declarationDigest(declaration(sessions)), /invalid_session/);
  }
});

test("blank checks use Rust Unicode White_Space, without JS BOM trimming", () => {
  const blank = "\u0009\u000a\u000b\u000c\u000d \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";
  for (const key of [...blank]) assert.throws(() => declarationDigest(declaration([session({ key })])), /invalid_session/);
  for (const scope of [{ type: blank, kind: "note" }, { type: "Document", kind: blank }]) {
    assert.throws(() => declarationDigest(declaration([session({ scope })])), /invalid_session/);
  }
  for (const key of ["\ufeff", "\u200b", "\u180e", "\u{10000}"]) {
    assert.equal(canonicalDeclaration(declaration([session({ key })])).sessions[0].key, key);
  }
});

test("parsed session fields are data only, not getter-backed or prototype material", () => {
  let invoked = 0;
  const getter = { ...session(), get key() { invoked++; return "doc"; } };
  assert.throws(() => declarationDigest(declaration([getter])), /invalid_session/);
  const inherited = Object.assign(Object.create({ key: "doc" }), session());
  assert.throws(() => declarationDigest(declaration([inherited])), /invalid_session/);
  const accessorDeclaration = { needs: [], effects: [], get sessions() { invoked++; return []; } };
  assert.throws(() => declarationDigest(accessorDeclaration), /invalid_session/);
  assert.equal(invoked, 0);
});

test("digest support leaves parseDeclaration, install planning and fake hosting refused", async () => {
  for (const sessions of [[], [session()]]) {
    const candidate = declaration(sessions);
    assert.doesNotThrow(() => declarationDigest(candidate));
    const parsed = parseDeclaration(candidate);
    assert.deepEqual(errors(parsed).map((f) => f.rule), ["declaration.shape"]);
    assert.deepEqual(splitNeeds(parsed), { snapshot: [], onRequestSql: [], onRequestHost: [] });
    const descriptor = { package: "agent.session", version: "1.0.0", runtime: "native.html.v1", declaration: candidate };
    const html = "<!doctype html><html><head></head><body></body></html>";
    assert.throws(() => planInstall({ descriptor, html, homeId: "home", reason: "Test" }),
      (error) => error.findings.some((f) => f.rule === "declaration.shape"));
    await assert.rejects(startFakeHost({ descriptor, html }), /exactly 'needs' and 'effects'/);
  }
});

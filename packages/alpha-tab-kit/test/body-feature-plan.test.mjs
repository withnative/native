import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { planBodyFeatureInstall } from '@withnative/alpha-tab-kit/body-feature-plan';
import { planBodyFeatureInstall as rootPlanner } from '../src/index.mjs';
import { planInstall, runInstall } from '../src/install.mjs';
import { parseDeclaration } from '../src/declaration.mjs';
import { validatePackage } from '../src/validate.mjs';
import { canonicalDeclaration, declarationDigest, installDigest } from '../src/digest.mjs';
import { canonicalJson } from '../src/jcs.mjs';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const vectors = read('vectors/session-digest-vectors.json');
const legacy = read('vectors/legacy-install-plan-8951.json');
const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Reader</title></head><body><main><h1>Reader</h1></main></body></html>';
const body = { need: 'records.body.read.v1', scope: 'viewer-visible-current-bodies' };
const declaration = () => ({ needs: [{ ...body }], effects: [] });
const session = () => ({ session: 'session.body.v1', key: 'doc', scope: { type: 'Document', kind: '*' }, mode: 'view', presence: false });
const sql = (key = 'rows') => ({ need: 'sql.snapshot.v1', key, label: 'Rows', sql: 'SELECT id FROM records ORDER BY id LIMIT 20' });
const params = (decl = declaration()) => ({ descriptor: { package: 'example.reader', version: '1.0.0', runtime: 'native.html.v1', declaration: decl }, html, homeId: 'home', reason: 'Prepare reader source' });
const plan = (decl = declaration(), patch = {}) => planBodyFeatureInstall({ ...params(decl), ...patch });
const refused = (decl, rule) => assert.throws(() => plan(decl), (e) => e.findings?.some((f) => f.rule === rule));

test('typed subpath and JS root expose the same pure opt-in planner', () => {
  assert.equal(rootPlanner, planBodyFeatureInstall);
});

test('descriptor-only handoff is closed, exact Cookie target with one retained original intent', () => {
  const p = plan();
  assert.deepEqual(Object.keys(p), ['kind', 'package', 'version', 'digests', 'sourceSteps', 'hostInstall', 'hostAvailability']);
  assert.equal(p.kind, 'alpha-tab.body-feature-plan.v1');
  assert.deepEqual(Object.keys(p.hostInstall), ['operation', 'method', 'pathTemplate', 'arguments']);
  assert.equal(p.hostInstall.operation, 'alpha-tabs.body-feature');
  assert.equal(p.hostInstall.method, 'POST');
  assert.equal(p.hostInstall.pathTemplate, '/databases/{db_id}/alpha-tabs/body-feature');
  const { idempotency_key, ...args } = p.hostInstall.arguments;
  assert.match(idempotency_key, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(args, { action: 'install', package: 'example.reader', version: '1.0.0', digest: p.digests.digest,
    artifact_id: '{{record_id}}', source_revision: '{{source_revision}}', declaration: declaration(), reason: params().reason });
  assert.equal(JSON.parse(JSON.stringify(p)).hostInstall.arguments.idempotency_key, idempotency_key);
  assert.notEqual(plan().hostInstall.arguments.idempotency_key, idempotency_key, 'a fresh plan is a new intent, not retry');
  assert.deepEqual(p.hostAvailability, { body: body.scope, otherReads: false, effects: false, sessions: false });
  assert.deepEqual(p.sourceSteps.map((s) => s.step), ['create-note', 'source-revision', 'rekind-artifact']);
  assert.equal(p.digests.declaration_digest, 'b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4');
});

test('all mixed declaration bytes, effect bounds and sessions are preserved but withheld', () => {
  const vector = vectors.rust_qualified.find((v) => v.name === 'descriptor SQL params effects sessions');
  const original = structuredClone(vector.declaration);
  const p = plan(original);
  assert.deepEqual(p.hostInstall.arguments.declaration, vector.declaration);
  assert.equal(p.digests.declaration_digest, vector.declaration_digest);
  assert.equal(canonicalJson(canonicalDeclaration(p.hostInstall.arguments.declaration)), vector.canonical_bytes);
  assert.equal(installDigest(vectors.bundle_sha256, p.digests.declaration_digest, vectors.runtime), vector.install_digest);
  original.needs[1].sql = 'changed'; original.sessions.reverse();
  assert.deepEqual(p.hostInstall.arguments.declaration, vector.declaration, 'later author changes cannot reconstruct the original intent');
  assert.throws(() => { p.hostInstall.arguments.declaration.sessions.push(session()); }, TypeError);
  assert.throws(() => { p.hostInstall.arguments.idempotency_key = 'new'; }, TypeError);
  assert.deepEqual(p.hostAvailability, { body: body.scope, otherReads: false, effects: false, sessions: false });
});

test('total64 counts body descriptor while SQL subset remains eight', () => {
  const needs = [{ ...body }, ...Array.from({ length: 8 }, (_, i) => sql(`n${i}`)), ...Array.from({ length: 55 }, (_, i) => `inert.${i}`)];
  assert.equal(plan({ needs, effects: [] }).hostInstall.arguments.declaration.needs.length, 64);
  refused({ needs: [...needs, 'extra'], effects: [] }, 'declaration.needs');
  refused({ needs: [{ ...body }, ...Array.from({ length: 9 }, (_, i) => sql(`n${i}`))], effects: [] }, 'declaration.sql-need-count');
});

test('closed descriptor, duplicates, cross-kind collisions and unknown objects refuse', () => {
  for (const needs of [[body, body], [body, body.need], [body, sql(body.need)], [{ ...body, scope: 'all' }],
    [{ ...body, extra: true }], [body, { need: 'future.v1' }]]) assert.throws(() => plan({ needs, effects: [] }));
  refused({ ...declaration(), extra: [] }, 'declaration.shape');
  refused({ needs: [body, '\u0085'], effects: [] }, 'declaration.needs');
  refused({ ...declaration(), effects: ['\u0085'] }, 'declaration.effects');
  assert.doesNotThrow(() => plan({ needs: [body, '\ufeff'], effects: ['\ufeff'] }));
});

test('bare strings stay inert and historical same-name SQL key stays SQL', () => {
  for (const needs of [[body.need], [sql(body.need)]]) {
    const d = { needs, effects: [] };
    refused(d, 'body-read.required');
    assert.equal(parseDeclaration(d).findings.length, 0);
    assert.doesNotThrow(() => planInstall(params(d)));
  }
  assert.equal(declarationDigest({ needs: [body.need], effects: [] }), '914433578a9fd9c09e8627a5bd23c3e54018a6b19bb7523801381a252575fc8d');
  const oldSql = vectors.rust_qualified.find((v) => v.name === 'same old SQL key remains SQL');
  assert.equal(declarationDigest(oldSql.declaration), oldSql.declaration_digest);
});

test('SQL params, keys and safety lint still refuse malformed or unsafe mixed declarations', () => {
  for (const s of [{ ...sql(), params: [{ name: 'id', type: 'float' }] }, { ...sql(), params: [{ name: 'id', type: 'integer', max_len: 2 }] },
    { ...sql(), params: [{ name: 'id', type: 'text', required: 1 }] }, { ...sql(), params: Array(9).fill({ name: 'id', type: 'text' }) },
    { ...sql(), key: 'Bad' }, { ...sql(), extra: true }, { ...sql(), sql: 'DELETE FROM records' }]) {
    assert.throws(() => plan({ needs: [body, s], effects: [] }));
  }
  refused({ needs: [body, sql(), sql()], effects: [] }, 'declaration.sql-need-key');
  refused({ needs: [body, sql(), 'rows'], effects: [] }, 'declaration.sql-need-key');
});

test('all effect families retain target/bound validation, cannot target body descriptor', () => {
  const vector = vectors.rust_qualified.find((v) => v.name === 'descriptor SQL params effects sessions');
  for (const effect of vector.declaration.effects) {
    const d = structuredClone(vector.declaration);
    d.effects = [{ ...effect, target: { need: body.need } }];
    refused(d, 'declaration.effects');
    assert.throws(() => plan({ ...d, effects: [{ ...effect, extra: true }] }));
    assert.throws(() => plan({ ...d, effects: [effect.effect] }));
    refused({ ...d, effects: [effect, effect] }, 'declaration.effects');
  }
  assert.throws(() => plan({ ...declaration(), effects: [{ effect: 'future.v1' }] }));
  refused({ ...declaration(), effects: Array(65).fill('inert') }, 'declaration.effects');
});

test('sessions absent/empty/duplicates and unbounded baseline strings/count remain distinct', () => {
  const absent = plan();
  const empty = plan({ ...declaration(), sessions: [] });
  assert.equal(Object.hasOwn(absent.hostInstall.arguments.declaration, 'sessions'), false);
  assert.deepEqual(empty.hostInstall.arguments.declaration.sessions, []);
  assert.notEqual(absent.digests.declaration_digest, empty.digests.declaration_digest);
  const d = { ...declaration(), sessions: Array.from({ length: 129 }, () => ({ ...session(), key: 'k'.repeat(4096) })) };
  assert.deepEqual(plan(d).hostInstall.arguments.declaration.sessions, d.sessions);
  const duplicates = { ...declaration(), sessions: [session(), session()] };
  assert.notEqual(plan(duplicates).digests.declaration_digest, plan({ ...declaration(), sessions: [session()] }).digests.declaration_digest);
});

test('every closed baseline session member/type/scope/mode/presence is checked', () => {
  const s = session();
  for (const sessions of [null, {}, 'no', [null], [1], [[]], [{ ...s, mode: 'write' }], [{ ...s, presence: 0 }],
    [{ ...s, session: 'future' }], [{ ...s, extra: true }], [{ ...s, key: '' }], [{ ...s, key: '\u0085' }],
    [{ ...s, scope: { type: 'Document' } }], [{ ...s, scope: { type: 'Document', kind: '', extra: true } }]]) {
    refused({ ...declaration(), sessions }, 'declaration.sessions');
  }
  for (const field of Object.keys(s)) {
    const missing = { ...s }; delete missing[field];
    refused({ ...declaration(), sessions: [missing] }, 'declaration.sessions');
  }
  const unicode = { ...declaration(), sessions: [session(), { ...s, key: '\ufeff' }, { ...s, key: '\u{10000}' }, { ...s, key: '\ue000' }] };
  assert.deepEqual(plan(unicode).hostInstall.arguments.declaration, unicode, 'no canonical sorting of author intent');
  assert.deepEqual(canonicalDeclaration(unicode).sessions.map((s) => s.key), ['doc', '\ue000', '\ufeff', '\u{10000}']);
});

test('generic parser/validator/planner still refuse descriptor and optional sessions', () => {
  for (const d of [declaration(), { ...declaration(), sessions: [] }, { ...declaration(), sessions: [session()] }]) {
    assert.ok(parseDeclaration(d).findings.some((f) => f.severity === 'error'));
    assert.equal(validatePackage(params(d)).ok, false);
    assert.throws(() => planInstall(params(d)), /does not validate/);
    assert.doesNotThrow(() => plan(d));
  }
});

test('runInstall rejects new kind before client/callback/steps access or ANY writes', async () => {
  let writes = 0, callbacks = 0, reads = 0;
  await assert.rejects(runInstall(plan(), { call() { writes++; } }, { onStep() { callbacks++; } }), /refuses before source writes/);
  await assert.rejects(runInstall({ kind: 'alpha-tab.body-feature-plan.v1', get steps() { reads++; throw 0; } }, { call() { writes++; } }), /refuses before source writes/);
  assert.deepEqual([writes, callbacks, reads], [0, 0, 0]);
});

test('source steps preserve full BOM/scalars, guarded chunks and pre-rekind event capture', () => {
  const text = '\ufeff' + html.replace('Reader</h1>', '😀€Reader</h1>');
  const p = plan(declaration(), { html: text, chunkBytes: 7 });
  let prefix = '';
  for (const s of p.sourceSteps.filter((s) => s.step === 'create-note' || s.step.startsWith('append-'))) {
    if (s.arguments.if_body_digest) assert.equal(s.arguments.if_body_digest, createHash('sha256').update(prefix).digest('hex'));
    const chunk = s.arguments.body ?? s.arguments.body_append;
    assert.ok(Buffer.byteLength(chunk) <= 7); prefix += chunk;
    assert.equal(s.expect.body_digest, createHash('sha256').update(prefix).digest('hex'));
    assert.equal(s.expect.body_bytes, Buffer.byteLength(prefix));
  }
  assert.equal(prefix, text);
  assert.deepEqual(p.sourceSteps.slice(-2).map((s) => s.step), ['source-revision', 'rekind-artifact']);
  assert.deepEqual(p.sourceSteps.at(-2).capture, { source_revision: 'rows[0].id' });
  assert.equal(p.sourceSteps.at(-1).arguments.if_body_digest, p.digests.bundle_sha256);
});

test('replacement is an explicit normal remove source step and removed-generation placeholder', () => {
  const p = plan(declaration(), { replaceInstallEventId: 'old-install-event' });
  assert.deepEqual(p.sourceSteps.at(-1), { step: 'remove-previous-install', executor: 'artifacts_write', operation: 'manage_alpha_tabs.remove',
    arguments: { package: p.package, expected_install_event_id: 'old-install-event', reason: `${params().reason} (install refuses a package that is already installed)` } });
  assert.equal(p.hostInstall.arguments.expected_install_event_id, '{{removed_event_id}}');
  assert.equal(Object.hasOwn(plan().hostInstall.arguments, 'expected_install_event_id'), false);
});

test('explicit historical chunked plan bytes and digests match immutable8951 normal/replacement vectors', () => {
  const descriptor = read('fixtures/probe-descriptor.json');
  const probeHtml = readFileSync(new URL('fixtures/probe-queued.html', import.meta.url), 'utf8');
  const p = { descriptor, html: probeHtml, homeId: 'c59dffa3-a401-431a-a44b-c79cae9b8346', reason: 'Install the kit probe', chunkBytes: 700 };
  for (const [patch, expected] of [[{}, legacy.normal_sha256], [{ replaceInstallEventId: 'old-install-event' }, legacy.replace_sha256]]) {
    const actual = planInstall({ ...p, ...patch, chunked: true });
    assert.equal(createHash('sha256').update(JSON.stringify(actual)).digest('hex'), expected);
    assert.deepEqual(actual.digests, legacy.digests);
  }
});

test('closed parameters and parsed-data constraints fail without accessor/toJSON execution', () => {
  for (const patch of [{ request: null }, { cookie: 'x' }, { run_key: 'x' }, { html: null }, { descriptor: null }, { reason: '' },
    { chunkBytes: 3 }, { chunkBytes: Infinity }, { sources: [{}] }, { replaceInstallEventId: 1 }, { completenessBudget: { unknown: 1 } }]) {
    assert.throws(() => plan(declaration(), patch));
  }
  let read = 0;
  const p = params(); Object.defineProperty(p, 'html', { enumerable: true, get() { read++; return html; } });
  assert.throws(() => planBodyFeatureInstall(p));
  assert.throws(() => plan({ ...declaration(), sessions: Array(1) }));
  assert.throws(() => plan({ ...declaration(), needs: [body, '\ud800'] }));
  assert.throws(() => planBodyFeatureInstall({ ...params(), toJSON() { read++; return {}; } }));
  assert.equal(read, 0);
});

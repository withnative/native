import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readKitAssets, validateManifest, validateCatalog, sha256, DEFAULT_KIT_DELIVERY } from '../src/fake-host/kit-assets.mjs';
import { recordObservationProtocol } from '../../native-launcher/src/recordObservationLaunch.mjs';
const root = fileURLToPath(new URL('../../../', import.meta.url));
const canonical = resolve(root, 'crates/artifact-html/kit-releases');
const packaged = resolve(root, 'packages/alpha-tab-kit/supplied-kit');
const encode = value => JSON.stringify(value, null, 2) + '\n';
test('package is an exact mirror of the reviewed canonical releases', async () => {
  const source = await readKitAssets(canonical), mirror = await readKitAssets();
  assert.deepEqual(mirror, source); assert.equal(source.releases[0].manifest.version, '1.0.0');
  assert.deepEqual(Object.keys(source.catalog).sort(), ['releases', 'schema']);
  const versions = source.releases.map(release => release.manifest.version);
  const files = ['catalog.json', ...versions.flatMap(version =>
    ['core.js', 'core.d.ts', 'manifest.json'].map(file => `${version}/${file}`))];
  for (const name of files) assert.deepEqual(await readFile(resolve(canonical, name)), await readFile(resolve(packaged, name)));
  const pkg = JSON.parse(await readFile(resolve(root, 'packages/alpha-tab-kit/package.json')));
  assert.equal(pkg.version, '0.1.0'); assert.ok(pkg.files.includes('supplied-kit/'));
  for (const version of versions) {
    assert.equal(pkg.exports[`./supplied-kit/${version}/types`], `./supplied-kit/${version}/core.d.ts`);
    assert.equal(pkg.exports[`./supplied-kit/${version}/manifest.json`], `./supplied-kit/${version}/manifest.json`);
  }
});
// The source-backed default must retain the record channel when a new immutable
// kit ships. Admission stays an explicit launcher decision, never a semver range.
test('source-backed default kit is admitted to the launcher record-observation protocol', async () => {
  const identity = JSON.parse(await readFile(resolve(root, 'web/apps/src/kit/supplied/core-release.json'), 'utf8'));
  const { release } = DEFAULT_KIT_DELIVERY.resolve(identity.major);
  assert.equal(release.version, identity.version, 'fake-host default must match the source-backed kit');
  assert.ok(recordObservationProtocol(release) > 0,
    `kit ${release.version} needs reviewed launcher record-observation admission before becoming the default`);
});
test('closed manifests and catalogs reject identity, paths, bounds and extra fields', async () => {
  const { catalog, releases } = await readKitAssets(canonical), manifest = releases[0].manifest;
  for (const patch of [{ extra: true }, { version: '1.00.0' }, { version: '../1.0.0' }, { major: 2 }, { factory: 'other' }, { bridge: 'other' }, { layer: 'ui' }, { js: { ...manifest.js, file: '../core.js' } }, { types: { ...manifest.types, bytes: 65537 } }, { js: { ...manifest.js, bytes: 155649 } }, { js: { ...manifest.js, sha256: 'A'.repeat(64) } }]) assert.throws(() => validateManifest({ ...manifest, ...patch }));
  for (const changed of [{ ...catalog, active: '1.0.0' }, { ...catalog, releases: [catalog.releases[0], catalog.releases[0]] }, { ...catalog, releases: [{ ...catalog.releases[0], manifest: '../manifest.json' }] }, { ...catalog, releases: [{ ...catalog.releases[0], major: 2 }] }]) assert.throws(() => validateCatalog(changed));
});
// TEST ONLY catalogs: fixtures are intentionally unrelated to production release admission.
async function fixtureCatalog(dir) {
  const entries = [];
  for (const [version, fixture] of [['1.0.0', 'factory-a.js'], ['1.0.1', 'factory-b.js']]) {
    const js = await readFile(resolve(root, 'web/apps/test/fixtures/supplied-kit', fixture));
    const types = Buffer.from(`// TEST ONLY ${version}\ndeclare namespace Fixture { interface Kit { readonly fixture: string } }\n`);
    const asset = (file, bytes) => ({ file, bytes: bytes.length, sha256: sha256(bytes) });
    const manifest = { schema: 'native.app-kit.release.v1', version, major: 1, layer: 'core', factory: 'native.app-kit.core.factory.v1', bridge: 'native.html.bridge.v1', js: asset('core.js', js), types: asset('core.d.ts', types) };
    const text = encode(manifest); await mkdir(resolve(dir, version));
    await writeFile(resolve(dir, version, 'core.js'), js); await writeFile(resolve(dir, version, 'core.d.ts'), types); await writeFile(resolve(dir, version, 'manifest.json'), text);
    entries.push({ version, major: 1, manifest: `${version}/manifest.json`, manifest_sha256: sha256(text) });
  }
  const catalog = { schema: 'native.app-kit.catalog.v1', releases: entries }; await writeFile(resolve(dir, 'catalog.json'), encode(catalog)); return catalog;
}
test('two test-only releases keep ordered independent hashes and compatible contracts; tampering refuses', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'test-only-kit-catalog-'));
  try {
    const catalog = await fixtureCatalog(dir); const { releases } = await readKitAssets(dir);
    assert.equal(releases.length, 2); assert.notEqual(releases[0].manifest.js.sha256, releases[1].manifest.js.sha256); assert.notEqual(releases[0].manifest.types.sha256, releases[1].manifest.types.sha256);
    for (const key of ['major', 'layer', 'factory', 'bridge']) assert.equal(releases[0].manifest[key], releases[1].manifest[key]);
    assert.throws(() => validateCatalog({ ...catalog, releases: [...catalog.releases].reverse() }), /ordered/);
    assert.throws(() => validateCatalog({ ...catalog, releases: [catalog.releases[0], catalog.releases[0]] }), /duplicate/);
    for (const [name, pattern] of [['core.js', /hash\/length/], ['core.d.ts', /hash\/length/], ['manifest.json', /manifest hash/]]) {
      const path = resolve(dir, '1.0.1', name), original = await readFile(path); await writeFile(path, Buffer.concat([original, Buffer.from('tamper')])); await assert.rejects(readKitAssets(dir), pattern); await writeFile(path, original);
    }
    const wrong = JSON.parse(await readFile(resolve(dir, '1.0.1/manifest.json'))); wrong.version = '1.0.2'; const text = encode(wrong);
    await writeFile(resolve(dir, '1.0.1/manifest.json'), text); catalog.releases[1].manifest_sha256 = sha256(text); await writeFile(resolve(dir, 'catalog.json'), encode(catalog)); await assert.rejects(readKitAssets(dir), /identity drift/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

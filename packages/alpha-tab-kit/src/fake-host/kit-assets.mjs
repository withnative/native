/** Node-only custody reader and immutable host-owned delivery selection. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw new Error(`supplied kit: ${message}`); };
function closed(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail('unknown or missing fields');
}
function versionMajor(version, major) {
  const match = typeof version === 'string' && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version);
  if (!match || !Number.isSafeInteger(major) || major < 1 || major > 65535 || Number(match[1]) !== major
    || match.slice(1).some(part => !Number.isSafeInteger(Number(part)) || Number(part) > 65535)) fail('invalid version/major');
}
const hash = value => { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('invalid hash'); };
const json = (bytes, cap) => {
  if (bytes.length > cap) fail('metadata bounds exceeded');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
};
export function validateCatalog(catalog) {
  closed(catalog, ['schema', 'releases']);
  if (catalog.schema !== 'native.app-kit.catalog.v1' || !Array.isArray(catalog.releases) || catalog.releases.length < 1 || catalog.releases.length > 128) fail('invalid catalog');
  const seen = new Set();
  for (const entry of catalog.releases) {
    closed(entry, ['version', 'major', 'manifest', 'manifest_sha256']);
    versionMajor(entry.version, entry.major);
    if (seen.has(entry.version)) fail('duplicate release');
    seen.add(entry.version);
    if (entry.manifest !== `${entry.version}/manifest.json`) fail('invalid manifest path');
    hash(entry.manifest_sha256);
  }
  const ordered = [...catalog.releases].sort((a, b) => {
    const aa = a.version.split('.').map(Number), bb = b.version.split('.').map(Number);
    return aa[0] - bb[0] || aa[1] - bb[1] || aa[2] - bb[2];
  });
  if (catalog.releases.some((entry, i) => entry !== ordered[i])) fail('catalog is not ordered');
  return catalog;
}
export function validateManifest(manifest) {
  closed(manifest, ['schema', 'version', 'major', 'layer', 'factory', 'bridge', 'js', 'types']);
  versionMajor(manifest.version, manifest.major);
  if (manifest.schema !== 'native.app-kit.release.v1' || manifest.layer !== 'core'
    || manifest.factory !== 'native.app-kit.core.factory.v1' || manifest.bridge !== 'native.html.bridge.v1') fail('invalid release contract');
  for (const [key, file, cap] of [['js', 'core.js', 65536], ['types', 'core.d.ts', 32768]]) {
    const asset = manifest[key];
    closed(asset, ['file', 'bytes', 'sha256']);
    if (asset.file !== file || !Number.isSafeInteger(asset.bytes) || asset.bytes < 1 || asset.bytes > cap) fail('invalid asset path/bounds');
    hash(asset.sha256);
  }
  return manifest;
}
export async function readKitAssets(root = fileURLToPath(new URL('../../supplied-kit/', import.meta.url))) {
  const catalog = validateCatalog(json(await readFile(resolve(root, 'catalog.json')), 65536));
  const releases = [];
  for (const entry of catalog.releases) {
    // Paths are derived from validated identities and fixed output names.
    const manifestBytes = await readFile(resolve(root, entry.version, 'manifest.json'));
    if (sha256(manifestBytes) !== entry.manifest_sha256) fail('manifest hash drift');
    const manifest = validateManifest(json(manifestBytes, 8192));
    if (manifest.version !== entry.version || manifest.major !== entry.major) fail('catalog identity drift');
    const js = await readFile(resolve(root, entry.version, 'core.js'));
    const types = await readFile(resolve(root, entry.version, 'core.d.ts'));
    for (const [key, bytes] of [['js', js], ['types', types]]) {
      if (bytes.length !== manifest[key].bytes || sha256(bytes) !== manifest[key].sha256) fail(`${key} hash/length drift`);
      new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    }
    if (/<\/script|<!--/i.test(js.toString('utf8'))) fail('unsafe inline script text');
    releases.push(Object.freeze({ manifest: Object.freeze(manifest), manifestBytes, js, types }));
  }
  return Object.freeze({ catalog, releases: Object.freeze(releases) });
}

const admittedDeliveries = new WeakSet();
export function assertKitDelivery(delivery) {
  if (!admittedDeliveries.has(delivery)) fail("delivery owner is not admitted");
  return delivery;
}

/** Closed, bounded explicit selection. Resolve once per prepared document. */
export function createKitDelivery(inventory, selector = {schema: 'native.app-kit.selector.v1', selections: [{major: 1, version: '1.1.0'}]}) {
  const catalog = validateCatalog(inventory.catalog);
  if (inventory.releases.length !== catalog.releases.length) fail('inventory cardinality drift');
  const admitted = new Map();
  for (const [index, entry] of catalog.releases.entries()) {
    const retained = inventory.releases[index], m = validateManifest(retained.manifest);
    if (!retained.manifestBytes || sha256(retained.manifestBytes) !== entry.manifest_sha256
      || JSON.stringify(validateManifest(json(retained.manifestBytes, 8192))) !== JSON.stringify(m)) fail('manifest hash drift');
    if (m.version !== entry.version || m.major !== entry.major) fail('catalog identity drift');
    for (const key of ['js', 'types']) {
      const bytes = retained[key];
      if (bytes.length !== m[key].bytes || sha256(bytes) !== m[key].sha256) fail(`${key} hash/length drift`);
      new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    }
    const js = retained.js.toString('utf8');
    if (/<\/script|<!--/i.test(js)) fail('unsafe inline script text');
    const release = Object.freeze({version: m.version, major: m.major, layer: m.layer, factory: m.factory, bridge: m.bridge, js_sha256: m.js.sha256, types_sha256: m.types.sha256});
    admitted.set(m.version, Object.freeze({js, release}));
  }
  closed(selector, ['schema', 'selections']);
  if (selector.schema !== 'native.app-kit.selector.v1' || !Array.isArray(selector.selections) || selector.selections.length > catalog.releases.length) fail('invalid selector');
  const selected = new Map();
  for (const selection of selector.selections) {
    closed(selection, ['major', 'version']);
    versionMajor(selection.version, selection.major);
    const release = admitted.get(selection.version);
    if (!release || release.release.major !== selection.major || selected.has(selection.major)) fail('invalid selector selection');
    selected.set(selection.major, release);
  }
  const delivery = Object.freeze({resolve(major) {
    const resolved = selected.get(major);
    if (!resolved) throw new Error(`Native app kit major ${major} is unavailable on this host [kit_major_unavailable]`);
    return resolved;
  }});
  admittedDeliveries.add(delivery);
  return delivery;
}
export const DEFAULT_KIT_DELIVERY = createKitDelivery(await readKitAssets());

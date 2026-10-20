import {readKitAssets, createKitDelivery, sha256} from '../../src/fake-host/kit-assets.mjs';
const selector=version=>({schema:'native.app-kit.selector.v1',selections:[{major:1,version}]});
export async function fixtureDelivery(version) {
  const inventory=await readKitAssets();
  const a=inventory.releases[0];
  const js=Buffer.from(a.js.toString('utf8').replace('const version = "1.0.0"','const version = "1.0.1"')+'\n/* test-only B */');
  const manifest={...a.manifest,version:'1.0.1',js:{...a.manifest.js,bytes:js.length,sha256:sha256(js)}};
  const manifestBytes=Buffer.from(JSON.stringify(manifest));
  const catalog={schema:inventory.catalog.schema,releases:[inventory.catalog.releases[0],{version:'1.0.1',major:1,manifest:'1.0.1/manifest.json',manifest_sha256:sha256(manifestBytes)}]};
  return createKitDelivery({catalog,releases:[a,{manifest,manifestBytes,js,types:a.types}]},selector(version));
}

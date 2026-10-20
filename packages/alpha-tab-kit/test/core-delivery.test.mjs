import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createKitDelivery, readKitAssets, DEFAULT_KIT_DELIVERY, sha256} from '../src/fake-host/kit-assets.mjs';
import {injectBridge, startFakeHost} from '../src/fake-host/server.mjs';
import {fixtureDelivery} from './helpers/fixture-kit-delivery.mjs';
const source=readFileSync(new URL('./fixtures/core-source.html',import.meta.url),'utf8');
const declaration=JSON.parse(readFileSync(new URL('../../../web/apps/src/apps/template/declaration.json',import.meta.url),'utf8'));
const descriptor={package:'core-source-fixture',version:'0.0.0',declaration,kit:{major:1}};
const selector=version=>({schema:'native.app-kit.selector.v1',selections:[{major:1,version}]});
test('shared selector vectors and immutable admitted selection',async()=>{
  assert.throws(()=>injectBridge(source,'https://parent.test/</script>'),/invalid host origin/);
  const inventory=await readKitAssets();
  const vectors=JSON.parse(readFileSync(new URL('./vectors/kit-selector.json',import.meta.url)));
  for(const v of vectors){if(v.valid)assert.ok(createKitDelivery(inventory,v.selector));else assert.throws(()=>createKitDelivery(inventory,v.selector),undefined,v.name);}
  const mutable=selector('1.0.0');const delivery=createKitDelivery(inventory,mutable);mutable.selections[0].version='1.0.1';
  assert.equal(delivery.resolve(1).release.version,'1.0.0');
  assert.throws(()=>delivery.resolve(2),/kit_major_unavailable/);
  assert.throws(()=>createKitDelivery({...inventory,releases:[{...inventory.releases[0],js:Buffer.from('bad')},...inventory.releases.slice(1)]},selector('1.0.0')),/hash\/length/);
});
test('fake direct and server retain exact prepared release, rollback and source restoration',async()=>{
  const a=await fixtureDelivery('1.0.0'),b=await fixtureDelivery('1.0.1');
  const old=injectBridge(source,'https://parent.test',a),newer=injectBridge(source,'https://parent.test',b);
  assert.notEqual(old,newer);assert.equal(injectBridge(source,'https://parent.test',a),old);
  assert.equal(injectBridge(source,'https://parent.test',b),newer);
  const legacy=source.replace(/<script type="application\/json" id="native-app-kit">.*?<\/script>/,'');
  assert.match(injectBridge(legacy,'https://parent.test',b),/kitFactory=null/);
  assert.throws(()=>injectBridge(source,"https://parent.test",{resolve:()=>a.resolve(1)}),/not admitted/);
  const host=await startFakeHost({descriptor,html:source,kitDelivery:a,fixtures:{sql:{'records.recent':[]}}});
  try {
    const first=await(await fetch(host.origin+'/frame?session=1')).text();

    assert.equal(await(await fetch(host.origin+'/frame?session=1')).text(),first);
    host.selectKitDeliveryForNextSession(b);
    const session=await(await fetch(host.origin+'/__host/frame-session',{method:'POST'})).json();
    assert.equal(session.kit_release.version,'1.0.1');assert.notEqual(await(await fetch(host.origin+session.url)).text(),first);
    assert.equal(await(await fetch(host.origin+'/frame?session=1')).text(),first);
    assert.equal(host.kit_release.js_sha256,a.resolve(1).release.js_sha256);
  }finally{await host.close()}
});

test('shared asset corruption vectors fail admission including correctly rehashed unsafe bytes',async()=>{
  const inventory=await readKitAssets();
  const cases=JSON.parse(readFileSync(new URL('./vectors/kit-asset-corruption.json',import.meta.url)));
  for(const name of cases){
    const m=structuredClone(inventory.releases[0].manifest);let js=Buffer.from(inventory.releases[0].js),types=Buffer.from(inventory.releases[0].types);
    if(name==='hash')m.js.sha256='0'.repeat(64);
    if(name==='length')m.js.bytes++;
    if(name==='utf8')js=Buffer.from([255]);
    if(name==='unsafe-inline')js=Buffer.from('(() => null)() /* </ScRiPt */');
    if(name==='js-cap')js=Buffer.alloc(65537,32);
    if(name==='types-utf8')types=Buffer.from([255]);
    if(name==='manifest-extra')m.extra=true;
    if(!['hash','length'].includes(name)){m.js.bytes=js.length;m.js.sha256=sha256(js);}
    m.types.bytes=types.length;m.types.sha256=sha256(types);
    const manifestBytes=Buffer.from(JSON.stringify(m)),catalog=structuredClone(inventory.catalog);
    catalog.releases[0].manifest_sha256=name==='manifest-hash'?'0'.repeat(64):sha256(manifestBytes);
    if(name==='catalog-extra')catalog.extra=true;
    assert.throws(()=>createKitDelivery({catalog,releases:[{manifest:m,manifestBytes,js,types}]},selector('1.0.0')),undefined,name);
  }
});

test('long canonical origins compose legacy and opted-in sources with a nondefault port',()=>{
  const hostname=[63,63,63,61].map((n,i)=>String.fromCharCode(97+i).repeat(n)).join('.');
  const legacy=source.replace(/<script type="application\/json" id="native-app-kit">.*?<\/script>/,'');
  assert.notEqual(legacy,source);
  for(const port of ['',':65535']){
    const origin=`https://${hostname}${port}`;
    assert.equal(origin.length,261+port.length);assert.equal(new URL(origin).origin,origin);
    for(const html of [legacy,source])assert.ok(injectBridge(html,origin).includes(JSON.stringify(origin)));
  }
  assert.throws(()=>injectBridge(legacy,`https://${'a'.repeat(505)}`),/host origin bounds exceeded/);
});

test('frame preparation and co-edit sessions use separate routes and bounded inventories',async()=>{
  const calls=[];
  const v2={...descriptor,declaration:{contract:'native.app.v2',needs:[],effects:[]}};
  const host=await startFakeHost({descriptor:v2,html:source,latencyMs:0,fixtures:{sql:{'records.recent':[]}},sessions:({recordId})=>{
    calls.push(recordId);
    return recordId==='locked'?{code:'forbidden',message:'no access to locked'}:null;
  }});
  const open=async recordId=>(await fetch(host.origin+'/__host/session',{method:'POST',body:JSON.stringify({recordId,mode:'edit'})})).json();
  const prepare=()=>fetch(host.origin+'/__host/frame-session',{method:'POST'});
  try{
    const first=await(await fetch(host.origin+'/frame?session=1')).text();
    // Co-edit opens must not allocate retained frames or exhaust their 32 slots.
    for(let i=0;i<34;i++)assert.deepEqual(await open('live'),{status:'ok'});
    assert.deepEqual(await open('locked'),{status:'refused',code:'forbidden',message:'no access to locked'});
    assert.equal(calls.length,35);
    const next=await(await prepare()).json();assert.equal(next.url,'/frame?session=2');
    assert.deepEqual(next.kit_release,host.kit_release);
    assert.equal(await(await fetch(host.origin+'/frame?session=1')).text(),first);
    for(let i=0;i<30;i++)assert.equal((await prepare()).status,200);
    assert.equal((await prepare()).status,500);
    assert.equal(await(await fetch(host.origin+'/frame?session=1')).text(),first);
    assert.equal((await fetch(host.origin+'/frame?session=33')).status,404);
    assert.deepEqual(await open('live'),{status:'ok'});
    assert.equal(calls.length,36);
  }finally{await host.close();}
});

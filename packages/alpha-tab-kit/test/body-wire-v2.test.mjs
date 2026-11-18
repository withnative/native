import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {createBodyWireV2} from '../src/body-wire-v2.mjs';
import {createBodyWire} from '../src/body-wire.mjs';
const encode=s=>new TextEncoder().encode(s),sha=s=>createHash('sha256').update(s).digest('hex');
const wire=createBodyWireV2();
const page=()=>({contract:'records.body.read.v2',record_id:'"\\',revision:`body:v1:l:${'a'.repeat(64)}`,body_digest:sha('x'),body_present:true,
  encoding:'utf-8',start_byte:0,end_byte:1,total_bytes:1,text:'x',complete:true,next_cursor:null,
  limits:{max_page_bytes:32768,max_response_bytes:262144},evidence:{state:'live',record_version:'rec:42',
    committed:{body_present:true,body_digest:sha('base'),body_event:{id:'"\\',seq:'40'}},live:{room_state:'active',dirty:true}}});
const decode=value=>wire.decodeHttp(encode(typeof value==='string'?value:JSON.stringify(value)));
const bad=value=>assert.notEqual(decode(value).status,'parsed');
test('v2 data roundtrip is unqualified and v1 stays closed',()=>{
  const r=decode(page());assert.equal(r.status,'parsed');assert.equal(r.qualification,'unqualified');assert.equal(r.value.record_id,'"\\');
  assert.equal(createBodyWire().decodeHttp(encode(JSON.stringify(page()))).kind,'invalid');
  bad({...page(),contract:'records.body.read.v1'});
  const request={contract:'records.body.read.v2',record_id:'"\\',page_bytes:4};
  const typed=wire.validateTypedRequest(request);assert.equal(typed.kind,'request');assert.equal(wire.validateRawRequest(typed.request_json).kind,'request');
  assert.equal(wire.validateTypedRequest({...request,revision:page().revision,cursor:'pin'}).kind,'request');
  for(const extra of [{revision:page().revision},{cursor:'pin'},{revision:page().revision+'\n',cursor:'pin'},{contract:'records.body.read.v1'},{page_bytes:3},{page_bytes:32769},{page_bytes:null},{as_of:1}])assert.equal(wire.validateTypedRequest({...request,...extra}).kind,'invalid');
});
test('duplicate-aware raw scan rejects escaped aliases at every nested schema depth',()=>{
  const raw=JSON.stringify(page());
  for(const [needle,replacement] of [
    ['"contract":','"contract":"records.body.read.v2","con\\u0074ract":'],
    ['"state":','"state":"live","st\\u0061te":'],
    ['"record_version":','"record_version":"rec:42","record_versio\\u006e":'],
    ['"body_present":true,"body_digest":'+JSON.stringify(sha('base')),'"body_present":true,"body_prese\\u006et":true,"body_digest":'+JSON.stringify(sha('base'))],
    ['"id":','"id":"first","i\\u0064":'],
    ['"room_state":','"room_state":"active","room_stat\\u0065":'],
    ['"max_page_bytes":','"max_page_bytes":32768,"max_page_byt\\u0065s":'],
  ]) {assert(raw.includes(needle),needle);bad(raw.replace(needle,replacement));}
  bad('{"contract":"records.body.read.v2","error":{"code":"access_lost","co\\u0064e":"access_lost","reason":"target"}}');
  assert.equal(wire.validateRawRequest('{"contract":"records.body.read.v2","record_id":"x","record_\\u0069d":"y"}').kind,'invalid');
  const text=page();text.text='"body_event":{"id":"not a key"}';text.total_bytes=text.end_byte=Buffer.byteLength(text.text);text.body_digest=sha(text.text);assert.equal(decode(text).status,'parsed');
});
test('raw byte, UTF8, grammar, nesting and closed scalar boundaries before parse',()=>{
  for(const raw of ['[]','null','{} trailing','\ufeff'+JSON.stringify(page()),JSON.stringify(page())+'{}',
    '{"contract":"records.body.read.v2","evidence":{"committed":{"body_event":{"id":{}}}}}',
    '{"contract":"records.body.read.v2","evidence":{"state":[]}}',
    '{"contract":"records.body.read.v2","limits":{"max_page_bytes":01}}',
    '{"contract":"records.body.read.v2","__proto__":{}}'])bad(raw);
  assert.equal(wire.decodeHttp(new Uint8Array([0xff])).kind,'invalid');assert.equal(wire.decodeHttp(new Uint8Array(262145)).kind,'invalid');
  assert.equal(wire.validateRawRequest(' '.repeat(4097)).kind,'invalid');
  assert.equal(wire.validateRawRequest('"'+'é'.repeat(2048)+'"').kind,'invalid');
  const p=page();p.text='\ud800';bad(p);
  for(const id of ['','x'.repeat(129),'é','x\n'])assert.equal(wire.validateTypedRequest({contract:'records.body.read.v2',record_id:id}).kind,'invalid');
  for(const id of ['x','x'.repeat(128),'"\\'])assert.equal(wire.validateTypedRequest({contract:'records.body.read.v2',record_id:id}).kind,'request');
});
test('closed refusal/transport variants cannot advertise not_offered or downgrade',()=>{
  for(const [code,reason] of [['revision_changed','incarnation'],['invalid_cursor','cursor'],['current_body_unavailable','sealed'],['current_body_unavailable','basis_changed']])assert.equal(decode({contract:'records.body.read.v2',error:{code,reason}}).status,'parsed');
  for(const [code,reason] of [['revision_changed','cursor'],['unknown','secret'],['not_offered','target']])bad({contract:'records.body.read.v2',error:{code,reason}});
  for(const reason of ['busy','timeout','cancelled','protocol','mount_unavailable','invalid_message'])assert.equal(decode({contract:'records.body.transport.v2',reason}).kind,'transport');
  for(const reason of ['not_offered','closed','network'])bad({contract:'records.body.transport.v2',reason});
  bad('{"contract":"records.body.transport.v2","reason":"busy","reas\\u006fn":"busy"}');
  assert.equal(wire.decodeHttp(encode('{"contract":"records.body.transport.v2","reason":"busy"}'),{recordId:'task',pageBytes:3}).kind,'invalid');
});
test('no global discovery/advertisement; typed traps cannot run through inspection',()=>{
  // Node lazily initializes web globals while materializing their descriptors.
  Object.getOwnPropertyDescriptors(globalThis);
  const before=Object.getOwnPropertyDescriptors(globalThis);createBodyWireV2();
  const after=Object.getOwnPropertyDescriptors(globalThis);
  assert.deepEqual(Reflect.ownKeys(after),Reflect.ownKeys(before));
  for(const key of Reflect.ownKeys(before))for(const field of ['value','get','set','writable','enumerable','configurable'])assert.equal(after[key][field],before[key][field]);
  const path=new URL('../src/body-wire-v2.mjs',import.meta.url).href;
  const child=spawnSync(process.execPath,['--input-type=module','-e',`
    import assert from 'node:assert/strict';
    Object.defineProperty(globalThis,'nativeArtifact',{configurable:true,get(){throw Error('global discovery');}});
    Object.defineProperty(globalThis,'window',{configurable:true,get(){throw Error('window discovery');}});
    Object.getOwnPropertyDescriptors(globalThis);
    const before=Object.getOwnPropertyDescriptors(globalThis);
    const m=await import(${JSON.stringify(path)});m.createBodyWireV2();
    const after=Object.getOwnPropertyDescriptors(globalThis);
    assert.deepEqual(Reflect.ownKeys(after),Reflect.ownKeys(before));
    for(const key of Reflect.ownKeys(before))for(const f of ['value','get','set','writable','enumerable','configurable'])assert.equal(after[key][f],before[key][f]);
  `],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
  const getter={contract:'records.body.read.v2'};Object.defineProperty(getter,'record_id',{enumerable:true,get(){throw Error('private');}});
  assert.equal(wire.validateTypedRequest(getter).kind,'invalid');
  assert.equal(wire.validateTypedRequest(new Proxy({}, {ownKeys(){throw Error('private');}})).kind,'invalid');
});

test('raw snapshot uses native bounded byte length, not an authored getter; detached bytes refuse',()=>{
  const bytes=encode(JSON.stringify(page()));
  Object.defineProperty(bytes,'byteLength',{get(){throw Error('must not inspect');}});
  assert.equal(wire.decodeHttp(bytes).status,'parsed');
  const detached=encode(JSON.stringify(page()));structuredClone(detached.buffer,{transfer:[detached.buffer]});
  assert.equal(wire.decodeHttp(detached).kind,'invalid');
  assert.equal(wire.decodeHttp(new Proxy(bytes,{})).kind,'invalid');
});

test('P2 raw scanner/decoder/request codec retain captured intrinsics and real-crypto results',()=>{
  const path=new URL('../src/body-wire-v2.mjs',import.meta.url).href;
  const current=new URL('../src/body-current-v2.mjs',import.meta.url).href;
  const fixture=page(),wrong=page();wrong.text='y';
  const script=`
    import assert from 'node:assert/strict';
    const w=(await import(${JSON.stringify(path)})).createBodyWireV2(),m=await import(${JSON.stringify(current)});
    const text=${JSON.stringify(JSON.stringify(fixture))},badText=${JSON.stringify(JSON.stringify(wrong))};
    const encoder=new TextEncoder(),good=encoder.encode(text),bad=encoder.encode(badText);
    const duplicate=encoder.encode(text.replace('"id":','"id":"first","i\\\\u0064":'));
    const rawRequest=JSON.stringify({contract:'records.body.read.v2',record_id:'task',page_bytes:4});
    const def=Object.defineProperty,get=Object.getOwnPropertyDescriptor,restore=[],Bytes=Uint8Array;let hooks=0;
    const replace=(o,k,value)=>{restore[restore.length]=[o,k,get(o,k)];def(o,k,{configurable:true,writable:true,value});};
    replace(globalThis,'Uint8Array',function(){return new Bytes(good);});replace(globalThis,'TextDecoder',function(){throw Error('decoder');});
    replace(TextDecoder.prototype,'decode',()=>text);replace(TextEncoder.prototype,'encode',()=>good);
    replace(JSON,'parse',()=>(${JSON.stringify(fixture)}));replace(JSON,'stringify',()=>rawRequest);
    for(let j=0,ks=['create','hasOwn','getOwnPropertyDescriptor','getPrototypeOf','freeze'];j<ks.length;j++){const k=ks[j];replace(Object,k,()=>{throw Error(k);});}
    replace(Reflect,'ownKeys',()=>{throw Error('keys');});replace(Number,'isSafeInteger',()=>true);
    for(let j=0,ks=['includes','some','map','filter','join','push'];j<ks.length;j++){const k=ks[j];replace(Array.prototype,k,()=>{throw Error(k);});}
    replace(Array.prototype,Symbol.iterator,()=>{throw Error('iterator');});
    for(let j=0,ks=['charCodeAt','slice','startsWith'];j<ks.length;j++){const k=ks[j];replace(String.prototype,k,()=>{throw Error(k);});}
    replace(RegExp.prototype,'test',()=>true);replace(RegExp.prototype,'exec',()=>null);
    replace(WeakSet.prototype,'has',()=>true);replace(WeakSet.prototype,'add',()=>{});
    replace(Object.prototype,'toJSON',()=>{hooks++;throw Error('toJSON');});replace(Array.prototype,'toJSON',()=>{hooks++;throw Error('toJSON');});
    let decoded,rejected,request,yes,no;
    const complete=p=>({contract:'records.body.complete.v2',record_id:p.record_id,body:p.text,body_present:p.body_present,
      body_digest:p.body_digest,revision:p.revision,total_bytes:p.total_bytes,evidence:p.evidence});
    try{decoded=w.decodeHttp(good);rejected=w.decodeHttp(duplicate);request=w.validateRawRequest(rawRequest);
      yes=await m.verifyCompleteBodyV2(complete(decoded.value));no=await m.verifyCompleteBodyV2(complete(w.decodeHttp(bad).value));}
    finally{for(let i=restore.length-1;i>=0;i--){const r=restore[i];if(r[2])def(r[0],r[1],r[2]);else delete r[0][r[1]];}}
    assert.equal(decoded.status,'parsed');assert.equal(decoded.value.text,'x');assert.notEqual(rejected.status,'parsed');
    assert.equal(request.kind,'request');assert.equal(yes.status,'verified');assert.equal(no.status,'refused');assert.equal(no.reason,'digest_mismatch');assert.equal(hooks,0);
  `;
  const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

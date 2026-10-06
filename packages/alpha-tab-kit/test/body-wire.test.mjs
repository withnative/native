import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { createBodyWire } from '@withnative/alpha-tab-kit/body-wire';
const wire = createBodyWire();
const golden = JSON.parse(readFileSync(new URL('../fixtures/body-read-v1.json', import.meta.url)));
const bytes = text => new TextEncoder().encode(text);
const json = value => bytes(JSON.stringify(value));
const resultEqual = (actual, expected) => { assert.equal(Object.getPrototypeOf(actual),null); assert.deepEqual({...actual}, expected); };
const invalid = value => resultEqual(wire.decodeHttp(typeof value === 'string' ? bytes(value) : value), {kind:'invalid',reason:'protocol'});
const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const page = (text = 'é😀') => ({contract:'records.body.read.v1',record_id:'doc',revision:'opaque-revision',body_digest:'a'.repeat(64),body_present:true,encoding:'utf-8',start_byte:0,end_byte:Buffer.byteLength(text),total_bytes:Buffer.byteLength(text),text,complete:true,next_cursor:null,limits:{max_page_bytes:32768,max_response_bytes:262144}});
const envelope = (kind, extra = {}) => ({version:'native.html.bridge.v1',type:kind,request_id:'body-1',...extra});

test('owning factory/ESM/production bootstrap generation matches', () => {
  const result = spawnSync(process.execPath, ['scripts/generate-body-wire.mjs','--check'], {cwd:new URL('..',import.meta.url),encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/production bootstrap/);
  assert.doesNotMatch(readFileSync(new URL('../src/body-wire.mjs',import.meta.url),'utf8'),/import .*node:|eval\(|new Function/);
});
for (const value of golden) test(`same golden ${value.error.code}/${value.error.reason}`, () => {
  const result = wire.decodeHttp(json(value));
  assert.equal(result.kind,'body'); assert.deepEqual(JSON.parse(JSON.stringify(result.response)),value);
  assert.equal(Object.getPrototypeOf(result.response),null);
  assert.equal(Object.getPrototypeOf(result.response.error),null);
  assert.ok(Object.isFrozen(result.response.error));
});
test('legal reordered keys and every optional limit presence survive', () => {
  const optional=['max_body_bytes','max_source_bytes','max_provenance_payload_bytes','max_provenance_events','request_timeout_ms'];
  for(let mask=0;mask<32;mask++) {
    const p=page();for(let i=0;i<5;i++)if(mask&(1<<i))p.limits[optional[i]]=100000;
    const reordered=Object.fromEntries(Object.entries(p).reverse());
    const r=wire.decodeHttp(json(reordered),{recordId:'doc',pageBytes:7});
    assert.equal(r.kind,'body'); assert.equal(Object.getPrototypeOf(r.response.limits),null);
    assert.deepEqual(Object.keys(r.response.limits).sort(),Object.keys(p.limits).sort());
  }
});
test('decoded duplicates root/limits/error including escape-equivalent keys refuse', () => {
  const p=JSON.stringify(page());
  invalid(p.replace('"record_id":"doc"','"record_id":"doc","record_id":"doc"'));
  invalid(p.replace('"contract":','"\\u0063ontract":"records.body.read.v1","contract":'));
  invalid(p.replace('"max_page_bytes":32768','"max_page_bytes":32768,"max_\\u0070age_bytes":32768'));
  invalid('{"contract":"records.body.read.v1","error":{"code":"timeout","\\u0063ode":"timeout","reason":"request"}}');
});
test('closed shapes reject arrays, mixed schemas, objects, unknown fields and depth3', () => {
  for(const s of ['[]','null','{}','{"contract":"records.body.read.v1","error":[]}',
    '{"contract":"records.body.read.v1","error":{"code":{"code":"timeout"},"reason":"request"}}',
    '{"contract":"records.body.read.v1","error":{"code":"timeout","reason":"request","extra":0}}',
    '{"contract":"records.body.transport.v1","reason":"busy","error":{"code":"timeout","reason":"request"}}']) invalid(s);
  invalid(JSON.stringify({...page(),extra:0}));
  invalid(JSON.stringify({...page(),limits:{...page().limits,unknown:1}}));
});
test('complete JSON grammar before parse, no prefixes/trailing text or BOM', () => {
  const good=JSON.stringify(page());
  for(const n of ['01','+1','1.','1e','1e+','--1','NaN','Infinity']) invalid(good.replace('"start_byte":0','"start_byte":'+n));
  for(const s of [good+'{}',good+',',good.slice(0,-1)+',}',good.slice(0,-1),good.replace('"text":"é😀"','"text":"\\q"'),
    good.replace('"text":"é😀"','"text":"\n"'),good.replace('true','True'),'\ufeff'+good,' \ufeff'+good]) invalid(s);
  assert.equal(wire.decodeHttp(bytes(' \t\r\n'+good+' \n')).kind,'body');
  assert.equal(wire.decodeHttp(bytes(good.replace('"start_byte":0','"start_byte":0e0'))).kind,'body');
});
test('fatal UTF8 rejects invalid bytes and envelope BOM but preserves string BOM/scalars', () => {
  invalid(new Uint8Array([0xff])); invalid(new Uint8Array([0xc0,0xaf])); invalid(new Uint8Array([0xed,0xa0,0x80]));
  const p=page('\ufeffé😀'); assert.equal(wire.decodeHttp(json(p)).response.text,p.text);
  assert.equal(wire.decodeHttp(bytes(JSON.stringify(p).replace('\ufeff','\\ufeff'))).response.text,p.text);
  invalid(JSON.stringify(page()).replace('"text":"é😀"','"text":"\\ud800"'));
  invalid(new Uint16Array([123,125]));invalid(new Proxy(new Uint8Array([123,125]),{}));
});
test('Page semantics, correlation, offsets, presence and safe integers stay fail closed', () => {
  for(const p of [ {...page(),end_byte:1}, {...page(),total_bytes:9007199254740992}, {...page(),start_byte:-1},
    {...page(),complete:false,next_cursor:null}, {...page(),body_present:false}, {...page(),body_digest:'A'.repeat(64)},
    {...page(),revision:''}, {...page(),limits:{max_page_bytes:3,max_response_bytes:262144}},
    {...page(),limits:{max_page_bytes:32768,max_response_bytes:262145}},
    {...page(),limits:{max_page_bytes:32768,max_response_bytes:262144,request_timeout_ms:0}}]) invalid(json(p));
  assert.equal(wire.decodeHttp(json(page()),{recordId:'other',pageBytes:7}).kind,'invalid');
  assert.equal(wire.decodeHttp(json(page()),{recordId:'doc',pageBytes:4}).kind,'invalid');
  const empty={...page(''),body_digest:EMPTY};
  for(const body_present of [true,false])assert.equal(wire.decodeHttp(json({...empty,body_present})).kind,'body');
  invalid(json({...empty,body_digest:'0'.repeat(64)}));
});
test('raw string fidelity and actual surrogate rejection precede replacement encoding', () => {
  for(const raw of [' \n[null] ','{"record_id":"a","record_id":"b"}','\ufeff{}','{"record_id":"\\ud800"}']) {
    const r=wire.validateRawRequest(raw);assert.equal(r.kind,'request');assert.equal(r.request_json,raw);
  }
  assert.equal(wire.validateRawRequest('é'.repeat(2048)).kind,'request');
  for(const bad of ['é'.repeat(2049),'\ud800','\udc00',null,{},new String('{}')])assert.equal(wire.validateRawRequest(bad).kind,'invalid');
});
test('typed request keeps optional absence and requires exact data shape/correlation', () => {
  assert.equal(wire.validateTypedRequest({record_id:'doc'}).request_json,'{"record_id":"doc"}');
  assert.equal(wire.validateTypedRequest({record_id:'doc',revision:'r',cursor:'c'}).kind,'request');
  for(const bad of [{record_id:'doc',page_bytes:null},{record_id:'doc',revision:'r'}, {record_id:'doc',cursor:'c'},
    {record_id:'doc',extra:1},{record_id:'doc',page_bytes:3},{record_id:'doc',page_bytes:32769},
    {record_id:'\ud800'},[],null])resultEqual(wire.validateTypedRequest(bad),{kind:'invalid',reason:'invalid_message'});
});
test('HTTP transport discriminator is small, closed and distinct from engine refusals', () => {
  for(const reason of ['invalid_message','busy','mount_unavailable','timeout','cancelled','protocol'])
    resultEqual(wire.decodeHttp(json({contract:'records.body.transport.v1',reason})),{kind:'transport',reason});
  for(const reason of ['network','closed','not_offered','unknown'])invalid(json({contract:'records.body.transport.v1',reason}));
  invalid(' '.repeat(513)+JSON.stringify({contract:'records.body.transport.v1',reason:'busy'}));
  invalid(json({contract:'records.body.transport.v1',reason:'busy',error:{}}));
  assert.equal(wire.decodeHttp(json({contract:'records.body.read.v1',error:{code:'timeout',reason:'request'}})).kind,'body');
  invalid(json({contract:'records.body.read.v1',error:{code:'timeout',reason:'timeout'}}));
  invalid(json({contract:'records.body.read.v1',error:{code:'engine',reason:'private'.repeat(10000)}}));
  const mappings={InvalidIngress:'invalid_message',Busy:'busy',MountUnavailable:'mount_unavailable',Deadline:'timeout',Cancelled:'cancelled',HtmlUnavailable:'protocol',Engine:'protocol',Issued:'protocol',Retired:'protocol',AuthCatalog:'mount_unavailable'};
  for(const [variant,reason]of Object.entries(mappings))assert.equal(wire.mapHostRefusal(variant),reason);
});
test('escaped32KiB response >64KiB still obeys result and full nested envelope caps', () => {
  const p=page('\0'.repeat(32768)); const encoded=json(p);assert.ok(encoded.length>65536&&encoded.length<=262144);
  const r=wire.decodeHttp(encoded);assert.equal(r.kind,'body');
  const e=wire.encodeChannel(envelope('body-read-result',{response:p}),'result');
  assert.equal(e.kind,'encoded');assert.ok(e.utf8Bytes<=262656);assert.equal(Object.getPrototypeOf(e.data),null);
  invalid(new Uint8Array(262145));
  const exact={...p,limits:{...p.limits,max_response_bytes:encoded.length}};
  assert.equal(wire.decodeHttp(json(exact)).kind,'body');
  invalid(json({...p,limits:{...p.limits,max_response_bytes:json(exact).length-1}}));
});
test('channel request/cancel/transport/offering closed encoding never changes raw text', () => {
  const raw='"'.repeat(4096);const r=wire.encodeChannel(envelope('body-read',{request_json:raw}),'request');
  assert.equal(r.kind,'encoded');assert.equal(r.data.request_json,raw);assert.ok(r.utf8Bytes<=32768);
  assert.equal(wire.encodeChannel(envelope('body-read-cancel'),'cancel').kind,'encoded');
  assert.equal(wire.encodeChannel(envelope('body-read-transport',{reason:'closed'}),'transport').kind,'encoded');
  const offer={contract:'records.body.read.v1',scope:'viewer-visible-current-bodies',max_request_bytes:4096,max_response_bytes:262144,max_page_bytes:32768,max_body_bytes:16777216,request_timeout_ms:5000,max_inflight:1};
  assert.equal(wire.encodeChannel(offer,'offering').kind,'encoded');
  for(const v of [{...offer,max_response_bytes:65536},{...offer,extra:true}])assert.equal(wire.encodeChannel(v,'offering').kind,'invalid');
  assert.equal(wire.encodeChannel({...envelope('body-read-cancel'),extra:0},'cancel').kind,'invalid');
  assert.equal(wire.encodeChannel(envelope('body-read',{request_json:'é'.repeat(2049)}),'request').kind,'invalid');
});
test('hostile accessor/proxy exceptions are never inspected or forwarded', () => {
  let inspection=0,access=0;
  const thrown=new Proxy({}, {get(){inspection++;throw 0;},getPrototypeOf(){inspection++;throw 0;},ownKeys(){inspection++;throw 0;}});
  const getter={};Object.defineProperty(getter,'record_id',{enumerable:true,get(){access++;throw thrown;}});
  assert.equal(wire.validateTypedRequest(getter).kind,'invalid');
  for(const trap of ['getPrototypeOf','ownKeys','getOwnPropertyDescriptor']) {
    const hostile=new Proxy({record_id:'doc'},{[trap](){throw thrown;}});
    assert.equal(wire.validateTypedRequest(hostile).kind,'invalid');
    assert.equal(wire.validateBody(hostile).kind,'invalid');
    assert.equal(wire.encodeChannel(hostile,'request').kind,'invalid');
  }
  assert.equal(wire.validateBody(page(),new Proxy({},{ownKeys(){throw thrown;}})).kind,'invalid');
  assert.equal(wire.mapHostRefusal(thrown),'protocol');assert.equal(access,0);assert.equal(inspection,0);
});
test('captured parse only after scan; inherited toJSON/method poisoning cannot alter products', () => {
  const module=readFileSync(new URL('../src/body-wire.mjs',import.meta.url),'utf8');
  const context=vm.createContext({TextEncoder,TextDecoder});
  vm.runInContext(module.replace('export function createBodyWire()','function createBodyWire()')+';globalThis.w=wire',context);
  vm.runInContext('Object.prototype.toJSON=function(){throw new Error("poison")}; JSON.stringify=function(){throw new Error("poison")}; JSON.parse=function(){throw new Error("poison")}; String.prototype.charCodeAt=function(){throw 0}',context);
  const result=vm.runInContext('w.validateTypedRequest({record_id:"doc"})',context);
  assert.equal(result.request_json,'{"record_id":"doc"}');
});

test('captured define uses null-prototype descriptors after inherited descriptor-accessor poisoning', () => {
  const module=readFileSync(new URL('../src/body-wire.mjs',import.meta.url),'utf8');
  const context=vm.createContext({TextEncoder,TextDecoder});
  vm.runInContext(module.replace('export function createBodyWire()','function createBodyWire()')+';globalThis.w=wire',context);
  const p=page();
  const refusal=golden[0];
  const result=vm.runInContext(`
    (()=>{
    let accessorReads=0, thrownInspections=0;
    const thrown=new Proxy({}, {get(){thrownInspections++;throw 0;}});
    const capturedDefine=Object.defineProperty;
    for (const member of ['get','set','value','writable','enumerable','configurable']) {
      const descriptor=Object.create(null);
      descriptor.get=()=>{accessorReads++;throw thrown;};
      descriptor.configurable=true;
      capturedDefine(Object.prototype,member,descriptor);
    }
    const typed=w.validateTypedRequest({record_id:'doc'});
    const body=w.validateBody(${JSON.stringify(p)});
    const refusal=w.validateBody(${JSON.stringify(refusal)});
    const decoded=w.decodeHttp(new TextEncoder().encode(${JSON.stringify(JSON.stringify(p))}));
    const channel=w.encodeChannel({version:'native.html.bridge.v1',type:'body-read-result',request_id:'body-1',response:${JSON.stringify(p)}},'result');
    return {typed,body,refusal,decoded,channel,accessorReads,thrownInspections};
    })()
  `,context);
  assert.equal(result.accessorReads,0);
  assert.equal(result.thrownInspections,0);
  assert.equal(result.typed.kind,'request');
  assert.equal(result.typed.request_json,'{"record_id":"doc"}');
  for (const body of [result.body,result.decoded]) {
    assert.equal(body.kind,'body');
    assert.deepEqual(JSON.parse(JSON.stringify(body.response)),p);
  }
  assert.equal(result.refusal.kind,'body');
  assert.deepEqual(JSON.parse(JSON.stringify(result.refusal.response)),refusal);
  assert.equal(result.channel.kind,'encoded');
  assert.deepEqual(JSON.parse(JSON.stringify(result.channel.data)),envelope('body-read-result',{response:p}));
  for (const data of [result.body.response,result.body.response.limits,result.refusal.response.error,result.channel.data]) {
    assert.equal(Object.getPrototypeOf(data),null);
    assert.ok(Object.isFrozen(data));
    for (const key of Object.keys(data)) {
      const descriptor=Object.getOwnPropertyDescriptor(data,key);
      assert.equal(descriptor.enumerable,true);
      assert.equal(descriptor.writable,false);
      assert.equal(descriptor.configurable,false);
    }
  }
});


test('native parse is never called before closed duplicate-aware grammar succeeds', () => {
  const module=readFileSync(new URL('../src/body-wire.mjs',import.meta.url),'utf8');
  const context=vm.createContext({TextEncoder,TextDecoder});
  vm.runInContext('globalThis.parses=0; const originalParse=JSON.parse; JSON.parse=function(s){parses++;return originalParse(s)}',context);
  vm.runInContext(module.replace('export function createBodyWire()','function createBodyWire()')+';globalThis.w=wire',context);
  for(const raw of ['{}','{"contract":"records.body.read.v1","error":{"code":"timeout","code":"timeout","reason":"request"}}', '{"contract":"records.body.transport.v1","reason":"busy"} trailing']) {
    context.input=bytes(raw); assert.equal(vm.runInContext('w.decodeHttp(input).kind',context),'invalid');
    assert.equal(context.parses,0);
  }
  context.input=json(golden[0]);assert.equal(vm.runInContext('w.decodeHttp(input).kind',context),'body');assert.equal(context.parses,1);
});
test('raw HTTP caps are exact even with legal whitespace and transport uses512 not262144', () => {
  const p=JSON.stringify(page());
  assert.equal(wire.decodeHttp(bytes(p+' '.repeat(262144-Buffer.byteLength(p)))).kind,'body');
  invalid(bytes(p+' '.repeat(262145-Buffer.byteLength(p))));
  const t=JSON.stringify({contract:'records.body.transport.v1',reason:'busy'});
  assert.equal(wire.decodeHttp(bytes(t+' '.repeat(512-Buffer.byteLength(t)))).kind,'transport');
  invalid(bytes(t+' '.repeat(513-Buffer.byteLength(t))));
});
test('bounded owned snapshot accepts shared bytes without retaining caller memory', () => {
  const raw=json(page()); const shared=new Uint8Array(new SharedArrayBuffer(raw.length));shared.set(raw);
  const r=wire.decodeHttp(shared);assert.equal(r.kind,'body');shared.fill(0);assert.equal(r.response.text,'é😀');
});
test('channel IDs, fields and typed/expected proxies retain finite static failures', () => {
  assert.equal(wire.encodeChannel(envelope('body-read-cancel'), 'unknown').kind,'invalid');
  assert.equal(wire.encodeChannel({...envelope('body-read-cancel'),request_id:'x'.repeat(129)},'cancel').kind,'invalid');
  assert.equal(wire.validateTypedRequest({record_id:'doc',[Symbol('hidden')]:0}).kind,'invalid');
  assert.equal(wire.validateBody(page(),{recordId:'doc',pageBytes:7,extra:0}).kind,'invalid');
  assert.equal(wire.validateBody(page(),{recordId:'doc',pageBytes:7.5}).kind,'invalid');
});


test('expected is validated once even on transport and raw response has no invented correlation', () => {
  let reads=0;const expected=new Proxy({recordId:'doc',pageBytes:7},{ownKeys(target){reads++;return Reflect.ownKeys(target)}});
  assert.equal(wire.decodeHttp(json(page()),expected).kind,'body');assert.equal(reads,1);
  assert.equal(wire.decodeHttp(json({contract:'records.body.transport.v1',reason:'busy'}),{recordId:'doc',pageBytes:3}).kind,'invalid');
  assert.equal(wire.decodeHttp(json(page())).response.record_id,'doc');
});

test('valid continuation page is a single-page proof, not an assembler or recomputed CAS', () => {
  const p = {...page(),start_byte:6,end_byte:12,total_bytes:18,complete:false,next_cursor:'opaque-next'};
  const r = wire.decodeHttp(json(p),{recordId:'doc',pageBytes:6});
  assert.equal(r.kind,'body');
  assert.equal(r.response.body_digest,'a'.repeat(64)); // Deliberately unrelated to text hash.
  assert.equal(r.response.revision,'opaque-revision');
  assert.equal(r.response.next_cursor,'opaque-next');
  assert.equal(r.response.start_byte,6);
});

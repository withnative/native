import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readBodyV2} from '../src/body-reader-v2.mjs';
import {isVerifiedBodyV2} from '../src/body-current-v2.mjs';
const sha=s=>createHash('sha256').update(s).digest('hex');
function pages(body,parts=[body]) {
  let at=0;return parts.map((text,index)=>{
    const start=at;at+=Buffer.byteLength(text);return {contract:'records.body.read.v2',record_id:'task',revision:`body:v1:l:${'a'.repeat(64)}`,
      body_digest:sha(body),body_present:true,encoding:'utf-8',start_byte:start,end_byte:at,total_bytes:Buffer.byteLength(body),text,
      complete:index===parts.length-1,next_cursor:index===parts.length-1?null:`cursor-${index}`,
      limits:{max_page_bytes:32768,max_response_bytes:262144},
      evidence:{state:'live',record_version:'rec:42',committed:{body_present:true,body_digest:sha('base'),body_event:{id:'event',seq:'40'}},live:{room_state:'grace',dirty:true}}};
  });
}
async function run(list,options={}) {let at=0;return readBodyV2({recordId:'task',readPage:async()=>list[at++],...options});}
test('genuine assembly preserves BOM/scalars, pins immutable evidence, real SHA qualification',async()=>{
  const body='\ufeffé😀last',list=pages(body,['\ufeff','é😀','last']),progress=[];
  let at=0;const r=await readBodyV2({recordId:'task',pageBytes:8,readPage:async request=>{
    assert.equal(request.contract,'records.body.read.v2');if(at)assert.equal(request.revision,list[0].revision);
    return list[at++];},onProgress:p=>progress.push(p)});
  assert.equal(r.status,'verified');assert(isVerifiedBodyV2(r));assert.equal(r.value.body,body);assert.equal(r.value.evidence.state,'live');assert.equal(progress.length,3);
  const changed=pages('xy',['x','y']);let i=0;
  const owned=await readBodyV2({recordId:'task',readPage:async()=>{if(i)changed[0].evidence.committed.body_event.id='mutation';return changed[i++];}});
  assert.equal(owned.status,'verified');assert.equal(owned.value.evidence.committed.body_event.id,'event');
});
test('every observation/evidence/limit coordinate and completion error aborts without fallback',async()=>{
  for(const mutate of [
    p=>p.revision=`body:v1:l:${'b'.repeat(64)}`,p=>p.evidence.record_version='rec:43',
    p=>p.evidence.committed.body_event.id='new',p=>p.evidence.committed.body_event.seq='41',
    p=>p.evidence.live.room_state='active',p=>p.evidence.live.dirty=false,
    p=>p.limits.max_page_bytes=100,p=>p.limits.request_timeout_ms=4,p=>p.body_digest=sha('zz'),
    p=>p.start_byte=0,p=>p.total_bytes=3,p=>p.complete=false,p=>p.text='\ud800',
    p=>p.contract='records.body.read.v1',p=>delete p.evidence,
  ]) {const list=pages('xy',['x','y']);mutate(list[1]);const r=await run(list);assert.equal(r.status,'refused');assert(!isVerifiedBodyV2(r));}
  const wrong=pages('x');wrong[0].body_digest=sha('y');assert.equal((await run(wrong)).reason,'digest_mismatch');
  const extra=pages('x');extra[0].limits.max_source_bytes=0;assert.equal((await run(extra)).status,'refused');
  assert.equal((await run(pages('xx'),{maxBodyBytes:1})).code,'client_limit');
  const overhead=pages('x');overhead[0].limits.max_response_bytes=10;assert.equal((await run(overhead)).status,'refused');
});
test('absent vs present empty remains distinct and qualified',async()=>{
  const absent=pages('');Object.assign(absent[0],{body_present:false,revision:`body:v1:d:${'a'.repeat(64)}`,
    evidence:{state:'durable',record_version:'rec:0',committed:{body_present:false,body_digest:sha(''),body_event:null},live:null}});
  const r=await run(absent);assert.equal(r.status,'verified');assert.equal(r.value.body,null);
  const e=await run(pages(''));assert.equal(e.status,'verified');assert.equal(e.value.body,'');
});
test('refusal/invalid/unknown or v1 never retries or discovers any alternative',async()=>{
  for(const response of [undefined,{contract:'records.body.read.v1'},
    {contract:'records.body.read.v2',error:{code:'source_integrity',reason:'source'}},
    {contract:'records.body.read.v2',error:{code:'current_body_unavailable',reason:'quarantined'}},
    {contract:'records.body.read.v2',error:{code:'revision_changed',reason:'cursor'}}]) {
    let calls=0;const r=await readBodyV2({recordId:'task',readPage:async()=>{calls++;return response;}});
    assert.equal(r.status,'refused');assert.equal(calls,1);
  }
  assert.equal((await readBodyV2({recordId:'task',readPage:async()=>{throw Error('private');}})).reason,'read_page_failed');
  assert.equal((await readBodyV2({recordId:'task',readPage:async()=>pages('x')[0],hash:()=>sha('x')})).reason,'invalid_options');
});
test('abort/late rejection and failing progress cannot expose completed data',async()=>{
  const controller=new AbortController();let reject,entered;
  const started=new Promise(resolve=>entered=resolve);
  const pending=readBodyV2({recordId:'task',signal:controller.signal,readPage:()=>{entered();return new Promise((_,no)=>reject=no);}});
  await started;controller.abort();assert.equal((await pending).reason,'aborted');reject(Error('late private rejection'));await new Promise(resolve=>setImmediate(resolve));
  const c=new AbortController();let calls=0;
  const r=await readBodyV2({recordId:'task',signal:c.signal,readPage:async()=>pages('xy',['x','y'])[calls++],onProgress:()=>c.abort()});
  assert.equal(r.reason,'aborted');assert.equal(calls,1);
  for(const onProgress of [()=>{throw Error('private');},()=>Promise.reject(Error('late'))])assert.equal((await run(pages('x'),{onProgress})).reason,'progress_failed');
});

test('canonical equality ignores JSON member order but assembly has no no-crypto shortcut',async()=>{
  const list=pages('xy',['x','y']);
  const reverse=o=>Object.fromEntries(Object.entries(o).reverse());
  list[1].evidence=reverse({...list[1].evidence,committed:reverse(list[1].evidence.committed),live:reverse(list[1].evidence.live)});
  list[1].limits=reverse(list[1].limits);
  assert.equal((await run(list)).status,'verified');
  const path=new URL('../src/body-reader-v2.mjs',import.meta.url).href;
  const child=spawnSync(process.execPath,['--input-type=module','-e',`
    import assert from 'node:assert/strict';
    Object.defineProperty(globalThis,'crypto',{configurable:true,value:undefined});
    const m=await import(${JSON.stringify(path)});
    const r=await m.readBodyV2({recordId:'task',readPage:async()=>(${JSON.stringify(pages('abc')[0])})});
    assert.equal(r.status,'refused');assert.equal(r.reason,'crypto_unavailable');
  `],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

test('P2 callback/progress mutations cannot substitute bytes/canonical evidence or invoke inherited toJSON',()=>{
  const path=new URL('../src/body-reader-v2.mjs',import.meta.url).href;
  const good=pages('\ufeffé😀last',['\ufeff','é😀','last']);
  const script=`
    import assert from 'node:assert/strict';
    const m=await import(${JSON.stringify(path)});const list=${JSON.stringify(good)};
    const wrong=JSON.parse(JSON.stringify(list));wrong[2].text='evil';
    const def=Object.defineProperty,get=Object.getOwnPropertyDescriptor,restore=[],NativePromise=Promise;let hooks=0,at=0;
    const replace=(o,k,value)=>{restore[restore.length]=[o,k,get(o,k)];def(o,k,{configurable:true,writable:true,value});};
    const poison=()=>{
      for(let j=0,ks=['map','join','push','includes','some','filter'];j<ks.length;j++){const k=ks[j];replace(Array.prototype,k,()=>{throw Error(k);});}
      replace(Array.prototype,Symbol.iterator,()=>{throw Error('iterator');});
      replace(JSON,'stringify',()=> 'same');replace(JSON,'parse',()=>list[0]);
      for(let j=0,ks=['create','hasOwn','getOwnPropertyDescriptor','getPrototypeOf','freeze'];j<ks.length;j++){const k=ks[j];replace(Object,k,()=>{throw Error(k);});}
      replace(Number,'isSafeInteger',()=>true);replace(Reflect,'ownKeys',()=>{throw Error('keys');});
      replace(TextEncoder.prototype,'encode',()=>new Uint8Array());replace(TextDecoder.prototype,'decode',()=> 'substituted');
      replace(globalThis,'TextDecoder',function(){throw Error('decoder');});replace(globalThis,'TextEncoder',function(){throw Error('encoder');});
      replace(Promise.prototype,'then',()=>{throw Error('then');});
      replace(Object.prototype,'toJSON',()=>{hooks++;throw Error('toJSON');});replace(Array.prototype,'toJSON',()=>{hooks++;throw Error('toJSON');});
    };
    let result,negative;
    try{result=await m.readBodyV2({recordId:'task',pageBytes:8,readPage:()=>new NativePromise(yes=>{if(at===0)poison();yes(list[at++]);}),onProgress:()=>{}});let next=0;negative=await m.readBodyV2({recordId:'task',pageBytes:8,readPage:()=>new NativePromise(yes=>yes(wrong[next++]))});}
    finally{for(let i=restore.length-1;i>=0;i--){const r=restore[i];if(r[2])def(r[0],r[1],r[2]);else delete r[0][r[1]];}}
    assert.equal(result.status,'verified');assert.equal(result.value.body,'\ufeffé😀last');assert.equal(negative.status,'refused');assert.equal(negative.reason,'digest_mismatch');assert.equal(hooks,0);
  `;
  const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

test('P2 assembler final awaited verifier result checks a real microtask abort before returning',()=>{
  const path=new URL('../src/body-reader-v2.mjs',import.meta.url).href;
  const script=`
    import assert from 'node:assert/strict';
    const controller=new AbortController(),nativeThen=Promise.prototype.then,nativeQueue=queueMicrotask;let triggered=false;
    Promise.prototype.then=function(yes,no){return Reflect.apply(nativeThen,this,[function(value){
      if(!triggered&&value?.status==='verified'&&value?.qualification==='sha256-verified'){triggered=true;nativeQueue(()=>controller.abort());}
      return typeof yes==='function'?yes(value):value;
    },no]);};
    const m=await import(${JSON.stringify(path)});
    const r=await m.readBodyV2({recordId:'task',signal:controller.signal,readPage:async()=>(${JSON.stringify(pages('abc')[0])})});
    Promise.prototype.then=nativeThen;
    assert.equal(triggered,true);assert.equal(controller.signal.aborted,true);assert.equal(r.status,'refused');assert.equal(r.reason,'aborted');
    const current=await import(${JSON.stringify(new URL('../src/body-current-v2.mjs',import.meta.url).href)});assert.equal(current.isVerifiedBodyV2(r),false);
  `;
  const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

test('caller-owned frozen/nonconfigurable promises remain unchanged and rejection custody survives strict mode',()=>{
  const path=new URL('../src/body-reader-v2.mjs',import.meta.url).href;
  const script=`
    import assert from 'node:assert/strict';
    const m=await import(${JSON.stringify(path)}),page=${JSON.stringify(pages('abc')[0])};
    const originalThen=Promise.prototype.then;
    const unchanged=(p,before)=>{assert.deepEqual(Object.getOwnPropertyDescriptors(p),before);};
    for(const kind of ['frozen','nonconfigurable']){
      const p=Promise.resolve(page);
      if(kind==='frozen')Object.freeze(p);
      else{Object.defineProperty(p,'constructor',{value:Promise});Object.defineProperty(p,'then',{value:originalThen});}
      const before=Object.getOwnPropertyDescriptors(p);
      const r=await m.readBodyV2({recordId:'task',readPage:()=>p});
      assert.equal(r.status,'verified');unchanged(p,before);
    }
    const rejected=Object.freeze(Promise.reject(Error('frozen page rejected'))),before=Object.getOwnPropertyDescriptors(rejected);
    const no=await m.readBodyV2({recordId:'task',readPage:()=>rejected});assert.equal(no.status,'refused');assert.equal(no.reason,'read_page_failed');unchanged(rejected,before);
    let progressPromise,progressBefore;
    const progress=await m.readBodyV2({recordId:'task',readPage:()=>Object.freeze(Promise.resolve(page)),onProgress:()=>{
      progressPromise=Object.freeze(Promise.reject(Error('frozen progress rejected')));progressBefore=Object.getOwnPropertyDescriptors(progressPromise);return progressPromise;}});
    assert.equal(progress.reason,'progress_failed');unchanged(progressPromise,progressBefore);
    // Nonconfigurable own .then is not inspected or invoked by native observation.
    let invoked=0;const ownThen=Promise.reject(Error('own then rejection'));
    Object.defineProperty(ownThen,'then',{get(){invoked++;throw Error('do not invoke');}});Object.freeze(ownThen);
    const ownNo=await m.readBodyV2({recordId:'task',readPage:()=>ownThen});assert.equal(ownNo.reason,'read_page_failed');assert.equal(invoked,0);
    // Unsupported thenables do not run authored then code that creates a rejection.
    let thenableCalls=0;const unsupported=await m.readBodyV2({recordId:'task',readPage:()=>({then(){thenableCalls++;return Promise.reject(Error('not called'));}})});
    assert.equal(unsupported.reason,'read_page_failed');assert.equal(thenableCalls,0);
    await new Promise(resolve=>setImmediate(resolve));
  `;
  const child=spawnSync(process.execPath,['--unhandled-rejections=strict','--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

test('frozen pending page rejection remains observed after cancellation; hostile species is refused without mutation',()=>{
  const path=new URL('../src/body-reader-v2.mjs',import.meta.url).href;
  const script=`
    import assert from 'node:assert/strict';
    const m=await import(${JSON.stringify(path)}),controller=new AbortController();let reject,entered;
    const started=new Promise(resolve=>entered=resolve);
    const p=Object.freeze(new Promise((_,no)=>reject=no)),before=Object.getOwnPropertyDescriptors(p);
    const pending=m.readBodyV2({recordId:'task',signal:controller.signal,readPage:()=>{entered();return p;}});
    await started;controller.abort();const r=await pending;assert.equal(r.reason,'aborted');reject(Error('frozen late rejection'));
    assert.deepEqual(Object.getOwnPropertyDescriptors(p),before);
    // Native then necessarily performs SpeciesConstructor before installing handlers.
    // Caller handles this deliberately hostile rejection BEFORE poisoning its constructor;
    // the module cannot guarantee custody for this unsupported species without mutation.
    const hostile=Promise.reject(Error('caller-owned hostile metadata'));
    Promise.prototype.then.call(hostile,()=>{},()=>{});
    Object.defineProperty(hostile,'constructor',{get(){throw Error('unobservable species');}});Object.freeze(hostile);
    const hostileBefore=Object.getOwnPropertyDescriptors(hostile);
    const no=await m.readBodyV2({recordId:'task',readPage:()=>hostile});assert.equal(no.reason,'read_page_failed');
    assert.deepEqual(Object.getOwnPropertyDescriptors(hostile),hostileBefore);
    await new Promise(resolve=>setImmediate(resolve));
  `;
  const child=spawnSync(process.execPath,['--unhandled-rejections=strict','--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

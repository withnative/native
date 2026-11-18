import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {validateBodyEvidenceV2,validateBodyPageV2,validateCurrentBodyRecordV2,verifyCurrentBodyRecordV2,verifyCompleteBodyV2,isVerifiedBodyV2} from '../src/body-current-v2.mjs';
const sha = s => createHash('sha256').update(s).digest('hex');
const rev = state => `body:v1:${state}:${'a'.repeat(64)}`;
function record(body='stored',live=null) {
  const base={record_version:'rec:42',body_present:body!==null,body_digest:sha(body??''),body_event:body===null?null:{id:'event',seq:'40'}};
  return {id:'task',status:'found',body,body_digest:base.body_digest,version:'rec:42',record_version:'rec:42',
    body_read_contract:'native.current-body.v1',body_basis:{revision:rev('d'),...base},
    live_body:live===null?null:{contract:'native.live-body.v1',state:'live',revision:rev('l'),body:live,body_present:true,
      body_digest:sha(live),total_bytes:Buffer.byteLength(live),room_state:'grace',dirty:true,committed:{...base}}};
}
const refused = r => assert.equal(r.status,'refused');
test('parsing is explicitly unqualified; only real SHA promotes durable and live bytes',async()=>{
  for(const r of [record(),record(null),record(''),record('stored','observed'),record(null,'')]) {
    const p=validateCurrentBodyRecordV2(r,'task');assert.equal(p.status,'parsed');assert.equal(p.qualification,'unqualified');assert.equal(isVerifiedBodyV2(p),false);
    const v=await verifyCurrentBodyRecordV2(r,'task');assert.equal(v.status,'verified');assert.equal(v.qualification,'sha256-verified');assert.equal(isVerifiedBodyV2(v),true);
    assert.equal(isVerifiedBodyV2({...v}),false);assert(Object.isFrozen(v.value.evidence.committed));
  }
  const r=record('stored','observed');r.body_digest=r.body_basis.body_digest=r.live_body.committed.body_digest=sha('a lie');
  assert.equal(validateCurrentBodyRecordV2(r,'task').status,'parsed');refused(await verifyCurrentBodyRecordV2(r,'task'));
  const l=record('stored','observed');l.live_body.body_digest=sha('a lie');refused(await verifyCurrentBodyRecordV2(l,'task'));
});
test('absence, event/CAS ordering and full nested committed cross-matches',()=>{
  for(const mutate of [
    r=>{delete r.body;},r=>{r.body_basis.body_event=null;},r=>{r.body_basis.body_event.seq='43';},
    r=>{r.body_basis.record_version='rec:41';},r=>{r.record_version='rec:41';},
    r=>{r.live_body.committed.body_event={id:'other',seq:'40'};},r=>{r.live_body.committed.record_version='rec:41';},
    r=>{r.live_body.committed.body_present=false;},r=>{r.live_body.extra=1;},r=>{r.body_basis.birth='unapproved';},
  ]) { const r=record('stored','observed');mutate(r);refused(validateCurrentBodyRecordV2(r,'task')); }
  const absent=record(null);absent.body_basis.body_event={id:'event',seq:'1'};refused(validateCurrentBodyRecordV2(absent,'task'));
  const empty=record('');empty.body_basis.body_event=null;refused(validateCurrentBodyRecordV2(empty,'task'));
  const rec0=record(null);rec0.version=rec0.record_version=rec0.body_basis.record_version='rec:0';assert.equal(validateCurrentBodyRecordV2(rec0,'task').status,'parsed');
});
test('clean equal remains live; clean different rejects; dirty equal is legitimate',()=>{
  const clean=record('same','same');clean.live_body.dirty=false;
  const p=validateCurrentBodyRecordV2(clean,'task');assert.equal(p.value.selected.evidence.state,'live');
  const different=record('stored','observed');different.live_body.dirty=false;refused(validateCurrentBodyRecordV2(different,'task'));
  assert.equal(validateCurrentBodyRecordV2(record('same','same'),'task').status,'parsed');
  const empty=record(null,'');empty.live_body.dirty=false;assert.equal(validateCurrentBodyRecordV2(empty,'task').status,'parsed');
});
test('full-input scalar grammar: exact i64 max, one past, newline, prefix and graphic ID subset',()=>{
  const max='9223372036854775807';
  const r=record();r.version=r.record_version=r.body_basis.record_version=`rec:${max}`;r.body_basis.body_event.seq=max;
  assert.equal(validateCurrentBodyRecordV2(r,'task').status,'parsed');
  for(const seq of ['', '0','01','+1','-1',' 1','1\n','1\r','1.0','1e1','9223372036854775808']) {
    const v=record();v.body_basis.body_event.seq=seq;refused(validateCurrentBodyRecordV2(v,'task'));
  }
  for(const version of ['rec:01','rec:-1','rec:1\n','rec:9223372036854775808','rec:']) {
    const v=record();v.version=v.record_version=v.body_basis.record_version=version;refused(validateCurrentBodyRecordV2(v,'task'));
  }
  for(const revision of [rev('d')+'\n',rev('d').slice(0,-1),rev('l'),rev('d').replace('a','A')]) {
    const v=record();v.body_basis.revision=revision;refused(validateCurrentBodyRecordV2(v,'task'));
  }
  for(const id of ['x','x'.repeat(128),'"\\']) {const v=record();v.id=id;v.body_basis.body_event.id=id;assert.equal(validateCurrentBodyRecordV2(v,id).status,'parsed');}
  for(const id of ['', 'x'.repeat(129),'é','x\n','x\u007f']) {const v=record();v.id=id;refused(validateCurrentBodyRecordV2(v,id));const e=record();e.body_basis.body_event.id=id;refused(validateCurrentBodyRecordV2(e,'task'));}
  for(const digest of [sha('stored')+'\n',sha('stored').toUpperCase()]) {const v=record();v.body_digest=v.body_basis.body_digest=digest;refused(validateCurrentBodyRecordV2(v,'task'));}
});
test('own data only, inspection failures sanitized, extensible outer record; copies are deeply owned',()=>{
  const r=record('stored','observed');r.extra='allowed metadata';assert.equal(validateCurrentBodyRecordV2(r,'task').status,'parsed');
  const p=validateCurrentBodyRecordV2(r,'task');r.live_body.committed.body_event.id='mutated';assert.equal(p.value.selected.evidence.committed.body_event.id,'event');
  const getter=record();Object.defineProperty(getter,'body',{enumerable:true,get(){throw Error('must not run');}});refused(validateCurrentBodyRecordV2(getter,'task'));
  const inherited=Object.create(record());refused(validateCurrentBodyRecordV2(inherited,'task'));
  const trap=new Proxy({}, {ownKeys(){throw Error('secret');}});refused(validateCurrentBodyRecordV2(trap,'task'));
  const symbol=record();symbol.body_basis[Symbol('extra')]=0;refused(validateCurrentBodyRecordV2(symbol,'task'));
  const nullProto=Object.assign(Object.create(null),record());assert.equal(validateCurrentBodyRecordV2(nullProto,'task').status,'parsed');
  const hidden=record();Object.defineProperty(hidden,'body',{value:'stored',enumerable:false});refused(validateCurrentBodyRecordV2(hidden,'task'));
});
test('evidence and pages cannot claim complete qualification',()=>{
  const r=record();const e={state:'durable',record_version:r.version,committed:{body_present:true,body_digest:r.body_digest,body_event:{id:'event',seq:'40'}},live:null};
  const p=validateBodyEvidenceV2(e);assert.equal(p.qualification,'unqualified');assert(!isVerifiedBodyV2(p));
  refused(validateBodyPageV2({contract:'records.body.read.v1'}));
});
test('actual platform SHA vectors and no-crypto/rejected/detached/cancelled digest paths',async()=>{
  for(const body of ['', 'abc','\ufeffé😀'])assert.equal((await verifyCurrentBodyRecordV2(record(body),'task')).status,'verified');
  const module=new URL('../src/body-current-v2.mjs',import.meta.url).href;
  for(const mode of ['missing','reject','detached','cancel']) {
    const script=`
      import assert from 'node:assert/strict';
      const mode=${JSON.stringify(mode)};
      let late;
      Object.defineProperty(globalThis,'crypto',{configurable:true,value:mode==='missing'?undefined:{subtle:{digest(){
        if(mode==='reject')return Promise.reject(Error('private'));
        if(mode==='detached'){const b=new ArrayBuffer(32);structuredClone(b,{transfer:[b]});return Promise.resolve(b);}
        return new Promise((_,reject)=>{late=reject;});
      }}}});
      const m=await import(${JSON.stringify(module)});const c=new AbortController();
      const pending=m.verifyCurrentBodyRecordV2(${JSON.stringify(record('abc'))},'task',{signal:c.signal});
      if(mode==='cancel') {queueMicrotask(()=>c.abort());}
      const r=await pending;assert.equal(r.status,'refused');assert.equal(m.isVerifiedBodyV2(r),false);
      assert.equal(r.reason,mode==='missing'?'crypto_unavailable':mode==='cancel'?'aborted':'crypto_failed');
      if(late)late(Error('late crypto rejection'));await new Promise(resolve=>setImmediate(resolve));
    `;
    const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
  }
});

test('P2 captured intrinsics preserve real SHA and provenance after hostile same-realm mutation',()=>{
  const module=new URL('../src/body-current-v2.mjs',import.meta.url).href;
  const good=record('stored','observed'),wrong=record('stored','observed');wrong.live_body.body_digest=sha('claimed');
  const script=`
    import assert from 'node:assert/strict';
    const m=await import(${JSON.stringify(module)});
    const good=${JSON.stringify(good)}, wrong=${JSON.stringify(wrong)};
    const def=Object.defineProperty,get=Object.getOwnPropertyDescriptor,restore=[];
    const replace=(o,k,value)=>{restore[restore.length]=[o,k,get(o,k)];def(o,k,{configurable:true,writable:true,value});};
    const Bytes=Uint8Array;let hooks=0;
    replace(globalThis,'Uint8Array',function(){return new Bytes(${JSON.stringify([...Buffer.from(sha('claimed'),'hex')])});});
    replace(globalThis,'ArrayBuffer',function(){throw Error('constructor');});
    replace(WeakSet.prototype,'has',()=>true);replace(WeakSet.prototype,'add',()=>{});
    replace(Array,'from',()=>{throw Error('from');});
    for(let j=0,ks=['includes','some','map','filter','join','push'];j<ks.length;j++){const k=ks[j];replace(Array.prototype,k,()=>{throw Error(k);});}
    replace(Array.prototype,Symbol.iterator,()=>{throw Error('iterator');});
    for(let j=0,ks=['charCodeAt','slice','startsWith','padStart'];j<ks.length;j++){const k=ks[j];replace(String.prototype,k,()=>{throw Error(k);});}
    replace(Number.prototype,'toString',()=> 'claimed');replace(Number,'isSafeInteger',()=>true);
    for(let j=0,ks=['create','hasOwn','getOwnPropertyDescriptor','getPrototypeOf','freeze'];j<ks.length;j++){const k=ks[j];replace(Object,k,()=>{throw Error(k);});}
    replace(Reflect,'ownKeys',()=>{throw Error('ownKeys');});replace(Reflect,'apply',()=>{throw Error('apply');});
    replace(JSON,'parse',()=>good);replace(JSON,'stringify',()=> 'substitute');
    replace(RegExp.prototype,'test',()=>true);replace(RegExp.prototype,'exec',()=>null);
    replace(TextEncoder.prototype,'encode',()=>new Bytes(0));replace(globalThis,'TextEncoder',function(){throw Error('encoder');});
    replace(Object.prototype,'toJSON',()=>{hooks++;throw Error('inherited toJSON');});
    replace(Array.prototype,'toJSON',()=>{hooks++;throw Error('inherited array toJSON');});
    let yes,no,forged,parsed;
    try {parsed=m.validateCurrentBodyRecordV2(good,'task');yes=await m.verifyCurrentBodyRecordV2(good,'task');no=await m.verifyCurrentBodyRecordV2(wrong,'task');forged=m.isVerifiedBodyV2({status:'verified'});}
    finally {for(let i=restore.length-1;i>=0;i--){const r=restore[i];if(r[2])def(r[0],r[1],r[2]);else delete r[0][r[1]];}}
    assert.equal(parsed.status,'parsed');assert.equal(yes.status,'verified');assert.equal(no.status,'refused');assert.equal(no.reason,'digest_mismatch');
    assert.equal(forged,false);assert.equal(hooks,0);assert.equal(m.isVerifiedBodyV2(yes),true);
  `;
  const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

test('P2 final hash microtask cancellation refuses both verifiers after genuine hash fulfillment',()=>{
  const path=new URL('../src/body-current-v2.mjs',import.meta.url).href;
  for(const mode of ['complete','current','current-first']) {
    const fixture=record('stored','observed');
    const script=`
      import assert from 'node:assert/strict';
      const controller=new AbortController(),nativeThen=Promise.prototype.then,nativeQueue=queueMicrotask;
      const expected=${JSON.stringify(mode==='current-first'?sha('stored'):sha('observed'))};let triggered=false;
      // Observe actual hash-string fulfillment, preserving all native crypto bytes/results.
      Promise.prototype.then=function(yes,no){return Reflect.apply(nativeThen,this,[function(value){
        if(!triggered&&value===expected){triggered=true;nativeQueue(()=>controller.abort());}
        return typeof yes==='function'?yes(value):value;
      },no]);};
      const m=await import(${JSON.stringify(path)});const fixture=${JSON.stringify(fixture)};
      const value={contract:'records.body.complete.v2',record_id:'task',body:fixture.live_body.body,body_present:true,
        body_digest:fixture.live_body.body_digest,revision:fixture.live_body.revision,total_bytes:fixture.live_body.total_bytes,
        evidence:{state:'live',record_version:'rec:42',committed:{body_present:true,body_digest:fixture.body_digest,body_event:{id:'event',seq:'40'}},live:{room_state:'grace',dirty:true}}};
      const r=${mode==='complete'?'await m.verifyCompleteBodyV2(value,{signal:controller.signal})':"await m.verifyCurrentBodyRecordV2(fixture,'task',{signal:controller.signal})"};
      Promise.prototype.then=nativeThen;
      assert.equal(triggered,true);assert.equal(controller.signal.aborted,true);assert.equal(r.status,'refused');assert.equal(r.reason,'aborted');assert.equal(m.isVerifiedBodyV2(r),false);
    `;
    const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
  }
});

test('required platform plus private constant-scratch SHA256 agree on NIST, padding and UTF8 vectors',async()=>{
  // FIPS180-4 algorithm vectors; no FIPS validation/compliance claim.
  const vectors=[
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq','248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
    ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu','cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1'],
    ['a'.repeat(1000000),'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0'],
    ['\ufeffé😀\0漢字\r\n',sha('\ufeffé😀\0漢字\r\n')],
  ];
  for(const count of [54,55,56,57,63,64,65,118,119,120,121,127,128,129])vectors.push(['x'.repeat(count),sha('x'.repeat(count))]);
  for(const [body,expected] of vectors){
    assert.equal(sha(body),expected);
    const selected=validateCurrentBodyRecordV2(record(body),'task').value.selected;
    const result=await verifyCompleteBodyV2(selected);assert.equal(result.status,'verified');assert.equal(result.value.body_digest,expected);
    if(body){const wrong={...selected,body_digest:sha('wrong'),evidence:{...selected.evidence,committed:{...selected.evidence.committed,body_digest:sha('wrong')}}};
      const no=await verifyCompleteBodyV2(wrong);assert.equal(no.status,'refused');assert.equal(no.reason,'digest_mismatch');}
  }
});

test('transient producer-side ArrayBuffer then installed AFTER call cannot qualify substituted real crypto fulfillment',()=>{
  const path=new URL('../src/body-current-v2.mjs',import.meta.url).href;
  const script=`
    import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
    const m=await import(${JSON.stringify(path)});
    const wanted=createHash('sha256').update('claimed').digest('hex');
    const fake=Uint8Array.from(Buffer.from(wanted,'hex')).buffer;Object.setPrototypeOf(fake,null);
    const value={contract:'records.body.complete.v2',record_id:'task',body:'different',body_present:true,body_digest:wanted,
      revision:'body:v1:l:'+'a'.repeat(64),total_bytes:9,evidence:{state:'live',record_version:'rec:42',
      committed:{body_present:true,body_digest:wanted,body_event:{id:'event',seq:'40'}},live:{room_state:'active',dirty:true}}};
    const baseline=await m.verifyCompleteBodyV2(value);assert.equal(baseline.status,'refused');
    const pending=m.verifyCompleteBodyV2(value);let hooks=0;
    Object.defineProperty(ArrayBuffer.prototype,'then',{configurable:true,value:function(resolve){hooks++;delete ArrayBuffer.prototype.then;resolve(fake);}});
    let result;try{result=await pending;}finally{delete ArrayBuffer.prototype.then;}
    assert.equal(hooks,1);assert.equal(Object.hasOwn(ArrayBuffer.prototype,'then'),false);
    assert.equal(result.status,'refused');assert.equal(result.reason,'digest_mismatch');assert.equal(m.isVerifiedBodyV2(result),false);
  `;
  const child=spawnSync(process.execPath,['--unhandled-rejections=strict','--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);
});

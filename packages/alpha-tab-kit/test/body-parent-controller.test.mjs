// Synthetic lifecycle/fault tests, NOT an authenticated producer/HTTP proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const VERSION='native.html.bridge.v1';
const ready={type:'ready',version:VERSION,profile:'document',slides:0,features:['surface.reveal.v1','records.body.read.v1']};
const request=id=>({type:'body-read',version:VERSION,request_id:id,request_json:'{"record_id":"doc"}'});
const page={contract:'records.body.read.v1',record_id:'doc',revision:'r',body_digest:'a'.repeat(64),body_present:true,encoding:'utf-8',start_byte:0,end_byte:2,total_bytes:2,text:'é',complete:true,next_cursor:null,limits:{max_page_bytes:32768,max_response_bytes:262144}};
const flush=()=>new Promise(r=>setImmediate(r));

function setup() {
  const posts=[],timers=new Map(),pending=[],stats={retire:0,abort:0,clear:0,inspected:0},faults={};
  const port=new MessageChannel().port1;
  const ctx=vm.createContext({TextEncoder,TextDecoder,Uint8Array,URL,MessageEvent,MessageChannel,Event,AbortController,
    NativeMessagePort:MessagePort,NativePost:MessagePort.prototype.postMessage,Headers,ReadableStream,ReadableStreamDefaultReader,
    posts,stats,faults,port,location:{origin:'https://parent.invalid'},
    setTimeout:f=>{const id=timers.size+1;timers.set(id,f);return id;},
    clearTimeout:id=>{stats.clear++;if(faults.clear)throw 0;timers.delete(id);},
    fakeFetch:(url,options)=>{if(options.method==='DELETE'){stats.retire++;if(faults.retire)throw 0;return Promise.resolve();}
      options.signal.addEventListener('abort',()=>{stats.abort++;});
      return new Promise((resolve,reject)=>pending.push({resolve,reject,url,options}));},
  });
  vm.runInContext(`globalThis.savedThen=Promise.prototype.then;class MessagePort extends NativeMessagePort {};Object.defineProperty(MessagePort.prototype,'postMessage',{value:function(v){if(faults.post)throw new Proxy({}, {get(){stats.inspected++;throw 0;}});posts.push(v);}});
    class Response {constructor(text){this.text=text;} get url(){return 'https://parent.invalid/body';} get headers(){return new Headers({'content-type':'application/json','content-encoding':'identity'});} get body(){return new ReadableStream({start:c=>{c.enqueue(new TextEncoder().encode(this.text));c.close();}});}}
    globalThis.fetch=fakeFetch;`,ctx);
  const wire=readFileSync(new URL('../src/body-wire.mjs',import.meta.url),'utf8').replace('export function createBodyWire()','function createBodyWire()');
  const controller=readFileSync(new URL('../src/body-parent-controller.mjs',import.meta.url),'utf8').replace("import { createBodyWire } from './body-wire.mjs';",'').replace('export function createBodyParentController','function createBodyParentController');
  vm.runInContext(`globalThis.createWire=(()=>{${wire};return createBodyWire;})();globalThis.make=(()=>{const createBodyWire=createWire;${controller};return createBodyParentController;})();
    globalThis.selected=true;globalThis.c=make({token:'abm1.aa',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>selected});
    globalThis.windowSelection={};globalThis.outcomes=[];port.addEventListener('message',e=>outcomes.push(c.receive(e,{port,epoch:1})));`,ctx);
  const run=s=>vm.runInContext(s,ctx);
  const send=(v,epoch=1)=>{ctx.input=v;ctx.testEpoch=epoch;
    // Construct a native branded event with realm-local clone data; dispatch
    // through the actual port so currentTarget is genuine (not Window source).
    const body=JSON.stringify(v);
    return run(`(()=>{let result;const f=event=>{result=c.receive(event,{port,epoch:${epoch}});};port.addEventListener('probe',f);const probe=new MessageEvent('probe',{data:${body}});port.dispatchEvent(probe);port.removeEventListener('probe',f);return result;})()`);
  };
  const attach=()=>run('c.attach({port,epoch:1,window:windowSelection})');
  const finish=async(index=0,body=page)=>{ctx.responseText=JSON.stringify(body);const response=run('new Response(responseText)');pending[index].resolve(response);await flush();await flush();};
  return {ctx,run,send,attach,finish,posts,timers,pending,stats,faults,close:()=>{run('c.close()');port.close();}};
}

test('exact first READY enum, no Window-valued port source, ignored nonbody/stale epoch and bounded useful delivery',async()=>{
  const f=setup();try{
    const offer=f.attach();assert.equal(offer.max_inflight,1);
    assert.equal(f.run(`(()=>{const other=new MessageChannel();let outcome;other.port1.addEventListener('probe',e=>{outcome=c.receive(e,{port,epoch:1});});other.port1.dispatchEvent(new MessageEvent('probe',{data:${JSON.stringify(ready)}}));other.port1.close();other.port2.close();return outcome;})()`),'ignored','native wrong-port dispatch cannot enable the attached lane');
    assert.equal(f.send(ready,2),'ignored');assert.equal(f.send(ready),'ready');
    assert.equal(f.send({type:'diagnostic',message:'never inspected'}),'ignored');
    assert.equal(f.send(request('one')),'consumed');await f.finish();
    assert.equal(f.posts[0].response.text,'é');assert.equal(f.posts[0].type,'body-read-result');
    assert.equal(f.pending[0].options.headers['x-native-body-mount'],'abm1.aa');
    assert.equal(f.pending[0].options.redirect,'error');
  }finally{f.close();}
});

test('duplicate/malformed READY, duplicate attachment and transferred ports converge on once-only closed',async()=>{
  for(const mode of ['duplicate','malformed','attachment','transfer']){
    const f=setup();try{
      f.attach();let count=0;f.run('c.closed').then(()=>{count++;});
      if(mode==='duplicate'){assert.equal(f.send(ready),'ready');assert.equal(f.send(ready),'closed');}
      if(mode==='malformed')assert.equal(f.send({...ready,extra:1}),'closed');
      if(mode==='attachment')assert.throws(()=>f.attach(),/body attachment/);
      if(mode==='transfer'){
        assert.equal(f.run(`(()=>{let result;const q=new MessageChannel();const handler=e=>{result=c.receive(e,{port,epoch:1});};port.addEventListener('probe',handler);port.dispatchEvent(new MessageEvent('probe',{data:{type:'ready'},ports:[q.port1]}));port.removeEventListener('probe',handler);q.port1.close();q.port2.close();return result;})()`),'closed');
      }
      f.run('c.close();c.close()');await flush();assert.equal(count,1);assert.equal(f.stats.retire,1);
      assert.equal(f.send(request('later')),'closed');
    }finally{f.close();}
  }
});

test('ordinary matching cancel retains ticket until actual settlement and does not close controller',async()=>{
  const f=setup();try{
    f.attach();f.send(ready);let closed=0;f.run('c.closed').then(()=>{closed++;});
    f.send(request('one'));assert.equal(f.send({type:'body-read-cancel',version:VERSION,request_id:'one'}),'consumed');
    assert.equal(f.posts[0].reason,'cancelled');assert.equal(f.stats.abort,1);
    assert.equal(f.send(request('two')),'consumed');assert.equal(f.posts[1].reason,'busy');assert.equal(f.pending.length,1);
    await f.finish();assert.equal(f.posts.length,2,'late success of cancelled request is suppressed');assert.equal(closed,0);
    f.send(request('three'));assert.equal(f.pending.length,2);await f.finish(1);assert.equal(f.posts.at(-1).response.text,'é');
  }finally{f.close();}
});

test('request timeout resolves logical closure without new packet; late rejection observed, no ticket reset',async()=>{
  const f=setup();try{
    f.attach();f.send(ready);f.send(request('one'));let cleanup=0;
    f.run('c.closed').then(()=>{cleanup++;});
    [...f.timers.values()][0]();await flush();assert.equal(cleanup,1);assert.equal(f.stats.abort,1);assert.equal(f.stats.retire,1);
    assert.equal(f.send(request('later')),'closed');assert.equal(f.pending.length,1);assert.equal(f.posts.length,0);
    f.pending[0].reject(new Proxy({}, {get(){f.stats.inspected++;throw 0;}}));await flush();assert.equal(f.stats.inspected,0);assert.equal(f.posts.length,0);
    assert.throws(()=>f.attach(),/body attachment/);
  }finally{f.close();}
});

test('asynchronous fallback send and cancel send failures close without another author packet',async()=>{
  for(const mode of ['dispatch','cancel']){
    const f=setup();try{
      f.attach();f.send(ready);f.send(request('one'));f.faults.post=true;let closed=0;f.run('c.closed').then(()=>{closed++;});
      if(mode==='dispatch')await f.finish();else assert.equal(f.send({type:'body-read-cancel',version:VERSION,request_id:'one'}),'closed');
      await flush();assert.equal(closed,1);assert.equal(f.stats.retire,1);assert.equal(f.stats.inspected,0);
      if(mode==='cancel'){f.pending[0].reject(0);await flush();}
    }finally{f.close();}
  }
});

test('independent cleanup failures still resolve and attempt retirement exactly once',async()=>{
  const f=setup();try{
    f.attach();f.send(ready);f.send(request('one'));f.faults.clear=true;f.faults.retire=true;
    const done=f.run('c.closed');f.run('c.close();c.close()');await done;
    assert.equal(f.stats.abort,1);assert.equal(f.stats.clear,1);assert.equal(f.stats.retire,1);
    f.pending[0].reject(0);await flush();assert.equal(f.posts.length,0);
  }finally{f.close();}
});

test('safe native subclass/species promise custody survives parent prototype poisoning with zero thrown-error inspection',async()=>{
  const f=setup();try{
    f.attach();f.send(ready);
    const result=f.run(`(()=>{let hits=0;const d=Object.create(null);d.get=()=>{hits++;throw 0;};d.configurable=true;Object.defineProperty(Promise,Symbol.species,d);Object.defineProperty(Promise.prototype,'constructor',d);Promise.prototype.then=()=>{hits++;throw 0;};const observed=Reflect.apply(savedThen,c.closed,[()=>undefined]);c.close();return {observed,stats:()=>hits};})()`);
    await result.observed;await flush();assert.equal(result.stats(),0);assert.equal(f.stats.retire,1);
  }finally{f.close();}
});

test('current selection loss closes and suppresses late bytes; no legacy dispatch after ignored outcome',async()=>{
  const f=setup();try{
    f.attach();f.send(ready);f.send(request('one'));f.run('selected=false');
    assert.equal(f.send({type:'read',version:VERSION}),'closed');await f.finish();assert.equal(f.posts.length,0);assert.equal(f.stats.retire,1);
  }finally{f.close();}
});

test('generated inert vendor modules are byte-identical owning source, relative import stays exact',()=>{
  for(const name of ['body-wire.mjs','body-parent-controller.mjs']){
    assert.equal(readFileSync(new URL(`../../../experiments/demo-shell/public/lib/vendor/${name}`,import.meta.url),'utf8'),readFileSync(new URL(`../src/${name}`,import.meta.url),'utf8'));
  }
});

// G3 client grammar/custody controls only; no producer/ordinary authority proof.
const mixedReady = contextOffered => ({...ready, features: [...ready.features,
  ...(contextOffered ? ['app-view-report.v1'] : [])]});
const makeMixed = (f, contextOffered) => {
  f.ctx.contextChoice = contextOffered;
  f.run(`c.close();c=make({token:'abm1.bb',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>selected,composition:{kind:'ordinary-mixed.v1'}});
    c.attach({port,epoch:1,window:windowSelection,composition:{kind:'ordinary-mixed.v1',contextOffered:contextChoice}})`);
};

test('mixed native port READY freezes attach context once, preserves useful body and ignored ordinary enum',async()=>{
  for(const context of [false,true]){
    const f=setup();try{
      makeMixed(f,context);assert.equal(f.send(mixedReady(context),2),'ignored');
      assert.equal(f.send(mixedReady(context)),'ready');
      assert.equal(f.send({type:'read',version:VERSION,request_id:'ordinary',need:'metadata'}),'ignored');
      assert.equal(f.send(request('body')),'consumed');await f.finish();
      assert.equal(f.posts.at(-1).response.text,'é');
      assert.equal(f.pending[0].options.headers['x-native-body-mount'],'abm1.bb');
      assert.equal(f.send(mixedReady(context)),'closed','second native READY never becomes successor readiness');
    }finally{f.close();}
  }
});

test('mixed ctor/attach own DATA grammar rejects getters, inherited/missing/extra fields and default supplied composition',()=>{
  const f=setup();try{
    assert.equal(f.run(`(()=>{let calls=0;const q={token:'abm1.cc',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>true};
      Object.defineProperty(q,'composition',{enumerable:true,get(){calls++;throw new Proxy({}, {get(){calls++;throw 0;}})}});
      try{make(q);throw 1;}catch(e){if(e.message!=='body composition')throw e;}return calls;})()`),0);
    for(const expression of ['undefined','null',"{kind:'wrong'}","{kind:'ordinary-mixed.v1',extra:true}"]){
      assert.throws(()=>f.run(`make({token:'abm1.cc',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>true,composition:${expression}})`),/body composition/);
    }
    assert.throws(()=>f.run(`make(Object.assign(Object.create({composition:{kind:'ordinary-mixed.v1'}}),{token:'abm1.cc',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>true}))`),/body composition/);
    assert.throws(()=>f.run(`c.attach({port,epoch:1,window:windowSelection,composition:{kind:'ordinary-mixed.v1',contextOffered:false}})`),/body attachment/);
  }finally{f.close();}
  for(const expression of ['undefined','null',"{kind:'ordinary-mixed.v1'}","{kind:'ordinary-mixed.v1',contextOffered:1}","{kind:'ordinary-mixed.v1',contextOffered:false,extra:true}"]){
    const g=setup();try{
      g.run(`c.close();c=make({token:'abm1.dd',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>selected,composition:{kind:'ordinary-mixed.v1'}})`);
      assert.throws(()=>g.run(`c.attach({port,epoch:1,window:windowSelection,composition:${expression}})`),/body attachment/);
    }finally{g.close();}
  }
  const g=setup();try{
    g.run(`c.close();c=make({token:'abm1.dd',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>selected,composition:{kind:'ordinary-mixed.v1'}});globalThis.getterCalls=0;`);
    assert.throws(()=>g.run(`c.attach({port,epoch:1,window:windowSelection,get composition(){getterCalls++;throw 0;}})`),/body attachment/);
    assert.equal(g.run('getterCalls'),0);
  }finally{g.close();}
});

test('mixed exact READY catalogue refuses missing/extra/context mismatch/ARM/duplicates and dense-data violations',()=>{
  const variants=[['records.body.read.v1'],['surface.reveal.v1'],[...ready.features,'intent-arm-confirm.v1'],
    [...ready.features,'unknown'],[...ready.features,'surface.reveal.v1'],[...ready.features,'app-view-report.v1']];
  for(const features of variants){const f=setup();try{makeMixed(f,false);assert.equal(f.send({...ready,features}),'closed');}finally{f.close();}}
  const f=setup();try{makeMixed(f,true);assert.equal(f.send(ready),'closed');}finally{f.close();}
  for(const expression of ["(()=>{const a=['surface.reveal.v1','records.body.read.v1'];delete a[0];return a;})()",
    "Object.assign(['surface.reveal.v1','records.body.read.v1'],{extra:true})",
    "(()=>{const a=['surface.reveal.v1','records.body.read.v1'];Object.defineProperty(a,0,{enumerable:true,get(){getterCalls++;throw 0;}});return a;})()",
    "(()=>{const a=['surface.reveal.v1','records.body.read.v1'];a[Symbol('extra')]=1;return a;})()"]){
    const g=setup();try{makeMixed(g,false);g.run('globalThis.getterCalls=0');
      assert.equal(g.run(`(()=>{let answer;const fn=e=>{answer=c.receive(e,{port,epoch:1});};port.addEventListener('probe',fn);port.dispatchEvent(new MessageEvent('probe',{data:{type:'ready',version:'${VERSION}',profile:'document',slides:0,features:${expression}}}));port.removeEventListener('probe',fn);return answer;})()`),'closed');
      assert.equal(g.run('getterCalls'),0);
    }finally{g.close();}
  }
});

test('mixed close/cancel keeps original physical client ticket and suppresses old holder ABA late publication',async()=>{
  const f=setup();try{
    makeMixed(f,true);f.send(mixedReady(true));f.send(request('held'));
    f.send({type:'body-read-cancel',version:VERSION,request_id:'held'});
    f.send(request('overlap'));assert.equal(f.posts.at(-1).reason,'busy');assert.equal(f.pending.length,1);
    f.run('selected=false;c.close();selected=true');
    let closed=0;f.run('c.closed').then(()=>{closed++;});
    const before=f.posts.length;await f.finish();await flush();
    assert.equal(f.posts.length,before);assert.equal(closed,1);
    assert.equal(f.send(request('after')),'closed');assert.equal(f.pending.length,1);
  }finally{f.close();}
});

test('mixed copies attach primitives once rather than retaining a mutable caller object',()=>{
  const f=setup();try{
    f.run(`c.close();c=make({token:'abm1.ee',endpoint:'/body',retireEndpoint:'/retire',isCurrent:()=>selected,composition:{kind:'ordinary-mixed.v1'}});
      globalThis.choice={kind:'ordinary-mixed.v1',contextOffered:false};c.attach({port,epoch:1,window:windowSelection,composition:choice});choice.contextOffered=true;`);
    assert.equal(f.send(ready),'ready');
    assert.throws(()=>f.run(`c.attach({port,epoch:2,window:windowSelection,composition:choice})`),/body attachment/);
  }finally{f.close();}
});

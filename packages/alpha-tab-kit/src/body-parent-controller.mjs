// Internal host-only lane. Capture BEFORE authored frames; no launch/Db/account
// selection, Window listener, port transfer or source authority lives here.
import { createBodyWire } from './body-wire.mjs';
const wire=createBodyWire(),apply=Reflect.apply,own=Object.getOwnPropertyDescriptor;
const create=Object.create,define=Object.defineProperty,freeze=Object.freeze,keys=Reflect.ownKeys,proto=Object.getPrototypeOf;
const objectProto=Object.prototype,isArray=Array.isArray,safeInteger=Number.isSafeInteger;
const BasePromise=Promise,then=BasePromise.prototype.then,fetchPage=globalThis.fetch,URL_=URL;
const P=class extends BasePromise {};
const data=(o,k,v)=>{const d=create(null);d.value=v;d.enumerable=true;define(o,k,d);return o;};
// Native-owned promises only. Safe species AND safe own then are necessary:
// await adoption otherwise consults a possibly poisoned native prototype.
const derive=function(yes,no){return apply(then,this,[yes,no]);};
data(P,Symbol.species,P);data(P.prototype,'then',derive);freeze(P.prototype);freeze(P);
const secure=p=>{data(p,'constructor',P);data(p,'then',derive);return p;};
const observe=p=>{apply(then,secure(p),[undefined,()=>{}]);};
const getter=(p,k)=>{for(;p;p=proto(p)){const d=own(p,k);if(d&&d.get)return d.get;}throw 0;};
const read=(g,v)=>apply(g,v,[]),messageData=getter(MessageEvent.prototype,'data'),messagePorts=getter(MessageEvent.prototype,'ports');
const eventTarget=getter(Event.prototype,'currentTarget');
const post=MessagePort.prototype.postMessage;
const AC=AbortController,signal=getter(AC.prototype,'signal'),abort=AC.prototype.abort;
const responseHeaders=getter(Response.prototype,'headers'),responseUrl=getter(Response.prototype,'url'),responseBody=getter(Response.prototype,'body');
const headerGet=Headers.prototype.get,getReader=ReadableStream.prototype.getReader,readerRead=ReadableStreamDefaultReader.prototype.read;
const readerCancel=ReadableStreamDefaultReader.prototype.cancel,readerRelease=ReadableStreamDefaultReader.prototype.releaseLock;
const Bytes=Uint8Array,typed=proto(Bytes.prototype),byteLength=getter(typed,'byteLength');
const bytesSet=Bytes.prototype.set,subarray=Bytes.prototype.subarray,timer=setTimeout,clear=clearTimeout;
const has=Reflect.has;
const value=(o,k)=>{const d=own(o,k);if(!d||!own(d,'value')||!d.enumerable)throw 0;return d.value;};
const shape=(o,fields)=>{if(!o||typeof o!=='object'||(proto(o)!==objectProto&&proto(o)!==null))throw 0;
  const list=keys(o);if(list.length!==fields.length)throw 0;
  for(let i=0;i<fields.length;i++)value(o,fields[i]);};
const offer=create(null);
for(const [k,v] of [['contract','records.body.read.v1'],['scope','viewer-visible-current-bodies'],['max_request_bytes',4096],['max_response_bytes',262144],['max_page_bytes',32768],['max_body_bytes',16777216],['request_timeout_ms',5000],['max_inflight',1]])data(offer,k,v);
const encodedOffer=wire.encodeChannel(freeze(offer),'offering').data;


/** Trusted issuance/custody inputs, never frame-provided selectors or flags. */
export function createBodyParentController(configuration) {
  // Host-only grammar selection; never look up a caller getter or retain it.
  let mixed=false;
  try {
    const d=own(configuration,'composition');
    if(d){if(!own(d,'value')||!d.enumerable)throw 0;
      shape(d.value,['kind']);if(value(d.value,'kind')!=='ordinary-mixed.v1')throw 0;mixed=true;
    }else if(has(configuration,'composition'))throw 0;
  }catch{throw new Error('body composition');}
  const {token,endpoint,retireEndpoint,isCurrent}=configuration;
  const origin=globalThis.location.origin;
  for(const url of [endpoint,retireEndpoint]){const u=new URL_(url,origin);if(u.origin!==origin||u.username||u.password||u.hash)throw new Error('body endpoint');}
  if(typeof token!=='string'||token.length>6400||!/^abm1\.[0-9a-f]+$/.test(token)||typeof isCurrent!=='function')throw new Error('body mount');
  const pageUrl=new URL_(endpoint,origin).href,retireUrl=new URL_(retireEndpoint,origin).href;
  let live=true,ready=false,attached=null,ticket=null,retired=false,resolveClosed;
  const closed=freeze(secure(new P(yes=>{resolveClosed=yes;})));
  const current=()=>{try{return live&&attached!==null&&isCurrent()===true;}catch{return false;}};
  const send=(p,id,kind,extra)=>{const e=create(null);data(e,'version','native.html.bridge.v1');data(e,'type',kind==='result'?'body-read-result':'body-read-transport');data(e,'request_id',id);data(e,kind==='result'?'response':'reason',extra);
    const encoded=wire.encodeChannel(e,kind);if(encoded.kind!=='encoded')throw 0;apply(post,p,[encoded.data]);};
  const retire=()=>{if(retired)return;retired=true;try{observe(fetchPage(retireUrl,{method:'DELETE',credentials:'same-origin',redirect:'error',headers:{'x-native-body-mount':token}}));}catch{}};
  const close=()=>{
    if(!live)return;live=false;ready=false;
    // Guards/ticket terminal first; each cleanup independent; notification is
    // logical closure, NEVER retirement success, settlement or physical ACK.
    if(ticket&&!ticket.terminal)ticket.terminal='closed';
    try {
      if(ticket){try{apply(abort,ticket.controller,[]);}catch{}try{clear(ticket.timer);}catch{}}
      try{retire();}catch{}
    }finally{try{resolveClosed();}catch{}}
  };
  const fail=()=>{close();return 'closed';};
  const terminal=(t,reason)=>{
    if(t.terminal)return;t.terminal=reason;
    try{apply(abort,t.controller,[]);}catch{}
    if(!current()){close();return;}
    try{send(t.port,t.id,'transport',reason);}catch{close();}
  };
  const collect=async(response,t)=>{
    if(!current()||t.terminal)throw 0;
    const headers=read(responseHeaders,response);
    if(read(responseUrl,response)!==pageUrl||apply(headerGet,headers,['content-type'])!=='application/json'||apply(headerGet,headers,['content-encoding'])!=='identity')throw 0;
    const stream=read(responseBody,response);if(!stream)throw 0;
    const reader=apply(getReader,stream,[]),buffer=new Bytes(262144);let used=0,done=false;
    try{for(;;){const step=await secure(apply(readerRead,reader,[]));if(!current()||t.terminal)throw 0;
      if(step.done){done=true;break;}const length=read(byteLength,step.value);if(length>262144-used)throw 0;
      apply(bytesSet,buffer,[step.value,used]);used+=length;
    }return wire.decodeHttp(apply(subarray,buffer,[0,used]));}
    finally{if(!done)try{observe(apply(readerCancel,reader,[]));}catch{}try{apply(readerRelease,reader,[]);}catch{}}
  };
  const dispatch=async(t,raw)=>{
    let reason='network';
    try {
      const response=await secure(fetchPage(pageUrl,{method:'POST',credentials:'same-origin',redirect:'error',headers:{'content-type':'application/json','x-native-body-mount':token},body:raw,signal:read(signal,t.controller)}));
      reason='protocol';const result=await secure(collect(response,t));
      if(t.terminal||!current()||ticket!==t||attached.port!==t.port||attached.epoch!==t.epoch){if(!current())close();return;}
      if(result.kind==='body')send(t.port,t.id,'result',result.response);
      else {send(t.port,t.id,'transport',result.kind==='transport'?result.reason:'protocol');if(result.kind==='invalid'||result.reason==='protocol')close();}
    }catch{if(!current())close();else if(!t.terminal&&ticket===t)try{send(t.port,t.id,'transport',reason);if(reason==='protocol')close();}catch{close();}}
    finally{try{clear(t.timer);}catch{}if(ticket===t)ticket=null;}
  };
  const attach=attachment=>{try{
    let contextOffered=false;
    const d=own(attachment,'composition');
    if(mixed){if(!d||!own(d,'value')||!d.enumerable)throw 0;
      shape(d.value,['kind','contextOffered']);
      if(value(d.value,'kind')!=='ordinary-mixed.v1'||typeof value(d.value,'contextOffered')!=='boolean')throw 0;
      contextOffered=value(d.value,'contextOffered');
    }else if(has(attachment,'composition'))throw 0;
    const {port,epoch,window}=attachment;
    if(!live||attached||!port||!window||!safeInteger(epoch)||epoch<1||isCurrent()!==true)throw 0;
    attached=mixed?freeze({port,epoch,window,contextOffered}):freeze({port,epoch,window});return encodedOffer;
  }catch{close();throw new Error('body attachment');}};
  const receive=(event,context)=>{try{
    if(!live)return 'closed';if(!current())return fail();
    if(context.port!==attached.port||context.epoch!==attached.epoch)return 'ignored';
    // Port events are tied to the genuine dispatching port, not Window source.
    if(read(eventTarget,event)!==attached.port)return 'ignored';
    if(read(messagePorts,event).length!==0)return fail();
    const input=read(messageData,event),type=value(input,'type');
    if(type==='ready'){
      shape(input,['version','type','profile','slides','features']);
      if(value(input,'version')!=='native.html.bridge.v1'||ready)return fail();
      const count=value(input,'slides'),profile=value(input,'profile'),features=value(input,'features');
      if(!safeInteger(count)||count<0||profile!==(count===0?'document':'slides')||!isArray(features))return fail();
      const length=own(features,'length').value;if(length>32||keys(features).length!==length+1)return fail();
      if(mixed){
        if(length!==(attached.contextOffered?3:2))return fail();
        let body=false,reveal=false,context=false;
        for(let i=0;i<length;i++){const f=value(features,String(i));
          if(f==='records.body.read.v1'&&!body)body=true;
          else if(f==='surface.reveal.v1'&&!reveal)reveal=true;
          else if(f==='app-view-report.v1'&&attached.contextOffered&&!context)context=true;
          else return fail();}
        if(!body||!reveal||context!==attached.contextOffered)return fail();
        ready=true;return 'ready';
      }
      let body=false,reveal=false;
      for(let i=0;i<length;i++){const f=value(features,String(i));if(f==='records.body.read.v1'&&!body)body=true;else if(f==='surface.reveal.v1'&&!reveal)reveal=true;else return fail();}
      if(!body)return fail();ready=true;return 'ready';
    }
    if(type!=='body-read'&&type!=='body-read-cancel')return 'ignored';
    const e=wire.encodeChannel(input,type==='body-read'?'request':'cancel');if(e.kind!=='encoded'||!ready)return fail();
    const data=e.data;
    if(type==='body-read-cancel'){if(ticket&&data.request_id===ticket.id)terminal(ticket,'cancelled');return live?'consumed':'closed';}
    if(ticket){send(attached.port,data.request_id,'transport','busy');return 'consumed';}
    const t={id:data.request_id,port:attached.port,epoch:attached.epoch,controller:new AC(),terminal:null,timer:null};ticket=t;
    t.timer=timer(close,10000);
    observe(dispatch(t,data.request_json));return 'consumed';
  }catch{return fail();}};
  return freeze(data(data(data(data(create(null),'attach',attach),'receive',receive),'close',close),'closed',closed));
}

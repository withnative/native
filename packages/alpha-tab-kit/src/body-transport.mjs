// Public author convenience wrapper. Only the real injected host grants access.
// A supplied API is trusted caller wiring, never proof of server admission.
const apply=Reflect.apply,own=Object.getOwnPropertyDescriptor,create=Object.create,define=Object.defineProperty,freeze=Object.freeze,keys=Reflect.ownKeys,proto=Object.getPrototypeOf,objectProto=Object.prototype;
const BasePromise=Promise,then=BasePromise.prototype.then;
const P=class extends BasePromise {};const species=create(null);species.value=P;define(P,Symbol.species,species);freeze(P.prototype);freeze(P);
const AC=AbortController,abort=AC.prototype.abort,signal=own(AC.prototype,'signal').get;
const aborted=own(Object.getPrototypeOf(new AC().signal),'aborted').get;
const add=EventTarget.prototype.addEventListener,remove=EventTarget.prototype.removeEventListener;
const error=reason=>{const e=create(null);e.name='BodyTransportError';e.reason=reason;return freeze(e);};
const fail=reason=>{const p=new P((_,reject)=>reject(error(reason)));apply(then,p,[undefined,()=>{}]);return p;};
export function createBodyTransport(api=globalThis.nativeArtifact) {
  let disposed=false,body,read,raw,offering,pending=null;
  try {
    const d=own(api,'body');if(!d||!own(d,'value'))throw 0;body=d.value;
    const a=own(body,'readPage'),b=own(body,'readPageRaw'),o=own(body,'offering');
    if(!a||!b||!own(a,'value')||!own(b,'value')||typeof a.value!=='function'||typeof b.value!=='function')throw 0;
    read=a.value;raw=b.value;
    // This specific accessor is the trusted injected namespace's live offering.
    offering=o&&own(o,'get')?o.get:()=>o&&own(o,'value')?o.value:null;
  } catch { body=null; }
  const invoke=(method,value,options)=>{
    let external,listener,controller,local=null;
    try {
      if(options!==undefined){if(!options||typeof options!=='object'||(proto(options)!==objectProto&&proto(options)!==null))throw 0;const list=keys(options);if(list.length>1)throw 0;
        if(list.length){const d=own(options,'signal');if(list[0]!=='signal'||!d||!own(d,'value')||!d.enumerable)throw 0;external=d.value;}
      }
      if(external!==undefined&&apply(aborted,external,[])===true)return fail('cancelled');
      if(disposed)return fail('closed');if(!body)return fail('not_offered');if(pending)return fail('busy');
      controller=new AC();listener=()=>apply(abort,controller,[]);
      if(external!==undefined)apply(add,external,['abort',listener]);
      local={controller};pending=local;
      const p=apply(method,body,[value,{signal:apply(signal,controller,[])}]);
      const clean=()=>{if(external!==undefined)try{apply(remove,external,['abort',listener]);}catch{}if(pending===local)pending=null;};
      apply(then,p,[clean,clean]);return p;
    }catch{if(external!==undefined&&listener)try{apply(remove,external,['abort',listener]);}catch{}if(local&&pending===local)pending=null;return fail('invalid_message');}
  };
  const out=create(null);out.readPage=(v,o)=>invoke(read,v,o);out.readPageRaw=(v,o)=>invoke(raw,v,o);out.dispose=()=>{disposed=true;if(pending)try{apply(abort,pending.controller,[]);}catch{}};
  const d=create(null);d.get=()=>{try{return !disposed&&body?apply(offering,body,[]):null;}catch{return null;}};d.enumerable=true;define(out,'offering',d);
  return freeze(out);
}

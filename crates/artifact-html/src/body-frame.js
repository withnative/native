// Trusted bootstrap capture precedes author code. This lane has no source/token.
function bodyFrameFactory(I) {
  const {wire,apply,create,define,freeze,own,keys,proto,objectProto,Promise: BasePromise,then,parse,
    listen,unlisten,post,timer,clear,aborted,safeInteger} = I;
  const data=(o,k,v)=>{const d=create(null);d.value=v;d.enumerable=true;define(o,k,d);return o;};
  const P=class extends BasePromise {};const species=create(null);species.value=P;define(P,I.species,species);freeze(P.prototype);freeze(P);
  const error=reason=>freeze(data(data(create(null),'name','BodyTransportError'),'reason',reason));
  const reject=reason=>{const p=new P((_,no)=>no(error(reason)));apply(then,p,[undefined,()=>{}]);return p;};
  const shape=o=>{if(!o||typeof o!=='object'||(proto(o)!==objectProto&&proto(o)!==null))throw 0;
    const list=keys(o);if(list.length>1)throw 0;let signal;
    for(let n=0;n<list.length;n++){if(list[n]!=='signal')throw 0;const d=own(o,'signal');if(!d||!d.enumerable||!own(d,'value'))throw 0;signal=d.value;}
    if(signal!==undefined)apply(aborted,signal,[]);return signal;};
  let port=null,offering=null,enabled=false,closed=false,pending=null,sequence=0;
  const isAborted=s=>s!==undefined&&apply(aborted,s,[])===true;
  const send=(id,kind,extra)=>{const v=create(null);data(v,'version','native.html.bridge.v1');data(v,'type',kind==='request'?'body-read':'body-read-cancel');data(v,'request_id',id);
    if(kind==='request')data(v,'request_json',extra);const e=wire.encodeChannel(v,kind);if(e.kind!=='encoded')throw 0;post(port,e.data);};
  const finish=(p,reason,value,cancel)=>{if(pending!==p)return;if(cancel){try{send(p.id,'cancel');}catch{}}
    pending=null;clear(p.timer);if(p.signal!==undefined)try{unlisten(p.signal,'abort',p.abort);}catch{}
    if(reason)p.no(error(reason));else p.yes(value);};
  const close=()=>{if(closed)return;closed=true;enabled=false;offering=null;if(pending)finish(pending,'closed',undefined,true);port=null;};
  const request=(value,options,raw)=>{
    try {
      const signal=options===undefined?undefined:shape(options);
      if(isAborted(signal))return reject('cancelled');
      if(closed)return reject('closed');if(!enabled||!port||!offering)return reject('not_offered');
      const checked=raw?wire.validateRawRequest(value):wire.validateTypedRequest(value);
      if(checked.kind!=='request')return reject('invalid_message');if(pending)return reject('busy');
      if(!safeInteger(sequence+1)){close();return reject('closed');}
      let expected=null;if(!raw){const q=parse(checked.request_json),id=own(q,'record_id'),size=own(q,'page_bytes');expected={id:id.value,bytes:size?size.value:32768};}
      const id='body-'+(++sequence);
      const promise=new P((yes,no)=>{
        const p={id,yes,no,signal,expected,timer:null,abort:null};pending=p;
        p.abort=()=>{try{if(isAborted(signal))finish(p,'cancelled',undefined,true);}catch{finish(p,'invalid_message',undefined,true);}};
        p.timer=timer(()=>{finish(p,'timeout',undefined,true);close();},10000);
        try{if(signal!==undefined)listen(signal,'abort',p.abort);if(isAborted(signal)){finish(p,'cancelled',undefined,true);return;}send(id,'request',checked.request_json);}catch{finish(p,'protocol',undefined,false);close();}
      });
      // Observe rejection even if author abandons the promise; no diagnostics.
      apply(then,promise,[undefined,()=>{}]);return promise;
    } catch { return reject('invalid_message'); }
  };
  const api=create(null);data(api,'readPage',(value,options)=>request(value,options,false));data(api,'readPageRaw',(value,options)=>request(value,options,true));
  const d=create(null);d.get=()=>enabled&&!closed?offering:null;d.enumerable=true;define(api,'offering',d);freeze(api);
  return freeze({api,close,
    connect:(p,candidate,feature)=>{try{if(closed||port)return;port=p;const e=wire.encodeChannel(candidate,'offering');if(feature===true&&e.kind==='encoded')offering=e.data;}catch{offering=null;}},
    ready:()=>{enabled=!!offering&&!closed;return enabled;},
    receive:(value,ports)=>{try{
      const t=own(value,'type');if(!t||!own(t,'value')||(t.value!=='body-read-result'&&t.value!=='body-read-transport'))return false;
      if(ports.length!==0){close();return true;}const kind=t.value==='body-read-result'?'result':'transport';const e=wire.encodeChannel(value,kind);
      if(e.kind!=='encoded'){close();return true;}const v=e.data,p=pending;if(!p||v.request_id!==p.id)return true;
      if(isAborted(p.signal)){finish(p,'cancelled',undefined,true);return true;}
      if(kind==='transport'){finish(p,v.reason);return true;}
      const b=v.response;if(p.expected&&!b.error&&(b.record_id!==p.expected.id||b.end_byte-b.start_byte>p.expected.bytes)){finish(p,'protocol');close();return true;}
      finish(p,null,b);return true;
    }catch{close();return true;}}
  });
}

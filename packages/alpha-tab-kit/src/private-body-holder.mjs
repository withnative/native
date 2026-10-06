// Dedicated PRIVATE holder; SOLE Window handshake/port/startup timer owner.
// Capture this trusted parent module before mounting any authored frame.
import { createBodyParentController } from './body-parent-controller.mjs';
const apply=Reflect.apply,own=Object.getOwnPropertyDescriptor,freeze=Object.freeze,proto=Object.getPrototypeOf;
const then=Promise.prototype.then,isArray=Array.isArray,includes=Array.prototype.includes,URL_=URL;
const add=EventTarget.prototype.addEventListener,remove=EventTarget.prototype.removeEventListener;
const start=MessagePort.prototype.start,closePort=MessagePort.prototype.close;
// Window methods live on the actual global in Chromium, not Window.prototype.
const winPost=globalThis.postMessage,Channel=MessageChannel;
const getter=(p,k)=>{for(;p;p=proto(p)){const d=own(p,k);if(d&&d.get)return d.get;}throw 0;};
const read=(g,v)=>apply(g,v,[]),messageData=getter(MessageEvent.prototype,'data'),messagePorts=getter(MessageEvent.prototype,'ports');
const messageSource=getter(MessageEvent.prototype,'source'),messageOrigin=getter(MessageEvent.prototype,'origin');
const frameWindow=getter(HTMLIFrameElement.prototype,'contentWindow'),connected=getter(Node.prototype,'isConnected');
const frameSrc=own(HTMLIFrameElement.prototype,'src').set,timer=setTimeout,clear=clearTimeout;
const value=(o,k)=>{const d=own(o,k);if(!d||!own(d,'value')||!d.enumerable)throw 0;return d.value;};
/** Host-only inputs are genuine issuance/selection, not data from frame messages. */
export function createPrivateBodyHolder({frame,token,launchUrl,endpoint,retireEndpoint,isCurrent}) {
  let live=true,port=null,ready=false,epoch=0,handshakeTimer=null,controller=null,selectedWindow;
  const current=()=>{try{return live&&read(frameWindow,frame)===selectedWindow&&read(connected,frame)&&isCurrent()===true;}catch{return false;}};
  const dispose=()=>{
    if(!live)return;live=false;ready=false;epoch++;
    // Independent bounded cleanup; no thrown object or thenable can escape a
    // closed-promise continuation. Controller notification is NOT physical ACK.
    try{controller?.close();}catch{}
    try{clear(handshakeTimer);}catch{}
    try{apply(remove,globalThis,['message',handshake]);}catch{}
    try{apply(remove,globalThis,['pagehide',dispose]);}catch{}
    const old=port;port=null;if(old)try{apply(closePort,old,[]);}catch{}
  };
  const receive=(event,captured,version)=>{
    if(port!==captured||epoch!==version)return;
    const outcome=controller.receive(event,{port:captured,epoch:version});
    if(outcome==='ready'){ready=true;try{clear(handshakeTimer);}catch{dispose();}return;}
    if(outcome==='consumed')return;
    if(outcome==='closed'){dispose();return;}
    // Closed nonbody policy. Never inspect diagnostics or dispatch legacy
    // read/effect/session/context messages. No readiness inheritance.
    if(outcome==='ignored')dispose();
  };
  const handshake=event=>{try{
    if(port||!current()||read(messageSource,event)!==selectedWindow||read(messageOrigin,event)!=='null')return;
    if(read(messagePorts,event).length!==0)return;const data=read(messageData,event);
    if(value(data,'type')!=='native-html-bootstrap'||value(data,'version')!=='native.html.bridge.v1')return;
    const features=value(data,'features');if(!isArray(features)||own(features,'length').value>32||!apply(includes,features,['records.body.read.v1'])){dispose();return;}
    const c=new Channel();port=c.port1;const captured=port,version=++epoch;
    const offering=controller.attach({port:captured,epoch:version,window:selectedWindow});
    apply(add,captured,['message',event=>receive(event,captured,version)]);
    apply(add,captured,['messageerror',dispose]);apply(add,captured,['close',dispose]);apply(start,captured,[]);
    apply(winPost,selectedWindow,[{type:'native-html-init',version:'native.html.bridge.v1',input:null,host_features:['records.body.read.v1'],body_read:offering},'*',[c.port2]]);
  }catch{dispose();}};
  try {
    selectedWindow=read(frameWindow,frame);const launch=new URL_(launchUrl);
    if(!selectedWindow||!/^https?:$/.test(launch.protocol)||launch.username||launch.password||launch.hash||launch.search||typeof isCurrent!=='function')throw 0;
    controller=createBodyParentController({token,endpoint,retireEndpoint,isCurrent:current});
    // Native-owned frozen private-species promise; captured then, observation
    // of the derived promise, BEFORE navigation/author code, no callback grant.
    const derived=apply(then,controller.closed,[dispose]);
    apply(then,derived,[undefined,()=>{}]);
    apply(add,globalThis,['message',handshake]);apply(add,globalThis,['pagehide',dispose]);
    handshakeTimer=timer(dispose,10000);
    apply(frameSrc,frame,[launch.href]);
  }catch{dispose();throw new Error('private body startup');}
  return freeze({dispose});
}

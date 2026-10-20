(()=>{"use strict";
const HOST=__NATIVE_WORKBENCH_ORIGIN__, VERSION="native.html.bridge.v1";
const apply=Reflect.apply,own=Object.getOwnPropertyDescriptor,parentOf=Object.getPrototypeOf,define=Object.defineProperty,freezeObject=Object.freeze,objectKeys=Object.keys,isFrozen=Object.isFrozen,NativeString=String,arrayPush=Array.prototype.push,arrayIndexOf=Array.prototype.indexOf,arraySplice=Array.prototype.splice,arrayIncludes=Array.prototype.includes;
const getter=(proto,name)=>{for(let current=proto;current;current=parentOf(current)){const descriptor=own(current,name);if(descriptor?.get)return descriptor.get}};
const read=(nativeGetter,value)=>apply(nativeGetter,value,[]),eventAdd=EventTarget.prototype.addEventListener,eventRemove=EventTarget.prototype.removeEventListener,eventPrevent=Event.prototype.preventDefault,eventStop=Event.prototype.stopImmediatePropagation,portPost=MessagePort.prototype.postMessage,portStart=MessagePort.prototype.start,portClose=MessagePort.prototype.close,elementClosest=Element.prototype.closest,elementAttribute=Element.prototype.getAttribute;
const pristineEvent=new Event("native-html-bootstrap"),messageData=getter(MessageEvent.prototype,"data"),messageSource=getter(MessageEvent.prototype,"source"),messageOrigin=getter(MessageEvent.prototype,"origin"),messagePorts=getter(MessageEvent.prototype,"ports"),eventTarget=getter(Event.prototype,"target"),eventTrusted=own(pristineEvent,"isTrusted")?.get||getter(Event.prototype,"isTrusted"),eventPrevented=getter(Event.prototype,"defaultPrevented"),nodeType=getter(Node.prototype,"nodeType"),keyValue=getter(KeyboardEvent.prototype,"key"),shiftValue=getter(KeyboardEvent.prototype,"shiftKey"),mouseCtrl=getter(MouseEvent.prototype,"ctrlKey"),mouseMeta=getter(MouseEvent.prototype,"metaKey"),mouseButton=getter(MouseEvent.prototype,"button"),pageTransitionPersisted=getter(PageTransitionEvent.prototype,"persisted"),eventType=getter(Event.prototype,"type"),keyRepeat=getter(KeyboardEvent.prototype,"repeat");
const listen=(target,type,listener,options)=>apply(eventAdd,target,[type,listener,options]),unlisten=(target,type,listener,options)=>apply(eventRemove,target,[type,listener,options]),prevent=event=>apply(eventPrevent,event,[]),stop=event=>apply(eventStop,event,[]),post=(port,value,transfer)=>apply(portPost,port,transfer?[value,transfer]:[value]),start=port=>apply(portStart,port,[]),isElement=value=>!!value&&read(nodeType,value)===1,attribute=(element,name)=>apply(elementAttribute,element,[name]),closest=(element,selector)=>apply(elementClosest,element,[selector]),trusted=event=>!!eventTrusted&&read(eventTrusted,event)===true,prevented=event=>!!eventPrevented&&read(eventPrevented,event)===true;
let channel=null, initialized=false, current=0, slides=[], queued=[], heldInput, heldSeq=null, heldDigest, heldViewState, inputSubscribers=[];
let resolveReady, rejectReady;
const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject});
const jsonStringify=JSON.stringify,jsonParse=JSON.parse,isArray=Array.isArray,NativePromise=Promise,pendingIntents=Object.create(null);let pendingIntentCount=0;
let armFeature=false,pendingArm=null,armTimer=null;
/* Presentation belongs to the host. Capture DOM/CSS primitives before authored
   scripts; append tokens then override after authored styles have parsed. */
const SKIN_FEATURE="app.skin.v1",SKIN_SCHEMA="native.app-skin.v1";
const skinDOM=(()=>{if(typeof Document!=="function"||typeof HTMLStyleElement!=="function"||typeof CSSStyleSheet!=="function"||typeof CSSStyleRule!=="function"||typeof CSSStyleDeclaration!=="function")return null;
const skinCreate=Document.prototype.createElement,skinAppend=Node.prototype.appendChild,skinRemove=Node.prototype.removeChild,skinParent=getter(Node.prototype,"parentNode"),skinText=own(Node.prototype,"textContent").set,skinSheet=getter(HTMLStyleElement.prototype,"sheet"),skinRules=getter(CSSStyleSheet.prototype,"cssRules"),skinRuleStyle=getter(CSSStyleRule.prototype,"style"),skinInsert=CSSStyleSheet.prototype.insertRule,skinSet=CSSStyleDeclaration.prototype.setProperty,skinDocumentState=getter(Document.prototype,"readyState");
const skinHead=document.head,skinTokens=apply(skinCreate,document,["style"]),skinOverride=apply(skinCreate,document,["style"]);
const remove=node=>{const parent=read(skinParent,node);if(parent)apply(skinRemove,parent,[node])};
return freezeObject({loading:()=>read(skinDocumentState,document)==="loading",paint(value){remove(skinTokens);remove(skinOverride);apply(skinText,skinTokens,[""]);apply(skinText,skinOverride,[""]);if(!value)return;apply(skinAppend,skinHead,[skinTokens]);const sheet=read(skinSheet,skinTokens);apply(skinInsert,sheet,[":root{}",0]);const rule=read(skinRules,sheet)[0],style=read(skinRuleStyle,rule);for(const key of objectKeys(value.tokens))apply(skinSet,style,[key,value.tokens[key]]);apply(skinText,skinOverride,[value.css]);apply(skinAppend,skinHead,[skinOverride])}})})();
const skinInteger=Number.isSafeInteger;
let skinClosed=false,skinFeature=false,skinRevision=-1,skinParsed=false,skinCurrent=null,skinSubscribers=[],skinSnapshot=freezeObject({labels:freezeObject({})});
const paintSkin=()=>{if(skinParsed)skinDOM?.paint(skinCurrent)};
const receiveSkin=data=>{if(skinClosed||!skinFeature||data.skin_version!==SKIN_SCHEMA||!skinInteger(data.revision)||data.revision<0||data.revision<=skinRevision)return;const value=data.skin;if(value!==null&&(!value||typeof value!=="object"||isArray(value)||typeof value.css!=="string"||!value.tokens||!value.labels))return;skinRevision=data.revision;skinCurrent=value===null?null:freeze(jsonParse(jsonStringify(value)));const labels=skinCurrent?skinCurrent.labels:{};skinSnapshot=freezeObject({labels:freezeObject({...labels})});paintSkin();for(const subscriber of [...skinSubscribers]){try{subscriber(skinSnapshot)}catch{}}};
const skinApi=freezeObject({subscribe(callback){if(typeof callback!=="function")throw new TypeError("skin subscriber must be a function");pushValue(skinSubscribers,callback);try{callback(skinSnapshot)}catch{}let active=true;return ()=>{if(!active)return;active=false;const index=apply(arrayIndexOf,skinSubscribers,[callback]);if(index>=0)apply(arraySplice,skinSubscribers,[index,1])}}});
const closeSkin=()=>{skinClosed=true;skinSubscribers=[];skinCurrent=null;skinSnapshot=freezeObject({labels:freezeObject({})});paintSkin()};

const LOCATION_FEATURE="surface.location.v1",UNSAVED_FEATURE="surface.unsaved.v1",COMMENT_FRAME_FEATURE="comment.keeps-body-frame.v1",locationPattern=/^[A-Za-z0-9._:-]{1,128}(?![\s\S])/,locationTest=RegExp.prototype.test,unsavedPattern=/^[^\0-\x1f\x7f]{1,200}$/;
let locationFeature=false,unsavedFeature=false,commentFrameFeature=false;
const publishLocation=recordId=>{if(contextClosed)throw new TypeError("location observation unavailable");if(recordId!==null&&(typeof recordId!=="string"||!apply(locationTest,locationPattern,[recordId])))throw new TypeError("invalid record location");if(locationFeature)send({type:"location",version:VERSION,location_version:LOCATION_FEATURE,record_id:recordId})};
const publishUnsaved=state=>{if(contextClosed)throw new TypeError("unsaved observation unavailable");if(state!==null&&(typeof state!=="object"||isArray(state)||!objectKeys(state).every(field=>field==="reason")||(typeof state.reason!=="undefined"&&(typeof state.reason!=="string"||!apply(locationTest,unsavedPattern,[state.reason])))))throw new TypeError("invalid unsaved state");if(unsavedFeature)send({type:"unsaved",version:VERSION,unsaved_version:UNSAVED_FEATURE,state})};
/* Disarm on a macrotask, not a microtask. Chromium runs a microtask checkpoint
   between a capture listener and the target listener, so a microtask disarm
   cleared the flag before the author's own click handler ran. The consumed flag
   still bounds the event at one proposal. */
const setTimer=setTimeout,clearTimer=clearTimeout,requestFrame=requestAnimationFrame;
const intentId=value=>typeof value==="string"&&value.length>0&&value.length<=128&&value.trim()===value&&!/[\u0000-\u001f\u007f]/.test(value);
const intentMap=value=>!!value&&typeof value==="object"&&!isArray(value)&&objectKeys(value).length<=32;
/* Layer 1 of the activation gate, mirroring navigation's trusted-click runtime.
   Only the event that COMPLETES a gesture may arm a proposal. A mouse click, a
   touch tap, and Enter/Space on a control each dispatch exactly one trusted
   click; an HTML5 drag dispatches exactly one trusted drop. Arming on every
   event in the sequence instead (pointerdown/mousedown/pointerup/mouseup/click)
   admitted five proposals for one physical click. Message/load/focus/submit are
   deliberately absent: postMessage, requestSubmit() and focus() all dispatch
   trusted events, so admitting them would hand author code the gesture it must
   not have. A proposal made while unarmed is NOT refused: it is sent marked as
   not gesture-backed, and the host routes it to the Apply tray. The mark is a
   frame-supplied claim, so the host treats it as necessary but never
   sufficient. */
const gestureEvents=["click","drop"];
let gestureArmed=false,gestureUsed=false,keyRepeating=false,gestureEpoch=0;
const releaseGesture=()=>{gestureArmed=false;gestureUsed=false};
/* `gestureArmed` also bounds a single physical action that dispatches more than
   one terminal event in one task: a click on a label[for] dispatches a trusted
   click on the label and a synthesised trusted click on its control. Re-arming
   on the second would reset the consumed flag, so an armed gesture stays armed
   until its macrotask release. Separate gestures are separate tasks, so the
   release has always run before the next one. */
const armGesture=event=>{if(!trusted(event))return;const type=read(eventType,event);if(!apply(arrayIncludes,gestureEvents,[type]))return;if(type==="click"&&keyRepeating)return;if(gestureArmed)return;gestureArmed=true;gestureUsed=false;gestureEpoch++;setTimer(releaseGesture,0)};
for(const name of gestureEvents)listen(window,name,armGesture,true);
/* A held key autorepeats trusted keydown, and on a control each repeat also
   dispatches a trusted click. Track the repeat state so only the click from the
   initial press arms; a fresh pointer gesture clears it. */
const trackKeyRepeat=event=>{if(!trusted(event))return;keyRepeating=read(keyRepeat,event)===true};
const clearKeyRepeat=event=>{if(trusted(event))keyRepeating=false};
listen(window,"keydown",trackKeyRepeat,true);
listen(window,"keyup",clearKeyRepeat,true);
for(const name of ["pointerdown","mousedown","touchstart"])listen(window,name,clearKeyRepeat,true);
/* A refused proposal is reported through the existing diagnostic channel so an
   author can see why a control did nothing instead of a bare console exception.
   Only a bounded reason code crosses the bridge -- the host owns the wording.
   Throttled to one report per 250ms and 16 per frame, so a loop cannot flood
   the host. The thrown TypeError is unchanged; this is an addition. Only a
   malformed, duplicate or oversized proposal is refused: a well-formed proposal
   made outside a completed gesture is still sent, marked as not gesture-backed,
   and the host routes it to the Apply tray rather than committing it. */
let refusalReported=false,refusalReports=0;
const reportBoundedRefusal=(code,reason)=>{if(refusalReports>=16||refusalReported)return;refusalReported=true;refusalReports+=1;setTimer(()=>{refusalReported=false},250);report(code,{reason})};
const refuseProposal=(reason,message)=>{reportBoundedRefusal("html_intent_refused",reason);throw new TypeError(message)};
const propose=intent=>{const backed=gestureArmed&&!gestureUsed;if(backed)gestureUsed=true;if(!intent||typeof intent!=="object"||isArray(intent)||objectKeys(intent).some(key=>!["request_id","entry_id","slots","values"].includes(key)))refuseProposal("malformed","artifact intent contains unsupported fields");const request_id=intent.request_id,entry_id=intent.entry_id,slots=intent.slots??{},values=intent.values??{};if(!intentId(request_id)||!intentId(entry_id)||!intentMap(slots)||!intentMap(values)||objectKeys(slots).some(key=>!intentId(key)||typeof slots[key]!=="string"||slots[key].length>256)||objectKeys(values).some(key=>!intentId(key)))refuseProposal("malformed","artifact intent is malformed");if(own(pendingIntents,request_id)||(pendingArm&&pendingArm.request_id===request_id)||pendingIntentCount>=32)refuseProposal("duplicate","artifact intent request is duplicate or queue is full");const encoded=jsonStringify({request_id,entry_id,slots,values});if(encoded.length>65536)refuseProposal("too_large","artifact intent exceeds bridge limit");const payload=jsonParse(encoded);return new NativePromise((resolve,reject)=>{pendingIntents[request_id]={resolve,reject};pendingIntentCount+=1;try{send({version:VERSION,type:"intent",intent:payload,gesture_backed:backed})}catch(error){delete pendingIntents[request_id];pendingIntentCount-=1;reject(error)}})};
const settleIntent=data=>{if(!intentId(data.request_id)||!own(pendingIntents,data.request_id)||!data.result||typeof data.result!=="object"||isArray(data.result))return;let result;try{const encoded=jsonStringify(data.result);if(encoded.length>65536)return;result=freeze(jsonParse(encoded))}catch{return}const pending=pendingIntents[data.request_id];delete pendingIntents[data.request_id];pendingIntentCount-=1;pending.resolve(result)};
/* Eager view-state publish for the successor frame. A body change is a new
   document, so no framework state survives it; the frame hands its own view
   state (open tab, expanded rows, wizard step) to the host, which holds the
   opaque blob and delivers it in the successor's init before first paint.
   Validated like propose() so authors get a synchronous TypeError at the call
   site rather than silent loss: the value must survive a pristine JSON
   round-trip and fit the same 65536 bound, and the optional schema is an
   advisory intent id. Coalesced to at most one posted message per animation
   frame, latest wins, so a per-keystroke publisher costs one message a frame.
   There is deliberately no acknowledgement and no bounded wait: no host
   decision rides on this message, so it adds no wall-clock liveness surface.
   If it is lost the successor cold-boots, which is today's behaviour. Before
   the port opens it takes one reserved slot in `queued`, collapsing onto any
   view state already waiting there, so it cannot exhaust the 32-slot buffer.
   Refusals share propose()'s single throttled refusal budget rather than
   arming a second timer: one budget for artifact misbehaviour, and no new
   wall-clock surface on this path. */
const refuseViewState=(reason,message)=>{reportBoundedRefusal("html_view_state_refused",reason);throw new TypeError(message)};
const sendViewState=value=>{if(channel)post(channel,value);else{for(let index=0;index<queued.length;index+=1){if(queued[index]&&queued[index].type==="view-state"){queued[index]=value;return}}if(queued.length<32)pushValue(queued,value)}};
let pendingViewState=null,viewStateScheduled=false;
const flushViewState=()=>{viewStateScheduled=false;const message=pendingViewState;pendingViewState=null;if(message)sendViewState(message)};
const setViewState=(value,options)=>{let schema;if(options!==undefined){if(!options||typeof options!=="object"||isArray(options))refuseViewState("malformed","view state options must be an object");if(objectKeys(options).some(key=>key!=="schema"))refuseViewState("malformed","view state options contain unsupported fields");const givenSchema=options.schema;if(givenSchema!==undefined){if(!intentId(givenSchema))refuseViewState("malformed","view state schema must be an intent id");schema=givenSchema}}let encoded;try{encoded=jsonStringify(value)}catch{refuseViewState("malformed","view state must be JSON-serializable")}if(typeof encoded!=="string")refuseViewState("malformed","view state must be JSON-serializable");if(encoded.length>65536)refuseViewState("too_large","view state exceeds bridge limit");const payload=jsonParse(encoded);pendingViewState={version:VERSION,type:"view-state",view_state:schema===undefined?{value:payload}:{value:payload,schema}};if(!viewStateScheduled){viewStateScheduled=true;if(typeof requestFrame==="function")apply(requestFrame,window,[flushViewState]);else flushViewState()}};
const pushValue=(array,value)=>apply(arrayPush,array,[value]),indexOfValue=(array,value)=>apply(arrayIndexOf,array,[value]),spliceValue=(array,start,deleteCount)=>apply(arraySplice,array,[start,deleteCount]);
/* On-request reads. Offered only for the needs the host lists in its init,
   so a host without the capability refuses at the call site instead of
   leaving a promise that never settles. The frame names a need and bounded
   params; the host decides, re-checking consent and the viewer's authority
   on every request, and answers with {status, code, need, result}. At most
   8 reads in flight; params are bounded like proposals. */
let offeredNeeds=[],pendingReadCount=0,readSeq=0;const pendingReads=Object.create(null);
const refuseRead=(reason,message)=>{reportBoundedRefusal("html_read_refused",reason);throw new TypeError(message)};
const readNeed=(need,params)=>{if(!intentId(need)||!apply(arrayIncludes,offeredNeeds,[need]))refuseRead("undeclared","this host offers no such read");const given=params===undefined?{}:params;if(!given||typeof given!=="object"||isArray(given))refuseRead("malformed","read params must be an object");let encoded;try{encoded=jsonStringify(given)}catch{refuseRead("malformed","read params must be JSON-serializable")}if(typeof encoded!=="string"||encoded.length>4096)refuseRead("too_large","read params exceed bridge limit");if(pendingReadCount>=8)refuseRead("busy","too many reads in flight");readSeq+=1;const request_id="read-"+readSeq;const payload=jsonParse(encoded);return new NativePromise((resolve,reject)=>{pendingReads[request_id]={resolve,reject};pendingReadCount+=1;try{send({version:VERSION,type:"read",request_id,need,params:payload})}catch(error){delete pendingReads[request_id];pendingReadCount-=1;reject(error)}})};
const settleRead=data=>{if(typeof data.request_id!=="string"||!own(pendingReads,data.request_id))return;let answer;try{const encoded=jsonStringify({status:data.status,code:data.code,need:data.need,result:data.result,keyed_freshness:data.keyed_freshness});answer=encoded.length>1048576?freezeObject({status:"unavailable",code:"too_large"}):freeze(jsonParse(encoded))}catch{answer=freezeObject({status:"unavailable",code:"malformed"})}const pending=pendingReads[data.request_id];delete pendingReads[data.request_id];pendingReadCount-=1;pending.resolve(answer)};
/* App calls (app contract v2). Offered only when the host's init lists
   "app.call.v2", so neither nativeArtifact.call nor window.native exists on
   any other host. Unlike read there is no declared need: the frame names an
   operation and a JSON args object, and the host decides. call returns
   {request_id, confirmed} at once so an app can key an optimistic row;
   confirmed settles on the matching call-result and rejects with an Error
   carrying {status, code, message}. At most 8 calls in flight, args at most
   256 KiB serialized, answer at most 1 MiB. There is no gesture rule. */
const CALL_FEATURE="app.call.v2";let callFeature=false,callClosed=false,pendingCallCount=0,callSeq=0;const pendingCalls=Object.create(null);
const callFailure=(status,code,message,applied)=>{const error=new Error(NativeString(message??"").slice(0,512));define(error,"status",{value:status,enumerable:true});define(error,"code",{value:code,enumerable:true});if(applied===true)define(error,"applied",{value:true,enumerable:true});return error};
const refuseCall=(request_id,code,message)=>{reportBoundedRefusal("html_call_refused",code);return freezeObject({request_id,confirmed:NativePromise.reject(callFailure("refused",code,message))})};
const callOperation=(operation,args)=>{callSeq+=1;const request_id="call-"+callSeq;if(typeof operation!=="string"||operation.length<1||operation.length>128)return refuseCall(request_id,"malformed","call operation must be a non-empty string");const given=args===undefined?{}:args;if(!given||typeof given!=="object"||isArray(given))return refuseCall(request_id,"malformed","call args must be an object");let encoded;try{encoded=jsonStringify(given)}catch{return refuseCall(request_id,"malformed","call args must be JSON-serializable")}if(typeof encoded!=="string")return refuseCall(request_id,"malformed","call args must be JSON-serializable");if(encoded.length>262144)return refuseCall(request_id,"too_large","call args exceed bridge limit");const payload=jsonParse(encoded);if(!payload||typeof payload!=="object"||isArray(payload))return refuseCall(request_id,"malformed","call args must serialize to an object");if(callClosed)return refuseCall(request_id,"port_closed","the host port is closed");if(pendingCallCount>=8)return refuseCall(request_id,"busy","too many calls in flight");const confirmed=new NativePromise((resolve,reject)=>{pendingCalls[request_id]={resolve,reject};pendingCallCount+=1;try{send({version:VERSION,type:"call",request_id,operation,args:payload})}catch(error){delete pendingCalls[request_id];pendingCallCount-=1;reject(error)}});return freezeObject({request_id,confirmed})};
const settleCall=data=>{if(typeof data.request_id!=="string"||!own(pendingCalls,data.request_id))return;let answer;try{const encoded=jsonStringify({status:data.status,code:data.code,message:data.message,result:data.result,applied:data.applied===true?true:undefined});answer=encoded.length>1048576?freezeObject({status:"error",code:"too_large"}):freeze(jsonParse(encoded))}catch{answer=freezeObject({status:"error",code:"malformed"})}const pending=pendingCalls[data.request_id];delete pendingCalls[data.request_id];pendingCallCount-=1;if(answer.status==="ok")pending.resolve(answer.result);else if(answer.status==="refused"||answer.status==="uncertain"||answer.status==="error")pending.reject(callFailure(answer.status,typeof answer.code==="string"?answer.code:null,answer.message,answer.applied));else pending.reject(callFailure("error","malformed",""))};
const closeCalls=()=>{callClosed=true;for(const id of objectKeys(pendingCalls)){const pending=pendingCalls[id];delete pendingCalls[id];pending.reject(callFailure("uncertain","port_closed","the host port closed before the call was answered"))}pendingCallCount=0};
/* Floating-chat presentation (task e27b79d). App calls
   native.presentation.setFloatingChat({suppress:boolean}); host feature
   app.presentation.v1. Promise<boolean>: true means host accepted/stored,
   not that Desktop painted. Exact single enumerable own data
   property {suppress:boolean} on a plain object, no symbols/getters, <=256B. */
const PRESENTATION_FEATURE="app.presentation.v1";
const presentationOwnKeys=Reflect.ownKeys,presentationObjectProto=parentOf({});
let presentationFeature=false,presentationClosed=false,presentationSeq=0,presentationCount=0;
const pendingPresentation=Object.create(null);
const refusePresentation=(reason,message)=>{reportBoundedRefusal("html_presentation_refused",reason);throw new TypeError(message)};
const setFloatingChat=value=>{if(!presentationFeature||!channel||presentationClosed)return NativePromise.resolve(false);if(!value||typeof value!=="object"||isArray(value))refusePresentation("malformed","presentation preference must be {suppress:boolean}");const proto=parentOf(value);if(proto!==presentationObjectProto&&proto!==null)refusePresentation("malformed","presentation preference must be {suppress:boolean}");let keys;try{keys=apply(presentationOwnKeys,undefined,[value])}catch{refusePresentation("malformed","presentation preference must be {suppress:boolean}")}if(!isArray(keys)||keys.length!==1||keys[0]!=="suppress")refusePresentation("malformed","presentation preference must be {suppress:boolean}");const desc=own(value,"suppress");if(!desc||!desc.enumerable||!own(desc,"value")||typeof desc.value!=="boolean")refusePresentation("malformed","presentation preference must be {suppress:boolean}");let encoded;try{encoded=jsonStringify({suppress:desc.value})}catch{refusePresentation("malformed","presentation preference must be JSON-serializable")}if(typeof encoded!=="string"||encoded.length>256)refusePresentation("too_large","presentation preference exceeds bridge limit");if(presentationCount>=8){reportBoundedRefusal("html_presentation_refused","busy");return NativePromise.resolve(false)}presentationSeq+=1;const request_id="presentation-"+presentationSeq;const payload=jsonParse(encoded);return new NativePromise(resolve=>{pendingPresentation[request_id]=resolve;presentationCount+=1;try{send({version:VERSION,type:"presentation",request_id,presentation_version:PRESENTATION_FEATURE,suppress:payload.suppress})}catch(error){delete pendingPresentation[request_id];presentationCount-=1;resolve(false)}})};
const settlePresentation=data=>{if(typeof data.request_id!=="string"||!own(pendingPresentation,data.request_id))return;const resolve=pendingPresentation[data.request_id];delete pendingPresentation[data.request_id];presentationCount-=1;try{resolve(data.status==="ok"&&data.accepted===true)}catch{}};
const closePresentation=()=>{presentationClosed=true;for(const id of objectKeys(pendingPresentation)){const resolve=pendingPresentation[id];delete pendingPresentation[id];try{resolve(false)}catch{}}presentationCount=0};
const presentationApi=freezeObject({setFloatingChat});
const exposeNative=()=>{if(suppliedKit)return;try{define(window,"native",{value:freezeObject({...(callFeature?{call:callOperation}:{}),...(sessionFeature?{session:sessionApi}:{}),...(subscribeFeature?{query:queryOperation,subscribe:subscribeOperation}:{}),...(agentsFeature?{agents:agentsApi}:{}),...(agentSessionsFeature?{agentSessions:agentSessionsSurface()}:{}),...(presentationFeature?{presentation:presentationApi}:{}),...(skinFeature?{skin:skinApi}:{})}),writable:false,configurable:false})}catch{reportBoundedRefusal("html_call_refused","alias_unavailable")}};
const onInput=callback=>{if(typeof callback!=="function")throw new TypeError("input subscriber must be a function");pushValue(inputSubscribers,callback);return()=>{const index=indexOfValue(inputSubscribers,callback);if(index>=0)spliceValue(inputSubscribers,index,1)}};
/* Inbound reveal (task fb8564c). The host may reveal one already-authorized
   record to an opted-in frame AFTER backend admission; this is advisory only,
   with no ack and no effect authority, and stays separate from input
   rows/digest/revision and P7. The callback receives one deep-frozen
   {record_id}: an exact persisted id over [A-Za-z0-9._:-], 1..128,
   matching backend admission — never names, bodies, ancestors, installs
   or sequences, and the frame invokes no tools for it. A reveal arriving
   after init but before registration is retained latest-one and replayed
   once to the first subscriber; the slot clears before the callback runs,
   so reentrant registration cannot re-deliver it. Unsupported payload
   fields are dropped, never frozen in. */
const REVEAL_FEATURE="surface.reveal.v1";
let revealSubscribers=[],pendingReveal=null;
/* Exact persisted-id shape, matching backend admission. The pristine exec
   is captured at load and applied to the owned pattern, so later author
   tampering with RegExp.prototype.test/exec, the RegExp global, or string
   helpers cannot change the verdict; only a primitive bounded string is
   ever tested. The pattern carries no flags, so exec holds no lastIndex
   state across calls. */
const revealPattern=/^[A-Za-z0-9._:-]{1,128}$/;
const regExpExec=RegExp.prototype.exec;
const revealId=value=>typeof value==="string"&&value.length>0&&value.length<=128&&apply(regExpExec,revealPattern,[value])!==null;
const deliverRevealTo=target=>{const count=revealSubscribers.length;for(let index=0;index<count;index+=1){const subscriber=revealSubscribers[index];if(typeof subscriber!=="function")continue;try{apply(subscriber,undefined,[target])}catch(error){report("html_reveal_failed",{message:detailOf(error)})}}};
const deliverReveal=data=>{if(data?.version!==VERSION||!initialized)return;const record_id=data?.record_id;if(!revealId(record_id)){report("html_reveal_dropped",{reason:"malformed"});return}let target;try{target=freezeObject({record_id})}catch{report("html_reveal_dropped",{reason:"freeze-failed"});return}if(!revealSubscribers.length){pendingReveal=target;return}deliverRevealTo(target)};
const onReveal=callback=>{if(typeof callback!=="function")throw new TypeError("reveal subscriber must be a function");pushValue(revealSubscribers,callback);if(pendingReveal!==null){const retained=pendingReveal;pendingReveal=null;deliverRevealTo(retained)}return()=>{const index=indexOfValue(revealSubscribers,callback);if(index>=0)spliceValue(revealSubscribers,index,1)}};
const clearReveal=()=>{pendingReveal=null};
/* App sessions (app contract v2, live co-editing). Offered only when the host's
   init lists "app.session.v2", so neither nativeArtifact.session nor
   window.native.session exists on any other host. open(recordId, {mode})
   returns a channel {send, onMessage, close} at once and posts session-open on
   the main port; the host answers session-opened with exactly one transferred
   MessagePort (the session's private port) or session-refused. Frames are plain
   JSON objects with a string op, passed through unchanged both ways, at most
   1 MiB serialized. send() queues (at most 64 frames) until the port arrives.
   A refusal, a bad transfer, a closed main or session port, or a queue
   overflow is delivered once as {op:"session.error",code,message} and the
   channel then closes; an error with no subscriber yet is held for the first
   one. At most 16 open sessions per frame. The session port is started on the
   first subscription, so frames arriving before it wait in the browser's port
   queue instead of being dropped. close() posts {type:"session-close"} on the
   session port, then closes it, and is idempotent; the bridge does the same
   when it fails a session whose port has arrived, so the host learns of the
   end without a MessagePort close event (Chromium has none).
   A session-opened for a session already closed (or unknown) gets
   {type:"session-close"} posted on its port, then the port is closed, so the
   host frees the session it opened. A host frame that ends a session
   ({op:"session.closed"}, or a {op:"session.refused"} naming a key: a refused
   open, as the broker treats them) is delivered, then frees the slot, drops
   the queue and closes the port; a later send is refused. Other refusals (a
   resync, refused updates) leave the session open. Frames queued before the
   port arrives are bounded by count per session and, across the frame's
   sessions, by 4 MiB in total. */
const SESSION_FEATURE="app.session.v2";let sessionFeature=false,sessionsClosed=false,sessionSeq=0,openSessionCount=0,sessionQueuedBytes=0;const sessions=Object.create(null);
const sessionRecordId=value=>typeof value==="string"&&value.length>0&&value.length<=128&&apply(regExpExec,/[\u0000-\u001f\u007f\s]/,[value])===null;
const refuseSession=(reason,message)=>{reportBoundedRefusal("html_session_refused",reason);throw new TypeError(message)};
const endPort=(port,notify)=>{if(notify)try{post(port,{type:"session-close"})}catch{}try{apply(portClose,port,[])}catch{}};
const releasePorts=ports=>{if(!ports)return;for(let index=0;index<ports.length;index+=1)endPort(ports[index],true)};
const sessionPayload=value=>{if(!value||typeof value!=="object"||isArray(value))return"malformed";let encoded;try{encoded=jsonStringify(value)}catch{return"malformed"}if(typeof encoded!=="string")return"malformed";const size=contextBytes(encoded,1048576);if(size>1048576)return"too_large";const payload=jsonParse(encoded);if(!payload||typeof payload!=="object"||isArray(payload)||typeof payload.op!=="string")return"malformed";return{payload,size}};
const deliverSession=(session,frame)=>{const list=[];for(let index=0;index<session.subscribers.length;index+=1)pushValue(list,session.subscribers[index]);for(const subscriber of list){try{apply(subscriber,undefined,[frame])}catch(error){report("html_session_failed",{message:detailOf(error)})}}};
const dropQueue=session=>{sessionQueuedBytes-=session.queueBytes;session.queueBytes=0;session.queue=[]};
const endSession=(session,notify=true)=>{session.done=true;if(own(sessions,session.request_id)){delete sessions[session.request_id];openSessionCount-=1}const port=session.port;session.port=null;dropQueue(session);if(port)endPort(port,notify)};
const failSession=(session,code,message)=>{if(session.done)return;const frame=freezeObject({op:"session.error",code,message:bounded(message)});const heard=session.subscribers.length>0;if(heard)deliverSession(session,frame);else session.held=frame;endSession(session);session.subscribers=[]};
const startSession=session=>{if(session.port&&!session.started&&session.subscribers.length){session.started=true;start(session.port)}};
const sessionSend=(session,frame)=>{const measured=sessionPayload(frame);if(typeof measured==="string")refuseSession(measured,measured==="too_large"?"session frame exceeds bridge limit":"session frames must be JSON objects with a string op");if(session.done){if(session.hostEnded)refuseSession("closed","the host ended this session");return}const{payload,size}=measured;if(session.port){try{post(session.port,payload)}catch{failSession(session,"port_closed","the session port closed")}}else if(session.queue.length>=64)failSession(session,"queue_full","too many frames sent before the session opened");else if(sessionQueuedBytes+size>4194304)failSession(session,"too_large","too many bytes sent before the session opened");else{pushValue(session.queue,payload);session.queueBytes+=size;sessionQueuedBytes+=size}};
const sessionSubscribe=(session,callback)=>{if(typeof callback!=="function")throw new TypeError("session subscriber must be a function");if(session.done&&!session.held)return()=>{};pushValue(session.subscribers,callback);if(session.held){const held=session.held;session.held=null;NativePromise.resolve().then(()=>{try{apply(callback,undefined,[held])}catch(error){report("html_session_failed",{message:detailOf(error)})}})}startSession(session);return()=>{const index=indexOfValue(session.subscribers,callback);if(index>=0)spliceValue(session.subscribers,index,1)}};
const openSession=(recordId,options)=>{if(!sessionRecordId(recordId))refuseSession("malformed","session record id must be a bounded printable string");const given=options===undefined?{}:options;if(!given||typeof given!=="object"||isArray(given)||objectKeys(given).some(key=>key!=="mode"))refuseSession("malformed","session options must be an object with an optional mode");const mode=given.mode===undefined?"edit":given.mode;if(mode!=="edit"&&mode!=="view")refuseSession("malformed","session mode must be edit or view");sessionSeq+=1;const request_id="session-"+sessionSeq;const session={request_id,port:null,queue:[],queueBytes:0,subscribers:[],held:null,started:false,done:false,hostEnded:false};const channel_=freezeObject({send:frame=>sessionSend(session,frame),onMessage:callback=>sessionSubscribe(session,callback),close:()=>{if(!session.done){endSession(session);session.subscribers=[];session.held=null}}});if(sessionsClosed||!channel){failSession(session,"port_closed","the host port closed");return channel_}if(openSessionCount>=16){reportBoundedRefusal("html_session_refused","busy");failSession(session,"busy","too many open sessions");return channel_}sessions[request_id]=session;openSessionCount+=1;try{send({version:VERSION,type:"session-open",request_id,record_id:recordId,mode})}catch(error){failSession(session,"port_closed","the host port closed")}return channel_};
const sessionApi=freezeObject({open:openSession});
const relaySession=(session,event)=>{if(session.done)return;const measured=sessionPayload(read(messageData,event));if(typeof measured==="string"){reportBoundedRefusal("html_session_dropped",measured);return}const frame=freeze(measured.payload);if(frame.op!=="session.closed"&&!(frame.op==="session.refused"&&typeof frame.key==="string")){deliverSession(session,frame);return}if(session.subscribers.length>0)deliverSession(session,frame);else session.held=frame;session.hostEnded=true;endSession(session,false);session.subscribers=[]};
const settleSession=(data,ports)=>{const id=data.request_id,session=typeof id==="string"&&own(sessions,id)?sessions[id]:null;if(!session||session.done||session.port){releasePorts(ports);return}if(data.type==="session-refused"){releasePorts(ports);failSession(session,typeof data.code==="string"?data.code.slice(0,128):"refused",data.message);return}if(!ports||ports.length!==1){releasePorts(ports);failSession(session,"protocol","the host did not transfer exactly one session port");return}const port=ports[0];session.port=port;listen(port,"message",event=>relaySession(session,event));listen(port,"messageerror",()=>failSession(session,"port_closed","the session port closed"));listen(port,"close",()=>failSession(session,"port_closed","the session port closed"));const backlog=session.queue;dropQueue(session);for(const item of backlog){if(session.done)break;try{post(port,item)}catch{failSession(session,"port_closed","the session port closed")}}startSession(session)};
const closeSessions=()=>{sessionsClosed=true;for(const id of objectKeys(sessions))failSession(sessions[id],"port_closed","the host port closed")};
/* App queries and subscriptions (app contract v2, instant reads). Offered only
   when the host's init lists "app.subscribe.v2", so neither
   nativeArtifact.query/subscribe nor window.native.query/subscribe exists on
   any other host. query({sql, params?}) resolves {rows, columns, truncated}
   and rejects with an Error carrying {status, code, message}. subscribe(
   {sql, params?}, onResult) returns an idempotent unsubscribe at once; the host
   pushes results, delivered as {status:"ready", rows, columns, truncated,
   cached} and, for a failure, {status:"error", code, message, terminal}. A
   terminal error (a refusal, the host ending the subscription, or the host
   port closing) frees the slot; a non-terminal one leaves it open. Refusals are
   never thrown: only a non-function callback is. A refused subscribe's one
   terminal error is delivered even if the app unsubscribes before it arrives,
   so the caller always learns of it. Wire, frame to host:
   {type:"query", request_id, query:{sql, parameters}}, {type:"subscribe",
   subscription_id, query} and {type:"unsubscribe", subscription_id}; host to
   frame: query-result, subscription-result (delivery is monotonic: a delivery
   not greater than the last one is dropped) and subscription-error. A query
   may instead be structured, query_record's own {steps, order?, limit?,
   offset?} (app contract v2 R4): it travels as given, the host answers it from
   its local store when it can answer exactly or from the engine otherwise, and
   its result has the same {rows, columns, truncated} shape, one row per
   record. The two forms do not mix. The query
   object is at most 256 KiB serialized, each result at most 1 MiB; at most 8
   queries in flight and 32 open subscriptions per frame. A query refused for
   its shape or a cap rejects with status "refused"; one that could not be
   dispatched or answered because the host port closed (issued after, or in
   flight at, the close) rejects with status "error" and code "port_closed".
   There is no as_of sequence. */
const SUBSCRIBE_FEATURE="app.subscribe.v2";let subscribeFeature=false,subscribeClosed=false,pendingQueryCount=0,querySeq=0,subscriptionSeq=0,openSubscriptionCount=0;const pendingQueries=Object.create(null),subscriptions=Object.create(null);
const queryWire=given=>{let encoded,structured;try{if(!given||typeof given!=="object"||isArray(given)||objectKeys(given).some(key=>key!=="sql"&&key!=="params"&&key!=="steps"&&key!=="order"&&key!=="limit"&&key!=="offset"))return{code:"malformed",message:"query must be an object with sql and optional params, or steps and optional order, limit and offset"};structured=!!own(given,"steps");if(structured?!!own(given,"sql")||!!own(given,"params"):!!own(given,"order")||!!own(given,"limit")||!!own(given,"offset"))return{code:"malformed",message:"a query is either sql with params or steps with order, limit and offset"};encoded=structured?jsonStringify({steps:given.steps,order:given.order,limit:given.limit,offset:given.offset}):jsonStringify({sql:given.sql,parameters:given.params===undefined?[]:given.params})}catch{return{code:"malformed",message:"query must be JSON-serializable"}}if(typeof encoded!=="string")return{code:"malformed",message:"query must be JSON-serializable"};if(encoded.length>262144)return{code:"too_large",message:"query exceeds bridge limit"};const query=jsonParse(encoded);if(structured){if(!query||!isArray(query.steps)||query.steps.length<1)return{code:"malformed",message:"a structured query needs a non-empty steps array"};return{query}}if(!query||typeof query.sql!=="string"||query.sql.length<1||!isArray(query.parameters))return{code:"malformed",message:"query needs a non-empty sql string and an optional params array"};return{query}};
const resultOf=value=>{if(!value||typeof value!=="object"||isArray(value)||!isArray(value.rows)||!isArray(value.columns))return"malformed";let encoded;try{encoded=jsonStringify({rows:value.rows,columns:value.columns,truncated:value.truncated===true})}catch{return"malformed"}if(typeof encoded!=="string")return"malformed";if(encoded.length>1048576)return"too_large";return freeze(jsonParse(encoded))};
const refuseQuery=(code,message,status="refused")=>{reportBoundedRefusal("html_query_refused",code);return NativePromise.reject(callFailure(status,code,message))};
const queryOperation=query=>{const wire=queryWire(query);if(!wire.query)return refuseQuery(wire.code,wire.message);if(subscribeClosed)return refuseQuery("port_closed","the host port is closed","error");if(pendingQueryCount>=8)return refuseQuery("busy","too many queries in flight");querySeq+=1;const request_id="query-"+querySeq;return new NativePromise((resolve,reject)=>{pendingQueries[request_id]={resolve,reject};pendingQueryCount+=1;try{send({version:VERSION,type:"query",request_id,query:wire.query})}catch(error){delete pendingQueries[request_id];pendingQueryCount-=1;reject(error)}})};
const settleQuery=data=>{if(typeof data.request_id!=="string"||!own(pendingQueries,data.request_id))return;const pending=pendingQueries[data.request_id];delete pendingQueries[data.request_id];pendingQueryCount-=1;if(data.status==="ok"){const result=resultOf(data.result);if(typeof result==="string")pending.reject(callFailure("error",result,"the query result could not be delivered"));else pending.resolve(result)}else pending.reject(callFailure(data.status==="refused"?"refused":"error",typeof data.code==="string"?data.code.slice(0,128):null,data.message))};
const subscriptionError=(code,message,terminal)=>freezeObject({status:"error",code,message:bounded(message),terminal});
const deliverSubscription=(subscription,frame,refusal)=>{if(subscription.silenced&&!refusal)return;try{apply(subscription.callback,undefined,[frame])}catch(error){report("html_subscription_failed",{message:detailOf(error)})}};
const endSubscription=(subscription,notify)=>{if(subscription.done)return;subscription.done=true;if(own(subscriptions,subscription.id)){delete subscriptions[subscription.id];openSubscriptionCount-=1;if(notify)try{send({version:VERSION,type:"unsubscribe",subscription_id:subscription.id})}catch{}}};
const failSubscription=(subscription,code,message)=>{if(subscription.done)return;endSubscription(subscription,false);deliverSubscription(subscription,subscriptionError(code,message,true))};
const subscribeOperation=(query,callback)=>{if(typeof callback!=="function")throw new TypeError("subscription callback must be a function");const subscription={id:null,callback,done:false,silenced:false,delivery:-1};const unsubscribe=()=>{subscription.silenced=true;endSubscription(subscription,true)};const refuse=(code,message)=>{subscription.done=true;reportBoundedRefusal("html_subscribe_refused",code);const frame=subscriptionError(code,message,true);NativePromise.resolve().then(()=>deliverSubscription(subscription,frame,true));return unsubscribe};const wire=queryWire(query);if(!wire.query)return refuse(wire.code,wire.message);if(subscribeClosed)return refuse("port_closed","the host port is closed");if(openSubscriptionCount>=32)return refuse("subscription_limit","too many open subscriptions");subscriptionSeq+=1;subscription.id="subscription-"+subscriptionSeq;subscriptions[subscription.id]=subscription;openSubscriptionCount+=1;try{send({version:VERSION,type:"subscribe",subscription_id:subscription.id,query:wire.query})}catch{endSubscription(subscription,false);return refuse("port_closed","the host port is closed")}return unsubscribe};
const receiveSubscription=data=>{const subscription=typeof data.subscription_id==="string"&&own(subscriptions,data.subscription_id)?subscriptions[data.subscription_id]:null;if(!subscription||subscription.done)return;if(data.type==="subscription-error"){const code=typeof data.code==="string"?data.code.slice(0,128):"error";if(data.terminal===true)failSubscription(subscription,code,data.message);else deliverSubscription(subscription,subscriptionError(code,data.message,false));return}const delivery=data.delivery;if(typeof delivery!=="number"||delivery<0||delivery%1!==0||delivery<=subscription.delivery){reportBoundedRefusal("html_subscription_dropped","delivery");return}subscription.delivery=delivery;const result=resultOf(data.result);if(typeof result==="string"){deliverSubscription(subscription,subscriptionError(result,"the subscription result could not be delivered",false));return}deliverSubscription(subscription,freezeObject({status:"ready",rows:result.rows,columns:result.columns,truncated:result.truncated,cached:data.cached===true}))};
const closeSubscriptions=()=>{subscribeClosed=true;for(const id of objectKeys(pendingQueries)){const pending=pendingQueries[id];delete pendingQueries[id];pending.reject(callFailure("error","port_closed","the host port closed before the query was answered"))}pendingQueryCount=0;for(const id of objectKeys(subscriptions)){const subscription=subscriptions[id];if(subscription)failSubscription(subscription,"port_closed","the host port closed")}};
/* Asking an agent (app contract v2, Shapes bf7cfa5 v1.2). Offered only when
   the host's init lists "app.agents.v2", which the host grants only to its
   first-party allowlist, so neither nativeArtifact.agents nor
   window.native.agents exists on any other host. list() resolves a frozen
   AgentSummary[]; concurrent calls share one request, and it resolves [] if
   the port closes first. ask({to, comment_id}) never rejects: it resolves the
   host's AskResult, {ok:true, ask_id} or {ok:false, code, message}. The app
   names only an agent and its comment: the host re-reads the comment, builds
   the context itself and checks its own user activation, so there is no
   gesture rule here. onStatus(cb) returns an idempotent unsubscribe and gets
   each frozen AskStatus the host pushes, which is only ever for asks this
   frame started. At most 4 asks in flight (a fifth resolves busy); to is at
   most 64 characters and comment_id at most 128, printable without spaces; an
   agent list is at most 64 KiB serialized, an ask result or a status at most
   4 KiB. Wire, frame to host: {type:"agents-list", request_id} and
   {type:"agents-ask", request_id, to, comment_id}; host to frame:
   agents-list-result, agents-ask-result and agents-status. Closing the port
   resolves every pending ask unavailable, saying the agent may already have
   started, and ends every status subscription. */
const AGENTS_FEATURE="app.agents.v2";let agentsFeature=false,agentsClosed=false,pendingAskCount=0,agentsSeq=0,pendingAgentList=null;const pendingAsks=Object.create(null),agentStatusSubscribers=[];
const ASK_CODES=["unavailable","not_ready","invalid","duplicate","refused","busy"],ASK_STATES=["starting","working","needs_you","done","error"];
const agentId=(value,max)=>typeof value==="string"&&value.length>0&&value.length<=max&&apply(regExpExec,/[\u0000-\u001f\u007f\s]/,[value])===null;
const agentsJson=(value,max)=>{try{const encoded=jsonStringify(value);if(typeof encoded!=="string"||encoded.length>max)return null;return jsonParse(encoded)}catch{return null}};
const askRefusal=(code,message)=>freezeObject({ok:false,code,message});
const agentSummaries=value=>{const list=agentsJson(value,65536),out=[];if(!isArray(list))return freezeObject(out);for(let index=0;index<list.length;index+=1){const item=list[index];if(!item||typeof item!=="object"||isArray(item)||!agentId(item.id,128)||typeof item.label!=="string"||item.label.length>128||typeof item.ready!=="boolean")continue;const summary={id:item.id,label:item.label,ready:item.ready};if(item.reason==="not_installed"||item.reason==="unavailable")summary.reason=item.reason;pushValue(out,freezeObject(summary))}return freezeObject(out)};
const askResultOf=value=>{const result=agentsJson(value,4096);if(result&&result.ok===true&&agentId(result.ask_id,256))return freezeObject({ok:true,ask_id:result.ask_id});if(result&&result.ok===false&&apply(arrayIncludes,ASK_CODES,[result.code]))return askRefusal(result.code,bounded(result.message));return askRefusal("unavailable","the host's answer to the ask could not be read")};
const listAgents=()=>{if(agentsClosed||!channel)return NativePromise.resolve(freezeObject([]));if(pendingAgentList)return pendingAgentList.promise;agentsSeq+=1;const request_id="agents-"+agentsSeq;let settle;const promise=new NativePromise(resolve=>{settle=resolve});pendingAgentList={request_id,resolve:settle,promise};try{send({version:VERSION,type:"agents-list",request_id})}catch{pendingAgentList=null;settle(freezeObject([]))}return promise};
const askAgent=request=>{let to,comment_id;try{if(!request||typeof request!=="object"||isArray(request))throw 0;to=request.to;comment_id=request.comment_id}catch{to=null}if(!agentId(to,64)||!agentId(comment_id,128)){reportBoundedRefusal("html_ask_refused","invalid");return NativePromise.resolve(askRefusal("invalid","ask needs an agent id of at most 64 characters and a comment id of at most 128"))}if(agentsClosed||!channel)return NativePromise.resolve(askRefusal("unavailable","the host port is closed"));if(pendingAskCount>=4){reportBoundedRefusal("html_ask_refused","busy");return NativePromise.resolve(askRefusal("busy","too many asks in flight"))}agentsSeq+=1;const request_id="agents-"+agentsSeq;return new NativePromise(resolve=>{pendingAsks[request_id]=resolve;pendingAskCount+=1;try{send({version:VERSION,type:"agents-ask",request_id,to,comment_id})}catch{delete pendingAsks[request_id];pendingAskCount-=1;resolve(askRefusal("unavailable","the host port is closed"))}})};
const settleAgentList=data=>{if(!pendingAgentList||data.request_id!==pendingAgentList.request_id)return;const pending=pendingAgentList;pendingAgentList=null;pending.resolve(agentSummaries(data.agents))};
const settleAsk=data=>{if(typeof data.request_id!=="string"||!own(pendingAsks,data.request_id))return;const resolve=pendingAsks[data.request_id];delete pendingAsks[data.request_id];pendingAskCount-=1;resolve(askResultOf(data.result))};
const deliverAgentStatus=data=>{if(!agentsFeature||agentsClosed)return;const status=agentsJson(data.status,4096);if(!status||typeof status!=="object"||isArray(status)||!agentId(status.ask_id,256)||!agentId(status.comment_id,128)||!apply(arrayIncludes,ASK_STATES,[status.state])||typeof status.at_ms!=="number"){reportBoundedRefusal("html_agent_status_dropped","malformed");return}const frame={ask_id:status.ask_id,comment_id:status.comment_id,state:status.state,at_ms:status.at_ms};if(typeof status.message==="string")frame.message=bounded(status.message);const delivered=freezeObject(frame),list=[];for(let index=0;index<agentStatusSubscribers.length;index+=1)pushValue(list,agentStatusSubscribers[index]);for(let index=0;index<list.length;index+=1){try{apply(list[index],undefined,[delivered])}catch(error){report("html_agent_status_failed",{message:detailOf(error)})}}};
const onAgentStatus=callback=>{if(typeof callback!=="function")throw new TypeError("status subscriber must be a function");pushValue(agentStatusSubscribers,callback);let active=true;return()=>{if(!active)return;active=false;const index=indexOfValue(agentStatusSubscribers,callback);if(index>=0)spliceValue(agentStatusSubscribers,index,1)}};
const closeAgents=()=>{agentsClosed=true;if(pendingAgentList){const pending=pendingAgentList;pendingAgentList=null;pending.resolve(freezeObject([]))}for(const id of objectKeys(pendingAsks)){const resolve=pendingAsks[id];delete pendingAsks[id];resolve(askRefusal("unavailable","the host port closed before the ask was answered; the agent may already have started"))}pendingAskCount=0;agentStatusSubscribers.length=0};
const agentsApi=freezeObject({list:listAgents,ask:askAgent,onStatus:onAgentStatus});
/* Agent sessions transport (app.agent-sessions.v2). The frame lists the viewer's Paseo
   sessions, follows one session's summarized timeline and sends text into it; there is no
   stop, relay, filtering or Native write here. list(cursor?) resolves Result<SessionPage>;
   follow({hostId,hostEpoch,sessionId},callback) resolves Result<{dispose}> with a bridge-minted subscription
   id whose callback slot is reserved before posting, because the host may emit the initial
   snapshot while the follow promise is still unsettled; send({hostId,hostEpoch,sessionId,text,requestId})
   posts the public requestId as the wire request_id so the Desktop can dedupe, and resolves
   Result<{requestId,delivery}>. A terminal ended event removes its slot before delivery, so a
   replacement follow is allowed, late events for the dead slot are ignored, and a follow
   result landing late unsubscribes instead of resurrecting. At most 4 follows and 16 results
   in flight (more resolve busy); session, subscription and send ids are 1-128 [A-Za-z0-9:_-],
   cursors 1-4096 characters, text non-blank at 16 KiB UTF-8; pages, timelines and results are
   bounded at 100 session/timeline items, 32 hosts and 256 KiB UTF-8 per result envelope.
   Session rows require a reachable listed host with the same epoch. Wire, frame to host:
   {type:"agent-sessions-list",request_id,cursor?},
   {type:"agent-sessions-follow",request_id,host_id,host_epoch,session_id,subscription_id},
   {type:"agent-sessions-unsubscribe",subscription_id},
   {type:"agent-sessions-send",request_id,host_id,host_epoch,session_id,text},
   {type:"agent-sessions-mark-read",request_id,read_request_id,host_id,host_epoch,session_id},
   and watch/unwatch-list with one subscription id; host to frame includes the
   corresponding finite results, bounded list-changed revision hints and timeline events.
   A send refused before dispatch resolves unavailable, while a post
   that throws with the channel open may already have dispatched, so it resolves delivery
   unknown; a send whose promise rejects after posting, that outlives its own 30 s deadline,
   or that is still pending when the port closes resolves delivery unknown, and is never
   re-sent. List and follow deadlines free their pending slots (a follow deadline also drops
   its reserved callback and unsubscribes), resolving unavailable. Closing the
   port resolves every pending list, follow and watch unavailable, every dispatched
   send/read unknown, and drops every callback and list watch.
   Opening a conversation (app.agent-sessions.open-conversation.v1, offered beside
   app.agent-sessions.v2 only when the shell says the Desktop can open one; without
   it the method does not exist). openConversation({hostId,hostEpoch,sessionId}, {depth}?)
   resolves Result<{}>: quick (the default) opens the side pane, full the Agent HQ
   window, and any other depth resolves invalid. Wire, frame to host:
   {type:"agent-sessions-open-conversation",request_id,host_id,host_epoch,session_id,depth?}.
   Starting sessions (app.agent-sessions.create.v1, offered beside app.agent-sessions.v2 only when
   the shell says the Desktop can start sessions; without it neither method exists). catalog()
   resolves Result<Catalog> (hosts with providers, models, modes and workspaces, each bounded as the
   Desktop bounds them; malformed or oversize replies resolve unavailable). create({requestId,hostId,
   hostEpoch,provider,model,modeId?,thinkingOptionId?,workspaceId,newWorktree?:{baseBranch},
   initialPrompt}) resolves {ok:true,value:session} or {ok:false,error:{code,message}} and posts the
   public requestId as the wire request_id, untouched: the Desktop owns idempotency and this bridge
   mints, derives and keeps no key. A request refused before the post resolves a definite code
   (invalid_request, busy, create_unsupported); a second create under a requestId still in flight
   resolves outcome_unknown (checked before capacity), because the first may start a session. Once posted the session may exist, so a
   timeout, a post that throws, a closed port, a malformed reply (the session and message are checked
   strictly against the Desktop's limits, never repaired or truncated; unknown optional keys are
   ignored) or a reply that is not a success for the requested host or a typed code from the
   Desktop's own list all resolve outcome_unknown,
   never a definite failure, and nothing is ever re-sent. Wire: {type:"agent-sessions-catalog",
   request_id} and {type:"agent-sessions-create",request_id,host_id,host_epoch,provider,model,
   mode_id?,thinking_option_id?,workspace_id,new_worktree?:{base_branch},initial_prompt}.
   Slice C1/C2 additions. app.agent-sessions.adopted.v1, offered only for a Desktop that listed
   agent-access.v3, adds createStatus(requestId) and cancel(requestId) (Result<{state,result?}> and
   Result<{state,acknowledged,result?}>, never rejecting, posted with a fresh id and
   create_request_id) and lets send and create carry quoted: up to 8 {from,text,sourceMessageId?} items, from 1..32,
   text 1..12288 non-blank, sourceMessageId a canonical lowercase UUID owner-claimed reference (f38936b S7.3). Without that feature quoted resolves unavailable (send) or
   create_unsupported (create). A create waits up to 205 s, a send 145 s (a first-send dialog), a
   catalog 60 s, createStatus and cancel 50 s; every other call keeps 30 s.
   Follow-up controls for Attention (app.agent-sessions.followup.v1, offered beside
   app.agent-sessions.v2 only when the shell says the Desktop has all four; without it
   agentSessions.followup does not exist). followup.status(), followup.continue(),
   followup.getSettings() and followup.setSettings({enabled?,provider?,model?}) each
   resolve Result<value>; setSettings needs at least one key and carries no mode or
   workspace. continue and setSettings must be called inside the user's click: the host
   spends the gesture and Desktop checks fresh input. A refusal made by the automation
   is a value with a message, not a code. Values are checked strictly against the
   Desktop contract; anything else resolves unavailable, and a timeout or closed port
   resolves unavailable even for a change that may have landed, so read status again.
   Wire, frame to host: {type:"agent-sessions-followup-status"|"-continue"|"-settings-get",
   request_id} and {type:"agent-sessions-followup-settings-set",request_id,enabled?,
   provider?,model?}; each is answered by its type plus "-result". */
const AGENT_SESSIONS_FEATURE="app.agent-sessions.v2",AGENT_SESSIONS_CREATE_FEATURE="app.agent-sessions.create.v1",AGENT_SESSIONS_ADOPTED_FEATURE="app.agent-sessions.adopted.v1",AGENT_SESSIONS_OPEN_CONVERSATION_FEATURE="app.agent-sessions.open-conversation.v1",AGENT_SESSIONS_SAVED_FEATURE="app.agent-sessions.saved.v1",AGENT_SESSIONS_FOLLOWUP_FEATURE="app.agent-sessions.followup.v1";let agentSessionsFollowupFeature=false,agentSessionsSavedFeature=false,agentSessionsAdoptedFeature=false,agentSessionsCreateFeature=false,agentSessionsFeature=false,agentSessionsOpenConversationFeature=false,agentSessionsClosed=false,agentSessionsSeq=0,agentSessionsInflight=0;const agentSessionsPending=Object.create(null),agentSessionFollows=Object.create(null);let agentSessionListWatch=null;
const SESSION_RESULT_CODES=["refused","invalid","unavailable","gone","busy"],SESSION_EVENT_KINDS=["snapshot","update","resync","ended"];
const AGENT_SESSIONS_TIMEOUT_MS=30000;
const nextAgentSessionsId=prefix=>{agentSessionsSeq+=1;let id=prefix+agentSessionsSeq;while(own(agentSessionsPending,id)){agentSessionsSeq+=1;id=prefix+agentSessionsSeq}return id};
const sessionIdOk=value=>typeof value==="string"&&value.length>0&&value.length<=128&&apply(regExpExec,/^[A-Za-z0-9:_-]+$/,[value])!==null;
const sessionText=(value,max)=>typeof value==="string"&&value.length<=max;
const sessionTimelineIdOk=value=>typeof value==="string"&&value.length>0&&value.length<=256;
const sessionAdvisoryIdOk=value=>typeof value==="string"&&value.length>0&&value.length<=128;
const sessionToolDetailOk=value=>typeof value==="string"&&value.length>0&&value.length<=256&&apply(regExpExec,/^\S+(?: \S+)*$/u,[value])!==null;
const sessionAttentionOf=value=>{if(value===undefined)return undefined;if(value===null)return null;if(!value||typeof value!=="object"||isArray(value))return undefined;if(value.kind!=="blocked"&&value.kind!=="decision"&&value.kind!=="review"&&value.kind!=="done")return undefined;if(typeof value.message!=="string"||value.message.length>500)return undefined;return freezeObject({kind:value.kind,message:value.message})};
const sessionPermissionOf=value=>{if(value===undefined)return undefined;if(value===null)return null;if(!value||typeof value!=="object"||isArray(value))return undefined;if(!sessionAdvisoryIdOk(value.requestId))return undefined;if(value.kind!=="question"&&value.kind!=="plan"&&value.kind!=="tool"&&value.kind!=="mode"&&value.kind!=="other")return undefined;if(value.title!==undefined&&(typeof value.title!=="string"||value.title.length>256))return undefined;return value.title===undefined?freezeObject({requestId:value.requestId,kind:value.kind}):freezeObject({requestId:value.requestId,kind:value.kind,title:value.title})};
const sessionCapabilitiesOf=(value,reachable)=>{if(!reachable)return undefined;if(value===undefined)return undefined;if(!value||typeof value!=="object"||isArray(value))return undefined;const out={};if(value.markRead===true)out.markRead=true;if(value.listChanged===true)out.listChanged=true;if(value.scopedPermissions===true)out.scopedPermissions=true;if(value.create===true)out.create=true;if(value.chooseFolder===true)out.chooseFolder=true;return objectKeys(out).length?freezeObject(out):undefined};
const sessionTextEncoder=(typeof TextEncoder==="function")?new TextEncoder():null;
const sessionUtf8Bytes=text=>{if(sessionTextEncoder){try{return sessionTextEncoder.encode(text).length}catch{}}return text.length*4};
const sessionRefusal=code=>freezeObject({ok:false,code});
const sessionJson=(value,max)=>{try{const encoded=jsonStringify(value);if(typeof encoded!=="string"||encoded.length>max||sessionUtf8Bytes(encoded)>max)return null;return jsonParse(encoded)}catch{return null}};
const sessionSummaryOf=item=>{if(!item||typeof item!=="object"||isArray(item)||!sessionIdOk(item.id)||!sessionIdOk(item.hostId)||!sessionIdOk(item.hostEpoch)||!sessionText(item.hostLabel,256))return null;if(!(item.title===null||sessionText(item.title,512)))return null;if(!sessionText(item.provider,128))return null;if(!(item.model===null||sessionText(item.model,256)))return null;if(!sessionText(item.status,128)||!sessionText(item.lastActivity,128))return null;const workspace=item.workspace;if(!workspace||typeof workspace!=="object"||isArray(workspace))return null;if(!(workspace.id===null||sessionIdOk(workspace.id)))return null;if(!(workspace.name===null||sessionText(workspace.name,500)))return null;return freezeObject({id:item.id,hostId:item.hostId,hostLabel:item.hostLabel,hostEpoch:item.hostEpoch,title:item.title,provider:item.provider,model:item.model,status:item.status,lastActivity:item.lastActivity,workspace:freezeObject({id:workspace.id,name:workspace.name}),...(typeof item.unread==="boolean"?{unread:item.unread}:{}),...((value=>value===undefined?{}:{attentionRequest:value})(sessionAttentionOf(item.attentionRequest))),...((value=>value===undefined?{}:{pendingPermission:value})(sessionPermissionOf(item.pendingPermission)))})};
const sessionPageOf=page=>{if(!page||typeof page!=="object"||isArray(page)||!isArray(page.sessions)||!isArray(page.hosts)||page.sessions.length>100||page.hosts.length>32)return null;const sessions=[],hosts=[],seen=Object.create(null),targets=Object.create(null);for(const host of page.hosts){if(!host||!sessionIdOk(host.id)||own(seen,host.id)||!sessionText(host.label,256)||(host.status!=="reachable"&&host.status!=="unreachable")||!(host.epoch===null||sessionIdOk(host.epoch))||(host.status==="reachable"&&host.epoch===null))return null;seen[host.id]=host;const capabilities=sessionCapabilitiesOf(host.capabilities,host.status==="reachable");pushValue(hosts,freezeObject({id:host.id,label:host.label,status:host.status,epoch:host.epoch,...(capabilities===undefined?{}:{capabilities})}))}for(let index=0;index<page.sessions.length;index+=1){const summary=sessionSummaryOf(page.sessions[index]);if(!summary||!own(seen,summary.hostId)||seen[summary.hostId].status!=="reachable"||seen[summary.hostId].epoch!==summary.hostEpoch)return null;const key=jsonStringify([summary.hostId,summary.hostEpoch,summary.id]);if(own(targets,key))return null;targets[key]=true;pushValue(sessions,summary)}if(page.nextCursor!==undefined&&(typeof page.nextCursor!=="string"||page.nextCursor.length<1||page.nextCursor.length>4096))return null;const result=freezeObject({sessions:freezeObject(sessions),hosts:freezeObject(hosts),...(page.nextCursor===undefined?{}:{nextCursor:page.nextCursor})});return sessionUtf8Bytes(jsonStringify({ok:true,value:result}))<=262144?result:null};
const sessionPageResultOf=value=>{const result=sessionJson(value,262144);if(result&&result.ok===true){const page=sessionPageOf(result.value);if(page)return freezeObject({ok:true,value:page});return sessionRefusal("unavailable")}if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);return sessionRefusal("unavailable")};
const sessionFollowResultOf=value=>{const result=sessionJson(value,262144);if(result&&result.ok===true)return freezeObject({ok:true});if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);return sessionRefusal("unavailable")};
const sessionItemOf=item=>{if(!item||typeof item!=="object"||isArray(item)||!sessionTimelineIdOk(item.id))return null;if(item.kind==="message"){if((item.role!=="user"&&item.role!=="assistant")||!sessionText(item.text,16384))return null;return freezeObject({id:item.id,kind:"message",role:item.role,text:item.text})}if(item.kind==="tool"){if(!sessionText(item.title,1024)||!sessionText(item.status,128))return null;return freezeObject({id:item.id,kind:"tool",title:item.title,status:item.status,...(sessionToolDetailOk(item.detail)?{detail:item.detail}:{})})}if(item.kind!=="status"||!sessionText(item.status,128))return null;return freezeObject({id:item.id,kind:"status",status:item.status})};
const sessionEventOf=event=>{if(!event||typeof event!=="object"||isArray(event))return null;if(event.kind==="snapshot"||event.kind==="update"){if(!isArray(event.items)||event.items.length>100)return null;const items=[];for(let index=0;index<event.items.length;index+=1){const item=sessionItemOf(event.items[index]);if(!item)return null;pushValue(items,item)}const framed=freezeObject({kind:event.kind,items:freezeObject(items)});if(sessionUtf8Bytes(jsonStringify(framed))>262144)return null;return framed}if(event.kind==="ended"){if(!apply(arrayIncludes,SESSION_RESULT_CODES,[event.code]))return null;return freezeObject({kind:"ended",code:event.code})}if(event.kind!=="resync")return null;return freezeObject({kind:"resync"})};
const sendReceiptOf=(value,requestId)=>{const result=sessionJson(value,262144);if(result&&result.ok===true&&result.value&&typeof result.value==="object"&&!isArray(result.value)){if(result.value.requestId===requestId&&(result.value.delivery==="acknowledged"||result.value.delivery==="unknown"))return freezeObject({ok:true,value:freezeObject({requestId:result.value.requestId,delivery:result.value.delivery})});return freezeObject({ok:true,value:freezeObject({requestId,delivery:"unknown"})})}if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);return freezeObject({ok:true,value:freezeObject({requestId,delivery:"unknown"})})};
const listAgentSessions=input=>{let cursor;try{cursor=input==null?undefined:input.cursor}catch{cursor=undefined}if(cursor!==undefined&&(typeof cursor!=="string"||cursor.length<1||cursor.length>4096)){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}const request_id=nextAgentSessionsId("agent-sessions-");return new NativePromise(resolve=>{const pending={kind:"list",resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{const wire={version:VERSION,type:"agent-sessions-list",request_id};if(cursor!==undefined)wire.cursor=cursor;send(wire)}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const followAgentSession=(input,callback)=>{if(typeof callback!=="function")throw new TypeError("session follower must be a function");let session_id,host_id,host_epoch;try{session_id=input&&typeof input==="object"&&!isArray(input)?input.sessionId:null;host_id=input.hostId;host_epoch=input.hostEpoch}catch{session_id=null}if(!sessionIdOk(session_id)||!sessionIdOk(host_id)||!sessionIdOk(host_epoch)){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(objectKeys(agentSessionFollows).length>=4){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}const request_id=nextAgentSessionsId("agent-sessions-");agentSessionsSeq+=1;const subscription_id="agent-session-follow-"+agentSessionsSeq;return new NativePromise(resolve=>{agentSessionFollows[subscription_id]={host_id,host_epoch,session_id,callback,request_id};const pending={kind:"follow",resolve,subscription_id,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;if(own(agentSessionFollows,subscription_id)){delete agentSessionFollows[subscription_id];try{send({version:VERSION,type:"agent-sessions-unsubscribe",subscription_id})}catch{}}resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-follow",request_id,host_id,host_epoch,session_id,subscription_id})}catch{clearTimer(pending.timer);delete agentSessionFollows[subscription_id];delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const disposeAgentSessionFollow=subscription_id=>()=>{if(!own(agentSessionFollows,subscription_id))return;delete agentSessionFollows[subscription_id];try{send({version:VERSION,type:"agent-sessions-unsubscribe",subscription_id})}catch{}};
const sendAgentSession=input=>{let session_id,host_id,host_epoch,text,requestId,quotedRaw;try{if(!input||typeof input!=="object"||isArray(input))throw 0;session_id=input.sessionId;host_id=input.hostId;host_epoch=input.hostEpoch;text=input.text;requestId=input.requestId;quotedRaw=input.quoted}catch{session_id=null}if(!sessionIdOk(session_id)||!sessionIdOk(host_id)||!sessionIdOk(host_epoch)){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(typeof text!=="string"||text.trim().length===0||sessionUtf8Bytes(text)>16384){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(!sessionIdOk(requestId)){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}let quoted;if(quotedRaw!==undefined){quoted=sessionQuotedOf(quotedRaw);if(!quoted){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(!agentSessionsAdoptedFeature)return NativePromise.resolve(sessionRefusal("unavailable"))}if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}if(own(agentSessionsPending,requestId)){reportBoundedRefusal("html_agent_sessions_refused","refused");return NativePromise.resolve(sessionRefusal("refused"))}return new NativePromise(resolve=>{const pending={kind:"send",resolve,request_id:requestId,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[requestId]!==pending)return;delete agentSessionsPending[requestId];agentSessionsInflight-=1;resolve(freezeObject({ok:true,value:freezeObject({requestId,delivery:"unknown"})}))},AGENT_SESSIONS_SEND_TIMEOUT_MS);agentSessionsPending[requestId]=pending;agentSessionsInflight+=1;try{const wire={version:VERSION,type:"agent-sessions-send",request_id:requestId,host_id,host_epoch,session_id,text};if(quoted!==undefined)wire.quoted=quoted;send(wire)}catch{clearTimer(pending.timer);delete agentSessionsPending[requestId];agentSessionsInflight-=1;resolve(freezeObject({ok:true,value:freezeObject({requestId,delivery:"unknown"})}))}})};
const markAgentSessionRead=input=>{let host_id,host_epoch,session_id,read_request_id;try{if(!input||typeof input!=="object"||isArray(input))throw 0;host_id=input.hostId;host_epoch=input.hostEpoch;session_id=input.sessionId;read_request_id=input.requestId}catch{host_id=null}if(!sessionIdOk(host_id)||!sessionIdOk(host_epoch)||!sessionIdOk(session_id)||!sessionIdOk(read_request_id))return NativePromise.resolve(sessionRefusal("invalid"));if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-read-");return new NativePromise(resolve=>{const pending={kind:"markRead",resolve,read_request_id,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(freezeObject({ok:true,value:freezeObject({requestId:read_request_id,delivery:"unknown"})}))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-mark-read",request_id,read_request_id,host_id,host_epoch,session_id})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(freezeObject({ok:true,value:freezeObject({requestId:read_request_id,delivery:"unknown"})}))}})};
const SESSION_CREATE_CODES=["invalid_request","refused","busy","host_unreachable","host_epoch_changed","create_unsupported","provider_unavailable","model_unavailable","workspace_not_found","worktree_unsupported","create_failed","outcome_unknown"],SESSION_CREATE_KEYS=["requestId","hostId","hostEpoch","provider","model","modeId","thinkingOptionId","workspaceId","newWorktree","initialPrompt","quoted"];
const AGENT_SESSIONS_CATALOG_TIMEOUT_MS=60000,AGENT_SESSIONS_CREATE_TIMEOUT_MS=205*1000,AGENT_SESSIONS_SEND_TIMEOUT_MS=145*1000,AGENT_SESSIONS_STATUS_TIMEOUT_MS=50*1000;
const createFailure=(code,message)=>freezeObject({ok:false,error:freezeObject({code,message})});
const createUnknown=()=>createFailure("outcome_unknown","The session may have started. Retry with the same requestId to find out; it cannot start a second one.");
const sessionPrintable=value=>{for(let index=0;index<value.length;index+=1){const unit=value.charCodeAt(index);if(unit<=31||unit===127)return false}return true};
const catalogTextOk=value=>typeof value==="string"&&value.length>0&&value.length<=256&&sessionPrintable(value);
const catalogWorkspaceIdOk=value=>typeof value==="string"&&value.length>0&&value.length<=512&&sessionPrintable(value);
const catalogObject=value=>!!value&&typeof value==="object"&&!isArray(value);
const catalogModelOf=model=>{if(!catalogObject(model)||!catalogTextOk(model.id)||!sessionText(model.label,256))return null;if(model.description!==undefined&&!sessionText(model.description,1024))return null;if(model.featured!==undefined&&typeof model.featured!=="boolean")return null;if(model.isDefault!==undefined&&typeof model.isDefault!=="boolean")return null;if(!isArray(model.thinkingOptions)||model.thinkingOptions.length>16)return null;const thinkingOptions=[];for(let index=0;index<model.thinkingOptions.length;index+=1){const option=model.thinkingOptions[index];if(!catalogObject(option)||!catalogTextOk(option.id)||!sessionText(option.label,256))return null;pushValue(thinkingOptions,freezeObject({id:option.id,label:option.label}))}if(model.defaultThinkingOptionId!==undefined&&!catalogTextOk(model.defaultThinkingOptionId))return null;return freezeObject({id:model.id,label:model.label,...(model.description===undefined?{}:{description:model.description}),...(model.featured===undefined?{}:{featured:model.featured}),...(model.isDefault===undefined?{}:{isDefault:model.isDefault}),thinkingOptions:freezeObject(thinkingOptions),...(model.defaultThinkingOptionId===undefined?{}:{defaultThinkingOptionId:model.defaultThinkingOptionId})})};
const catalogProviderOf=provider=>{if(!catalogObject(provider)||!catalogTextOk(provider.id)||!sessionText(provider.label,256)||typeof provider.available!=="boolean")return null;if(provider.unavailableReason!==undefined&&!sessionText(provider.unavailableReason,500))return null;if(!isArray(provider.models)||provider.models.length>64||!isArray(provider.modes)||provider.modes.length>16)return null;if(provider.defaultModeId!==undefined&&!catalogTextOk(provider.defaultModeId))return null;const models=[],modes=[];for(let index=0;index<provider.models.length;index+=1){const model=catalogModelOf(provider.models[index]);if(!model)return null;pushValue(models,model)}for(let index=0;index<provider.modes.length;index+=1){const mode=provider.modes[index];if(!catalogObject(mode)||!catalogTextOk(mode.id)||!sessionText(mode.label,256)||(mode.description!==undefined&&!sessionText(mode.description,1024)))return null;pushValue(modes,freezeObject({id:mode.id,label:mode.label,...(mode.description===undefined?{}:{description:mode.description})}))}return freezeObject({id:provider.id,label:provider.label,available:provider.available,...(provider.unavailableReason===undefined?{}:{unavailableReason:provider.unavailableReason}),models:freezeObject(models),modes:freezeObject(modes),...(provider.defaultModeId===undefined?{}:{defaultModeId:provider.defaultModeId})})};
const catalogWorkspaceOf=workspace=>{if(!catalogObject(workspace)||!catalogWorkspaceIdOk(workspace.id)||!sessionText(workspace.name,500)||!sessionText(workspace.path,1024))return null;if(workspace.projectName!==undefined&&!sessionText(workspace.projectName,500))return null;if(workspace.kind!==undefined&&!apply(arrayIncludes,["ordinary","folder","worktree"],[workspace.kind]))return null;if(workspace.isGitRepo!==undefined&&typeof workspace.isGitRepo!=="boolean")return null;return freezeObject({id:workspace.id,name:workspace.name,path:workspace.path,...(workspace.kind===undefined?{}:{kind:workspace.kind}),...(workspace.projectName===undefined?{}:{projectName:workspace.projectName}),...(workspace.isGitRepo===undefined?{}:{isGitRepo:workspace.isGitRepo})})};
const sessionCatalogOf=catalog=>{if(!catalogObject(catalog)||!isArray(catalog.hosts)||catalog.hosts.length>32)return null;const hosts=[],seen=Object.create(null);for(let index=0;index<catalog.hosts.length;index+=1){const host=catalog.hosts[index];if(!catalogObject(host)||!sessionIdOk(host.hostId)||own(seen,host.hostId)||!sessionText(host.hostLabel,256)||(host.status!=="reachable"&&host.status!=="unreachable")||!(host.hostEpoch===null||sessionIdOk(host.hostEpoch))||(host.status==="reachable"&&host.hostEpoch===null))return null;if(!isArray(host.providers)||host.providers.length>16||!isArray(host.workspaces)||host.workspaces.length>200)return null;if(host.workspacesTruncated!==undefined&&host.workspacesTruncated!==true)return null;seen[host.hostId]=true;const providers=[],workspaces=[];for(let at=0;at<host.providers.length;at+=1){const provider=catalogProviderOf(host.providers[at]);if(!provider)return null;pushValue(providers,provider)}for(let at=0;at<host.workspaces.length;at+=1){const workspace=catalogWorkspaceOf(host.workspaces[at]);if(!workspace)return null;pushValue(workspaces,workspace)}const row=freezeObject({hostId:host.hostId,hostLabel:host.hostLabel,hostEpoch:host.hostEpoch,status:host.status,providers:freezeObject(providers),workspaces:freezeObject(workspaces),...(host.workspacesTruncated===true?{workspacesTruncated:true}:{})});if(sessionUtf8Bytes(jsonStringify(row))>65536)return null;pushValue(hosts,row)}const result=freezeObject({hosts:freezeObject(hosts)});return sessionUtf8Bytes(jsonStringify({ok:true,value:result}))<=262144?result:null};
const catalogResultOf=value=>{const result=sessionJson(value,262144);if(result&&result.ok===true){const catalog=sessionCatalogOf(result.value);if(catalog)return freezeObject({ok:true,value:catalog});return sessionRefusal("unavailable")}if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);return sessionRefusal("unavailable")};
const createSummaryOf=item=>{if(!catalogObject(item)||!sessionIdOk(item.id)||!sessionIdOk(item.hostId)||!sessionIdOk(item.hostEpoch)||!sessionText(item.hostLabel,256)||!(item.title===null||sessionText(item.title,500))||!sessionText(item.provider,128)||!(item.model===null||sessionText(item.model,256))||!sessionText(item.status,128)||!sessionText(item.lastActivity,128))return null;const workspace=item.workspace;if(!catalogObject(workspace)||!(workspace.id===null||sessionIdOk(workspace.id))||!(workspace.name===null||sessionText(workspace.name,500)))return null;if(item.createdAt!==undefined&&!sessionText(item.createdAt,128))return null;if(item.parentId!==undefined&&!sessionIdOk(item.parentId))return null;if(item.unread!==undefined&&typeof item.unread!=="boolean")return null;const attention=item.attentionRequest;if(attention!==undefined&&attention!==null&&(!catalogObject(attention)||!(attention.kind==="blocked"||attention.kind==="decision"||attention.kind==="review"||attention.kind==="done")||!sessionText(attention.message,500)))return null;const permission=item.pendingPermission;if(permission!==undefined&&permission!==null&&(!catalogObject(permission)||!sessionAdvisoryIdOk(permission.requestId)||!(permission.kind==="question"||permission.kind==="plan"||permission.kind==="tool"||permission.kind==="mode"||permission.kind==="other")||(permission.title!==undefined&&!sessionText(permission.title,256))))return null;return freezeObject({id:item.id,hostId:item.hostId,hostLabel:item.hostLabel,hostEpoch:item.hostEpoch,title:item.title,provider:item.provider,model:item.model,status:item.status,lastActivity:item.lastActivity,workspace:freezeObject({id:workspace.id,name:workspace.name}),...(item.createdAt===undefined?{}:{createdAt:item.createdAt}),...(item.parentId===undefined?{}:{parentId:item.parentId}),...(item.unread===undefined?{}:{unread:item.unread}),...(attention===undefined?{}:{attentionRequest:attention===null?null:freezeObject({kind:attention.kind,message:attention.message})}),...(permission===undefined?{}:{pendingPermission:permission===null?null:freezeObject({requestId:permission.requestId,kind:permission.kind,...(permission.title===undefined?{}:{title:permission.title})})})})};
const createResultOf=(value,pending)=>{const result=sessionJson(value,262144);if(result&&result.ok===true){const summary=createSummaryOf(result.value);if(summary&&summary.hostId===pending.host_id)return freezeObject({ok:true,value:summary})}else if(result&&result.ok===false&&catalogObject(result.error)&&apply(arrayIncludes,SESSION_CREATE_CODES,[result.error.code])&&sessionText(result.error.message,500))return createFailure(result.error.code,result.error.message);return createUnknown()};
const catalogAgentSessions=()=>{if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}const request_id=nextAgentSessionsId("agent-sessions-catalog-");return new NativePromise(resolve=>{const pending={kind:"catalog",resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_CATALOG_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-catalog",request_id})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const chooseFolderAgentSessions=input=>{if(!catalogObject(input)||objectKeys(input).length!==2||!own(input,"hostId")||!own(input,"hostEpoch")||!sessionIdOk(input.hostId)||!sessionIdOk(input.hostEpoch))return NativePromise.resolve(sessionRefusal("invalid"));const host_id=input.hostId,host_epoch=input.hostEpoch;if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}const request_id=nextAgentSessionsId("agent-sessions-choose-folder-");return new NativePromise(resolve=>{const pending={kind:"chooseFolder",resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},335000);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-choose-folder",request_id,host_id,host_epoch})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const createAgentSession=input=>{let requestId,hostId,hostEpoch,provider,model,modeId,thinkingOptionId,workspaceId,newWorktree,initialPrompt,quotedRaw,keys;try{if(!catalogObject(input))throw 0;keys=objectKeys(input);requestId=input.requestId;hostId=input.hostId;hostEpoch=input.hostEpoch;provider=input.provider;model=input.model;modeId=input.modeId;thinkingOptionId=input.thinkingOptionId;workspaceId=input.workspaceId;newWorktree=input.newWorktree;initialPrompt=input.initialPrompt;quotedRaw=input.quoted}catch{keys=null}if(!keys||!keys.every(key=>SESSION_CREATE_KEYS.includes(key))||!sessionIdOk(requestId)||!sessionIdOk(hostId)||!sessionIdOk(hostEpoch)||!catalogTextOk(provider)||!catalogTextOk(model)||!catalogWorkspaceIdOk(workspaceId)||(modeId!==undefined&&!catalogTextOk(modeId))||(thinkingOptionId!==undefined&&!catalogTextOk(thinkingOptionId))||(newWorktree!==undefined&&!(catalogObject(newWorktree)&&objectKeys(newWorktree).length===1&&catalogTextOk(newWorktree.baseBranch)))||typeof initialPrompt!=="string"||initialPrompt.trim().length===0||sessionUtf8Bytes(initialPrompt)>16384){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(createFailure("invalid_request","The start request is not valid"))}let quoted;if(quotedRaw!==undefined){quoted=sessionQuotedOf(quotedRaw);if(!quoted){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(createFailure("invalid_request","The start request is not valid"))}if(!agentSessionsAdoptedFeature)return NativePromise.resolve(createFailure("create_unsupported","Quoted words are not available here"))}if(own(agentSessionsPending,requestId)){reportBoundedRefusal("html_agent_sessions_refused","refused");return NativePromise.resolve(createUnknown())}if(agentSessionsClosed||!channel)return NativePromise.resolve(createFailure("create_unsupported","Starting sessions is not available here"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(createFailure("busy","Too many requests are in flight"))}const baseBranch=newWorktree===undefined?undefined:newWorktree.baseBranch;return new NativePromise(resolve=>{const pending={kind:"create",resolve,host_id:hostId,request_id:requestId,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[requestId]!==pending)return;delete agentSessionsPending[requestId];agentSessionsInflight-=1;resolve(createUnknown())},AGENT_SESSIONS_CREATE_TIMEOUT_MS);agentSessionsPending[requestId]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-create",request_id:requestId,host_id:hostId,host_epoch:hostEpoch,provider,model,...(modeId===undefined?{}:{mode_id:modeId}),...(thinkingOptionId===undefined?{}:{thinking_option_id:thinkingOptionId}),workspace_id:workspaceId,...(baseBranch===undefined?{}:{new_worktree:{base_branch:baseBranch}}),initial_prompt:initialPrompt,...(quoted===undefined?{}:{quoted})})}catch{clearTimer(pending.timer);delete agentSessionsPending[requestId];agentSessionsInflight-=1;resolve(createUnknown())}})};
const stopAgentSessionListWatch=slot=>{if(agentSessionListWatch!==slot)return;agentSessionListWatch=null;try{send({version:VERSION,type:"agent-sessions-unwatch-list",subscription_id:slot.subscription_id})}catch{}};
const watchAgentSessionList=callback=>{if(typeof callback!=="function")throw new TypeError("list watcher must be a function");if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionListWatch||agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-watch-");agentSessionsSeq+=1;const subscription_id="agent-session-list-"+agentSessionsSeq;const slot={subscription_id,callback,revision:-1};agentSessionListWatch=slot;return new NativePromise(resolve=>{const pending={kind:"watchList",resolve,slot,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;stopAgentSessionListWatch(slot);resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-watch-list",request_id,subscription_id})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;stopAgentSessionListWatch(slot);resolve(sessionRefusal("unavailable"))}})};
const permissionScalarOk=value=>typeof value==="string"&&value.length>=1&&value.length<=1024&&sessionUtf8Bytes(value)<=1024&&apply(regExpExec,/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u,[value])===null;
const permissionKeys=(value,allowed,needed)=>!!value&&typeof value==="object"&&!isArray(value)&&objectKeys(value).every(key=>allowed.includes(key))&&needed.every(key=>own(value,key));
const permissionText=(value,max,min=0)=>typeof value==="string"&&value.length>=min&&value.length<=max;
const permissionActionOf=value=>{const action=sessionJson(value,16384);if(!action||!permissionKeys(action,["kind","behavior","actionId","answers"],["kind"]))return null;if(action.kind==="tool_decision"&&permissionKeys(action,["kind","behavior"],["kind","behavior"])&&(action.behavior==="allow"||action.behavior==="deny"))return action;if(action.kind==="plan_action"&&permissionKeys(action,["kind","actionId"],["kind","actionId"])&&permissionText(action.actionId,128,1))return action;if(action.kind==="question_dismiss"&&permissionKeys(action,["kind"],["kind"]))return action;if(action.kind!=="question_answers"||!permissionKeys(action,["kind","answers"],["kind","answers"])||!isArray(action.answers)||action.answers.length<1||action.answers.length>16)return null;for(const a of action.answers){if(!permissionKeys(a,["questionIndex","optionIndexes","text"],["questionIndex"])||!Number.isInteger(a.questionIndex)||a.questionIndex<0||a.questionIndex>15||(a.optionIndexes===undefined&&a.text===undefined)||(a.optionIndexes!==undefined&&(!isArray(a.optionIndexes)||a.optionIndexes.length>32||a.optionIndexes.some(i=>!Number.isInteger(i)||i<0||i>31)))||(a.text!==undefined&&!permissionText(a.text,4000)))return null}return action};
const permissionFormOf=(value,id)=>{if(!permissionKeys(value,["kind","requestId","provider","name","title","description","preview","planText","actions","canDismiss","questions"],["kind","requestId","provider","name"])||value.requestId!==id||(value.provider!=="claude"&&value.provider!=="codex")||!permissionText(value.name,16384,1)||(value.title!==undefined&&!permissionText(value.title,2000))||(value.description!==undefined&&!permissionText(value.description,2000)))return null;if(value.kind==="tool"){if(!permissionKeys(value,["kind","requestId","provider","name","title","description","preview"],["kind","requestId","provider","name"]))return null;if(value.preview!==undefined){if(!permissionKeys(value.preview,["command","cwd","filePath","query","url"],[])||objectKeys(value.preview).some(k=>!permissionText(value.preview[k],16384)))return null}}else if(value.kind==="plan"){if(!permissionKeys(value,["kind","requestId","provider","name","title","description","planText","actions"],["kind","requestId","provider","name","actions"])||(value.planText!==undefined&&!permissionText(value.planText,16384))||!isArray(value.actions)||value.actions.length<2||value.actions.length>8)return null;for(const a of value.actions)if(!permissionKeys(a,["id","label","behavior","variant","intent"],["id","label","behavior","intent"])||!permissionText(a.id,128,1)||!permissionText(a.label,256,1)||!(["allow","deny"].includes(a.behavior))||!(["implement","implement_resume","dismiss"].includes(a.intent))||(a.variant!==undefined&&!(["primary","secondary","danger"].includes(a.variant))))return null}else if(value.kind==="question"){if(!permissionKeys(value,["kind","requestId","provider","name","title","description","canDismiss","questions"],["kind","requestId","provider","name","canDismiss","questions"])||value.canDismiss!==true||!isArray(value.questions)||value.questions.length<1||value.questions.length>16)return null;for(const q of value.questions){if(!permissionKeys(q,["header","question","options","multiSelect","allowText","allowEmpty"],["header","question","options","multiSelect","allowText","allowEmpty"])||!permissionText(q.header,128,1)||!permissionText(q.question,2000,1)||!isArray(q.options)||q.options.length>32||typeof q.multiSelect!=="boolean"||typeof q.allowText!=="boolean"||q.allowEmpty!==false)return null;for(const o of q.options)if(!permissionKeys(o,["label","description"],["label"])||!permissionText(o.label,256,1)||(o.description!==undefined&&!permissionText(o.description,2000)))return null}}else return null;return sessionUtf8Bytes(jsonStringify(value))<=16384?freeze(value):null};
const permissionUnknown=freezeObject({ok:true,value:freezeObject({outcome:freezeObject({status:"unknown"})})});
const permissionResultOf=(value,pending)=>{const result=sessionJson(value,24576);if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);if(pending.kind==="openInPaseo"||pending.kind==="openConversation")return result&&result.ok===true&&permissionKeys(result.value,[],[])?freezeObject({ok:true,value:freezeObject({})}):sessionRefusal("unavailable");if(!result||result.ok!==true||!permissionKeys(result.value,["outcome"],["outcome"]))return pending.kind==="respondToPermission"?permissionUnknown:sessionRefusal("unavailable");const outcome=result.value.outcome;if(pending.kind==="getPermissionForm"){if(permissionKeys(outcome,["status","code"],["status","code"])&&outcome.status==="refused"&&(outcome.code==="gone"||outcome.code==="unsupported"))return freezeObject({ok:true,value:freezeObject({outcome:freeze(outcome)})});if(!permissionKeys(outcome,["status","form"],["status","form"])||outcome.status!=="supported")return sessionRefusal("unavailable");const form=permissionFormOf(outcome.form,pending.permission_request_id);return form?freezeObject({ok:true,value:freezeObject({outcome:freezeObject({status:"supported",form})})}):sessionRefusal("unavailable")};if(permissionKeys(outcome,["status"],["status"])&&(outcome.status==="acknowledged"||outcome.status==="unknown"))return freezeObject({ok:true,value:freezeObject({outcome:freeze(outcome)})});if(permissionKeys(outcome,["status","code"],["status","code"])&&outcome.status==="refused"&&["gone","busy","invalid","unsupported"].includes(outcome.code))return freezeObject({ok:true,value:freezeObject({outcome:freeze(outcome)})});return permissionUnknown};
const requestAgentSessionPermission=(kind,input)=>{let target,permission_request_id,operation_key,correlation,action;try{if(!input||typeof input!=="object"||isArray(input))throw 0;target={host_id:input.hostId,host_epoch:input.hostEpoch,session_id:input.sessionId};permission_request_id=input.permissionRequestId;operation_key=input.operationKey;correlation=input.requestId;action=input.action}catch{return NativePromise.resolve(sessionRefusal("invalid"))}if(!sessionIdOk(target.host_id)||!sessionIdOk(target.host_epoch)||!sessionIdOk(target.session_id))return NativePromise.resolve(sessionRefusal("invalid"));if(kind!=="openInPaseo"&&(!permissionScalarOk(permission_request_id)||!permissionText(correlation,128,1)))return NativePromise.resolve(sessionRefusal("invalid"));if(kind==="respondToPermission"&&(!permissionScalarOk(operation_key)||!(action=permissionActionOf(action))))return NativePromise.resolve(sessionRefusal("invalid"));if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-permission-");return new NativePromise(resolve=>{const pending={kind,resolve,permission_request_id,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(kind==="respondToPermission"?permissionUnknown:sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:kind==="openInPaseo"?"agent-sessions-open-in-paseo":kind==="getPermissionForm"?"agent-sessions-get-permission-form":"agent-sessions-respond-to-permission",request_id,...target,...(kind==="openInPaseo"?{}:{permission_request_id,...(kind==="getPermissionForm"?{form_request_id:correlation}:{operation_key,response_request_id:correlation,action})})})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(kind==="respondToPermission"?permissionUnknown:sessionRefusal("unavailable"))}})};
const requestAgentSessionOpenConversation=(input,options)=>{let target,depth;try{if(!input||typeof input!=="object"||isArray(input))throw 0;target={host_id:input.hostId,host_epoch:input.hostEpoch,session_id:input.sessionId};depth=options===undefined?input.depth:options.depth}catch{return NativePromise.resolve(sessionRefusal("invalid"))}if(!sessionIdOk(target.host_id)||!sessionIdOk(target.host_epoch)||!sessionIdOk(target.session_id)||(depth!==undefined&&!(typeof depth==="string"&&(depth==="quick"||depth==="full"))))return NativePromise.resolve(sessionRefusal("invalid"));if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-permission-");return new NativePromise(resolve=>{const pending={kind:"openConversation",resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{const wire={version:VERSION,type:"agent-sessions-open-conversation",request_id,...target};if(depth!==undefined)wire.depth=depth;send(wire)}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const settleAgentSessionsPermission=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];const kind=data.type==="agent-sessions-open-in-paseo-result"?"openInPaseo":data.type==="agent-sessions-open-conversation-result"?"openConversation":data.type==="agent-sessions-get-permission-form-result"?"getPermissionForm":data.type==="agent-sessions-respond-to-permission-result"?"respondToPermission":null;if(pending.kind!==kind)return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(permissionResultOf(data.result,pending))};
const sessionQuotedOf=value=>{const items=sessionJson(value,262144);if(!isArray(items)||items.length>8)return null;const out=[];for(let index=0;index<items.length;index+=1){const item=items[index];if(!catalogObject(item)||!own(item,"from")||!own(item,"text"))return null;const keys=objectKeys(item);if(!(keys.length===2||(keys.length===3&&own(item,"sourceMessageId"))))return null;if(typeof item.from!=="string"||item.from.length<1||item.from.length>32||typeof item.text!=="string"||item.text.length<1||item.text.length>12288||item.text.trim().length===0)return null;if(item.sourceMessageId!==undefined&&(typeof item.sourceMessageId!=="string"||apply(regExpExec,/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,[item.sourceMessageId])===null))return null;pushValue(out,item.sourceMessageId===undefined?freezeObject({from:item.from,text:item.text}):freezeObject({from:item.from,text:item.text,sourceMessageId:item.sourceMessageId}))}return freezeObject(out)};
const SESSION_CREATE_STATES=["unknown_request","preparing","confirming","dispatching","dispatched","settled","cancelled","terminal_mismatch","refused_retryable"];
const createVerdictOf=result=>{if(!catalogObject(result))return null;if(result.ok===true){const summary=createSummaryOf(result.value);return summary?freezeObject({ok:true,value:summary}):null}if(result.ok===false&&catalogObject(result.error)&&apply(arrayIncludes,SESSION_CREATE_CODES,[result.error.code])&&sessionText(result.error.message,500))return createFailure(result.error.code,result.error.message);return null};
const createStateOf=(value,withAcknowledged)=>{if(!catalogObject(value)||!apply(arrayIncludes,SESSION_CREATE_STATES,[value.state]))return null;const out={state:value.state};if(withAcknowledged){if(typeof value.acknowledged!=="boolean")return null;out.acknowledged=value.acknowledged}if(value.result!==undefined){const result=createVerdictOf(value.result);if(!result)return null;out.result=result}return freezeObject(out)};
const startControlResultOf=(value,withAcknowledged)=>{const result=sessionJson(value,262144);if(result&&result.ok===true){const state=createStateOf(result.value,withAcknowledged);return state?freezeObject({ok:true,value:state}):sessionRefusal("unavailable")}if(result&&result.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);return sessionRefusal("unavailable")};
const requestAgentSessionStartControl=(kind,input)=>{let create_request_id;try{if(!input||typeof input!=="object"||isArray(input))throw 0;create_request_id=input.requestId}catch{create_request_id=null}if(!sessionIdOk(create_request_id)){reportBoundedRefusal("html_agent_sessions_refused","invalid");return NativePromise.resolve(sessionRefusal("invalid"))}if(agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16){reportBoundedRefusal("html_agent_sessions_refused","busy");return NativePromise.resolve(sessionRefusal("busy"))}const request_id=nextAgentSessionsId(kind==="cancel"?"agent-sessions-cancel-":"agent-sessions-status-");return new NativePromise(resolve=>{const pending={kind,resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_STATUS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:kind==="cancel"?"agent-sessions-cancel":"agent-sessions-create-status",request_id,create_request_id})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const settleAgentSessionsStartControl=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];const kind=data.type==="agent-sessions-cancel-result"?"cancel":data.type==="agent-sessions-create-status-result"?"createStatus":null;if(pending.kind!==kind)return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(startControlResultOf(data.result,kind==="cancel"))};
const settleAgentSessionsCatalog=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="catalog")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(catalogResultOf(data.result))};
const settleAgentSessionsChooseFolder=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="chooseFolder")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);const result=sessionJson(data.result,8192);if(result?.ok===true){const folder=result.value===null?null:catalogWorkspaceOf(result.value);pending.resolve(result.value===null||folder?freezeObject({ok:true,value:folder}):sessionRefusal("unavailable"))}else pending.resolve(result?.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code])?sessionRefusal(result.code):sessionRefusal("unavailable"))};
const settleAgentSessionsCreate=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="create")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(createResultOf(data.result,pending))};
const settleAgentSessionsMarkRead=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="markRead")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(sendReceiptOf(data.result,pending.read_request_id))};
const settleAgentSessionsWatchList=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="watchList")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);const result=sessionFollowResultOf(data.result),slot=pending.slot;if(!result.ok||agentSessionListWatch!==slot){stopAgentSessionListWatch(slot);pending.resolve(result.ok?sessionRefusal("unavailable"):result);return}pending.resolve(freezeObject({ok:true,value:freezeObject({dispose:()=>stopAgentSessionListWatch(slot)})}))};
const deliverAgentSessionListChanged=data=>{const slot=agentSessionListWatch;if(!agentSessionsFeature||agentSessionsClosed||!slot||data.subscription_id!==slot.subscription_id||!skinInteger(data.revision)||data.revision<0||data.revision<=slot.revision||sessionUtf8Bytes(jsonStringify(data))>1024)return;slot.revision=data.revision;try{apply(slot.callback,undefined,[freezeObject({revision:data.revision})])}catch(error){report("html_agent_sessions_event_failed",{message:detailOf(error)})}};
const deliverAgentSessionListWatchEnded=data=>{const slot=agentSessionListWatch;if(!agentSessionsFeature||agentSessionsClosed||!slot||data.subscription_id!==slot.subscription_id||sessionUtf8Bytes(jsonStringify(data))>1024)return;try{apply(slot.callback,undefined,[freezeObject({ended:true})])}catch(error){report("html_agent_sessions_event_failed",{message:detailOf(error)})}};
const settleAgentSessionsList=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="list")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(sessionPageResultOf(data.result))};
const settleAgentSessionsFollow=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="follow")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);const slot=own(agentSessionFollows,pending.subscription_id)?agentSessionFollows[pending.subscription_id]:null;const result=sessionFollowResultOf(data.result);if(!result.ok){if(slot)delete agentSessionFollows[pending.subscription_id];pending.resolve(result);return}if(!slot){try{send({version:VERSION,type:"agent-sessions-unsubscribe",subscription_id:pending.subscription_id})}catch{}pending.resolve(freezeObject({ok:true,value:freezeObject({dispose:()=>{}})}));return}pending.resolve(freezeObject({ok:true,value:freezeObject({dispose:disposeAgentSessionFollow(pending.subscription_id)})}))};
const settleAgentSessionsSend=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(pending.kind!=="send")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(sendReceiptOf(data.result,pending.request_id))};
const deliverAgentSessionEvent=data=>{if(!agentSessionsFeature||agentSessionsClosed)return;const slot=typeof data.subscription_id==="string"&&own(agentSessionFollows,data.subscription_id)?agentSessionFollows[data.subscription_id]:null;if(!slot)return;if(data.host_id!==slot.host_id||data.host_epoch!==slot.host_epoch||data.session_id!==slot.session_id){reportBoundedRefusal("html_agent_sessions_event_dropped","malformed");return}const event=sessionEventOf(data.event);if(!event){reportBoundedRefusal("html_agent_sessions_event_dropped","malformed");return}if(event.kind==="ended")delete agentSessionFollows[data.subscription_id];const targeted=freezeObject({...event,hostId:slot.host_id,hostEpoch:slot.host_epoch,sessionId:slot.session_id});if(sessionUtf8Bytes(jsonStringify(targeted))>262144)return;const callback=slot.callback;try{apply(callback,undefined,[targeted])}catch(error){report("html_agent_sessions_event_failed",{message:detailOf(error)})}};
const closeAgentSessions=()=>{agentSessionsClosed=true;for(const id of objectKeys(agentSessionsPending)){const pending=agentSessionsPending[id];delete agentSessionsPending[id];clearTimer(pending.timer);if(pending.kind==="send"||pending.kind==="markRead")pending.resolve(freezeObject({ok:true,value:freezeObject({requestId:pending.kind==="send"?pending.request_id:pending.read_request_id,delivery:"unknown"})}));else if(pending.kind==="respondToPermission")pending.resolve(permissionUnknown);else if(pending.kind==="create")pending.resolve(createUnknown());else pending.resolve(sessionRefusal("unavailable"))}agentSessionsInflight=0;for(const id of objectKeys(agentSessionFollows))delete agentSessionFollows[id];if(agentSessionListWatch)stopAgentSessionListWatch(agentSessionListWatch)};
const agentSessionsApi=freezeObject({protocolVersion:2,list:listAgentSessions,follow:followAgentSession,send:sendAgentSession,markRead:markAgentSessionRead,watchList:watchAgentSessionList,openInPaseo:input=>requestAgentSessionPermission("openInPaseo",input),getPermissionForm:input=>requestAgentSessionPermission("getPermissionForm",input),respondToPermission:input=>requestAgentSessionPermission("respondToPermission",input)});
const agentSessionsCreateApi=freezeObject({...agentSessionsApi,catalog:catalogAgentSessions,chooseFolder:chooseFolderAgentSessions,create:createAgentSession});
const agentSessionsAdoptedApi=freezeObject({...agentSessionsCreateApi,createStatus:input=>requestAgentSessionStartControl("createStatus",input),cancel:input=>requestAgentSessionStartControl("cancel",input)});
/* Saved-session source commands: only Desktop main chooses command ids and binding. */
const savedSessionResultOf=(kind,raw)=>{const result=sessionJson(raw,524288);if(result?.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);if(!result||result.ok!==true)return sessionRefusal("unavailable");const v=result.value,count=n=>Number.isSafeInteger(n)&&n>=0;let valid=false;if(kind==="save"||kind==="stopSaving")valid=permissionKeys(v,["requestId","delivery"],["requestId","delivery"])&&sessionIdOk(v.requestId)&&(v.delivery==="acknowledged"||v.delivery==="unknown");else if(kind==="saveStatus")valid=permissionKeys(v,["label","detail","folderId","confirmedSeq"],["label"])&&apply(arrayIncludes,["absent","requested","accepted","ok","paused","refused","error"],[v.label])&&(v.detail===undefined||permissionText(v.detail,1024))&&(v.folderId===undefined||sessionIdOk(v.folderId))&&(v.confirmedSeq===undefined||count(v.confirmedSeq));else if(kind==="previewSaved")valid=permissionKeys(v,["text","excludedCounts"],["text","excludedCounts"])&&permissionText(v.text,65536)&&permissionKeys(v.excludedCounts,["reasoning","toolInput","images"],["reasoning","toolInput","images"])&&count(v.excludedCounts.reasoning)&&count(v.excludedCounts.toolInput)&&count(v.excludedCounts.images);return valid?freezeObject({ok:true,value:freeze(v)}):sessionRefusal("unavailable")};
const savedSessionWire=freezeObject({save:"save",stopSaving:"stop-saving",saveStatus:"save-status",previewSaved:"preview-saved"});
const requestAgentSessionSaved=(kind,input)=>{if(!permissionKeys(input,["hostId","hostEpoch","sessionId"],["hostId","hostEpoch","sessionId"]))return NativePromise.resolve(sessionRefusal("invalid"));const target=sessionJson(input,1024);if(!permissionKeys(target,["hostId","hostEpoch","sessionId"],["hostId","hostEpoch","sessionId"])||!sessionIdOk(target.hostId)||!sessionIdOk(target.hostEpoch)||!sessionIdOk(target.sessionId))return NativePromise.resolve(sessionRefusal("invalid"));if(!agentSessionsSavedFeature||agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-saved-");return new NativePromise(resolve=>{const pending={kind,resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_STATUS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-"+savedSessionWire[kind],request_id,host_id:target.hostId,host_epoch:target.hostEpoch,session_id:target.sessionId})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const settleAgentSessionsSaved=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(!own(savedSessionWire,pending.kind)||data.type!=="agent-sessions-"+savedSessionWire[pending.kind]+"-result")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(savedSessionResultOf(pending.kind,data.result))};
/* Follow-up controls for Attention: Desktop checks first-party launch, fresh input and every limit. */
const followupWire=freezeObject({status:"status",continue:"continue",getSettings:"settings-get",setSettings:"settings-set"});
const followupCount=n=>Number.isSafeInteger(n)&&n>=0,followupMessage=value=>permissionText(value,2000),followupName=value=>permissionText(value,256,1),followupWorkspaceId=value=>permissionText(value,512,1);
const followupStatusKeys=["state","reason","limit","launchesToday","dailyCeiling","burst","running","maxConcurrent","queued","queuedAt","worker","executesOn","updatedAt"],followupWorkerKeys=["provider","model","modeId","workspaceId"],followupViewKeys=["configured","enabled","provider","model","modeId","options","optionsReason"];
const followupStatusOk=v=>{if(!permissionKeys(v,followupStatusKeys,followupStatusKeys)||!apply(arrayIncludes,["enabled","disabled","paused","limit_reached","unavailable"],[v.state])||(v.reason!==null&&!followupMessage(v.reason))||!apply(arrayIncludes,[null,"burst","daily"],[v.limit])||![v.launchesToday,v.dailyCeiling,v.running,v.maxConcurrent,v.updatedAt].every(followupCount)||!(v.queued===null||followupCount(v.queued))||!(v.queuedAt===null||followupCount(v.queuedAt))||!(v.executesOn===null||v.executesOn==="this Desktop"))return false;const b=v.burst,w=v.worker;return permissionKeys(b,["launches","limit","windowMs"],["launches","limit","windowMs"])&&followupCount(b.launches)&&followupCount(b.limit)&&followupCount(b.windowMs)&&(w===null||(permissionKeys(w,followupWorkerKeys,followupWorkerKeys)&&followupName(w.provider)&&followupName(w.model)&&followupName(w.modeId)&&followupWorkspaceId(w.workspaceId)))};
const followupSettingsOk=v=>{if(!catalogObject(v))return false;if(v.configured===false)return permissionKeys(v,["configured","reason"],["configured","reason"])&&followupMessage(v.reason);if(v.configured!==true||!permissionKeys(v,followupViewKeys,followupViewKeys)||typeof v.enabled!=="boolean"||!followupName(v.provider)||!followupName(v.model)||!followupName(v.modeId)||!(v.optionsReason===null||followupMessage(v.optionsReason))||!isArray(v.options)||v.options.length>16)return false;return v.options.every(o=>permissionKeys(o,["provider","label","modeId","models"],["provider","label","modeId","models"])&&followupName(o.provider)&&followupName(o.label)&&followupName(o.modeId)&&isArray(o.models)&&o.models.length<=64&&o.models.every(m=>permissionKeys(m,["id","label"],["id","label"])&&followupName(m.id)&&followupName(m.label)))};
const followupResultOf=(kind,raw)=>{const result=sessionJson(raw,262144);if(result?.ok===false&&apply(arrayIncludes,SESSION_RESULT_CODES,[result.code]))return sessionRefusal(result.code);if(!result||result.ok!==true)return sessionRefusal("unavailable");const v=result.value;let valid=false;if(kind==="status")valid=followupStatusOk(v);else if(kind==="getSettings")valid=followupSettingsOk(v);else if(kind==="continue")valid=permissionKeys(v,["continued","message","status"],["continued","message","status"])&&typeof v.continued==="boolean"&&followupMessage(v.message)&&followupStatusOk(v.status);else if(kind==="setSettings")valid=permissionKeys(v,["result","message","settings","status"],["result","message","status"])&&apply(arrayIncludes,["applied","saved","unchanged","refused"],[v.result])&&followupMessage(v.message)&&followupStatusOk(v.status)&&(v.result==="refused"?!own(v,"settings"):followupSettingsOk(v.settings));return valid?freezeObject({ok:true,value:freeze(v)}):sessionRefusal("unavailable")};
const requestAgentSessionFollowup=(kind,input)=>{let fields={};if(kind==="setSettings"){const given=catalogObject(input)?sessionJson(input,2048):null;if(!permissionKeys(given,["enabled","provider","model"],[])||objectKeys(given).length===0||(own(given,"enabled")&&typeof given.enabled!=="boolean")||(own(given,"provider")&&!followupName(given.provider))||(own(given,"model")&&!followupName(given.model)))return NativePromise.resolve(sessionRefusal("invalid"));fields=given}if(!agentSessionsFollowupFeature||agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal("unavailable"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal("busy"));const request_id=nextAgentSessionsId("agent-sessions-followup-");return new NativePromise(resolve=>{const pending={kind,resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))},AGENT_SESSIONS_TIMEOUT_MS);agentSessionsPending[request_id]=pending;agentSessionsInflight+=1;try{send({version:VERSION,type:"agent-sessions-followup-"+followupWire[kind],request_id,...fields})}catch{clearTimer(pending.timer);delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal("unavailable"))}})};
const settleAgentSessionsFollowup=data=>{if(typeof data.request_id!=="string"||!own(agentSessionsPending,data.request_id))return;const pending=agentSessionsPending[data.request_id];if(!own(followupWire,pending.kind)||data.type!=="agent-sessions-followup-"+followupWire[pending.kind]+"-result")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(followupResultOf(pending.kind,data.result))};
const agentSessionsFollowupApi=freezeObject({status:()=>requestAgentSessionFollowup("status"),continue:()=>requestAgentSessionFollowup("continue"),getSettings:()=>requestAgentSessionFollowup("getSettings"),setSettings:input=>requestAgentSessionFollowup("setSettings",input)});
const agentSessionsBaseSurface=()=>{const api=agentSessionsCreateFeature?(agentSessionsAdoptedFeature?agentSessionsAdoptedApi:agentSessionsCreateApi):agentSessionsApi;return agentSessionsOpenConversationFeature?freezeObject({...api,openConversation:(input,options)=>requestAgentSessionOpenConversation(input,options)}):api;};
const agentSessionsSavedSurface=()=>{const api=agentSessionsBaseSurface();return agentSessionsSavedFeature?freezeObject({...api,save:input=>requestAgentSessionSaved("save",input),stopSaving:input=>requestAgentSessionSaved("stopSaving",input),saveStatus:input=>requestAgentSessionSaved("saveStatus",input),previewSaved:input=>requestAgentSessionSaved("previewSaved",input)}):api;};
const agentSessionsSurface=()=>{const api=agentSessionsSavedSurface();return agentSessionsFollowupFeature?freezeObject({...api,followup:agentSessionsFollowupApi}):api;};
/* ARM transport: confirmation-first and non-authorizing. The frame may ASK the
   trusted host to prepare a confirmation for one strict request; only the host
   decides and only a later trusted host Apply submits. arm() is injected
   unconditionally so malformed requests fail synchronously, but it succeeds
   only when the host advertised intent-arm-confirm.v1 on the pinned init AND
   the private channel is open: an absent/malformed advertisement, a
   new-runtime/old-host pair, or a pre-init call resolves unavailable LOCALLY
   with NO message, so an old host never sees a speculative ARM and there is NO
   propose()/type:intent fallback. The request reuses propose()'s exact strict
   request_id/entry_id/slots/values shape, and the wire envelope carries no
   package nonce and no gesture mark. At most one ARM is outstanding; a second
   request, or a request id already pending as a proposal, resolves busy rather
   than sharing identity. One matching armed ack (duplicates ignored) clears the
   15000ms pre-ack timer and sends intent-arm-ready, a liveness receipt that
   carries NO authority. A timeout instead sends intent-arm-cancel (only on the
   captured channel) and resolves unavailable, never submitted-uncertain. The
   terminal intent-arm-result settles the promise for the host's full result
   vocabulary: cancelled/rejected/committed/conflict/uncertain plus the
   unavailable/busy/needs_confirmation cancellation forms; no write-success
   timeout is invented after ack. A post that throws before it sends resolves
   unavailable rather than rejecting, since nothing was submitted. */
const ARM_TIMEOUT_MS=15000,ARM_RESULTS=["cancelled","rejected","committed","conflict","uncertain","unavailable","busy","needs_confirmation"];
const refuseArm=(reason,message)=>{reportBoundedRefusal("html_arm_refused",reason);throw new TypeError(message)};
const unavailableArm=code=>freezeObject({status:"unavailable",code});
const clearArmTimer=()=>{if(armTimer!==null){clearTimer(armTimer);armTimer=null}};
const arm=intent=>{if(!armFeature||!channel)return NativePromise.resolve(unavailableArm("arm_unavailable"));if(pendingArm)return NativePromise.resolve(unavailableArm("arm_busy"));if(!intent||typeof intent!=="object"||isArray(intent)||objectKeys(intent).some(key=>!["request_id","entry_id","slots","values"].includes(key)))refuseArm("malformed","artifact arm contains unsupported fields");const request_id=intent.request_id,entry_id=intent.entry_id,slots=intent.slots??{},values=intent.values??{};if(!intentId(request_id)||!intentId(entry_id)||!intentMap(slots)||!intentMap(values)||objectKeys(slots).some(key=>!intentId(key)||typeof slots[key]!=="string"||slots[key].length>256)||objectKeys(values).some(key=>!intentId(key)))refuseArm("malformed","artifact arm is malformed");if(own(pendingIntents,request_id))return NativePromise.resolve(unavailableArm("arm_busy"));const encoded=jsonStringify({request_id,entry_id,slots,values});if(encoded.length>65536)refuseArm("too_large","artifact arm exceeds bridge limit");const payload=jsonParse(encoded);return new NativePromise(resolve=>{const activeChannel=channel;pendingArm={resolve,request_id,acked:false};armTimer=setTimer(()=>{armTimer=null;const pending=pendingArm;if(!pending)return;pendingArm=null;if(channel===activeChannel){try{post(channel,{version:VERSION,type:"intent-arm-cancel",request_id:pending.request_id})}catch{}}pending.resolve(unavailableArm("arm_timeout"))},ARM_TIMEOUT_MS);try{post(activeChannel,{version:VERSION,type:"intent-arm",intent:payload})}catch(error){clearArmTimer();pendingArm=null;resolve(unavailableArm("arm_unavailable"))}})};
const settleArmAck=data=>{if(!pendingArm||pendingArm.acked||data?.request_id!==pendingArm.request_id||data?.status!=="armed"||!channel)return;pendingArm.acked=true;clearArmTimer();try{post(channel,{version:VERSION,type:"intent-arm-ready",request_id:pendingArm.request_id})}catch{}};
const settleArmResult=data=>{if(!pendingArm||data?.request_id!==pendingArm.request_id||!data.result||typeof data.result!=="object"||isArray(data.result))return;let result;try{const encoded=jsonStringify(data.result);if(encoded.length>65536)return;result=freeze(jsonParse(encoded))}catch{return}if(typeof result.status!=="string"||!apply(arrayIncludes,ARM_RESULTS,[result.status]))return;const pending=pendingArm;pendingArm=null;clearArmTimer();pending.resolve(result)};
/* Closed optional Body attempts. A prepare is never a grant. Only an opaque
   channel-bound handle crosses submit; a timeout is always unverified. A submit
   is always forwarded with its own gesture mark and the count of completed
   trusted gestures: the host, not this frame, decides whether a click or the
   person's autosave consent authorises it, and refuses `gesture_required`
   otherwise. */
const BODY_ATTEMPT_FEATURE="native.html.body-attempt.v1";
let bodyAttemptGeneration=null,bodyAttemptClosed=false,bodyAttemptSeq=0;
const bodyAttemptPending=Object.create(null);
const bodyAttemptRefused=code=>freezeObject({status:"refused",code,message:"Body Save is unavailable. Your draft is retained."});
const bodyAttemptUncertain=()=>freezeObject({status:"uncertain",code:"uncertain",message:"The outcome is unverified. Retain the draft and retry the same attempt."});
const bodyAttemptId=v=>typeof v==="string"&&v.length>0&&v.length<=128&&apply(regExpExec,/^[A-Za-z0-9._:-]{1,128}$/,[v])!==null;
const bodyAttemptRequest=(type,value)=>{
 if(!initialized||!channel||bodyAttemptClosed||!bodyAttemptGeneration)return new NativePromise(resolve=>resolve(bodyAttemptRefused("unsupported")));
 if(objectKeys(bodyAttemptPending).length>=8)return new NativePromise(resolve=>resolve(bodyAttemptRefused("busy")));
 let backed=false;
 if(type==="body-attempt-submit"){backed=gestureArmed&&!gestureUsed;if(backed)gestureUsed=true;}
 const request_id="body-attempt-"+(++bodyAttemptSeq),activeChannel=channel,generation=bodyAttemptGeneration;
 const envelope={version:VERSION,type,request_id,generation,...value,...(type==="body-attempt-submit"?{gesture_backed:backed,gesture_epoch:gestureEpoch}:{})};
 let encoded;try{encoded=jsonStringify(envelope)}catch{throw new TypeError("Body request is malformed")}
 if(encoded.length>3211264||contextBytes(encoded,3211264)>3211264)throw new TypeError("Complete Body request exceeds bridge limit");
 return new NativePromise(resolve=>{const pending={resolve,type,generation,channel:activeChannel,timer:null};bodyAttemptPending[request_id]=pending;
 pending.timer=setTimer(()=>{if(bodyAttemptPending[request_id]!==pending)return;delete bodyAttemptPending[request_id];resolve(type==="body-attempt-submit"?bodyAttemptUncertain():bodyAttemptRefused("prepare_timeout"))},45000);
 try{post(activeChannel,jsonParse(encoded))}catch{delete bodyAttemptPending[request_id];clearTimer(pending.timer);resolve(bodyAttemptRefused("not_submitted"))}
 });
};
const bodyAttemptPrepare=candidate=>{
 if(!candidate||typeof candidate!=="object"||isArray(candidate)||objectKeys(candidate).length!==4||objectKeys(candidate).some(k=>!["entry_id","target_id","body","expected_body_digest"].includes(k))
  ||!bodyAttemptId(candidate.entry_id)||!bodyAttemptId(candidate.target_id)||typeof candidate.body!=="string"||typeof candidate.expected_body_digest!=="string"
  ||apply(regExpExec,/^[0-9a-f]{64}$/,[candidate.expected_body_digest])===null)throw new TypeError("Body candidate is malformed");
 const text=candidate.body;for(let i=0;i<text.length;i++){const n=apply(contextCharCode,text,[i]);if(n===0)throw new TypeError("Body source contains NUL");if(n>=55296&&n<=56319){const next=apply(contextCharCode,text,[++i]);if(!(next>=56320&&next<=57343))throw new TypeError("Body source contains unpaired surrogate")}else if(n>=56320&&n<=57343)throw new TypeError("Body source contains unpaired surrogate")}
 if(contextBytes(text,524288)>524288)throw new TypeError("Body source exceeds byte limit");
 return bodyAttemptRequest("body-attempt-prepare",{candidate:jsonParse(jsonStringify(candidate))});
};
const bodyAttemptHandle=(type,attempt_id)=>{if(!bodyAttemptId(attempt_id))throw new TypeError("Body attempt handle is malformed");return bodyAttemptRequest(type,{attempt_id})};
const settleBodyAttempt=data=>{
 const p=bodyAttemptPending[data?.request_id];if(!p||p.channel!==channel||p.generation!==bodyAttemptGeneration||data.generation!==p.generation)return;
 let result;try{const encoded=jsonStringify(data.result);if(typeof encoded!=="string"||encoded.length>65536)return;result=freeze(jsonParse(encoded))}catch{return}
 if(!result||typeof result!=="object"||isArray(result))return;
 delete bodyAttemptPending[data.request_id];clearTimer(p.timer);p.resolve(result);
};
const closeBodyAttempts=()=>{bodyAttemptClosed=true;bodyAttemptGeneration=null;for(const k of objectKeys(bodyAttemptPending)){const p=bodyAttemptPending[k];delete bodyAttemptPending[k];clearTimer(p.timer);p.resolve(p.type==="body-attempt-submit"?bodyAttemptUncertain():bodyAttemptRefused("closed"))}};
const bodyAttemptApi=freezeObject({get offering(){return !bodyAttemptClosed&&bodyAttemptGeneration?freezeObject({generation:bodyAttemptGeneration}):null},prepare:bodyAttemptPrepare,
 prepareUndo:attempt_id=>bodyAttemptHandle("body-attempt-undo",attempt_id),submit:attempt_id=>bodyAttemptHandle("body-attempt-submit",attempt_id)});
/* Optional on-demand app observations. Registration is capability-only; no
   report leaves this private port without a live host request. Input delivery
   acknowledgements are deliberately not promoted to committed-render evidence. */
const CONTEXT_FEATURE="app-view-report.v1",contextAbort=AbortController,contextAbortMethod=AbortController.prototype.abort,contextNow=Date.now,contextClock=performance.now.bind(performance),contextResolve=Promise.resolve.bind(Promise),contextCharCode=String.prototype.charCodeAt,contextFinite=Number.isFinite,contextInteger=Number.isSafeInteger,contextMin=Math.min,contextSignal=getter(AbortController.prototype,"signal");
// Every app can report rendered text; a custom reporter adds app-specific state.
let renderedContextSeq=0;
const contextClip=(value,max)=>{let text="",bytes=0;for(const point of NativeString(value??"")){const n=contextBytes(point);if(bytes+n>max)break;text+=point;bytes+=n}return text};
const contextVisible=element=>{
 if(!element?.isConnected||closest(element,"script,style,svg,input,textarea,[data-view-private]"))return null;
 let box={left:0,top:0,right:innerWidth,bottom:innerHeight};
 for(let node=element,depth=0;node&&depth++<64;node=node.parentElement){const style=getComputedStyle(node);
  if(node.hidden||node.getAttribute("aria-hidden")==="true"||style.display==="none"||style.visibility==="hidden"||style.visibility==="collapse"||style.opacity==="0"||style.contentVisibility==="hidden")return null;
  if(node.tagName==="DETAILS"&&!node.open&&!node.querySelector("summary")?.contains(element))return null;
  if(/auto|scroll|hidden|clip/.test(style.overflow+style.overflowX+style.overflowY)){const r=node.getBoundingClientRect();box={left:Math.max(box.left,r.left),top:Math.max(box.top,r.top),right:Math.min(box.right,r.right),bottom:Math.min(box.bottom,r.bottom)}}
 }
 const r=element.getBoundingClientRect();return r.right>box.left&&r.left<box.right&&r.bottom>box.top&&r.top<box.bottom?box:null;
};
const renderedContextReport=request=>{
 if(request.signal.aborted||!document.body)throw new Error("view unavailable");
 const walker=document.createTreeWalker(document.body,4),chunks=[];let node,visited=0,points=0,truncated=false;
 const deadline=contextClock()+Math.min(request.remainingMs,100);
 while((node=walker.nextNode())&&++visited<=1024&&points<8192&&contextClock()<deadline){
  const parent=node.parentElement,clip=parent&&contextVisible(parent);if(!clip)continue;
  const value=node.textContent??"";if(!value.trim())continue;
  const range=document.createRange();range.selectNodeContents(node);const rects=[...range.getClientRects()];
  const overlaps=r=>r.right>clip.left&&r.left<clip.right&&r.bottom>clip.top&&r.top<clip.bottom;
  if(!rects.some(overlaps))continue;
  let visible=value;
  if(!rects.every(r=>r.left>=clip.left&&r.right<=clip.right&&r.top>=clip.top&&r.bottom<=clip.bottom)){
   visible="";let offset=0;for(const point of value){if(++points>8192||contextClock()>=deadline)break;range.setStart(node,offset);offset+=point.length;range.setEnd(node,offset);if([...range.getClientRects()].some(overlaps))visible+=point}
  }else points+=value.length;
  if(visible)pushValue(chunks,visible);
 }
 truncated=!!node;
 const omitted=["structured_state","source_references","drafts","pixels"],text=contextClip(chunks.join("\n").trim(),16384);
 if(truncated||text.length<chunks.join("\n").trim().length)pushValue(omitted,"text_budget");
 const report={version:"native.app-view-report.v1",viewSeq:++renderedContextSeq,observedAt:contextNow(),coherence:"unknown",completeness:"partial",omitted,committedInput:{status:"unknown"},regions:[{id:"rendered",role:"document",text}]};
 const selection=getSelection();if(selection&&!selection.isCollapsed&&selection.rangeCount===1){const range=selection.getRangeAt(0),start=range.startContainer.parentElement,end=range.endContainer.parentElement;
  let valid=!!start&&!!end&&document.body.contains(start)&&document.body.contains(end)&&!!contextVisible(start)&&!!contextVisible(end);
  if(valid){const selected=document.createTreeWalker(document.body,4);let piece,count=0;while((piece=selected.nextNode())){if(++count>1024||contextClock()>=deadline){valid=false;break}if(range.intersectsNode(piece)&&piece.textContent?.trim()&&!contextVisible(piece.parentElement)){valid=false;break}}}
  if(valid)report.selection={regionId:"rendered",quote:contextClip(selection.toString(),4096),draft:!!closest(start,"[contenteditable]:not([contenteditable=false])")};
  else pushValue(omitted,"selection_unverified");
 }
 return report;
};
let contextFeature=false,contextReporter=renderedContextReport,contextGeneration=1,contextLastSeq=0,contextClosed=false;
const contextPending=Object.create(null);let contextCount=0;
const contextBytes=(value,limit=65536)=>{let n=0;for(let i=0;i<value.length;i++){const c=apply(contextCharCode,value,[i]);if(c<128)n++;else if(c<2048)n+=2;else if(c>=55296&&c<=56319&&i+1<value.length&&apply(contextCharCode,value,[i+1])>=56320&&apply(contextCharCode,value,[i+1])<=57343){n+=4;i++}else n+=3;if(n>limit)return n}return n};
const cancelContext=id=>{const p=contextPending[id];if(!p)return;delete contextPending[id];contextCount--;clearTimer(p.timer);apply(contextAbortMethod,p.controller,[])};
const clearContext=()=>{for(const id of objectKeys(contextPending))cancelContext(id)};
const closeContext=()=>{clearContext();contextClosed=true;contextReporter=null};
const publishContextRegistration=()=>{if(contextFeature&&!contextClosed)send({version:VERSION,type:"context-register",context_version:CONTEXT_FEATURE,generation:contextGeneration,available:contextReporter!==null})};
const registerContextReporter=reporter=>{if(typeof reporter!=="function")throw new TypeError("context reporter must be a function");if(contextClosed)throw new TypeError("context channel closed");clearContext();contextReporter=reporter;contextGeneration++;const generation=contextGeneration;publishContextRegistration();return()=>{if(contextGeneration!==generation)return;clearContext();contextReporter=renderedContextReport;contextGeneration++;publishContextRegistration()}};
const receiveContext=data=>{
 if(!contextFeature||contextClosed||data.context_version!==CONTEXT_FEATURE||!intentId(data.request_id)||data.generation!==contextGeneration)return;
 if(data.type==="context-cancel"){const p=contextPending[data.request_id];if(p&&p.seq===data.request_seq)cancelContext(data.request_id);return}
 if(data.type!=="context-request"||!contextReporter||!contextInteger(data.request_seq)||data.request_seq<=contextLastSeq||own(contextPending,data.request_id)||contextCount>=4||!contextFinite(data.remaining_ms)||!contextFinite(data.deadline_ms))return;
 contextLastSeq=data.request_seq;
 const remaining=contextMin(750,data.remaining_ms,data.deadline_ms-contextNow());if(remaining<=0)return;
 const id=data.request_id,generation=contextGeneration,controller=new contextAbort(),deadline=contextClock()+remaining,reporter=contextReporter;
 const p={controller,seq:data.request_seq,timer:setTimer(()=>cancelContext(id),remaining)};contextPending[id]=p;contextCount++;
 const finish=(report,failed)=>{if(contextPending[id]!==p||contextGeneration!==generation||contextClock()>=deadline)return;
  let encoded,status="available",reason="source_unavailable";try{if(failed)throw new Error("report unavailable");encoded=jsonStringify(report);if(typeof encoded!=="string")throw new Error("report unavailable");if(encoded.length>65536||contextBytes(encoded)>65536){reason="too_large";throw new Error("report too large")}}catch{status="unavailable";encoded=undefined}
  cancelContext(id);send({version:VERSION,type:"context-report",context_version:CONTEXT_FEATURE,request_id:id,request_seq:p.seq,generation,status,...(encoded===undefined?{reason}:{report_json:encoded})})};
 try{contextResolve(reporter(freezeObject({signal:read(contextSignal,controller),remainingMs:remaining}))).then(report=>finish(report,false),()=>finish(null,true))}catch{finish(null,true)}
};
/* BEGIN GENERATED BODY FACTORIES */
// Owning pure source. Generated ESM only in P0; bootstrap embedding is deferred.
// Intrinsics are supplied by a realm owner before untrusted author execution.
function bodyWireFactory(I) {
  const apply = I.apply, create = I.create, define = I.define, freeze = I.freeze;
  const own = I.own, ownKeys = I.ownKeys, proto = I.proto, isArray = I.isArray;
  const cc = (s, n) => apply(I.charCode, s, [n]);
  const slice = (s, a, b) => apply(I.slice, s, [a, b]);
  const set = (o, k, v) => {
    // Native ToPropertyDescriptor reads inherited members even when define is
    // captured. Keep the descriptor itself free of authored prototype hooks.
    const descriptor = create(null);
    descriptor.value = v;
    descriptor.enumerable = true;
    define(o, k, descriptor);
    return o;
  };
  const tree = () => create(null);
  const answer = (kind, key, value) => freeze(set(set(tree(), 'kind', kind), key, value));
  const invalid = answer('invalid', 'reason', 'protocol');
  const badRequest = answer('invalid', 'reason', 'invalid_message');
  const CONTRACT = 'records.body.read.v1', TRANSPORT = 'records.body.transport.v1';
  const VERSION = 'native.html.bridge.v1', EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const PAGE = ['contract', 'record_id', 'revision', 'body_digest', 'body_present', 'encoding',
    'start_byte', 'end_byte', 'total_bytes', 'text', 'complete', 'next_cursor', 'limits'];
  const LIMITS = ['max_page_bytes', 'max_response_bytes', 'max_body_bytes', 'max_source_bytes',
    'max_provenance_payload_bytes', 'max_provenance_events', 'request_timeout_ms'];
  const ROOT = [...PAGE, 'error', 'reason'], ERROR = ['code', 'reason'];
  const HTTP = ['invalid_message', 'busy', 'mount_unavailable', 'timeout', 'cancelled', 'protocol'];
  const LOCAL = [...HTTP, 'not_offered', 'closed', 'network'];
  const PAIRS = [
    ['invalid_params', 'request'], ['invalid_cursor', 'cursor'], ['cursor_expired', 'cursor'],
    ['resource_exhausted', 'result_budget'], ['unsupported_profile', 'primary_sqlite_required'],
    ['unsupported_capability', 'portability_policy'], ['source_integrity', 'source'],
    ['undeclared_read', 'descriptor'], ['adoption_required', 'source'], ['record_unavailable', 'target'],
    ['access_lost', 'target'], ['scope_denied', 'scope'], ['revision_changed', 'incarnation'],
    ['too_large', 'body_read_work_limit'], ['resource_exhausted', 'process_busy'],
    ['resource_exhausted', 'source_work_limit'], ['resource_exhausted', 'provenance_work_limit'],
    ['resource_exhausted', 'vm_work_limit'], ['timeout', 'request'], ['engine', 'integrity_or_execution'],
  ];
  const decoder = new I.Decoder('utf-8', { fatal: true, ignoreBOM: true });
  const integer = n => I.safeInteger(n) && n >= 0;
  const find = (a, value) => { for (let i = 0; i < a.length; i++) if (a[i] === value) return i; return -1; };
  const ascii = (s, max, graphic = false) => {
    if (typeof s !== 'string' || !s.length || s.length > max) return false;
    for (let i = 0; i < s.length; i++) { const c = cc(s, i); if (c > (graphic ? 126 : 127) || (graphic && c < 33)) return false; }
    return true;
  };
  // Scalar validation precedes encoding, so TextEncoder never replaces a surrogate.
  const utf8 = (s, cap) => {
    if (typeof s !== 'string' || s.length > cap) return -1;
    let bytes = 0;
    for (let i = 0; i < s.length; i++) {
      const c = cc(s, i);
      if (c < 128) bytes++; else if (c < 2048) bytes += 2;
      else if (c >= 0xd800 && c <= 0xdbff) {
        const low = cc(s, ++i); if (!(low >= 0xdc00 && low <= 0xdfff)) return -1;
        bytes += 4;
      } else if (c >= 0xdc00 && c <= 0xdfff) return -1;
      else bytes += 3;
      if (bytes > cap) return -1;
    }
    return bytes;
  };
  const hex = s => {
    if (typeof s !== 'string' || s.length !== 64) return false;
    for (let i = 0; i < 64; i++) { const c = cc(s, i); if (!(c >= 48 && c <= 57) && !(c >= 97 && c <= 102)) return false; }
    return true;
  };
  // One native ownKeys enumeration is unavoidable for exact structured shapes.
  // Check its size before descriptor reads/copies; no descriptor map or token list.
  const shape = (v, names, required = names.length) => {
    if (!v || typeof v !== 'object' || isArray(v)) return null;
    const p = proto(v); if (p !== null && p !== I.objectProto) return null;
    const ks = ownKeys(v);
    if (ks.length < required || ks.length > names.length) return null;
    const out = tree(); let bits = 0;
    for (let i = 0; i < ks.length; i++) {
      const k = ks[i], n = find(names, k); if (n < 0) return null;
      const d = own(v, k); if (!d || !d.enumerable || !own(d, 'value')) return null;
      set(out, k, d.value); bits |= 1 << n;
    }
    if ((bits & ((1 << required) - 1)) !== (1 << required) - 1) return null;
    return out;
  };
  const has = (v, k) => !!own(v, k);
  const encodedSize = (v, cap) => {
    const text = I.stringify(v);
    return utf8(text, cap);
  };
  const expectedOf = value => {
    if (value === undefined) return null;
    const e = shape(value, ['recordId', 'pageBytes']);
    if (!e || !ascii(e.recordId, 128, true) || !integer(e.pageBytes) || e.pageBytes < 4 || e.pageBytes > 32768) return false;
    return e;
  };
  const checkedBody = (value, e) => {
    if (value && typeof value === 'object' && has(value, 'error')) {
      const r = shape(value, ['contract', 'error']);
      if (!r || r.contract !== CONTRACT) return null;
      const error = shape(r.error, ERROR); if (!error || !ascii(error.code, 128, true) || !ascii(error.reason, 128, true)) return null;
      let known = false;
      for (let i = 0; i < PAIRS.length; i++) if (PAIRS[i][0] === error.code && PAIRS[i][1] === error.reason) known = true;
      if (!known) return null;
      const result = set(set(tree(), 'contract', CONTRACT), 'error', freeze(error));
      return encodedSize(result, 262144) < 0 ? null : freeze(result);
    }
    const p = shape(value, PAGE); if (!p || p.contract !== CONTRACT || p.encoding !== 'utf-8'
      || !ascii(p.record_id, 128, true) || (e && p.record_id !== e.recordId)
      || !ascii(p.revision, 1024) || !hex(p.body_digest) || typeof p.body_present !== 'boolean'
      || typeof p.complete !== 'boolean' || !integer(p.start_byte) || !integer(p.end_byte) || !integer(p.total_bytes)
      || p.start_byte > p.end_byte || p.end_byte > p.total_bytes) return null;
    const limits = shape(p.limits, LIMITS, 2);
    if (!limits || !integer(limits.max_page_bytes) || limits.max_page_bytes < 4 || limits.max_page_bytes > 32768
      || !integer(limits.max_response_bytes) || limits.max_response_bytes < 1 || limits.max_response_bytes > 262144) return null;
    for (let i = 2; i < LIMITS.length; i++) if (has(limits, LIMITS[i]) && (!integer(limits[LIMITS[i]]) || limits[LIMITS[i]] < 1)) return null;
    const bytes = utf8(p.text, 32768);
    if (bytes < 0 || bytes !== p.end_byte - p.start_byte || bytes > limits.max_page_bytes || (e && bytes > e.pageBytes)) return null;
    if (p.complete ? p.end_byte !== p.total_bytes || p.next_cursor !== null
      : p.end_byte >= p.total_bytes || !ascii(p.next_cursor, 1024) || bytes === 0) return null;
    if (!p.body_present && (!p.complete || p.total_bytes !== 0 || p.text !== '')) return null;
    if (p.total_bytes === 0 && p.body_digest !== EMPTY) return null;
    if (has(limits, 'max_body_bytes') && p.total_bytes > limits.max_body_bytes) return null;
    // Rebuild rather than replacing a nonwritable validated property.
    const result = tree();
    for (let i = 0; i < PAGE.length; i++) set(result, PAGE[i], PAGE[i] === 'limits' ? freeze(limits) : p[PAGE[i]]);
    return encodedSize(result, limits.max_response_bytes) < 0 ? null : freeze(result);
  };
  // Nonrecursive grammar pass. Fixed two frames, fixed vocabulary bitsets,
  // no token/AST list. Key decoding is bounded; values are scanned in place.
  const scan = text => {
    let at = 0, depth = 1, done = false;
    const frames = [{ names: ROOT, bits: 0, mode: 0, key: '' }, null];
    const ws = () => { while (at < text.length) { const c = cc(text, at); if (c !== 32 && c !== 9 && c !== 10 && c !== 13) break; at++; } };
    const digit = c => c >= 48 && c <= 57;
    const hexDigit = c => c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1;
    const string = key => {
      if (cc(text, at++) !== 34) return null;
      let decoded = '', units = 0;
      while (at < text.length) {
        let c = cc(text, at++);
        if (c === 34) return key ? decoded : true;
        if (c < 32) return null;
        if (c === 92) {
          c = cc(text, at++);
          if (c === 117) {
            c = 0;
            for (let n = 0; n < 4; n++) { const h = hexDigit(cc(text, at++)); if (h < 0) return null; c = c * 16 + h; }
          } else if (c === 98) c = 8; else if (c === 102) c = 12; else if (c === 110) c = 10;
          else if (c === 114) c = 13; else if (c === 116) c = 9;
          else if (c !== 34 && c !== 92 && c !== 47) return null;
        }
        if (key) { if (++units > 64 || c > 127) return null; decoded += I.fromCharCode(c); }
      }
      return null;
    };
    const number = () => {
      if (cc(text, at) === 45) at++;
      if (cc(text, at) === 48) at++;
      else { if (!(cc(text, at) >= 49 && cc(text, at) <= 57)) return false; while (digit(cc(text, at))) at++; }
      if (cc(text, at) === 46) { at++; if (!digit(cc(text, at))) return false; while (digit(cc(text, at))) at++; }
      if (cc(text, at) === 101 || cc(text, at) === 69) {
        at++; if (cc(text, at) === 43 || cc(text, at) === 45) at++;
        if (!digit(cc(text, at))) return false; while (digit(cc(text, at))) at++;
      }
      return true;
    };
    ws(); if (cc(text, at++) !== 123) return false;
    while (depth) {
      ws(); const f = frames[depth - 1], c = cc(text, at);
      if ((f.mode === 0 || f.mode === 4) && c === 125) {
        const complete = f.names === ROOT
          ? f.bits === (1 << 13) - 1 || f.bits === ((1 << 13) | 1) || f.bits === ((1 << 14) | 1)
          : f.names === LIMITS ? (f.bits & 3) === 3 : f.bits === 3;
        if (!complete) return false;
        at++; frames[depth - 1] = null; depth--; if (!depth) done = true; continue;
      }
      if (f.mode === 0 || f.mode === 1) {
        const key = string(true); if (key === null) return false;
        const n = find(f.names, key); if (n < 0 || (f.bits & (1 << n))) return false;
        f.bits |= 1 << n; f.key = key; f.mode = 2;
      } else if (f.mode === 2) { if (c !== 58) return false; at++; f.mode = 3; }
      else if (f.mode === 4) { if (c !== 44) return false; at++; f.mode = 1; }
      else {
        f.mode = 4;
        if (c === 123) {
          if (depth !== 1 || (f.key !== 'limits' && f.key !== 'error')) return false;
          frames[depth++] = { names: f.key === 'limits' ? LIMITS : ERROR, bits: 0, mode: 0, key: '' }; at++;
        } else if (c === 34) { if (string(false) === null) return false; }
        else if (c === 45 || digit(c)) { if (!number()) return false; }
        else if (slice(text, at, at + 4) === 'true' || slice(text, at, at + 4) === 'null') at += 4;
        else if (slice(text, at, at + 5) === 'false') at += 5;
        else return false;
      }
    }
    ws(); return done && at === text.length;
  };
  const validateBody = (value, expected) => {
    try {
      const e = expectedOf(expected); if (e === false) return invalid;
      const body = checkedBody(value, e); return body ? answer('body', 'response', body) : invalid;
    } catch { return invalid; }
  };
  const decodeHttp = (bytes, expected) => {
    try {
      const e = expectedOf(expected); if (e === false) return invalid;
      if (apply(I.typedName, bytes, []) !== 'Uint8Array') return invalid;
      const length = apply(I.byteLength, bytes, []); if (!length || length > 262144) return invalid;
      // Fixed owned snapshot: a growable/shared input cannot enlarge decoding
      // after the length check. Native set refuses growth beyond this capacity.
      const snapshot = new I.Bytes(length);
      apply(I.setBytes, snapshot, [bytes]);
      const text = apply(I.decode, decoder, [snapshot]); if (!scan(text)) return invalid;
      const v = I.parse(text); // Only after the complete duplicate-aware scan.
      if (v && own(v, 'contract')?.value === TRANSPORT) {
        const t = shape(v, ['contract', 'reason']);
        if (!t || length > 512 || find(HTTP, t.reason) < 0) return invalid;
        return answer('transport', 'reason', t.reason);
      }
      const body = checkedBody(v, e); return body ? answer('body', 'response', body) : invalid;
    } catch { return invalid; }
  };
  const validateRawRequest = value => {
    try { return utf8(value, 4096) < 0 ? badRequest : answer('request', 'request_json', value); } catch { return badRequest; }
  };
  const validateTypedRequest = value => {
    try {
      const r = shape(value, ['record_id', 'page_bytes', 'revision', 'cursor'], 1);
      if (!r || !ascii(r.record_id, 128, true) || (has(r, 'page_bytes') && (!integer(r.page_bytes) || r.page_bytes < 4 || r.page_bytes > 32768))
        || has(r, 'revision') !== has(r, 'cursor') || (has(r, 'revision') && (!ascii(r.revision, 1024) || !ascii(r.cursor, 1024)))) return badRequest;
      const text = I.stringify(r); return utf8(text, 4096) < 0 ? badRequest : answer('request', 'request_json', text);
    } catch { return badRequest; }
  };
  const encodeChannel = (value, kind) => {
    try {
      let data, cap;
      if (kind === 'offering') {
        const names = ['contract', 'scope', 'max_request_bytes', 'max_response_bytes', 'max_page_bytes', 'max_body_bytes', 'request_timeout_ms', 'max_inflight'];
        data = shape(value, names);
        if (!data || data.contract !== CONTRACT || data.scope !== 'viewer-visible-current-bodies' || data.max_request_bytes !== 4096
          || data.max_response_bytes !== 262144 || data.max_page_bytes !== 32768 || data.max_body_bytes !== 16777216
          || data.request_timeout_ms !== 5000 || data.max_inflight !== 1) return invalid;
        cap = 512;
      } else {
        const extra = kind === 'request' ? 'request_json' : kind === 'result' ? 'response' : kind === 'transport' ? 'reason' : null;
        if (!extra && kind !== 'cancel') return invalid;
        const names = extra ? ['version', 'type', 'request_id', extra] : ['version', 'type', 'request_id'];
        const input = shape(value, names);
        const type = kind === 'request' ? 'body-read' : kind === 'result' ? 'body-read-result' : kind === 'transport' ? 'body-read-transport' : 'body-read-cancel';
        if (!input || input.version !== VERSION || input.type !== type || !ascii(input.request_id, 128, true)) return invalid;
        data = tree();
        for (let i = 0; i < 3; i++) set(data, names[i], input[names[i]]);
        if (kind === 'request') {
          if (utf8(input.request_json, 4096) < 0) return invalid; set(data, extra, input.request_json); cap = 32768;
        } else if (kind === 'result') {
          const body = checkedBody(input.response, null); if (!body) return invalid; set(data, extra, body); cap = 262656;
        } else if (kind === 'transport') {
          if (find(LOCAL, input.reason) < 0) return invalid; set(data, extra, input.reason); cap = 512;
        } else cap = 512;
      }
      freeze(data); const bytes = encodedSize(data, cap); if (bytes < 0) return invalid;
      return freeze(set(set(set(tree(), 'kind', 'encoded'), 'data', data), 'utf8Bytes', bytes));
    } catch { return invalid; }
  };
  // Pure literal mapping only, never reads an exception or server Reply object.
  const mapHostRefusal = variant => {
    if (typeof variant !== 'string') return 'protocol';
    if (variant === 'InvalidIngress') return 'invalid_message';
    if (variant === 'Busy') return 'busy';
    if (variant === 'MountUnavailable' || variant === 'AuthCatalog') return 'mount_unavailable';
    if (variant === 'Deadline') return 'timeout';
    if (variant === 'Cancelled') return 'cancelled';
    return 'protocol';
  };
  return freeze({ decodeHttp, validateBody, validateTypedRequest, validateRawRequest, encodeChannel, mapHostRefusal });
}
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
/* END GENERATED BODY FACTORIES */
const bodySafeInteger=Number.isSafeInteger,bodyTyped=parentOf(Uint8Array.prototype),bodyWire=bodyWireFactory({
 apply,create:Object.create,define,freeze:freezeObject,own,ownKeys:Reflect.ownKeys,proto:parentOf,objectProto:Object.prototype,isArray,
 charCode:String.prototype.charCodeAt,slice:String.prototype.slice,fromCharCode:String.fromCharCode,safeInteger:Number.isSafeInteger,
 parse:jsonParse,stringify:jsonStringify,Encoder:TextEncoder,Decoder:TextDecoder,decode:TextDecoder.prototype.decode,
 Bytes:Uint8Array,setBytes:Uint8Array.prototype.set,byteLength:own(bodyTyped,"byteLength").get,typedName:own(bodyTyped,Symbol.toStringTag).get
});
const bodyLane=bodyFrameFactory({wire:bodyWire,apply,create:Object.create,define,freeze:freezeObject,own,keys:Reflect.ownKeys,proto:parentOf,objectProto:Object.prototype,
 Promise:NativePromise,species:Symbol.species,then:NativePromise.prototype.then,parse:jsonParse,listen,unlisten,post,timer:setTimer,clear:clearTimer,
 aborted:getter(parentOf(read(contextSignal,new contextAbort())),"aborted"),safeInteger:Number.isSafeInteger});
// Body-only initialization never sends an arbitrary failure to legacy diagnostics.
function initializeBody(data){try{const offered=own(data,"body_read"),features=own(data,"host_features");let feature=false;
 if(features&&features.enumerable&&own(features,"value")&&isArray(features.value)){const count=own(features.value,"length");
  if(count&&own(count,"value")&&bodySafeInteger(count.value)&&count.value<=32){for(let i=0;i<count.value;i++){const d=own(features.value,NativeString(i));if(!d||!d.enumerable||!own(d,"value")||typeof d.value!=="string"){feature=false;break;}if(d.value==="records.body.read.v1")feature=true;}}}
 bodyLane.connect(channel,offered&&offered.enumerable&&own(offered,"value")?offered.value:undefined,feature);bodyLane.ready();
}catch{bodyLane.close();}}
define(window,"nativeArtifact",{value:freezeObject({ready,propose,arm,bodyAttempt:bodyAttemptApi,get commentKeepsBodyFrame(){return commentFrameFeature},publishLocation,publishUnsaved,read:readNeed,get call(){return callFeature?callOperation:undefined},get session(){return sessionFeature?sessionApi:undefined},get query(){return subscribeFeature?queryOperation:undefined},get subscribe(){return subscribeFeature?subscribeOperation:undefined},get agents(){return agentsFeature?agentsApi:undefined},get agentSessions(){return agentSessionsFeature?agentSessionsSurface():undefined},get skin(){return skinFeature?skinApi:undefined},get presentation(){return presentationFeature?presentationApi:undefined},body:bodyLane.api,onInput,onReveal,setViewState,registerContextReporter,get input(){return heldInput},get inputDelivery(){return freezeObject({basis:"delivery_only",digest:typeof heldDigest==="string"?heldDigest:null,deliverySeq:contextInteger(heldSeq)&&heldSeq>=0?heldSeq:null})},get viewState(){return heldViewState}}),writable:false,configurable:false});
const kitFactory=__NATIVE_KIT_FACTORY__,kitRelease=__NATIVE_KIT_RELEASE__;
let suppliedKit=null,disposeKit=()=>{};
if(kitFactory){const owned=kitFactory(freezeObject({ready,onInput}),kitRelease);suppliedKit=owned.kit;disposeKit=owned.dispose;
try{define(window,"native",{value:freezeObject({kit:suppliedKit,get call(){return callFeature?callOperation:undefined},get session(){return sessionFeature?sessionApi:undefined},get query(){return subscribeFeature?queryOperation:undefined},get subscribe(){return subscribeFeature?subscribeOperation:undefined},get agents(){return agentsFeature?agentsApi:undefined},get agentSessions(){return agentSessionsFeature?agentSessionsSurface():undefined},get skin(){return skinFeature?skinApi:undefined},get presentation(){return presentationFeature?presentationApi:undefined}}),writable:false,configurable:false});
listen(window,"pagehide",disposeKit,true);listen(window,"unload",disposeKit,true);}catch(error){disposeKit();throw error}}
const bounded=value=>NativeString(value??"").slice(0,512);
const send=value=>{if(channel)post(channel,value);else if(queued.length<32)pushValue(queued,value)};
const report=(code,detail={})=>send({version:VERSION,type:"diagnostic",code,detail});
const freeze=value=>{if(value&&typeof value==="object"&&!isFrozen(value)){freezeObject(value);for(const key of objectKeys(value))freeze(value[key])}return value};
const detailOf=error=>{let detail="";try{detail=error&&error.message||error}catch{detail=""}return bounded(detail)};
const deliverInput=data=>{if(data?.version!==VERSION||!initialized||typeof data?.input_digest!=="string")return;const revision=data?.revision,seq=revision&&typeof revision==="object"?revision.content_event_seq:undefined;if(typeof seq!=="number")return;if(data.input_digest===heldDigest){send({version:VERSION,type:"input-applied",input_digest:data.input_digest});return}if(!(heldSeq==null||seq>heldSeq)){send({version:VERSION,type:"input-unhandled",input_digest:data.input_digest,reason:"stale"});return}let next;try{next=freeze(data.input)}catch(error){report("html_input_update_failed",{message:detailOf(error)});send({version:VERSION,type:"input-unhandled",input_digest:data.input_digest,reason:"freeze-failed"});return}if(!inputSubscribers.length){send({version:VERSION,type:"input-unhandled",input_digest:data.input_digest,reason:"no-subscriber"});return}heldInput=next;heldDigest=data.input_digest;heldSeq=seq;const delivery=freezeObject({input:next});let threw=false,failed="";const count=inputSubscribers.length;for(let index=0;index<count;index+=1){const subscriber=inputSubscribers[index];if(typeof subscriber!=="function")continue;try{apply(subscriber,undefined,[delivery])}catch(error){threw=true;failed=detailOf(error)}}if(threw){report("html_input_update_failed",{message:failed});send({version:VERSION,type:"input-unhandled",input_digest:data.input_digest,reason:"subscriber-threw"})}else send({version:VERSION,type:"input-applied",input_digest:data.input_digest})};
for(const name of ["RTCPeerConnection","webkitRTCPeerConnection","mozRTCPeerConnection"]){try{define(globalThis,name,{value:undefined,writable:false,configurable:false})}catch{}}
listen(window,"error",event=>report("html_runtime_error",{message:bounded(event.message),line:event.lineno||0,column:event.colno||0}),true);
listen(window,"unhandledrejection",event=>report("html_runtime_error",{message:bounded(event.reason)}),true);
listen(window,"securitypolicyviolation",event=>report("html_csp_violation",{directive:bounded(event.effectiveDirective),blocked:bounded(event.blockedURI).split(/[?#]/)[0]}),true);
function interactive(target){return isElement(target)&&!!closest(target,"input,textarea,select,button,a,[contenteditable]:not([contenteditable=false])")}
function show(index){if(!slides.length)return;current=Math.max(0,Math.min(index,slides.length-1));slides.forEach((slide,i)=>{slide.hidden=i!==current;slide.setAttribute("aria-hidden",NativeString(i!==current))});let live=document.getElementById("native-slide-status");if(!live){live=document.createElement("div");live.id="native-slide-status";live.setAttribute("role","status");live.setAttribute("aria-live","polite");live.style.cssText="position:fixed;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)";document.body.append(live)}live.textContent=`Slide ${current+1} of ${slides.length}`;dispatchEvent(new CustomEvent("native:slidechange",{detail:freezeObject({index:current,number:current+1,total:slides.length,id:slides[current].id})}));send({version:VERSION,type:"slidechange",index:current,total:slides.length})}
function command(action){if(action==="first")show(0);else if(action==="previous")show(current-1);else if(action==="next")show(current+1);else if(action==="last")show(slides.length-1)}
function setupSlides(){const deck=document.querySelector("main[data-native-deck]");if(!deck)return;slides=[...deck.children].filter(node=>node.matches("section[data-native-slide]"));show(0);listen(window,"keydown",event=>{const target=read(eventTarget,event),key=read(keyValue,event),shift=read(shiftValue,event);if(prevented(event)||interactive(target))return;const backwards=key==="ArrowLeft"||key==="PageUp"||(key===" "&&shift);const forwards=key==="ArrowRight"||key==="PageDown"||(key===" "&&!shift);if(backwards||forwards||key==="Home"||key==="End"){prevent(event);command(key==="Home"?"first":key==="End"?"last":backwards?"previous":"next")}},true)}
function navigationDisposition(event){return read(mouseCtrl,event)===true||read(mouseMeta,event)===true}
function navigationMessage(link,newTab){const message={version:VERSION,type:"navigation",recordId:attribute(link,"data-native-record-id"),href:attribute(link,"data-native-external-url")};if(newTab===true)message.newTab=true;return message}
listen(window,"click",event=>{if(!trusted(event)||prevented(event))return;const target=read(eventTarget,event),link=isElement(target)?closest(target,"[data-native-record-id],[data-native-external-url]"):null;if(!link)return;prevent(event);send(navigationMessage(link,navigationDisposition(event)))},true);
listen(window,"auxclick",event=>{if(!trusted(event)||prevented(event))return;if(read(mouseButton,event)!==1)return;const target=read(eventTarget,event),link=isElement(target)?closest(target,"[data-native-record-id],[data-native-external-url]"):null;if(!link)return;prevent(event);send(navigationMessage(link,true))},true);
function receive(event){const data=read(messageData,event),ports=read(messagePorts,event);if(initialized||read(messageSource,event)!==parent||read(messageOrigin,event)!==HOST||data?.type!=="native-html-init"||data?.version!==VERSION||ports.length!==1)return;stop(event);initialized=true;unlisten(window,"message",receive,true);channel=ports[0];listen(channel,"messageerror",disposeKit);listen(channel,"close",disposeKit);listen(channel,"message",message=>{const commandData=read(messageData,message);if(bodyLane.receive(commandData,read(messagePorts,message)))return;if(commandData?.version!==VERSION)return;if(commandData?.type==="native.skin")receiveSkin(commandData);else if(commandData?.type==="command"&&["first","previous","next","last"].includes(commandData.action))command(commandData.action);else if(commandData?.type==="input")deliverInput(commandData);else if(commandData?.type==="body-attempt-result")settleBodyAttempt(commandData);else if(commandData?.type==="intent-result")settleIntent(commandData);else if(commandData?.type==="read-result")settleRead(commandData);else if(commandData?.type==="call-result")settleCall(commandData);else if(commandData?.type==="session-opened"||commandData?.type==="session-refused")settleSession(commandData,read(messagePorts,message));else if(commandData?.type==="query-result")settleQuery(commandData);else if(commandData?.type==="subscription-result"||commandData?.type==="subscription-error")receiveSubscription(commandData);else if(commandData?.type==="agents-list-result")settleAgentList(commandData);else if(commandData?.type==="agents-ask-result")settleAsk(commandData);else if(commandData?.type==="agents-status")deliverAgentStatus(commandData);else if(commandData?.type==="agent-sessions-list-result")settleAgentSessionsList(commandData);else if(commandData?.type==="agent-sessions-follow-result")settleAgentSessionsFollow(commandData);else if(commandData?.type==="agent-sessions-send-result")settleAgentSessionsSend(commandData);else if(commandData?.type==="agent-sessions-choose-folder-result")settleAgentSessionsChooseFolder(commandData);else if(commandData?.type==="agent-sessions-catalog-result")settleAgentSessionsCatalog(commandData);else if(commandData?.type==="agent-sessions-create-result")settleAgentSessionsCreate(commandData);else if(commandData?.type==="agent-sessions-create-status-result"||commandData?.type==="agent-sessions-cancel-result")settleAgentSessionsStartControl(commandData);else if(commandData?.type==="agent-sessions-save-result"||commandData?.type==="agent-sessions-stop-saving-result"||commandData?.type==="agent-sessions-save-status-result"||commandData?.type==="agent-sessions-preview-saved-result")settleAgentSessionsSaved(commandData);else if(commandData?.type==="agent-sessions-mark-read-result")settleAgentSessionsMarkRead(commandData);else if(commandData?.type==="agent-sessions-followup-status-result"||commandData?.type==="agent-sessions-followup-continue-result"||commandData?.type==="agent-sessions-followup-settings-get-result"||commandData?.type==="agent-sessions-followup-settings-set-result")settleAgentSessionsFollowup(commandData);else if(commandData?.type==="agent-sessions-watch-list-result")settleAgentSessionsWatchList(commandData);else if(commandData?.type==="agent-sessions-open-in-paseo-result"||commandData?.type==="agent-sessions-open-conversation-result"||commandData?.type==="agent-sessions-get-permission-form-result"||commandData?.type==="agent-sessions-respond-to-permission-result")settleAgentSessionsPermission(commandData);else if(commandData?.type==="agent-sessions-list-changed")deliverAgentSessionListChanged(commandData);else if(commandData?.type==="agent-sessions-list-watch-ended")deliverAgentSessionListWatchEnded(commandData);else if(commandData?.type==="agent-sessions-event")deliverAgentSessionEvent(commandData);else if(commandData?.type==="intent-arm-ack")settleArmAck(commandData);else if(commandData?.type==="intent-arm-result")settleArmResult(commandData);else if(commandData?.type==="presentation-result")settlePresentation(commandData);else if(commandData?.type==="reveal")deliverReveal(commandData);else if(commandData?.type==="reveal-clear")pendingReveal=null;else if(commandData?.type==="context-request"||commandData?.type==="context-cancel")receiveContext(commandData)});start(channel);listen(channel,"messageerror",closeSkin);listen(channel,"close",closeSkin);listen(window,"pagehide",closeSkin,true);listen(channel,"messageerror",closeBodyAttempts);listen(channel,"close",closeBodyAttempts);listen(window,"pagehide",closeBodyAttempts,true);listen(channel,"messageerror",closeCalls);listen(channel,"close",closeCalls);listen(window,"pagehide",closeCalls,true);listen(channel,"messageerror",closeSessions);listen(channel,"close",closeSessions);listen(window,"pagehide",closeSessions,true);listen(channel,"messageerror",closeSubscriptions);listen(channel,"close",closeSubscriptions);listen(window,"pagehide",closeSubscriptions,true);listen(channel,"messageerror",closeAgents);listen(channel,"close",closeAgents);listen(window,"pagehide",closeAgents,true);listen(channel,"messageerror",closeAgentSessions);listen(channel,"close",closeAgentSessions);listen(window,"pagehide",closeAgentSessions,true);listen(channel,"messageerror",closePresentation);listen(channel,"close",closePresentation);listen(window,"pagehide",closePresentation,true);listen(channel,"messageerror",bodyLane.close);listen(channel,"close",bodyLane.close);listen(window,"pagehide",bodyLane.close,true);listen(window,"unload",bodyLane.close,true);listen(channel,"messageerror",clearReveal);listen(channel,"close",clearReveal);listen(channel,"messageerror",closeContext);listen(channel,"close",closeContext);listen(window,"pagehide",event=>{pendingReveal=null;if(trusted(event)&&read(pageTransitionPersisted,event)!==true){closeContext();send({version:VERSION,type:"unloading"})}},true);listen(window,"unload",clearReveal,true);listen(window,"unload",closeContext,true);try{if(isArray(data.needs))for(const need of data.needs)if(intentId(need)&&offeredNeeds.length<32)pushValue(offeredNeeds,need);if(isArray(data.host_features))for(const feature of data.host_features)if(feature==="intent-arm-confirm.v1")armFeature=true;else if(feature===CONTEXT_FEATURE)contextFeature=true;else if(feature===LOCATION_FEATURE)locationFeature=true;else if(feature===UNSAVED_FEATURE)unsavedFeature=true;else if(feature===CALL_FEATURE)callFeature=true;else if(feature===SESSION_FEATURE)sessionFeature=true;else if(feature===SUBSCRIBE_FEATURE)subscribeFeature=true;else if(feature===AGENTS_FEATURE)agentsFeature=true;else if(feature===AGENT_SESSIONS_FEATURE)agentSessionsFeature=true;else if(feature===AGENT_SESSIONS_CREATE_FEATURE)agentSessionsCreateFeature=true;else if(feature===AGENT_SESSIONS_ADOPTED_FEATURE)agentSessionsAdoptedFeature=true;else if(feature===AGENT_SESSIONS_SAVED_FEATURE)agentSessionsSavedFeature=true;else if(feature===AGENT_SESSIONS_FOLLOWUP_FEATURE)agentSessionsFollowupFeature=true;else if(feature===AGENT_SESSIONS_OPEN_CONVERSATION_FEATURE)agentSessionsOpenConversationFeature=true;else if(feature===COMMENT_FRAME_FEATURE)commentFrameFeature=true;else if(feature===PRESENTATION_FEATURE)presentationFeature=true;else if(feature===SKIN_FEATURE)skinFeature=true;if(callFeature||sessionFeature||subscribeFeature||agentsFeature||agentSessionsFeature||presentationFeature||skinFeature)exposeNative();if(isArray(data.host_features)&&apply(arrayIncludes,data.host_features,[BODY_ATTEMPT_FEATURE])&&bodyAttemptId(data.body_attempt?.generation))bodyAttemptGeneration=data.body_attempt.generation;initializeBody(data);receiveSkin({skin_version:SKIN_SCHEMA,revision:data.skin_revision??0,skin:data.skin??null});const input=freeze(data.input);heldInput=input;if(typeof data.input_digest==="string")heldDigest=data.input_digest;const initRevision=data.revision;if(initRevision&&typeof initRevision==="object"&&typeof initRevision.content_event_seq==="number")heldSeq=initRevision.content_event_seq;const incomingViewState=data.view_state;if(incomingViewState&&typeof incomingViewState==="object"&&!isArray(incomingViewState)&&"value"in incomingViewState){const envelope={value:incomingViewState.value};if(incomingViewState.schema!==undefined)envelope.schema=incomingViewState.schema;if(incomingViewState.from_body_digest!==undefined)envelope.from_body_digest=incomingViewState.from_body_digest;heldViewState=freeze(envelope)}const finish=()=>{skinParsed=true;paintSkin();setupSlides();resolveReady(heldViewState===undefined?freezeObject({input}):freezeObject({input,viewState:heldViewState}));send({version:VERSION,type:"ready",profile:slides.length?"slides":"document",slides:slides.length,features:[REVEAL_FEATURE,...(contextFeature?[CONTEXT_FEATURE]:[]),...(locationFeature?[LOCATION_FEATURE]:[]),...(unsavedFeature?[UNSAVED_FEATURE]:[]),...(bodyLane.api.offering?["records.body.read.v1"]:[]),...(skinFeature?[SKIN_FEATURE]:[])]});publishContextRegistration();for(const item of queued)post(channel,item);queued=[]};if(skinFeature&&skinDOM?.loading())listen(document,"DOMContentLoaded",finish,{once:true});else finish()}catch(error){disposeKit();rejectReady(error);report("html_delivery_failed",{message:bounded(error)})}}
listen(window,"message",receive,true);
const hostPost=parent.postMessage;apply(hostPost,parent,[{type:"native-html-bootstrap",version:VERSION,features:[CONTEXT_FEATURE,"records.body.read.v1",SKIN_FEATURE]},HOST]);
})();
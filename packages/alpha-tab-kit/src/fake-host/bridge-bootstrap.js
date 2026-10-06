(()=>{"use strict";
const HOST=__NATIVE_WORKBENCH_ORIGIN__, VERSION="native.html.bridge.v1";
const apply=Reflect.apply,own=Object.getOwnPropertyDescriptor,parentOf=Object.getPrototypeOf,define=Object.defineProperty,freezeObject=Object.freeze,objectKeys=Object.keys,isFrozen=Object.isFrozen,NativeString=String,arrayPush=Array.prototype.push,arrayIndexOf=Array.prototype.indexOf,arraySplice=Array.prototype.splice,arrayIncludes=Array.prototype.includes;
const getter=(proto,name)=>{for(let current=proto;current;current=parentOf(current)){const descriptor=own(current,name);if(descriptor?.get)return descriptor.get}};
const read=(nativeGetter,value)=>apply(nativeGetter,value,[]),eventAdd=EventTarget.prototype.addEventListener,eventRemove=EventTarget.prototype.removeEventListener,eventPrevent=Event.prototype.preventDefault,eventStop=Event.prototype.stopImmediatePropagation,portPost=MessagePort.prototype.postMessage,portStart=MessagePort.prototype.start,elementClosest=Element.prototype.closest,elementAttribute=Element.prototype.getAttribute;
const pristineEvent=new Event("native-html-bootstrap"),messageData=getter(MessageEvent.prototype,"data"),messageSource=getter(MessageEvent.prototype,"source"),messageOrigin=getter(MessageEvent.prototype,"origin"),messagePorts=getter(MessageEvent.prototype,"ports"),eventTarget=getter(Event.prototype,"target"),eventTrusted=own(pristineEvent,"isTrusted")?.get||getter(Event.prototype,"isTrusted"),eventPrevented=getter(Event.prototype,"defaultPrevented"),nodeType=getter(Node.prototype,"nodeType"),keyValue=getter(KeyboardEvent.prototype,"key"),shiftValue=getter(KeyboardEvent.prototype,"shiftKey"),mouseCtrl=getter(MouseEvent.prototype,"ctrlKey"),mouseMeta=getter(MouseEvent.prototype,"metaKey"),mouseButton=getter(MouseEvent.prototype,"button"),pageTransitionPersisted=getter(PageTransitionEvent.prototype,"persisted"),eventType=getter(Event.prototype,"type"),keyRepeat=getter(KeyboardEvent.prototype,"repeat");
const listen=(target,type,listener,options)=>apply(eventAdd,target,[type,listener,options]),unlisten=(target,type,listener,options)=>apply(eventRemove,target,[type,listener,options]),prevent=event=>apply(eventPrevent,event,[]),stop=event=>apply(eventStop,event,[]),post=(port,value,transfer)=>apply(portPost,port,transfer?[value,transfer]:[value]),start=port=>apply(portStart,port,[]),isElement=value=>!!value&&read(nodeType,value)===1,attribute=(element,name)=>apply(elementAttribute,element,[name]),closest=(element,selector)=>apply(elementClosest,element,[selector]),trusted=event=>!!eventTrusted&&read(eventTrusted,event)===true,prevented=event=>!!eventPrevented&&read(eventPrevented,event)===true;
let channel=null, initialized=false, current=0, slides=[], queued=[], heldInput, heldSeq=null, heldDigest, heldViewState, inputSubscribers=[];
let resolveReady, rejectReady;
const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject});
const jsonStringify=JSON.stringify,jsonParse=JSON.parse,isArray=Array.isArray,NativePromise=Promise,pendingIntents=Object.create(null);let pendingIntentCount=0;
let armFeature=false,pendingArm=null,armTimer=null;
const LOCATION_FEATURE="surface.location.v1",locationPattern=/^[A-Za-z0-9._:-]{1,128}(?![\s\S])/,locationTest=RegExp.prototype.test;
let locationFeature=false;
const publishLocation=recordId=>{if(contextClosed)throw new TypeError("location observation unavailable");if(recordId!==null&&(typeof recordId!=="string"||!apply(locationTest,locationPattern,[recordId])))throw new TypeError("invalid record location");if(locationFeature)send({type:"location",version:VERSION,location_version:LOCATION_FEATURE,record_id:recordId})};
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
 pending.timer=setTimer(()=>{if(bodyAttemptPending[request_id]!==pending)return;delete bodyAttemptPending[request_id];resolve(type==="body-attempt-submit"?bodyAttemptUncertain():bodyAttemptRefused("prepare_timeout"))},15000);
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
define(window,"nativeArtifact",{value:freezeObject({ready,propose,arm,bodyAttempt:bodyAttemptApi,publishLocation,read:readNeed,body:bodyLane.api,onInput,onReveal,setViewState,registerContextReporter,get input(){return heldInput},get inputDelivery(){return freezeObject({basis:"delivery_only",digest:typeof heldDigest==="string"?heldDigest:null,deliverySeq:contextInteger(heldSeq)&&heldSeq>=0?heldSeq:null})},get viewState(){return heldViewState}}),writable:false,configurable:false});
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
function receive(event){const data=read(messageData,event),ports=read(messagePorts,event);if(initialized||read(messageSource,event)!==parent||read(messageOrigin,event)!==HOST||data?.type!=="native-html-init"||data?.version!==VERSION||ports.length!==1)return;stop(event);initialized=true;unlisten(window,"message",receive,true);channel=ports[0];listen(channel,"message",message=>{const commandData=read(messageData,message);if(bodyLane.receive(commandData,read(messagePorts,message)))return;if(commandData?.version!==VERSION)return;if(commandData?.type==="command"&&["first","previous","next","last"].includes(commandData.action))command(commandData.action);else if(commandData?.type==="input")deliverInput(commandData);else if(commandData?.type==="body-attempt-result")settleBodyAttempt(commandData);else if(commandData?.type==="intent-result")settleIntent(commandData);else if(commandData?.type==="read-result")settleRead(commandData);else if(commandData?.type==="intent-arm-ack")settleArmAck(commandData);else if(commandData?.type==="intent-arm-result")settleArmResult(commandData);else if(commandData?.type==="reveal")deliverReveal(commandData);else if(commandData?.type==="reveal-clear")pendingReveal=null;else if(commandData?.type==="context-request"||commandData?.type==="context-cancel")receiveContext(commandData)});start(channel);listen(channel,"messageerror",closeBodyAttempts);listen(channel,"close",closeBodyAttempts);listen(window,"pagehide",closeBodyAttempts,true);listen(channel,"messageerror",bodyLane.close);listen(channel,"close",bodyLane.close);listen(window,"pagehide",bodyLane.close,true);listen(window,"unload",bodyLane.close,true);listen(channel,"messageerror",clearReveal);listen(channel,"close",clearReveal);listen(channel,"messageerror",closeContext);listen(channel,"close",closeContext);listen(window,"pagehide",event=>{pendingReveal=null;if(trusted(event)&&read(pageTransitionPersisted,event)!==true){closeContext();send({version:VERSION,type:"unloading"})}},true);listen(window,"unload",clearReveal,true);listen(window,"unload",closeContext,true);try{if(isArray(data.needs))for(const need of data.needs)if(intentId(need)&&offeredNeeds.length<32)pushValue(offeredNeeds,need);if(isArray(data.host_features))for(const feature of data.host_features)if(feature==="intent-arm-confirm.v1")armFeature=true;else if(feature===CONTEXT_FEATURE)contextFeature=true;else if(feature===LOCATION_FEATURE)locationFeature=true;if(isArray(data.host_features)&&apply(arrayIncludes,data.host_features,[BODY_ATTEMPT_FEATURE])&&bodyAttemptId(data.body_attempt?.generation))bodyAttemptGeneration=data.body_attempt.generation;initializeBody(data);const input=freeze(data.input);heldInput=input;if(typeof data.input_digest==="string")heldDigest=data.input_digest;const initRevision=data.revision;if(initRevision&&typeof initRevision==="object"&&typeof initRevision.content_event_seq==="number")heldSeq=initRevision.content_event_seq;const incomingViewState=data.view_state;if(incomingViewState&&typeof incomingViewState==="object"&&!isArray(incomingViewState)&&"value"in incomingViewState){const envelope={value:incomingViewState.value};if(incomingViewState.schema!==undefined)envelope.schema=incomingViewState.schema;if(incomingViewState.from_body_digest!==undefined)envelope.from_body_digest=incomingViewState.from_body_digest;heldViewState=freeze(envelope)}setupSlides();resolveReady(heldViewState===undefined?freezeObject({input}):freezeObject({input,viewState:heldViewState}));send({version:VERSION,type:"ready",profile:slides.length?"slides":"document",slides:slides.length,features:[REVEAL_FEATURE,...(contextFeature?[CONTEXT_FEATURE]:[]),...(locationFeature?[LOCATION_FEATURE]:[]),...(bodyLane.api.offering?["records.body.read.v1"]:[])]});publishContextRegistration();for(const item of queued)post(channel,item);queued=[]}catch(error){rejectReady(error);report("html_delivery_failed",{message:bounded(error)})}}
listen(window,"message",receive,true);
const hostPost=parent.postMessage;apply(hostPost,parent,[{type:"native-html-bootstrap",version:VERSION,features:[CONTEXT_FEATURE,"records.body.read.v1"]},HOST]);
})();
//! `native.html.v1`: prospective source policy, isolated delivery, and the
//! adapter-owned browser bootstrap.
//!
//! Canonical source stays in the record body. Everything in this module is a
//! disposable derivative: validation manifests, launch tickets, injected
//! bytes, and browser evidence are deliberately absent from SQLite/export.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, PRAGMA,
    REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{uri::Authority, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use html5ever::driver::ParseOpts;
use html5ever::interface::QuirksMode;
use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use percent_encoding::percent_decode_str;
use rand::RngCore;
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{Error, Result};

pub const RUNTIME_ID: &str = "native.html.v1";
pub const ADAPTER_REVISION: u64 = 4;
pub const BRIDGE_VERSION: &str = "native.html.bridge.v1";
/// The static declaration contract embedded in an authored HTML document.
///
/// HTML intentionally does not grow a JavaScript module/import surface. A
/// declaration is inert JSON in one well-known element and is parsed before
/// delivery; the host later turns the same values into the shared named-input
/// envelopes used by native.mdx.v2.
pub const MANIFEST_SCHEMA: &str = "native.html.artifact.v1";
pub const INTERACTIVE_MANIFEST_SCHEMA: &str = "native.html.artifact.v2";
pub const NAMED_INPUT_ABI: &str = "native.named-artifact-input.v1";
pub const COLLECTION_ENVELOPE: &str = "native.collection-envelope.v1";
pub const GROUPED_COUNT_ENVELOPE: &str = "native.grouped-count-envelope.v1";
pub const RELATION_ENVELOPE: &str = "native.relation-envelope.v1";
pub const ARTIFACT_RECORD_SCHEMA: &str = "native.artifact-record.v1";
/// Integer bounds preserved exactly by JSON parse and MessagePort delivery in
/// the production browser bridge. Named HTML inputs outside this range fail
/// closed before hashing or delivery.
pub const NAMED_INPUT_SAFE_INTEGER_MIN: i64 = -9_007_199_254_740_991;
pub const NAMED_INPUT_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
pub const BODY_LIMIT: usize = 524_288;
/// Body limit for installed app package bundles only: a record carrying the
/// package marker facet (see `artifacts::PACKAGE_FACET`). Every other
/// `native.html.v1` body stays at [`BODY_LIMIT`].
pub const PACKAGE_BODY_LIMIT: usize = 1_048_576;
/// The package marker: a `native.html.v1` record is an app package bundle, and
/// so allowed [`PACKAGE_BODY_LIMIT`], only when it carries this facet with
/// exactly this value. The kit's install plan sets it on the bundle record's
/// create; nothing else grants the larger limit.
pub const PACKAGE_FACET_KEY: &str = "app_package";
pub const PACKAGE_FACET_VALUE: &str = "true";

/// The body limit for a record whose [`PACKAGE_FACET_KEY`] facet value is
/// `marker` (`None` when it has no such facet).
pub fn body_limit_for_package_marker(marker: Option<&str>) -> usize {
    if marker == Some(PACKAGE_FACET_VALUE) {
        PACKAGE_BODY_LIMIT
    } else {
        BODY_LIMIT
    }
}
pub const DATA_ASSET_EACH_LIMIT: usize = 262_144;
pub const DATA_ASSET_TOTAL_LIMIT: usize = 393_216;
pub const DOM_NODE_LIMIT: usize = 10_000;
pub const CSS_RULE_LIMIT: usize = 5_000;
pub const SLIDE_LIMIT: usize = 200;
/// Workspace metadata can exceed 4 MiB before 5,000 records. Allow practical
/// growth without narrowing a bound Collection's authorized membership. These
/// are per-render budgets; launch/harness ticket stores retain aggregate caps.
pub const INPUT_RECORD_LIMIT: usize = 20_000;
pub const INPUT_JSON_LIMIT: usize = 16 * 1024 * 1024;
pub const BRIDGE_MESSAGE_LIMIT: usize = INPUT_JSON_LIMIT;
pub const TICKET_TTL: Duration = Duration::from_secs(30);
const LAUNCH_TICKET_MAX_COUNT: usize = 128;
const LAUNCH_TICKET_MAX_PER_PRINCIPAL: usize = 32;
const LAUNCH_TICKET_MAX_BYTES: usize = 64 * 1024 * 1024;
const HARNESS_TICKET_MAX_COUNT: usize = 32;
const HARNESS_TICKET_MAX_PER_PRINCIPAL: usize = 8;
const HARNESS_TICKET_MAX_BYTES: usize = 128 * 1024 * 1024;

const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=(), display-capture=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), clipboard-read=(), clipboard-write=(), web-share=(), local-fonts=(), idle-detection=(), screen-wake-lock=(), gamepad=(), accelerometer=(), gyroscope=(), magnetometer=(), ambient-light-sensor=(), publickey-credentials-get=(), screen-orientation=(), pointer-lock=(), presentation=(), fullscreen=()";

/// Installed immediately after the authored `<head>` start tag. The private
/// MessagePort is delivered only to this capture listener; authored scripts
/// cannot fabricate host navigation/slide messages by posting at the parent.
const BOOTSTRAP: &str = r#"(()=>{"use strict";
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
})();"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub workbench_origin: String,
    pub artifact_origin: String,
    additional_parent_origins: Vec<String>,
}

impl RuntimeConfig {
    pub fn new(
        workbench_origin: impl Into<String>,
        artifact_origin: impl Into<String>,
    ) -> Result<Self> {
        let workbench_origin = exact_origin(&workbench_origin.into(), "workbench origin")?;
        let artifact_origin = exact_origin(&artifact_origin.into(), "artifact origin")?;
        if workbench_origin == artifact_origin {
            return Err(Error::engine(
                "native.html.v1 requires a distinct artifact origin",
            ));
        }
        Ok(Self {
            workbench_origin,
            artifact_origin,
            additional_parent_origins: Vec::new(),
        })
    }

    pub fn with_parent_origins(
        mut self,
        origins: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self> {
        for raw in origins {
            let raw = raw.as_ref();
            let canonical = Self::exact_parent_origin(raw)?;
            if canonical == self.artifact_origin {
                return Err(Error::engine(
                    "parent origin must not equal artifact origin",
                ));
            }
            if canonical == self.workbench_origin {
                continue;
            }
            if !self.additional_parent_origins.contains(&canonical) {
                self.additional_parent_origins.push(canonical);
            }
        }
        Ok(self)
    }

    pub fn resolve_parent_origin(&self, requested: Option<&str>) -> Result<String> {
        let Some(raw) = requested else {
            if self.workbench_origin == self.artifact_origin {
                return Err(Error::engine(
                    "parent origin must not equal artifact origin",
                ));
            }
            return Ok(self.workbench_origin.clone());
        };
        let canonical = Self::exact_parent_origin(raw)?;
        if canonical == self.artifact_origin {
            return Err(Error::engine(
                "parent origin must not equal artifact origin",
            ));
        }
        if canonical == self.workbench_origin || self.additional_parent_origins.contains(&canonical)
        {
            return Ok(canonical);
        }
        Err(Error::engine("parent origin is not allowlisted"))
    }

    /// Canonicalize an artifact parent, preserving the desktop's literal origin.
    /// Public and artifact server origins still use the HTTP(S)-only parser.
    pub fn exact_parent_origin(raw: &str) -> Result<String> {
        if raw == "native-ui://app" {
            return Ok(raw.to_owned());
        }
        if raw.trim() != raw || raw.chars().any(char::is_control) || raw.contains('*') {
            return Err(Error::engine(
                "parent origin must be exact, without whitespace, controls or wildcards",
            ));
        }
        // URL parsing normalizes dot paths and backslashes. Check the raw
        // authority too, so those spellings cannot masquerade as exact origins.
        let authority = raw
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or_else(|| Error::engine("parent origin must contain a scheme and authority"))?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.contains(['/', '\\', '@', '?', '#']) {
            return Err(Error::engine(
                "parent origin must contain only an authority",
            ));
        }
        let canonical = exact_origin(raw, "parent origin")?;
        if canonical.contains('*') {
            return Err(Error::engine("parent origin must not contain '*'"));
        }
        Self::check_parent_scheme(&canonical)?;
        Ok(canonical)
    }

    fn check_parent_scheme(canonical: &str) -> Result<()> {
        let parsed = Url::parse(canonical).map_err(|_| Error::engine("invalid parent origin"))?;
        if parsed.scheme() == "https" {
            return Ok(());
        }
        let host = parsed.host_str().unwrap_or("");
        // Keep this identical to the serving binary's public-origin rule.
        // Url::host_str retains brackets around IPv6 addresses.
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
            || host.ends_with(".localhost");
        if parsed.scheme() == "http" && loopback {
            return Ok(());
        }
        Err(Error::engine(
            "parent origin must be HTTPS (HTTP allowed only on loopback)",
        ))
    }
}

fn exact_origin(raw: &str, label: &str) -> Result<String> {
    let parsed = Url::parse(raw).map_err(|_| Error::engine(format!("invalid {label}: {raw}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::engine(format!(
            "{label} must be an exact http(s) origin"
        )));
    }
    Ok(parsed.origin().ascii_serialization())
}

/// Parse exactly one HTTP Host header into a canonical DNS/IP host and an
/// effective port for the configured scheme. DNS names compare case-
/// insensitively; explicit default ports and omitted default ports are equal.
pub fn normalized_request_host(headers: &HeaderMap, scheme: &str) -> Option<(String, u16)> {
    let mut values = headers.get_all(HOST).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() || raw.contains('@') || raw.trim() != raw {
        return None;
    }
    let authority = Authority::from_str(raw).ok()?;
    let host = normalize_host(authority.host())?;
    let port = authority.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    Some((host, port))
}

fn normalize_host(host: &str) -> Option<String> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = IpAddr::from_str(unbracketed) {
        return Some(address.to_string());
    }
    Some(
        url::Host::parse(unbracketed)
            .ok()?
            .to_string()
            .to_ascii_lowercase(),
    )
}

pub fn host_matches_origin(headers: &HeaderMap, origin: &str) -> bool {
    let Ok(origin) = Url::parse(origin) else {
        return false;
    };
    let Some(expected_host) = origin.host_str() else {
        return false;
    };
    let Some(expected_port) = origin.port_or_known_default() else {
        return false;
    };
    let Some(expected_host) = normalize_host(expected_host) else {
        return false;
    };
    normalized_request_host(headers, origin.scheme())
        .is_some_and(|(host, port)| host == expected_host && port == expected_port)
}

fn config_slot() -> &'static RwLock<Option<RuntimeConfig>> {
    static CONFIG: OnceLock<RwLock<Option<RuntimeConfig>>> = OnceLock::new();
    CONFIG.get_or_init(|| RwLock::new(None))
}

pub fn configure(config: RuntimeConfig) {
    *config_slot().write().expect("HTML runtime config poisoned") = Some(config);
}

pub fn configuration() -> Option<RuntimeConfig> {
    config_slot()
        .read()
        .expect("HTML runtime config poisoned")
        .clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Document,
    Slides,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Slides => "slides",
        }
    }
}

pub const KIT_POLICY_SCHEMA: &str = "native.app-kit.v1";
pub const KIT_MAJOR_MAX: u32 = 65535;
pub const KIT_POLICY_JSON_LIMIT: usize = 1024;

/// Author-owned compatibility policy; resolved host releases are not consent pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KitPolicy {
    pub schema: String,
    pub major: u32,
}

fn parse_kit_policy(
    values: &[String],
) -> std::result::Result<Option<KitPolicy>, ValidationFailure> {
    if values.is_empty() {
        return Ok(None);
    }
    let invalid = |rule, message| {
        ValidationFailure::new(
            "html_invalid_kit_policy",
            message,
            json!({"phase":"validation","rule":rule}),
        )
    };
    if values.len() != 1 {
        return Err(invalid(
            "kit-policy-count",
            "native-app-kit must occur exactly once",
        ));
    }
    if values[0].len() > KIT_POLICY_JSON_LIMIT {
        return Err(invalid(
            "kit-policy-size",
            "native-app-kit JSON exceeds 1024 bytes",
        ));
    }
    let value: Value = serde_json::from_str(&values[0])
        .map_err(|_| invalid("kit-policy-json", "native-app-kit must contain valid JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("kit-policy-shape", "native-app-kit must be an object"))?;
    if object.len() != 2 || !object.contains_key("schema") || !object.contains_key("major") {
        return Err(invalid(
            "kit-policy-fields",
            "native-app-kit requires only schema and major",
        ));
    }
    if object["schema"].as_str() != Some(KIT_POLICY_SCHEMA) {
        return Err(invalid(
            "kit-policy-schema",
            "native-app-kit schema must be native.app-kit.v1",
        ));
    }
    // JSON numeric integers, including 1.0 and 1e0, agree with Number.isInteger in JS.
    let major = object["major"]
        .as_f64()
        .filter(|n| *n >= 1.0 && *n <= f64::from(KIT_MAJOR_MAX) && n.fract() == 0.0)
        .ok_or_else(|| {
            invalid(
                "kit-policy-major",
                "native-app-kit major must be an integer from 1 to 65535",
            )
        })?;
    Ok(Some(KitPolicy {
        schema: KIT_POLICY_SCHEMA.into(),
        major: major as u32,
    }))
}

#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kit_policy: Option<KitPolicy>,
    pub profile: Profile,
    pub body_digest: String,
    pub body_utf8_bytes: usize,
    pub static_dom_nodes: usize,
    pub css_rules: usize,
    pub data_asset_decoded_bytes_total: usize,
    pub slides: usize,
    /// Port declarations decoded from the inert HTML declaration surface.
    /// Empty means this is a legacy HTML artifact and keeps the historical
    /// zero/one `renders` input path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub artifact_ports: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_requests: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactions: Vec<native_artifact_runtime::mdx_v2::InteractionEntry>,
    /// True when the author supplied the declaration surface, including an
    /// explicitly empty manifest. It is intentionally omitted from the
    /// serialized validation manifest because it is an implementation detail,
    /// not source data.
    #[serde(skip)]
    pub named_inputs_declared: bool,
    /// Tier 1 write-path script diagnostics: undefined identifiers, unknown
    /// interaction entry ids, and unknown input port reads. Always warnings;
    /// an empty list is the ordinary state and is omitted from serialization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<crate::write_diagnostics::WriteDiagnostic>,
}

impl Manifest {
    /// Check availability against the admitted production default, separately from author validation.
    pub fn require_available_kit(&self) -> std::result::Result<(), ValidationFailure> {
        if let Some(policy) = &self.kit_policy {
            if !KitDelivery::default().selected_major(policy.major) {
                return Err(kit_delivery::unavailable(policy.major));
            }
        }
        Ok(())
    }

    /// The shared, runtime-neutral host interaction declaration. HTML has no
    /// module graph; its input ports and entries use the same executor schema.
    pub fn interaction_manifest(&self) -> native_artifact_runtime::mdx_v2::ArtifactManifest {
        native_artifact_runtime::mdx_v2::ArtifactManifest {
            schema: INTERACTIVE_MANIFEST_SCHEMA.into(),
            inputs: self
                .artifact_ports
                .iter()
                .map(|(port, declaration)| {
                    (
                        port.clone(),
                        serde_json::from_value(declaration.clone())
                            .expect("validated HTML input declaration"),
                    )
                })
                .collect(),
            module_inputs: BTreeMap::new(),
            capability_requests: self
                .capability_requests
                .iter()
                .map(|request| {
                    serde_json::from_value(request.clone())
                        .expect("validated HTML capability request")
                })
                .collect(),
            interactions: self.interactions.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidationFailure {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}

impl ValidationFailure {
    fn new(code: &'static str, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            message: message.into(),
            details,
        }
    }
}

#[derive(Default)]
struct Inspection {
    nodes: usize,
    html: usize,
    head: usize,
    body: usize,
    title: Vec<String>,
    lang: bool,
    charset: bool,
    viewport: bool,
    profile: Option<String>,
    mains: usize,
    h1: usize,
    headings: Vec<(u8, String)>,
    css: Vec<String>,
    assets: Vec<String>,
    deck_slides: Vec<(String, String, bool)>,
    deck_count: usize,
    declaration_values: Vec<String>,
    kit_policy_values: Vec<String>,
    /// Element `id` values that are valid JavaScript identifiers. Browsers
    /// expose these as named globals on `window`, so an authored script may
    /// reference them without declaring them.
    element_ids: Vec<String>,
    /// Every inline `<script>` in document order, JS or not, so the raw-source
    /// scan can pair bodies by index and recover the body offset each script
    /// parsed at. Non-JS bodies are recorded but never analyzed.
    scripts: Vec<crate::write_diagnostics::ScriptElement>,
    /// Elements seen so far per lower-case tag name, so a finding can name
    /// which occurrence of its element it came from.
    tag_counts: HashMap<String, usize>,
    /// Every rejection found by the walk, in document order. The walk records
    /// rather than returns so that one write reports all of them.
    violations: Vec<Violation>,
    /// Accessibility and layout conventions the source does not meet. These
    /// become located write warnings and never reject a write.
    advisories: Vec<Advisory>,
}

/// An element's lower-case tag name and its zero-based occurrence among
/// elements of that name, in DOM order.
type ElementRef = (String, usize);

struct Violation {
    failure: ValidationFailure,
    element: Option<ElementRef>,
}

impl From<ValidationFailure> for Violation {
    fn from(failure: ValidationFailure) -> Self {
        Self {
            failure,
            element: None,
        }
    }
}

struct Advisory {
    code: &'static str,
    message: String,
    element: Option<ElementRef>,
}

impl Inspection {
    fn violate(&mut self, failure: ValidationFailure, element: &ElementRef) {
        self.violations.push(Violation {
            failure,
            element: Some(element.clone()),
        });
    }

    fn advise(
        &mut self,
        code: &'static str,
        message: impl Into<String>,
        element: Option<ElementRef>,
    ) {
        self.advisories.push(Advisory {
            code,
            message: message.into(),
            element,
        });
    }
}

/// The most rejections one failure lists; the rest are counted, not named.
const VIOLATION_REPORT_LIMIT: usize = 20;
/// The most accessibility warnings one write reports.
const ADVISORY_REPORT_LIMIT: usize = 20;

fn attrs(handle: &Handle) -> BTreeMap<String, String> {
    let NodeData::Element { attrs, .. } = &handle.data else {
        return BTreeMap::new();
    };
    attrs
        .borrow()
        .iter()
        .map(|attr| {
            (
                attr.name.local.to_string().to_ascii_lowercase(),
                attr.value.to_string(),
            )
        })
        .collect()
}

fn text_content(handle: &Handle) -> String {
    let mut out = String::new();
    fn walk(node: &Handle, out: &mut String) {
        if let NodeData::Text { contents } = &node.data {
            out.push_str(&contents.borrow());
        }
        for child in node.children.borrow().iter() {
            walk(child, out);
        }
    }
    walk(handle, &mut out);
    out
}

fn policy(message: impl Into<String>, rule: &str) -> ValidationFailure {
    ValidationFailure::new(
        "html_policy_violation",
        message,
        json!({"phase":"validation","rule":rule}),
    )
}

fn declaration_failure(message: impl Into<String>, rule: &str) -> ValidationFailure {
    ValidationFailure::new(
        "html_named_input_invalid",
        message,
        json!({"phase":"validation","rule":rule}),
    )
}

fn valid_port_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Element `id` values become named properties on `window` in every browser,
/// so only an id that is itself a valid JavaScript identifier can be read as a
/// bare identifier.
fn valid_js_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_' || first == b'$')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_semantic_dependency(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "identity" | "semantic_version"))
        || object.len() != 2
    {
        return false;
    }
    let identity = object.get("identity").and_then(Value::as_str);
    let semantic_version = object.get("semantic_version").and_then(|value| {
        value.as_u64().or_else(|| {
            value.as_f64().and_then(|value| {
                (value.is_finite() && value.fract() == 0.0 && value >= 0.0).then_some(value as u64)
            })
        })
    });
    identity.is_some_and(|identity| {
        !identity.is_empty() && identity.len() <= 256 && !identity.chars().any(char::is_control)
    }) && semantic_version.is_some_and(|version| version > 0 && version <= u32::MAX as u64)
}

fn valid_projection(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.keys().any(|key| key != "kind" && key != "axis")
        || object.get("kind").and_then(Value::as_str) != Some("grouped_count")
    {
        return false;
    }
    let Some(axis) = object.get("axis").and_then(Value::as_object) else {
        return false;
    };
    match axis.get("kind").and_then(Value::as_str) {
        Some("record_field") => {
            axis.len() == 2 && axis.get("field").and_then(Value::as_str) == Some("kind")
        }
        Some("facet") => {
            axis.len() == 2
                && axis.get("key").and_then(Value::as_str).is_some_and(|key| {
                    !key.trim().is_empty() && key.len() <= 128 && !key.chars().any(char::is_control)
                })
        }
        _ => false,
    }
}

/// Validate one declaration using the same closed shape as `mdx_v2::InputDecl`.
/// Keeping this parser storage-independent avoids making the HTML adapter
/// depend on the compiler crate, while the host can deserialize the resulting
/// JSON into the shared typed declaration before it resolves any input.
fn valid_input_declaration(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "envelope"
                | "required"
                | "expose_to_root"
                | "projection"
                | "schema_sha256"
                | "relations"
        )
    }) {
        return false;
    }
    if object.get("envelope").and_then(Value::as_str).is_none()
        || object.get("required").and_then(Value::as_bool).is_none()
    {
        return false;
    }
    let envelope = object
        .get("envelope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let projection = object.get("projection");
    let schema_sha256 = object.get("schema_sha256");
    let relations = object.get("relations");
    let valid_digest = schema_sha256.is_none_or(|value| value.as_str().is_some_and(valid_sha256));
    let valid_relations = relations.is_none_or(|value| {
        let Some(relations) = value.as_object() else {
            return false;
        };
        relations.iter().all(|(name, dependency)| {
            valid_port_name(name) && valid_semantic_dependency(dependency)
        })
    });
    if !valid_digest || !valid_relations {
        return false;
    }
    match envelope {
        COLLECTION_ENVELOPE => {
            projection.is_none() && schema_sha256.is_none() && relations.is_none()
        }
        RELATION_ENVELOPE => {
            projection.is_none()
                && ((schema_sha256.is_none() && relations.is_none()) || schema_sha256.is_some())
        }
        GROUPED_COUNT_ENVELOPE => {
            projection.is_some_and(valid_projection)
                && schema_sha256.is_none()
                && relations.is_none()
        }
        _ => false,
    }
}

type ParsedNamedDeclaration = (
    BTreeMap<String, Value>,
    Vec<Value>,
    Vec<native_artifact_runtime::mdx_v2::InteractionEntry>,
    bool,
);

fn parse_named_declaration(
    values: &[String],
) -> std::result::Result<ParsedNamedDeclaration, ValidationFailure> {
    if values.is_empty() {
        return Ok((BTreeMap::new(), Vec::new(), Vec::new(), false));
    }
    if values.len() != 1 {
        return Err(declaration_failure(
            "HTML may contain exactly one native artifact input declaration",
            "declaration-count",
        ));
    }
    let raw = values.first().expect("checked");
    if raw.len() > INPUT_JSON_LIMIT {
        return Err(ValidationFailure::new(
            "html_named_input_too_large",
            "native HTML input declaration exceeds the serialized limit",
            json!({"phase":"validation","rule":"declaration-size","maximum":INPUT_JSON_LIMIT,"actual":raw.len()}),
        ));
    }
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        declaration_failure(
            format!("native HTML input declaration is not valid JSON: {error}"),
            "declaration-json",
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        declaration_failure(
            "native HTML input declaration must be a JSON object",
            "declaration-shape",
        )
    })?;
    let interactive =
        object.get("schema").and_then(Value::as_str) == Some(INTERACTIVE_MANIFEST_SCHEMA);
    if object.keys().any(|key| {
        !matches!(key.as_str(), "schema" | "inputs" | "capability_requests")
            && !(interactive && key == "interactions")
    }) || object.len() != if interactive { 4 } else { 3 }
    {
        return Err(declaration_failure(
            "native HTML input declaration has unknown or missing fields",
            "declaration-fields",
        ));
    }
    if !interactive && object.get("schema").and_then(Value::as_str) != Some(MANIFEST_SCHEMA) {
        return Err(declaration_failure(
            format!("native HTML input declaration must use schema '{MANIFEST_SCHEMA}'"),
            "declaration-schema",
        ));
    }
    let input_object = object
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            declaration_failure("native HTML inputs must be an object", "inputs-shape")
        })?;
    let mut inputs = BTreeMap::new();
    for (name, declaration) in input_object {
        if name == "default" || !valid_port_name(name) || !valid_input_declaration(declaration) {
            return Err(declaration_failure(
                format!("native HTML input port '{name}' is invalid or reserved"),
                "input-declaration",
            ));
        }
        inputs.insert(name.clone(), declaration.clone());
    }
    let requests = object
        .get("capability_requests")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            declaration_failure(
                "native HTML capability_requests must be an array",
                "capability-shape",
            )
        })?;
    let mut normalized_requests = Vec::with_capacity(requests.len());
    let mut seen = std::collections::BTreeSet::new();
    for request in requests {
        let request_object = request.as_object().ok_or_else(|| {
            declaration_failure(
                "native HTML capability request must be an object",
                "capability",
            )
        })?;
        if request_object
            .keys()
            .any(|key| key != "capability" && key != "scope")
            || request_object.len() != 2
            || request_object.get("capability").and_then(Value::as_str) != Some("input.read")
        {
            return Err(declaration_failure(
                "native HTML supports only input.read capability requests",
                "capability",
            ));
        }
        let scope = request_object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                declaration_failure("input.read scope must be an object", "capability-scope")
            })?;
        let port = scope
            .get("port")
            .and_then(Value::as_str)
            .filter(|port| scope.len() == 1 && inputs.contains_key(*port))
            .ok_or_else(|| {
                declaration_failure(
                    "input.read scope must name exactly one declared input port",
                    "capability-scope",
                )
            })?;
        if !seen.insert(port.to_owned()) {
            return Err(declaration_failure(
                format!("input.read capability for port '{port}' is duplicated"),
                "capability-duplicate",
            ));
        }
        normalized_requests.push(request.clone());
    }
    for (name, declaration) in &inputs {
        let exposed = declaration
            .get("expose_to_root")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !exposed {
            return Err(declaration_failure(
                format!("HTML named input '{name}' must set expose_to_root=true"),
                "capability-exposure",
            ));
        }
        if !seen.contains(name) {
            return Err(declaration_failure(
                format!("root input '{name}' is exposed without an exact input.read request"),
                "capability-exposure",
            ));
        }
    }
    let interactions = if interactive {
        serde_json::from_value(object["interactions"].clone()).map_err(|error| {
            declaration_failure(
                format!("invalid interaction declaration: {error}"),
                "interactions",
            )
        })?
    } else {
        Vec::new()
    };
    let typed_inputs = serde_json::from_value(
        serde_json::to_value(&inputs).expect("inputs serialize"),
    )
    .map_err(|error| declaration_failure(format!("invalid typed inputs: {error}"), "inputs"))?;
    native_artifact_runtime::mdx_v2::validate_interactions(&interactions, &typed_inputs).map_err(
        |failure| ValidationFailure::new(failure.code, failure.message, failure.details),
    )?;
    Ok((inputs, normalized_requests, interactions, true))
}

pub(crate) fn source_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let before = &source[..byte_offset.min(source.len())];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = before.rsplit_once('\n').map_or_else(
        || before.chars().count() + 1,
        |(_, tail)| tail.chars().count() + 1,
    );
    (line, column)
}

/// Byte offsets of authored start tags, grouped by lower-case tag name, in
/// source order. Comments, raw-text element bodies and `<template>` contents
/// (which the parsed DOM keeps outside the walked tree) are skipped, so a
/// lookalike inside them is never counted as an element. The parsed DOM
/// remains the authority for which elements exist: callers use an offset only
/// when the DOM and the source agree on how many elements of that name exist.
fn start_tag_offsets(source: &str) -> HashMap<String, Vec<usize>> {
    let lower = source.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut found: HashMap<String, Vec<usize>> = HashMap::new();
    let mut cursor = 0;
    while let Some(relative) = lower[cursor..].find('<') {
        let start = cursor + relative;
        if lower[start..].starts_with("<!--") {
            cursor = lower[start + 4..]
                .find("-->")
                .map_or(lower.len(), |end| start + 4 + end + 3);
            continue;
        }
        let name_start = start + 1;
        let name_end = bytes[name_start..]
            .iter()
            .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'-')
            .count()
            + name_start;
        let name = &lower[name_start..name_end];
        let Some(end) = tag_end(source, name_end) else {
            break;
        };
        let is_tag = bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic)
            && bytes
                .get(name_end)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/');
        if is_tag {
            found.entry(name.to_owned()).or_default().push(start);
        }
        if is_tag && name == "plaintext" {
            break;
        }
        if is_tag
            && matches!(
                name,
                "script"
                    | "style"
                    | "title"
                    | "textarea"
                    | "noscript"
                    | "xmp"
                    | "noembed"
                    | "noframes"
                    | "iframe"
                    | "template"
            )
        {
            let close = format!("</{name}");
            cursor = lower[end..]
                .find(&close)
                .map_or(lower.len(), |offset| end + offset);
            if cursor == lower.len() {
                break;
            }
            cursor += 2;
            continue;
        }
        cursor = end;
    }
    found
}

/// Where an element's start tag was authored, when the DOM and the source
/// agree on how many elements of that name exist.
fn element_position(
    source: &str,
    offsets: &HashMap<String, Vec<usize>>,
    dom_counts: &HashMap<String, usize>,
    (name, index): &ElementRef,
) -> Option<(usize, usize)> {
    let found = offsets.get(name)?;
    if found.len() != dom_counts.get(name).copied().unwrap_or_default() {
        return None;
    }
    found
        .get(*index)
        .map(|offset| source_position(source, *offset))
}

fn advisory_diagnostics(
    source: &str,
    offsets: &HashMap<String, Vec<usize>>,
    inspection: &Inspection,
) -> Vec<crate::write_diagnostics::WriteDiagnostic> {
    inspection
        .advisories
        .iter()
        .take(ADVISORY_REPORT_LIMIT)
        .map(|advisory| {
            let position = advisory.element.as_ref().and_then(|element| {
                element_position(source, offsets, &inspection.tag_counts, element)
            });
            let mut message = advisory.message.clone();
            if position.is_none() && advisory.element.is_some() {
                message.push_str(" (source position unavailable)");
            }
            let (line, column) = position.unwrap_or((1, 1));
            crate::write_diagnostics::WriteDiagnostic::new(
                advisory.code,
                message,
                None,
                line,
                column,
            )
        })
        .collect()
}

/// Fold every rejection into one failure. A lone rejection is returned as it
/// always was; several are listed in the message, each with its location, and
/// carried structurally under `details.violations`.
fn report_violations(
    source: &str,
    offsets: &HashMap<String, Vec<usize>>,
    dom_counts: &HashMap<String, usize>,
    violations: Vec<Violation>,
) -> ValidationFailure {
    let count = violations.len();
    let mut failures: Vec<ValidationFailure> = violations
        .into_iter()
        .map(|violation| {
            let mut failure = violation.failure;
            let position = violation
                .element
                .as_ref()
                .and_then(|element| element_position(source, offsets, dom_counts, element));
            if let (Some((line, column)), Some(details)) =
                (position, failure.details.as_object_mut())
            {
                details.entry("line").or_insert(json!(line));
                details.entry("column").or_insert(json!(column));
            }
            failure
        })
        .collect();
    if count == 1 {
        return failures.remove(0);
    }
    let listed = failures
        .iter()
        .take(VIOLATION_REPORT_LIMIT)
        .enumerate()
        .map(|(index, failure)| {
            let location = match (
                failure.details.get("line").and_then(Value::as_u64),
                failure.details.get("column").and_then(Value::as_u64),
            ) {
                (Some(line), Some(column)) => format!(" at line {line}, column {column}"),
                _ => String::new(),
            };
            let rule = failure
                .details
                .get("rule")
                .and_then(Value::as_str)
                .unwrap_or(failure.code);
            format!("({}) {}{location} [{rule}]", index + 1, failure.message)
        })
        .collect::<Vec<_>>()
        .join("; ");
    let mut message = format!("{count} problems; fix all of them before resubmitting: {listed}");
    if count > VIOLATION_REPORT_LIMIT {
        message.push_str(&format!("; and {} more", count - VIOLATION_REPORT_LIMIT));
    }
    let first = &failures[0];
    let mut details = first.details.clone();
    if let Some(object) = details.as_object_mut() {
        object.remove("line");
        object.remove("column");
        object.insert("violation_count".into(), json!(count));
        object.insert(
            "violations".into(),
            Value::Array(
                failures
                    .iter()
                    .take(VIOLATION_REPORT_LIMIT)
                    .map(|failure| {
                        json!({"code":failure.code,"message":failure.message,"details":failure.details})
                    })
                    .collect(),
            ),
        );
    }
    ValidationFailure::new(first.code, message, details)
}

fn heading_order_diagnostics(
    source: &str,
    tag_offsets: &HashMap<String, Vec<usize>>,
    headings: &[(u8, String)],
) -> Vec<crate::write_diagnostics::WriteDiagnostic> {
    let mut offsets = (1..=6u8)
        .flat_map(|level| {
            tag_offsets
                .get(&format!("h{level}"))
                .into_iter()
                .flatten()
                .map(move |offset| (level, *offset))
        })
        .collect::<Vec<_>>();
    offsets.sort_by_key(|(_, offset)| *offset);
    let positions_match = offsets.len() == headings.len()
        && offsets
            .iter()
            .zip(headings)
            .all(|(offset, heading)| offset.0 == heading.0);
    headings
        .windows(2)
        .enumerate()
        .filter(|(_, pair)| pair[1].0 > pair[0].0 + 1)
        .take(20)
        .map(|(index, pair)| {
            let (line, column) = if positions_match {
                source_position(source, offsets[index + 1].1)
            } else {
                (1, 1)
            };
            let label = |heading: &(u8, String)| {
                format!(
                    "h{} {:?}",
                    heading.0,
                    heading.1.trim().chars().take(80).collect::<String>()
                )
            };
            let mut message = format!(
                "heading levels skip from {} to {}; review the hierarchy",
                label(&pair[0]),
                label(&pair[1])
            );
            if !positions_match {
                message.push_str(" (source position unavailable)");
            }
            crate::write_diagnostics::WriteDiagnostic::new(
                "heading-order",
                message,
                None,
                line,
                column,
            )
        })
        .collect()
}

pub(crate) fn tag_end(source: &str, start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, byte) in source.as_bytes().get(start..)?.iter().copied().enumerate() {
        match (quote, byte) {
            (None, b'\'' | b'"') => quote = Some(byte),
            (Some(expected), actual) if expected == actual => quote = None,
            (None, b'>') => return Some(start + offset + 1),
            _ => {}
        }
    }
    None
}

fn skip_html_space(source: &str, mut offset: usize) -> usize {
    while source
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

/// Locate the injection point with a quote-aware scan. V1 rejects any content
/// before `<head>` and every head attribute, guaranteeing that the bootstrap
/// is the first executable element even for hostile quoted `>` characters.
fn bootstrap_insertion_offset(source: &str) -> std::result::Result<usize, ValidationFailure> {
    let mut offset = source
        .strip_prefix('\u{feff}')
        .map_or(0, |_| '\u{feff}'.len_utf8());
    offset = skip_html_space(source, offset);
    let doctype_end = tag_end(source, offset).ok_or_else(|| {
        ValidationFailure::new(
            "html_invalid_document",
            "document must begin with an HTML5 doctype",
            json!({"phase":"validation","rule":"document-preamble","line":1,"column":1}),
        )
    })?;
    if !source[offset..doctype_end]
        .trim()
        .eq_ignore_ascii_case("<!doctype html>")
    {
        return Err(ValidationFailure::new(
            "html_invalid_document",
            "document must begin with an HTML5 doctype",
            json!({"phase":"validation","rule":"document-preamble","line":1,"column":1}),
        ));
    }
    offset = skip_html_space(source, doctype_end);
    let html_end = tag_end(source, offset).ok_or_else(|| {
        ValidationFailure::new(
            "html_invalid_document",
            "doctype must be followed directly by the html element",
            json!({"phase":"validation","rule":"document-preamble"}),
        )
    })?;
    let html_open = &source[offset..html_end];
    if !html_open
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("<html"))
        || !html_open
            .as_bytes()
            .get(5)
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>')
    {
        let (line, column) = source_position(source, offset);
        return Err(ValidationFailure::new(
            "html_invalid_document",
            "doctype must be followed directly by the html element",
            json!({"phase":"validation","rule":"document-preamble","line":line,"column":column}),
        ));
    }
    offset = skip_html_space(source, html_end);
    let head_end = tag_end(source, offset).ok_or_else(|| {
        let (line, column) = source_position(source, offset);
        ValidationFailure::new(
            "html_invalid_document",
            "html start tag must be followed directly by an attribute-free head start tag",
            json!({"phase":"validation","rule":"bootstrap-order","line":line,"column":column}),
        )
    })?;
    if !source[offset..head_end].eq_ignore_ascii_case("<head>") {
        let (line, column) = source_position(source, offset);
        return Err(ValidationFailure::new(
            "html_invalid_document",
            "html start tag must be followed directly by an attribute-free head start tag",
            json!({"phase":"validation","rule":"bootstrap-order","line":line,"column":column}),
        ));
    }
    Ok(head_end)
}

fn inspect_node(
    node: &Handle,
    inspection: &mut Inspection,
    in_deck: bool,
) -> std::result::Result<(), ValidationFailure> {
    inspection.nodes += 1;
    if inspection.nodes > DOM_NODE_LIMIT {
        return Err(ValidationFailure::new(
            "html_policy_violation",
            "static DOM node limit exceeded",
            json!({"phase":"validation","limit":"static_dom_nodes","maximum":DOM_NODE_LIMIT}),
        ));
    }
    let mut children_in_deck = false;
    if let NodeData::Element { name, .. } = &node.data {
        let tag = name.local.to_string().to_ascii_lowercase();
        let attributes = attrs(node);
        let occurrence = inspection.tag_counts.entry(tag.clone()).or_default();
        let element = (tag.clone(), *occurrence);
        *occurrence += 1;
        if let Some(id) = attributes.get("id") {
            if valid_js_identifier(id) {
                inspection.element_ids.push(id.clone());
            }
        }
        if attributes
            .get("id")
            .is_some_and(|id| id.eq_ignore_ascii_case("native-app-kit"))
        {
            if tag != "script"
                || !attributes
                    .get("type")
                    .is_some_and(|t| t.eq_ignore_ascii_case("application/json"))
            {
                inspection.violate(
                    ValidationFailure::new(
                        "html_invalid_kit_policy",
                        "native-app-kit must be an inert script[type=application/json]",
                        json!({"phase":"validation","rule":"kit-policy-marker"}),
                    ),
                    &element,
                );
            }
            inspection.kit_policy_values.push(text_content(node));
        }
        match tag.as_str() {
            "html" => {
                inspection.html += 1;
                inspection.lang |= attributes.get("lang").is_some_and(|v| !v.trim().is_empty());
            }
            "head" => inspection.head += 1,
            "body" => inspection.body += 1,
            "title" => inspection.title.push(text_content(node)),
            "main" => {
                inspection.mains += 1;
                if attributes.contains_key("data-native-deck") {
                    inspection.deck_count += 1;
                    children_in_deck = true;
                }
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                if tag == "h1" {
                    inspection.h1 += 1;
                }
                inspection
                    .headings
                    .push((tag.as_bytes()[1] - b'0', text_content(node)));
            }
            "style" => inspection.css.push(text_content(node)),
            "meta" => {
                let http_equiv = attributes.get("http-equiv").map(|v| v.to_ascii_lowercase());
                let meta_name = attributes.get("name").map(|v| v.to_ascii_lowercase());
                if attributes
                    .get("charset")
                    .is_some_and(|v| v.eq_ignore_ascii_case("utf-8"))
                {
                    inspection.charset = true;
                }
                if meta_name.as_deref() == Some("viewport")
                    && attributes
                        .get("content")
                        .is_some_and(|v| v.to_ascii_lowercase().contains("width=device-width"))
                {
                    inspection.viewport = true;
                }
                if meta_name.as_deref() == Some("native-artifact-profile") {
                    if inspection.profile.is_some() {
                        inspection.violate(
                            policy("profile meta must occur at most once", "profile-count"),
                            &element,
                        );
                    } else {
                        inspection.profile = attributes
                            .get("content")
                            .map(|v| v.trim().to_ascii_lowercase());
                    }
                }
                if meta_name.as_deref() == Some("native-artifact-manifest") {
                    match attributes.get("content") {
                        Some(value) => inspection.declaration_values.push(value.clone()),
                        None => inspection.violate(
                            declaration_failure(
                                "native-artifact-manifest meta requires a content attribute",
                                "declaration-content",
                            ),
                            &element,
                        ),
                    }
                }
                if matches!(
                    http_equiv.as_deref(),
                    Some("content-security-policy" | "refresh")
                ) {
                    inspection.violate(
                        policy(
                            "authored CSP and refresh meta are forbidden",
                            "meta-http-equiv",
                        ),
                        &element,
                    );
                }
            }
            "base" | "iframe" | "frame" | "fencedframe" | "portal" | "object" | "embed" => {
                inspection.violate(
                    policy(format!("<{tag}> is forbidden"), "forbidden-element"),
                    &element,
                );
            }
            "script" => {
                if attributes.contains_key("src") {
                    inspection.violate(
                        policy("script[src] is forbidden", "external-script"),
                        &element,
                    );
                }
                if attributes
                    .get("type")
                    .is_some_and(|v| v.eq_ignore_ascii_case("importmap"))
                {
                    inspection.violate(policy("import maps are forbidden", "import-map"), &element);
                }
                let is_manifest = attributes
                    .get("type")
                    .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
                    && (attributes.get("id").is_some_and(|value| {
                        value.eq_ignore_ascii_case("native-artifact-manifest")
                    }) || attributes.contains_key("data-native-artifact-manifest"));
                if is_manifest {
                    inspection.declaration_values.push(text_content(node));
                }
                // Every inline script is listed in document order, manifest
                // included, so the raw-source scan can pair bodies by order.
                // The manifest is inert JSON and is marked non-executable.
                inspection
                    .scripts
                    .push(crate::write_diagnostics::ScriptElement {
                        text: text_content(node),
                        executable: !is_manifest
                            && crate::write_diagnostics::executable_script_type(
                                attributes.get("type").map(String::as_str),
                            ),
                    });
            }
            "link" => inspection.violate(
                policy(
                    "link elements are forbidden; artifacts are self-contained",
                    "external-link-resource",
                ),
                &element,
            ),
            "form" if attributes.contains_key("action") => {
                inspection.violate(policy("form[action] is forbidden", "form-action"), &element)
            }
            "img" if !attributes.contains_key("alt") => inspection.advise(
                "image-alt",
                "image has no alt; describe it, or use alt=\"\" if it is decorative",
                Some(element.clone()),
            ),
            "section" if in_deck && attributes.contains_key("data-native-slide") => {
                let id = attributes.get("id").cloned().unwrap_or_default();
                let labelled = attributes
                    .get("aria-labelledby")
                    .cloned()
                    .unwrap_or_default();
                let visible_heading = node.children.borrow().iter().any(|child| matches!(&child.data, NodeData::Element { name, .. } if matches!(name.local.as_ref(), "h1"|"h2"|"h3"|"h4"|"h5"|"h6")));
                inspection.deck_slides.push((id, labelled, visible_heading));
            }
            _ => {}
        }
        if attributes
            .get("tabindex")
            .and_then(|v| v.trim().parse::<i32>().ok())
            .is_some_and(|v| v > 0)
        {
            inspection.advise(
                "positive-tabindex",
                format!("<{tag}> has a positive tabindex, which overrides the natural focus order; use 0 or -1"),
                Some(element.clone()),
            );
        }
        if let Some(style) = attributes.get("style") {
            inspection.css.push(style.clone());
        }
        // An element already rejected by name (link, script[src], iframe,
        // form[action]) is reported once, not again for its URL attribute.
        let element_rejected = inspection.violations.last().is_some_and(|violation| {
            violation.element.as_ref() == Some(&element)
                && matches!(
                    violation.failure.details["rule"].as_str(),
                    Some(
                        "external-script"
                            | "external-link-resource"
                            | "forbidden-element"
                            | "form-action"
                    )
                )
        });
        for (key, value) in &attributes {
            if key.starts_with("on")
                || key == "style"
                || key == "class"
                || key == "id"
                || key == "lang"
                || key == "title"
                || key.starts_with("aria-")
                || key.starts_with("data-")
                || matches!(
                    key.as_str(),
                    "alt"
                        | "role"
                        | "hidden"
                        | "tabindex"
                        | "type"
                        | "charset"
                        | "content"
                        | "name"
                        | "http-equiv"
                        | "width"
                        | "height"
                        | "controls"
                        | "autoplay"
                        | "loop"
                        | "muted"
                        | "playsinline"
                        | "value"
                        | "min"
                        | "max"
                        | "step"
                        | "placeholder"
                        | "for"
                        | "disabled"
                        | "checked"
                        | "selected"
                        | "readonly"
                        | "required"
                        | "scope"
                        | "colspan"
                        | "rowspan"
                )
            {
                continue;
            }
            if key == "src" && tag == "img" {
                inspection.assets.push(value.clone());
                continue;
            }
            if key == "href" && tag == "a" && value.starts_with('#') {
                continue;
            }
            if matches!(
                key.as_str(),
                "href" | "src" | "srcset" | "poster" | "action" | "formaction" | "xlink:href"
            ) && !element_rejected
            {
                inspection.violate(
                    policy(
                        format!("URL-bearing attribute {key} on <{tag}> is forbidden"),
                        "url-attribute",
                    ),
                    &element,
                );
            }
        }
        if let Some(record_id) = attributes.get("data-native-record-id") {
            if record_id.trim().is_empty() || attributes.contains_key("data-native-external-url") {
                inspection.violate(
                    policy(
                        "host-mediated navigation must name exactly one non-empty destination",
                        "host-navigation",
                    ),
                    &element,
                );
            }
        }
        if let Some(href) = attributes.get("data-native-external-url") {
            match Url::parse(href) {
                Err(_) => inspection.violate(
                    policy(
                        "data-native-external-url must be an absolute http(s) URL",
                        "host-navigation",
                    ),
                    &element,
                ),
                Ok(parsed)
                    if !matches!(parsed.scheme(), "http" | "https")
                        || !parsed.username().is_empty()
                        || parsed.password().is_some() =>
                {
                    inspection.violate(
                        policy(
                            "data-native-external-url must be an absolute http(s) URL without credentials",
                            "host-navigation",
                        ),
                        &element,
                    )
                }
                Ok(_) => {}
            }
        }
    }
    if let NodeData::Element {
        template_contents, ..
    } = &node.data
    {
        if let Some(contents) = template_contents.borrow().as_ref() {
            inspect_template_kit(contents, inspection)?;
        }
    }
    for child in node.children.borrow().iter() {
        inspect_node(child, inspection, children_in_deck)?;
    }
    Ok(())
}

// Policy-only walk keeps legacy template contents outside the validator's DOM budget.
fn inspect_template_kit(
    node: &Handle,
    inspection: &mut Inspection,
) -> std::result::Result<(), ValidationFailure> {
    if let NodeData::Element {
        name,
        template_contents,
        ..
    } = &node.data
    {
        let attributes = attrs(node);
        if attributes
            .get("id")
            .is_some_and(|id| id.eq_ignore_ascii_case("native-app-kit"))
        {
            if name.local.as_ref() != "script"
                || !attributes
                    .get("type")
                    .is_some_and(|t| t.eq_ignore_ascii_case("application/json"))
            {
                return Err(ValidationFailure::new(
                    "html_invalid_kit_policy",
                    "native-app-kit must be an inert script[type=application/json]",
                    json!({"phase":"validation","rule":"kit-policy-marker"}),
                ));
            }
            inspection.kit_policy_values.push(text_content(node));
        }
        if let Some(contents) = template_contents.borrow().as_ref() {
            inspect_template_kit(contents, inspection)?;
        }
    }
    for child in node.children.borrow().iter() {
        inspect_template_kit(child, inspection)?;
    }
    Ok(())
}

fn decode_data_url(raw: &str) -> std::result::Result<usize, ValidationFailure> {
    let Some(rest) = raw.strip_prefix("data:") else {
        return Err(ValidationFailure::new(
            "html_asset_invalid",
            "asset URL must be data:",
            json!({"phase":"validation","rule":"data-url"}),
        ));
    };
    let Some((metadata, payload)) = rest.split_once(',') else {
        return Err(ValidationFailure::new(
            "html_asset_invalid",
            "malformed data URL",
            json!({"phase":"validation","rule":"data-url"}),
        ));
    };
    let mut parts = metadata.split(';');
    let mime = parts.next().unwrap_or("").to_ascii_lowercase();
    if !matches!(
        mime.as_str(),
        "image/png" | "image/jpeg" | "image/webp" | "image/avif" | "font/woff2"
    ) {
        return Err(ValidationFailure::new(
            "html_asset_invalid",
            format!("data asset MIME '{mime}' is not permitted"),
            json!({"phase":"validation","mime":mime}),
        ));
    }
    let base64 = parts.any(|part| part.eq_ignore_ascii_case("base64"));
    let bytes = if base64 {
        base64::engine::general_purpose::STANDARD
            .decode(payload.as_bytes())
            .map_err(|_| {
                ValidationFailure::new(
                    "html_asset_invalid",
                    "invalid base64 data asset",
                    json!({"phase":"validation","rule":"data-url-base64"}),
                )
            })?
    } else {
        percent_decode_str(payload).collect()
    };
    if bytes.len() > DATA_ASSET_EACH_LIMIT {
        return Err(ValidationFailure::new(
            "html_asset_too_large",
            "decoded data asset exceeds per-asset limit",
            json!({"phase":"validation","limit":"data_asset_decoded_bytes_each","maximum":DATA_ASSET_EACH_LIMIT,"actual":bytes.len()}),
        ));
    }
    Ok(bytes.len())
}

pub fn validate(source: &str) -> std::result::Result<Manifest, ValidationFailure> {
    validate_with_limit(source, BODY_LIMIT)
}

/// [`validate`] with the UTF-8 body limit chosen by the caller: [`BODY_LIMIT`]
/// for ordinary documents, [`PACKAGE_BODY_LIMIT`] for a record carrying the
/// package marker. Every other policy bound is unchanged.
pub fn validate_with_limit(
    source: &str,
    body_limit: usize,
) -> std::result::Result<Manifest, ValidationFailure> {
    let bytes = source.len();
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    if bytes > body_limit {
        return Err(ValidationFailure::new(
            "html_source_too_large",
            "HTML source exceeds the UTF-8 body limit",
            json!({"phase":"validation","limit":"body_utf8_bytes","maximum":body_limit,"actual":bytes,"body_digest":digest}),
        ));
    }
    bootstrap_insertion_offset(source)?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let doctype = Regex::new(r"(?is)^<!doctype\s+html\s*>").expect("doctype regex");
    if !doctype.is_match(source) {
        return Err(ValidationFailure::new(
            "html_invalid_document",
            "complete HTML must begin with an HTML5 doctype",
            json!({"phase":"validation","rule":"doctype","body_digest":digest}),
        ));
    }
    for (tag, expected) in [("html", 1usize), ("head", 1), ("body", 1)] {
        let regex = Regex::new(&format!(r"(?is)<\s*{tag}(?:\s|>)")).expect("tag regex");
        if regex.find_iter(source).count() != expected {
            return Err(ValidationFailure::new(
                "html_invalid_document",
                format!("document must contain exactly one <{tag}> start tag"),
                json!({"phase":"validation","rule":format!("{tag}-count"),"body_digest":digest}),
            ));
        }
    }
    let dom =
        html5ever::parse_document(RcDom::default(), ParseOpts::default()).one(source.to_string());
    if dom.quirks_mode.get() != QuirksMode::NoQuirks {
        return Err(ValidationFailure::new(
            "html_invalid_document",
            "document must parse in no-quirks mode",
            json!({"phase":"validation","rule":"no-quirks","body_digest":digest}),
        ));
    }
    let mut inspection = Inspection::default();
    inspect_node(&dom.document, &mut inspection, false)?;
    let mut violations = std::mem::take(&mut inspection.violations);
    let head = Some(("head".to_owned(), 0));
    let body = Some(("body".to_owned(), 0));
    if inspection.html != 1
        || inspection.head != 1
        || inspection.body != 1
        || !inspection.lang
        || inspection.title.len() != 1
        || inspection.title[0].trim().is_empty()
    {
        violations.push(
            ValidationFailure::new(
                "html_invalid_document",
                "document requires one html[lang], head, body and non-empty title",
                json!({"phase":"validation","rule":"document-envelope","body_digest":digest}),
            )
            .into(),
        );
    }
    if !inspection.charset {
        inspection.advise(
            "document-charset",
            "head has no <meta charset=\"utf-8\">; the host serves UTF-8 regardless, but declare it so the file stands alone",
            head.clone(),
        );
    }
    if !inspection.viewport {
        inspection.advise(
            "document-viewport",
            "head has no <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">, so narrow screens render a zoomed-out desktop layout",
            head,
        );
    }
    let profile = match inspection.profile.as_deref() {
        None | Some("document") => Some(Profile::Document),
        Some("slides") => Some(Profile::Slides),
        Some(other) => {
            violations.push(
                policy(
                    format!("unknown native artifact profile '{other}'"),
                    "profile",
                )
                .into(),
            );
            None
        }
    };
    match inspection.mains {
        1 => {}
        0 => inspection.advise(
            "landmarks",
            "artifact has no <main> landmark; wrap the primary content in one <main> so assistive technology can skip to it",
            body.clone(),
        ),
        count => inspection.advise(
            "landmarks",
            format!("artifact has {count} <main> elements; keep exactly one visible <main>"),
            Some(("main".to_owned(), 1)),
        ),
    }
    if inspection.h1 == 0 {
        inspection.advise(
            "missing-h1",
            "artifact has no <h1>; give it at least one top-level heading (it may be visually hidden)",
            body,
        );
    }
    let mut css_rules = 0usize;
    let css_url = Regex::new(r#"(?is)url\(\s*['\"]?([^'\")]+)['\"]?\s*\)"#).expect("CSS URL regex");
    let mut assets = std::mem::take(&mut inspection.assets);
    let css_comments = Regex::new(r"(?s)/\*.*?\*/").expect("CSS comment regex");
    for css in &inspection.css {
        let normalized = css_comments.replace_all(css, "").to_ascii_lowercase();
        if normalized.contains("@import") {
            violations.push(policy("CSS @import is forbidden", "css-import").into());
        }
        if normalized.contains("image-set(") || normalized.contains("-webkit-image-set(") {
            violations.push(
                policy(
                    "CSS image-set is forbidden; use a single quota-checked data URL",
                    "css-image-set",
                )
                .into(),
            );
        }
        if normalized.contains("http:")
            || normalized.contains("https:")
            || normalized.contains("url(//")
        {
            violations.push(policy("external CSS authority is forbidden", "css-url").into());
        }
        css_rules += css.bytes().filter(|b| *b == b'{').count();
        for capture in css_url.captures_iter(css) {
            let value = capture.get(1).map(|v| v.as_str().trim()).unwrap_or("");
            if value.starts_with("data:") {
                assets.push(value.to_string());
            } else if !value.starts_with('#') {
                violations.push(
                    policy(
                        format!(
                            "CSS url({}) is not a permitted data asset or fragment",
                            value.chars().take(80).collect::<String>()
                        ),
                        "css-url",
                    )
                    .into(),
                );
            }
        }
    }
    if css_rules > CSS_RULE_LIMIT {
        violations.push(policy("CSS rule limit exceeded", "css-rules").into());
    }
    let mut asset_total = 0usize;
    for asset in assets {
        match decode_data_url(&asset) {
            Ok(decoded) => asset_total += decoded,
            Err(failure) => violations.push(failure.into()),
        }
        if asset_total > DATA_ASSET_TOTAL_LIMIT {
            violations.push(
                ValidationFailure::new(
                    "html_asset_too_large",
                    "decoded data assets exceed aggregate limit",
                    json!({"phase":"validation","limit":"data_asset_decoded_bytes_total","maximum":DATA_ASSET_TOTAL_LIMIT,"actual":asset_total}),
                )
                .into(),
            );
            break;
        }
    }
    let mut slides = 0;
    match profile {
        Some(Profile::Slides) => {
            if inspection.deck_count != 1
                || !(2..=SLIDE_LIMIT).contains(&inspection.deck_slides.len())
            {
                violations.push(
                    policy(
                        "slides require one main[data-native-deck] with 2–200 direct slides",
                        "slides-structure",
                    )
                    .into(),
                );
            }
            let mut ids = std::collections::BTreeSet::new();
            if inspection
                .deck_slides
                .iter()
                .any(|(id, labelled, heading)| {
                    id.is_empty() || labelled.is_empty() || !heading || !ids.insert(id)
                })
            {
                violations.push(
                    policy(
                        "every slide needs a unique id, aria-labelledby, and visible heading",
                        "slide-accessible-name",
                    )
                    .into(),
                );
            }
            slides = inspection.deck_slides.len();
        }
        Some(Profile::Document) if inspection.deck_count != 0 => violations.push(
            policy(
                "document profile cannot declare a slide deck",
                "profile-structure",
            )
            .into(),
        ),
        _ => {}
    }
    let kit_policy = match parse_kit_policy(&inspection.kit_policy_values) {
        Ok(policy) => policy,
        Err(failure) => {
            violations.push(failure.into());
            None
        }
    };
    let tag_offsets = start_tag_offsets(source);
    let (artifact_ports, capability_requests, interactions, named_inputs_declared) =
        match parse_named_declaration(&inspection.declaration_values) {
            Ok(declaration) if violations.is_empty() => declaration,
            result => {
                if let Err(failure) = result {
                    violations.push(failure.into());
                }
                return Err(report_violations(
                    source,
                    &tag_offsets,
                    &inspection.tag_counts,
                    violations,
                ));
            }
        };
    let profile = profile.expect("an unknown profile is reported as a violation above");
    // The script pass runs last so it can name declared ports and interaction
    // entries. It is warning-only: a finding never reaches the failure path.
    let mut diagnostics = advisory_diagnostics(source, &tag_offsets, &inspection);
    diagnostics.extend(heading_order_diagnostics(
        source,
        &tag_offsets,
        &inspection.headings,
    ));
    diagnostics.extend(crate::write_diagnostics::html_write_diagnostics(
        source,
        &inspection.scripts,
        &artifact_ports.keys().cloned().collect::<Vec<_>>(),
        &interactions
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        &inspection.element_ids,
    ));
    // Test probe: only a body with an executable script runs the pass, so a
    // no-script body proves the fast path and a repeated body proves the cache.
    #[cfg(test)]
    if inspection.scripts.iter().any(|script| script.executable) {
        crate::write_diagnostics::test_probe::note(&digest);
    }
    Ok(Manifest {
        kit_policy,
        profile,
        body_digest: digest,
        body_utf8_bytes: bytes,
        static_dom_nodes: inspection.nodes,
        css_rules,
        data_asset_decoded_bytes_total: asset_total,
        slides,
        artifact_ports,
        capability_requests,
        interactions,
        named_inputs_declared,
        diagnostics,
    })
}

fn validation_cache() -> &'static Mutex<HashMap<String, Manifest>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Manifest>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(source: &str, body_limit: usize) -> String {
    let body_digest = Sha256::digest(source.as_bytes());
    let bootstrap_digest = Sha256::digest(BOOTSTRAP.as_bytes());
    let adapter_revision = ADAPTER_REVISION.to_be_bytes();
    let limits = format!(
        "{body_limit}:{DATA_ASSET_EACH_LIMIT}:{DATA_ASSET_TOTAL_LIMIT}:{DOM_NODE_LIMIT}:{CSS_RULE_LIMIT}:{SLIDE_LIMIT}"
    );
    let parts: [&[u8]; 10] = [
        b"native.artifact-html-cache.v1",
        &body_digest,
        RUNTIME_ID.as_bytes(),
        b"native-ce.html-policy@1",
        &adapter_revision,
        &bootstrap_digest,
        b"native-ce.html-csp@1",
        limits.as_bytes(),
        b"html5ever@0.39.0",
        b"native-ce.html-write-diagnostics@1",
    ];
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

/// Disposable validation cache. It is process-local by construction and its
/// length-delimited key includes every policy/transform/revision axis.
pub fn validate_cached(source: &str) -> std::result::Result<Manifest, ValidationFailure> {
    validate_cached_with_limit(source, BODY_LIMIT)
}

/// [`validate_cached`] with the body limit chosen by the caller; the limit is
/// part of the cache key, so a package-limit pass never answers an ordinary
/// validation of the same bytes.
pub fn validate_cached_with_limit(
    source: &str,
    body_limit: usize,
) -> std::result::Result<Manifest, ValidationFailure> {
    let key = cache_key(source, body_limit);
    if let Some(manifest) = validation_cache()
        .lock()
        .expect("HTML validation cache poisoned")
        .get(&key)
        .cloned()
    {
        return Ok(manifest);
    }
    let manifest = validate_with_limit(source, body_limit)?;
    let mut cache = validation_cache()
        .lock()
        .expect("HTML validation cache poisoned");
    if cache.len() >= 256 {
        cache.clear();
    }
    cache.insert(key, manifest.clone());
    Ok(manifest)
}

pub fn descriptor() -> Value {
    let bootstrap_digest = hex::encode(Sha256::digest(BOOTSTRAP.as_bytes()));
    json!({
        "id":RUNTIME_ID,"contract_version":1,"adapter_revision":ADAPTER_REVISION,
        "body_media_type":"text/html; charset=utf-8",
        "validator":{"id":"native-ce.html-policy","version":3,"html_parser":"html5ever@0.39.0"},
        "delivery_transform":{"id":"native-ce.html-bootstrap","version":1,"digest":bootstrap_digest},
        "input_envelope_version":"native.artifact-input.v1","named_input_envelope_version":NAMED_INPUT_ABI,
        "collection_envelope_version":COLLECTION_ENVELOPE,"relation_envelope_version":RELATION_ENVELOPE,
        "bridge_version":BRIDGE_VERSION,
        "declaration_surface":{"schema":MANIFEST_SCHEMA,"interactive_schema":INTERACTIVE_MANIFEST_SCHEMA,"element":"script[type=application/json][id=native-artifact-manifest] or meta[name=native-artifact-manifest]","exact_source":true,"capability":"input.read"},
        "execution_profile":"sandboxed-browser","profiles":["document","slides"],
        "requested_capabilities":["inline-script","inline-style","data-image","data-font","exact-input-read","host-mediated-navigation","host-mediated-write-proposal","host-fullscreen","ephemeral-render-verification"],
        "output_surface":"workbench.isolated-html-frame","diagnostic_format":"native.artifact-diagnostic.v1",
        "limits":{"body_utf8_bytes":BODY_LIMIT,"data_asset_decoded_bytes_each":DATA_ASSET_EACH_LIMIT,"data_asset_decoded_bytes_total":DATA_ASSET_TOTAL_LIMIT,"static_dom_nodes":DOM_NODE_LIMIT,"css_rules":CSS_RULE_LIMIT,"slides":SLIDE_LIMIT,"input_records":INPUT_RECORD_LIMIT,"input_json_bytes":INPUT_JSON_LIMIT,"bridge_message_bytes":BRIDGE_MESSAGE_LIMIT,"named_input_safe_integer_min":NAMED_INPUT_SAFE_INTEGER_MIN,"named_input_safe_integer_max":NAMED_INPUT_SAFE_INTEGER_MAX,"ready_timeout_ms":2000}
    })
}

fn inject(
    source: &str,
    workbench_origin: &str,
    manifest: &Manifest,
) -> std::result::Result<String, ValidationFailure> {
    KitDelivery::default()
        .compose(source, workbench_origin, manifest)
        .map(|(html, _)| html)
}

/// Transform cache identity, shared with manifest validation. Parent is a separate axis.
pub fn bundle_delivery_cache_key(source: &str, body_limit: usize) -> String {
    cache_key(source, body_limit)
}

/// Validate the current limit, compare the recomputed body hash, and inject
/// the signed parent using the same admitted bootstrap/kit path as tickets.
pub fn compose_bundle_delivery(
    source: &str,
    parent: &str,
    body_limit: usize,
) -> std::result::Result<String, ValidationFailure> {
    let parent = RuntimeConfig::exact_parent_origin(parent).map_err(|_| {
        ValidationFailure::new("invalid_parent_origin", "invalid bundle parent", json!({}))
    })?;
    let manifest = validate_cached_with_limit(source, body_limit)?;
    if manifest.body_digest != hex::encode(Sha256::digest(source.as_bytes())) {
        return Err(ValidationFailure::new(
            "body_digest_mismatch",
            "bundle body hash mismatch",
            json!({}),
        ));
    }
    inject(source, &parent, &manifest)
}

/// The ordinary ticket response headers, without issuing or storing a ticket.
/// The opaque reusable app frame carries no per-principal attestation data.
pub fn bundle_delivery_headers(parent: &str) -> Result<HeaderMap> {
    let parent = RuntimeConfig::exact_parent_origin(parent)?;
    Ok(ticket_response(Ticket {
        html: String::new(),
        expires: Instant::now(),
        principal: String::new(),
        _issuance_database: None,
        _artifact_id: String::new(),
        _body_digest: String::new(),
        _adapter_revision: ADAPTER_REVISION,
        parent_origin: parent,
        attestation: None,
    })
    .headers()
    .clone())
}

struct Ticket {
    html: String,
    expires: Instant,
    // The launch URL itself is the bearer capability. Issuance identity is
    // retained only for deterministic per-principal memory bounds; redemption
    // has no credential because the opaque child must not receive one.
    principal: String,
    _issuance_database: Option<String>,
    _artifact_id: String,
    _body_digest: String,
    _adapter_revision: u64,
    parent_origin: String,
    attestation: Option<Attestation>,
}

#[derive(Clone)]
struct Attestation {
    artifact_id: String,
    artifact_digest: String,
    body_digest: String,
    input_digest: String,
    adapter_digest: String,
    bootstrap_digest: String,
    csp_digest: String,
    input_mode: String,
    input_count: usize,
    input_abi: String,
    input_ports: Vec<String>,
}

struct HarnessTicket {
    html: String,
    expires: Instant,
    principal: String,
    _issuance_database: Option<String>,
    attestation: Attestation,
}

struct TicketStore<T> {
    entries: HashMap<String, T>,
    oldest: VecDeque<String>,
    bytes: usize,
}

impl<T> Default for TicketStore<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            oldest: VecDeque::new(),
            bytes: 0,
        }
    }
}

fn tickets() -> &'static Mutex<TicketStore<Ticket>> {
    static TICKETS: OnceLock<Mutex<TicketStore<Ticket>>> = OnceLock::new();
    TICKETS.get_or_init(|| Mutex::new(TicketStore::default()))
}

fn harness_tickets() -> &'static Mutex<TicketStore<HarnessTicket>> {
    static TICKETS: OnceLock<Mutex<TicketStore<HarnessTicket>>> = OnceLock::new();
    TICKETS.get_or_init(|| Mutex::new(TicketStore::default()))
}

fn remove_stored<T>(
    store: &mut TicketStore<T>,
    token: &str,
    bytes: impl Fn(&T) -> usize,
) -> Option<T> {
    let item = store.entries.remove(token)?;
    store.bytes = store.bytes.saturating_sub(bytes(&item));
    if let Some(position) = store.oldest.iter().position(|queued| queued == token) {
        store.oldest.remove(position);
    }
    Some(item)
}

#[allow(clippy::too_many_arguments)]
fn make_room<T>(
    store: &mut TicketStore<T>,
    now: Instant,
    principal: &str,
    item_bytes: usize,
    max_count: usize,
    max_per_principal: usize,
    max_bytes: usize,
    expires: impl Fn(&T) -> Instant + Copy,
    owner: impl Fn(&T) -> &str + Copy,
    bytes: impl Fn(&T) -> usize + Copy,
) -> std::result::Result<(), ValidationFailure> {
    if item_bytes > max_bytes {
        return Err(ValidationFailure::new(
            "html_delivery_failed",
            "HTML delivery derivative exceeds the bounded ticket store",
            json!({"phase":"delivery","limit":"ticket_bytes","maximum":max_bytes,"actual":item_bytes}),
        ));
    }
    let expired: Vec<String> = store
        .oldest
        .iter()
        .filter(|token| {
            store
                .entries
                .get(*token)
                .is_some_and(|item| expires(item) <= now)
        })
        .cloned()
        .collect();
    for token in expired {
        remove_stored(store, &token, bytes);
    }
    while store
        .entries
        .values()
        .filter(|item| owner(item) == principal)
        .count()
        >= max_per_principal
    {
        let token = store
            .oldest
            .iter()
            .find(|token| {
                store
                    .entries
                    .get(*token)
                    .is_some_and(|item| owner(item) == principal)
            })
            .cloned()
            .expect("principal count has an oldest ticket");
        remove_stored(store, &token, bytes);
    }
    while store.entries.len() >= max_count || store.bytes + item_bytes > max_bytes {
        let Some(token) = store.oldest.front().cloned() else {
            break;
        };
        remove_stored(store, &token, bytes);
    }
    Ok(())
}

fn take_launch_ticket(token: &str) -> Option<Ticket> {
    remove_stored(
        &mut tickets().lock().expect("ticket store poisoned"),
        token,
        |ticket| ticket.html.len(),
    )
}

fn take_harness_ticket(token: &str) -> Option<HarnessTicket> {
    remove_stored(
        &mut harness_tickets()
            .lock()
            .expect("harness ticket store poisoned"),
        token,
        |ticket| ticket.html.len(),
    )
}

pub struct Launch {
    pub kit_release: Option<KitRelease>,
    pub url: String,
    pub expires_in_ms: u64,
}

/// Caller-owned, bounded launch delivery with an immutable configuration.
/// Clones share tickets; separately constructed handles are isolated. Dropping
/// the last handle and router releases the store. Legacy APIs retain their
/// process-wide store independently of these instances.
#[doc(hidden)]
mod body_delivery;
mod kit_delivery;
mod sample_delivery;
#[doc(hidden)]
pub use body_delivery::{
    BodyDeliveryFailure, BodyLaunchContext, BodyMountMeta, BodyReservation, PreparedLaunch,
    PublishedLaunch,
};
pub use kit_delivery::{KitDelivery, KitRelease};
pub use sample_delivery::{
    LaunchOutcome, LaunchRefusal, SampleFailure, SamplePublicationLease, SamplePublicationMarker,
    SampleTicketReservation, StoreUnavailable, TicketLookup,
};

#[derive(Clone)]
pub struct LaunchDelivery {
    kit: Arc<KitDelivery>,
    config: Arc<RuntimeConfig>,
    tickets: Arc<Mutex<sample_delivery::SampleStore>>,
    body: Arc<body_delivery::BodyOwner>,
    #[cfg(any(test, feature = "test-support"))]
    legacy_fixture: Option<Arc<Mutex<TicketStore<Ticket>>>>,
}

impl LaunchDelivery {
    pub fn new(config: RuntimeConfig) -> Self {
        Self::with_kit(config, KitDelivery::default())
    }

    pub fn with_kit(config: RuntimeConfig, kit: KitDelivery) -> Self {
        let config = Arc::new(config);
        let kit = Arc::new(kit);
        let body = body_delivery::BodyOwner::new(config.clone());
        Self {
            kit,
            tickets: Arc::new(Mutex::new(sample_delivery::SampleStore::new(
                body.0.clone(),
            ))),
            body,
            config,
            #[cfg(any(test, feature = "test-support"))]
            legacy_fixture: None,
        }
    }

    /// New immutable selection for subsequent preparations, retaining shared
    /// ticket/body custody. Already composed documents are never reselected.
    pub fn with_kit_selection(&self, kit: KitDelivery) -> Self {
        let mut next = self.clone();
        next.kit = Arc::new(kit);
        next
    }

    /// Test fixture with its own legacy, sample and body stores. Normal
    /// construction continues to use the process-wide legacy store.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn isolated_fixture(config: RuntimeConfig) -> Self {
        let mut delivery = Self::new(config);
        // Busy and poisoned legacy-lane tests must not alter sibling routers.
        // Clones retain the same three stores and exercise the normal lookup.
        delivery.legacy_fixture = Some(Arc::new(Mutex::new(TicketStore::default())));
        delivery
    }

    fn legacy_tickets(&self) -> &Mutex<TicketStore<Ticket>> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(store) = &self.legacy_fixture {
            return store;
        }
        tickets()
    }

    pub fn issue_launch(
        &self,
        source: &str,
        manifest: &Manifest,
        principal: &str,
        database: Option<&str>,
        artifact_id: &str,
    ) -> std::result::Result<Launch, ValidationFailure> {
        let pending = self
            .reserve_sample_launch(source, manifest, principal, database, artifact_id)
            .map_err(|failure| {
                if let SampleFailure::KitMajorUnavailable(major) = failure {
                    return ValidationFailure::new(
                        "kit_major_unavailable",
                        format!("Native app kit major {major} is unavailable on this host"),
                        json!({"phase":"delivery","major":major}),
                    );
                }
                ValidationFailure::new(
                    "html_delivery_failed",
                    "sample delivery refused",
                    json!({"phase":"delivery"}),
                )
            })?;
        let launch = Launch {
            kit_release: pending.descriptor().kit_release.clone(),
            url: pending.descriptor().url.clone(),
            expires_in_ms: pending.descriptor().expires_in_ms,
        };
        pending
            .try_lock_for_publication(pending.original_ticket_deadline())
            .and_then(|lease| lease.commit(pending.original_ticket_deadline()))
            .map_err(|_| {
                ValidationFailure::new(
                    "html_delivery_failed",
                    "sample publication refused",
                    json!({"phase":"delivery"}),
                )
            })?;
        Ok(launch)
    }

    /// Serve typed instance launches plus the terminal global legacy lane. Harnesses remain on
    /// the legacy router and are never exposed through an instance handle.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/artifact-runtime/v1/launch/{ticket}", get(instance_launch))
            .with_state(self.clone())
    }

    /// Configured production composition: one typed launch lane, with the
    /// existing global verification harness retained on its separate path.
    pub fn configured_router(&self, config: RuntimeConfig) -> Router {
        self.router().merge(
            Router::new()
                .route(
                    "/internal/artifacts/verification/{ticket}",
                    get(verification_harness),
                )
                .with_state(Arc::new(config)),
        )
    }
}

pub fn issue_launch(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
) -> std::result::Result<Launch, ValidationFailure> {
    issue_launch_for_parent(source, manifest, principal, database, artifact_id, None)
}

/// Issue a one-use launch bound to an exact deployment-allowlisted parent.
/// The selected parent is frozen into both bootstrap HOST and delivered CSP.
/// Omitting it retains the configured workbench parent.
pub fn issue_launch_for_parent(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
    parent_origin: Option<&str>,
) -> std::result::Result<Launch, ValidationFailure> {
    let config = configuration().ok_or_else(|| {
        ValidationFailure::new(
            "html_delivery_failed",
            "native.html.v1 artifact origin is not configured",
            json!({"phase":"delivery","artifact_id":artifact_id}),
        )
    })?;
    issue_launch_with_attestation(
        source,
        manifest,
        principal,
        database,
        artifact_id,
        &config,
        parent_origin,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_launch_with_attestation(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
    config: &RuntimeConfig,
    parent_origin: Option<&str>,
    attestation: Option<Attestation>,
) -> std::result::Result<Launch, ValidationFailure> {
    issue_launch_in_store(
        source,
        manifest,
        principal,
        database,
        artifact_id,
        config,
        parent_origin,
        attestation,
        tickets(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_launch_in_store(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
    config: &RuntimeConfig,
    parent_origin: Option<&str>,
    attestation: Option<Attestation>,
    tickets: &Mutex<TicketStore<Ticket>>,
    now: Option<Instant>,
) -> std::result::Result<Launch, ValidationFailure> {
    issue_launch_in_store_with_kit(
        source,
        manifest,
        principal,
        database,
        artifact_id,
        config,
        parent_origin,
        attestation,
        tickets,
        now,
        &KitDelivery::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_launch_in_store_with_kit(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
    config: &RuntimeConfig,
    parent_origin: Option<&str>,
    attestation: Option<Attestation>,
    tickets: &Mutex<TicketStore<Ticket>>,
    now: Option<Instant>,
    kit: &KitDelivery,
) -> std::result::Result<Launch, ValidationFailure> {
    // Policy lives at issuance, before any ticket or bearer token is minted.
    // A router's later configuration cannot change this binding.
    let parent_origin = config.resolve_parent_origin(parent_origin).map_err(|_| {
        ValidationFailure::new(
            "html_parent_origin_denied",
            "requested HTML parent origin is invalid or not allowlisted",
            json!({"phase":"delivery","artifact_id":artifact_id}),
        )
    })?;
    let (html, kit_release) = kit.compose(source, &parent_origin, manifest)?;
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = hex::encode(random);
    let now = now.unwrap_or_else(Instant::now);
    let mut store = tickets.lock().expect("ticket store poisoned");
    if store.entries.contains_key(&token) {
        return Err(ValidationFailure::new(
            "html_delivery_failed",
            "ticket collision",
            json!({"phase":"delivery"}),
        ));
    }
    make_room(
        &mut store,
        now,
        principal,
        html.len(),
        LAUNCH_TICKET_MAX_COUNT,
        LAUNCH_TICKET_MAX_PER_PRINCIPAL,
        LAUNCH_TICKET_MAX_BYTES,
        |ticket| ticket.expires,
        |ticket| ticket.principal.as_str(),
        |ticket| ticket.html.len(),
    )?;
    store.bytes += html.len();
    store.oldest.push_back(token.clone());
    store.entries.insert(
        token.clone(),
        Ticket {
            html,
            expires: now + TICKET_TTL,
            principal: principal.into(),
            _issuance_database: database.map(str::to_string),
            _artifact_id: artifact_id.into(),
            _body_digest: manifest.body_digest.clone(),
            _adapter_revision: ADAPTER_REVISION,
            parent_origin,
            attestation,
        },
    );
    Ok(Launch {
        kit_release,
        url: format!(
            "{}/artifact-runtime/v1/launch/{token}",
            config.artifact_origin
        ),
        expires_in_ms: TICKET_TTL.as_millis() as u64,
    })
}

pub struct VerificationHarness {
    pub kit_release: Option<KitRelease>,
    pub url: String,
    pub expires_in_ms: u64,
}

pub struct VerificationHarnessRequest<'a> {
    pub source: &'a str,
    pub manifest: &'a Manifest,
    pub input: &'a Value,
    pub input_digest: &'a str,
    pub artifact_digest: &'a str,
    pub adapter_digest: &'a str,
    pub bootstrap_digest: &'a str,
    pub csp_digest: &'a str,
    pub input_mode: &'a str,
    pub input_count: usize,
    pub principal: &'a str,
    pub database: Option<&'a str>,
    pub artifact_id: &'a str,
}

/// Issue a one-use workbench-origin harness wrapping the same one-use artifact
/// launch path used by humans. The verifier receives only this URL and expected
/// digests; it never receives a database credential, path, body, or arbitrary
/// fetch target.
pub fn issue_verification_harness(
    request: VerificationHarnessRequest<'_>,
) -> std::result::Result<VerificationHarness, ValidationFailure> {
    let VerificationHarnessRequest {
        source,
        manifest,
        input,
        input_digest,
        artifact_digest,
        adapter_digest,
        bootstrap_digest,
        csp_digest,
        input_mode,
        input_count,
        principal,
        database,
        artifact_id,
    } = request;
    let config = configuration().ok_or_else(|| {
        ValidationFailure::new(
            "html_delivery_failed",
            "native.html.v1 artifact origin is not configured",
            json!({"phase":"verification","artifact_id":artifact_id}),
        )
    })?;
    let attestation = Attestation {
        artifact_id: artifact_id.into(),
        artifact_digest: artifact_digest.into(),
        body_digest: manifest.body_digest.clone(),
        input_digest: input_digest.into(),
        adapter_digest: adapter_digest.into(),
        bootstrap_digest: bootstrap_digest.into(),
        csp_digest: csp_digest.into(),
        input_mode: input_mode.into(),
        input_count,
        input_abi: input
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("native.artifact-input.v1")
            .to_owned(),
        input_ports: input
            .get("inputs")
            .and_then(Value::as_object)
            .map(|inputs| inputs.keys().cloned().collect())
            .unwrap_or_default(),
    };
    let input_json = serde_json::to_string(input)
        .expect("artifact input is JSON")
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    // A launch URL is a bearer capability. Prove that the enclosing harness
    // can fit before minting its child so a rejected harness can never leave
    // an unreachable live launch ticket behind. The placeholder token has the
    // same encoded length and alphabet class as the eventual random token.
    let placeholder_launch = format!(
        "{}/artifact-runtime/v1/launch/{}",
        config.artifact_origin,
        "0".repeat(64)
    );
    let launch_json = serde_json::to_string(&placeholder_launch).expect("launch URL JSON");
    let bridge_json = serde_json::to_string(BRIDGE_VERSION).expect("bridge JSON");
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Native artifact verification harness</title><style>html,body,main{{width:100%;height:100%;margin:0;overflow:hidden}}h1{{position:fixed;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}}iframe{{display:block;width:100%;height:100%;border:0}}</style></head><body><main><h1>Native artifact verification harness</h1><iframe id="artifact" src={launch_json} sandbox="allow-scripts" referrerpolicy="no-referrer" title="Artifact under verification" allow=""></iframe></main><script>(()=>{{"use strict";const input={input_json},version={bridge_json},frame=document.getElementById("artifact"),state={{ready:false,messages:[],startedAt:Date.now()}},diagnostics=[];let resolveReady,rejectReady;const ready=new Promise((resolve,reject)=>{{resolveReady=resolve;rejectReady=reject}}),verification={{}};Object.defineProperty(verification,"diagnostics",{{enumerable:true,get:()=>diagnostics.map(item=>Object.freeze({{...item}}))}});Object.freeze(verification);Object.defineProperty(window,"nativeArtifact",{{value:Object.freeze({{ready,verification}}),writable:false,configurable:false}});Object.defineProperty(window,"__nativeVerification",{{value:state,writable:false,configurable:false}});addEventListener("message",event=>{{if(state.ready||event.source!==frame.contentWindow||event.origin!=="null"||event.data?.type!=="native-html-bootstrap"||event.data?.version!==version)return;const channel=new MessageChannel();channel.port1.onmessage=message=>{{const data=message.data;if(data?.version!==version)return;if(state.messages.length<256)state.messages.push(data);if(data.type==="diagnostic"&&diagnostics.length<100)diagnostics.push({{code:String(data.code??"html_runtime_diagnostic").slice(0,128),message:String(data.detail?.message??"").slice(0,512),severity:data.code==="html_runtime_error"?"error":"warning"}});if(data.type==="ready"){{state.ready=true;resolveReady(Object.freeze({{profile:data.profile,slides:data.slides}}))}}}};channel.port1.onmessageerror=()=>rejectReady(new Error("artifact bridge message error"));channel.port1.start();frame.contentWindow.postMessage({{type:"native-html-init",version,input}},"*",[channel.port2])}}) }})();</script></body></html>"#
    );
    {
        let now = Instant::now();
        let mut store = harness_tickets()
            .lock()
            .expect("harness ticket store poisoned");
        make_room(
            &mut store,
            now,
            principal,
            html.len(),
            HARNESS_TICKET_MAX_COUNT,
            HARNESS_TICKET_MAX_PER_PRINCIPAL,
            HARNESS_TICKET_MAX_BYTES,
            |ticket| ticket.expires,
            |ticket| ticket.principal.as_str(),
            |ticket| ticket.html.len(),
        )?;
    }
    let launch = issue_launch_with_attestation(
        source,
        manifest,
        principal,
        database,
        artifact_id,
        &config,
        None,
        Some(attestation.clone()),
    )?;
    let actual_launch_json = serde_json::to_string(&launch.url).expect("launch URL JSON");
    debug_assert_eq!(launch_json.len(), actual_launch_json.len());
    let html = html.replacen(&launch_json, &actual_launch_json, 1);
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = hex::encode(random);
    let now = Instant::now();
    let mut store = harness_tickets()
        .lock()
        .expect("harness ticket store poisoned");
    let room = make_room(
        &mut store,
        now,
        principal,
        html.len(),
        HARNESS_TICKET_MAX_COUNT,
        HARNESS_TICKET_MAX_PER_PRINCIPAL,
        HARNESS_TICKET_MAX_BYTES,
        |ticket| ticket.expires,
        |ticket| ticket.principal.as_str(),
        |ticket| ticket.html.len(),
    );
    if let Err(failure) = room {
        drop(store);
        if let Some(token) = launch.url.rsplit('/').next() {
            take_launch_ticket(token);
        }
        return Err(failure);
    }
    store.bytes += html.len();
    store.oldest.push_back(token.clone());
    store.entries.insert(
        token.clone(),
        HarnessTicket {
            html,
            expires: now + TICKET_TTL,
            principal: principal.into(),
            _issuance_database: database.map(str::to_string),
            attestation,
        },
    );
    Ok(VerificationHarness {
        kit_release: launch.kit_release,
        url: format!(
            "{}/internal/artifacts/verification/{token}",
            config.workbench_origin
        ),
        expires_in_ms: TICKET_TTL.as_millis() as u64,
    })
}

fn csp(workbench_origin: &str) -> String {
    format!("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; media-src 'none'; connect-src 'none'; worker-src 'none'; child-src 'none'; frame-src 'none'; object-src 'none'; manifest-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors {workbench_origin}; webrtc 'block'; sandbox allow-scripts")
}

pub fn bootstrap_digest() -> String {
    hex::encode(Sha256::digest(BOOTSTRAP.as_bytes()))
}

pub fn content_security_policy(workbench_origin: &str) -> Result<String> {
    let origin = exact_origin(workbench_origin, "workbench origin")?;
    Ok(csp(&origin))
}

pub fn content_security_policy_digest(workbench_origin: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        content_security_policy(workbench_origin)?.as_bytes(),
    )))
}

async fn launch(
    State(config): State<Arc<RuntimeConfig>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    launch_response(&config, tickets(), &token, &headers, None)
}

async fn instance_launch(
    State(delivery): State<LaunchDelivery>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    delivery
        .lookup_launch(&token, &headers)
        .into_response(&headers, &delivery.config)
}

fn launch_response(
    config: &RuntimeConfig,
    tickets: &Mutex<TicketStore<Ticket>>,
    token: &str,
    headers: &HeaderMap,
    now: Option<Instant>,
) -> Response {
    if !host_matches_origin(headers, &config.artifact_origin) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ticket = remove_stored(
        &mut tickets.lock().expect("ticket store poisoned"),
        token,
        |ticket| ticket.html.len(),
    );
    let Some(ticket) = ticket else {
        return StatusCode::GONE.into_response();
    };
    if ticket.expires <= now.unwrap_or_else(Instant::now) {
        return StatusCode::GONE.into_response();
    }
    ticket_response(ticket)
}

fn ticket_response(ticket: Ticket) -> Response {
    let mut response = ticket.html.into_response();
    let h = response.headers_mut();
    for (name, value) in [
        (CONTENT_TYPE, "text/html; charset=utf-8"),
        (CONTENT_DISPOSITION, "inline"),
        (CACHE_CONTROL, "no-store, private"),
        (PRAGMA, "no-cache"),
        (REFERRER_POLICY, "no-referrer"),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    h.insert("x-dns-prefetch-control", HeaderValue::from_static("off"));
    h.insert("origin-agent-cluster", HeaderValue::from_static("?1"));
    h.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp(&ticket.parent_origin)).expect("validated CSP origin"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    if let Some(attestation) = &ticket.attestation {
        if insert_attestation_headers(h, attestation).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    response
}

fn insert_attestation_headers(headers: &mut HeaderMap, attestation: &Attestation) -> Result<()> {
    let values = [
        ("x-native-artifact-id", attestation.artifact_id.as_str()),
        (
            "x-native-artifact-digest",
            attestation.artifact_digest.as_str(),
        ),
        ("x-native-runtime-id", RUNTIME_ID),
        ("x-native-body-digest", attestation.body_digest.as_str()),
        ("x-native-input-digest", attestation.input_digest.as_str()),
        (
            "x-native-adapter-digest",
            attestation.adapter_digest.as_str(),
        ),
        (
            "x-native-bootstrap-digest",
            attestation.bootstrap_digest.as_str(),
        ),
        ("x-native-csp-digest", attestation.csp_digest.as_str()),
        ("x-native-input-mode", attestation.input_mode.as_str()),
        ("x-native-input-abi", attestation.input_abi.as_str()),
    ];
    for (name, value) in values {
        headers.insert(
            axum::http::header::HeaderName::from_static(name),
            HeaderValue::from_str(value)
                .map_err(|_| Error::engine("invalid native.html.v1 attestation header"))?,
        );
    }
    headers.insert(
        "x-native-adapter-revision",
        HeaderValue::from_str(&ADAPTER_REVISION.to_string())
            .map_err(|_| Error::engine("invalid native.html.v1 adapter revision"))?,
    );
    headers.insert(
        "x-native-input-count",
        HeaderValue::from_str(&attestation.input_count.to_string())
            .map_err(|_| Error::engine("invalid native.html.v1 input count"))?,
    );
    // The wire contract is a canonical port set, not declaration/request
    // insertion order. Keep this stable for the browser verifier and for
    // independently replayed launch descriptors.
    let mut input_ports = attestation.input_ports.clone();
    input_ports.sort();
    let ports = serde_json::to_string(&input_ports)
        .map_err(|_| Error::engine("invalid native.html.v1 input ports"))?;
    headers.insert(
        "x-native-input-ports",
        HeaderValue::from_str(&ports)
            .map_err(|_| Error::engine("invalid native.html.v1 input ports header"))?,
    );
    Ok(())
}

async fn verification_harness(
    State(config): State<Arc<RuntimeConfig>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !host_matches_origin(&headers, &config.workbench_origin) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ticket = take_harness_ticket(&token);
    let Some(ticket) = ticket else {
        return StatusCode::GONE.into_response();
    };
    if ticket.expires <= Instant::now() {
        return StatusCode::GONE.into_response();
    }
    let mut response = ticket.html.into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if insert_attestation_headers(headers, &ticket.attestation).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src {}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            config.artifact_origin
        ))
        .expect("validated harness CSP"),
    );
    response
}

pub fn router(config: RuntimeConfig) -> Router {
    Router::new()
        .route("/artifact-runtime/v1/launch/{ticket}", get(launch))
        .route(
            "/internal/artifacts/verification/{ticket}",
            get(verification_harness),
        )
        .with_state(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn document(extra: &str) -> String {
        format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fixture</title><style>body{{margin:0}}</style></head><body><main><h1>Hello</h1>{extra}</main></body></html>"#
        )
    }

    fn named_document(inputs: Value, capability_requests: Value) -> String {
        let declaration = serde_json::to_string(&json!({
            "schema": MANIFEST_SCHEMA,
            "inputs": inputs,
            "capability_requests": capability_requests,
        }))
        .unwrap();
        document(&format!(
            "<script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script>"
        ))
    }

    #[test]
    fn bootstrap_negotiates_full_replacement_skins_on_the_private_port() {
        assert!(BOOTSTRAP.contains("SKIN_FEATURE=\"app.skin.v1\""));
        assert!(BOOTSTRAP.contains("else if(feature===SKIN_FEATURE)skinFeature=true"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"native.skin\")receiveSkin(commandData)"));
        assert!(BOOTSTRAP.contains("data.revision<=skinRevision"));
        assert!(BOOTSTRAP.contains("skinClosed||!skinFeature"));
        assert!(BOOTSTRAP.contains("skin_revision??0"));
        assert!(BOOTSTRAP.contains("CSSStyleDeclaration.prototype.setProperty"));
        assert!(BOOTSTRAP.contains("skinText=own(Node.prototype,\"textContent\").set"));
        assert!(BOOTSTRAP.contains("DOMContentLoaded\",finish"));
        assert!(BOOTSTRAP.contains("skinSnapshot=freezeObject({labels:freezeObject({...labels})})"));
        assert!(BOOTSTRAP.contains("...(skinFeature?{skin:skinApi}:{})"));
        assert!(BOOTSTRAP.contains("get skin(){return skinFeature?skinApi:undefined}"));
        assert!(BOOTSTRAP.contains("...(skinFeature?[SKIN_FEATURE]:[])"));
    }

    // Browser qualification is explicit so the ordinary crate suite remains
    // usable without Node/Playwright. CI's Rust/core delivery browser lane runs this test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires Node 24 and the workbench Playwright Chromium installation"]
    async fn skin_bridge_real_compose_and_csp_browser() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let parent = format!("http://localhost:{port}");
        let artifact = format!("http://127.0.0.1:{port}");
        let delivery =
            LaunchDelivery::isolated_fixture(RuntimeConfig::new(&parent, &artifact).unwrap());
        let fixture = include_str!("../tests/fixtures/skin-test.html");
        let mut cases = Vec::new();
        for kit in [false, true] {
            let source = if kit {
                fixture.replace("</head>", "<script type=\"application/json\" id=\"native-app-kit\">{\"schema\":\"native.app-kit.v1\",\"major\":1}</script></head>")
            } else {
                fixture.to_owned()
            };
            let manifest = validate(&source).unwrap();
            // Exercise the real Rust insertion path as well as production
            // launch issuance/HTTP redemption, rather than extracting JS.
            assert!(inject(&source, &parent, &manifest)
                .unwrap()
                .contains("app.skin.v1"));
            for offered in [true, false] {
                let launch = delivery
                    .issue_launch(&source, &manifest, "skin-browser", None, "skin-fixture")
                    .unwrap();
                cases.push(json!({"url":launch.url,"kit":kit,"offered":offered}));
            }
        }
        let parent_html = format!(
            r#"<!doctype html><iframe sandbox="allow-scripts"></iframe><script>
const cases={cases},selected=cases[Number(new URL(location.href).searchParams.get('case'))],frame=document.querySelector('iframe');
addEventListener('message',event=>{{
 if(event.source!==frame.contentWindow||event.origin!=='null'||event.data?.type!=='native-html-bootstrap')return;
 const channel=new MessageChannel();window.probePort=channel.port1;
 channel.port1.onmessage=event=>{{if(event.data.type==='ready')window.probeReady=event.data;}};channel.port1.start();
 event.source.postMessage({{type:'native-html-init',version:'native.html.bridge.v1',host_features:selected.offered?['surface.location.v1','app.skin.v1']:['surface.location.v1'],skin_revision:1,skin:{{tokens:{{'--app-bg':'#010203'}},css:'h1{{border-radius:9px}}',labels:{{heading:'Initial'}}}}}},'*',[channel.port2]);
}});frame.src=selected.url;
</script>"#,
            cases = serde_json::to_string(&cases).unwrap()
        );
        let router = delivery.router().route(
            "/skin-probe",
            get(move || {
                let html = parent_html.clone();
                async move { axum::response::Html(html) }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let output = std::process::Command::new("node")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../experiments/demo-shell/check-app-skin-bridge.mjs"
            ))
            .arg(format!("{parent}/skin-probe"))
            .arg(csp(&parent))
            .output()
            .unwrap();
        server.abort();
        assert!(
            output.status.success(),
            "real skin bridge browser failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    #[test]
    fn kit_policy_shared_corpus_preserves_legacy_and_bounds_major() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../packages/alpha-tab-kit/test/vectors/kit-policy.json"
        ))
        .unwrap();
        for case in corpus.as_array().unwrap() {
            let result = validate(case["source"].as_str().unwrap());
            assert_eq!(
                result.is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}: {:?}",
                case["name"],
                result
            );
            if let Ok(manifest) = result {
                let expected = case["major"].as_u64().unwrap();
                assert_eq!(
                    manifest
                        .kit_policy
                        .as_ref()
                        .map(|p| u64::from(p.major))
                        .unwrap_or(0),
                    expected,
                    "{}",
                    case["name"]
                );
                let serialized = serde_json::to_value(&manifest).unwrap();
                assert_eq!(serialized.get("kit_policy").is_some(), expected != 0);
                if expected > 1 {
                    assert_eq!(
                        manifest.require_available_kit().unwrap_err().code,
                        "kit_major_unavailable"
                    );
                } else {
                    manifest.require_available_kit().unwrap();
                }
            }
        }
    }

    #[test]
    fn kit_policy_is_part_of_author_limits_and_legacy_delivery_is_unchanged() {
        let source = document(
            r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":1}</script>"#,
        );
        assert_eq!(
            validate_with_limit(&source, source.len() - 1)
                .unwrap_err()
                .code,
            "html_source_too_large"
        );
        let package_source =
            source.replace("</main>", &format!("{}</main>", " ".repeat(BODY_LIMIT)));
        assert_eq!(
            validate(&package_source).unwrap_err().code,
            "html_source_too_large"
        );
        assert!(validate_with_limit(&package_source, PACKAGE_BODY_LIMIT).is_ok());
        let manifest = validate(&source).unwrap();
        let current: Value =
            serde_json::from_str(include_str!("../kit-releases/1.1.0/manifest.json")).unwrap();
        assert!(inject(&source, "https://parent.test", &manifest)
            .unwrap()
            .contains(current["js"]["sha256"].as_str().unwrap()));
        let legacy = document("");
        let delivered =
            inject(&legacy, "https://parent.test", &validate(&legacy).unwrap()).unwrap();
        let bootstrap = BOOTSTRAP
            .replace("__NATIVE_WORKBENCH_ORIGIN__", r#""https://parent.test""#)
            .replace("__NATIVE_KIT_FACTORY__", "null")
            .replace("__NATIVE_KIT_RELEASE__", "null");
        let offset = bootstrap_insertion_offset(&legacy).unwrap();
        assert_eq!(
            delivered,
            format!(
                "{}<script>{}</script>{}",
                &legacy[..offset],
                bootstrap,
                &legacy[offset..]
            )
        );
    }

    #[test]
    fn kit_policy_refuses_legacy_launch_before_ticket_issuance() {
        let source = document(
            r#"<script type="application/json" id="native-app-kit">{"schema":"native.app-kit.v1","major":2}</script>"#,
        );
        let manifest = validate(&source).unwrap();
        let store = Mutex::new(TicketStore::default());
        let config = RuntimeConfig::new("https://parent.test", "https://artifact.test").unwrap();
        let failure = issue_launch_in_store(
            &source,
            &manifest,
            "principal",
            None,
            "artifact",
            &config,
            None,
            None,
            &store,
            None,
        )
        .err()
        .unwrap();
        assert_eq!(failure.code, "kit_major_unavailable");
        assert_eq!(failure.details["major"], 2);
        assert!(store.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn heading_skips_warn_with_the_authored_location_and_multiple_h1s_are_accepted() {
        let source =
            document("\n<h2>Workflow</h2>\n<h4>Your Mac</h4>\n<h1>Another top-level section</h1>");
        let manifest = validate(&source).expect("heading order is advisory");
        assert_eq!(manifest.diagnostics.len(), 1);
        let warning = &manifest.diagnostics[0];
        assert_eq!(warning.code, "heading-order");
        assert_eq!(warning.severity, "warning");
        assert_eq!((warning.line, warning.column), (3, 1));
        assert!(warning.message.contains("h2 \"Workflow\""));
        assert!(warning.message.contains("h4 \"Your Mac\""));
    }

    #[test]
    fn accessibility_conventions_warn_at_their_authored_location_instead_of_rejecting() {
        let source = "<!doctype html><html lang=\"en\"><head><title>Desktop</title></head><body>\n<div class=\"desktop\">\n<img src=\"data:image/png;base64,aQ==\">\n<button tabindex=\"2\">Start</button>\n</div></body></html>";
        let manifest = validate(source).expect("accessibility conventions are advisory");
        let found = manifest
            .diagnostics
            .iter()
            .map(|warning| (warning.code, warning.severity, warning.line))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            [
                ("image-alt", "warning", 3),
                ("positive-tabindex", "warning", 4),
                ("document-charset", "warning", 1),
                ("document-viewport", "warning", 1),
                ("landmarks", "warning", 1),
                ("missing-h1", "warning", 1),
            ]
        );
        assert!(manifest
            .diagnostics
            .iter()
            .all(|warning| !warning.message.contains("position unavailable")));
        let two_mains = document("\n<main>Second</main>");
        let warning = validate(&two_mains).unwrap().diagnostics.remove(0);
        assert_eq!(warning.code, "landmarks");
        assert!(warning.message.contains("2 <main> elements"));
        // lang and a non-empty title stay required: the host names the
        // artifact by its title and assistive technology reads by its lang.
        let untitled = document("").replace("<title>Fixture</title>", "<title> </title>");
        assert_eq!(
            validate(&untitled).unwrap_err().details["rule"],
            "document-envelope"
        );
    }

    #[test]
    fn every_rejection_is_reported_in_one_failure_with_its_own_location() {
        let source = document(
            "\n<link rel=\"stylesheet\" href=\"x.css\">\n<p>ok</p>\n<script src=\"https://evil.test/x.js\"></script>\n<iframe></iframe>\n<link rel=\"icon\" href=\"y.png\">",
        )
        .replace("<style>body{margin:0}</style>", "<style>@import 'x.css';</style>");
        let failure = validate(&source).unwrap_err();
        assert_eq!(failure.code, "html_policy_violation");
        assert_eq!(failure.details["violation_count"], 5);
        assert!(failure.details.get("line").is_none());
        let listed = failure.details["violations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|violation| {
                (
                    violation["details"]["rule"].as_str().unwrap().to_owned(),
                    violation["details"]["line"].as_u64(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            listed,
            [
                ("external-link-resource".to_owned(), Some(2)),
                ("external-script".to_owned(), Some(4)),
                ("forbidden-element".to_owned(), Some(5)),
                ("external-link-resource".to_owned(), Some(6)),
                ("css-import".to_owned(), None),
            ]
        );
        assert!(failure.message.starts_with("5 problems; fix all of them"));
        assert!(failure
            .message
            .contains("(3) <iframe> is forbidden at line 5, column 1 [forbidden-element]"));
        // One rejection keeps its original shape.
        let single = validate(&document("<iframe></iframe>")).unwrap_err();
        assert_eq!(single.message, "<iframe> is forbidden");
        assert!(single.details.get("violations").is_none());
        assert_eq!(single.details["line"], 1);
    }

    #[test]
    fn only_a_rejection_by_name_absorbs_the_elements_url_attribute() {
        // profile-count is not about URLs, so the href is its own rejection.
        let source = document("").replace(
            "<title>",
            "<meta name=\"native-artifact-profile\" content=\"document\"><meta name=\"native-artifact-profile\" content=\"document\" href=\"https://evil.test/\"><title>",
        );
        let failure = validate(&source).unwrap_err();
        let rules = failure.details["violations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|violation| violation["details"]["rule"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rules, ["profile-count", "url-attribute"]);
    }

    #[test]
    fn template_contents_do_not_skew_locations() {
        let source = document(
            "<template><div><img></div></template>\n<div><a href=\"https://evil.test/\">x</a></div>",
        );
        let failure = validate(&source).unwrap_err();
        assert_eq!(failure.details["rule"], "url-attribute");
        assert_eq!(failure.details["line"], 2);
    }

    #[test]
    fn a_long_list_of_rejections_is_capped() {
        let source = document(&"<iframe></iframe>".repeat(VIOLATION_REPORT_LIMIT + 3));
        let failure = validate(&source).unwrap_err();
        assert_eq!(
            failure.details["violation_count"],
            VIOLATION_REPORT_LIMIT + 3
        );
        assert_eq!(
            failure.details["violations"].as_array().unwrap().len(),
            VIOLATION_REPORT_LIMIT
        );
        assert!(failure.message.ends_with("; and 3 more"));
    }

    #[test]
    fn heading_location_ignores_comment_and_script_lookalikes() {
        let source = document("<!-- <h2>Fake</h2> -->\n<script>const sample = '<h3>Fake</h3>';</script>\n<h2>Real</h2>\n<h4>Nested</h4>");
        let warning = validate(&source).unwrap().diagnostics.remove(0);
        assert_eq!(warning.code, "heading-order");
        assert_eq!(warning.line, 4);
        assert!(warning.message.contains("h2 \"Real\""));
    }

    #[test]
    fn write_diagnostics_flag_an_undefined_identifier_at_its_body_position() {
        // The `taskClientNames` case from commit 3c2461b: a call to a function
        // the document never defines. Exactly one finding, at the body line a
        // person would click.
        let source = document("<script>\n  const names = taskClientNames();\n</script>");
        let manifest = validate(&source).expect("document validates; warnings never reject");
        assert_eq!(manifest.diagnostics.len(), 1);
        let finding = &manifest.diagnostics[0];
        assert_eq!(
            finding.format,
            crate::write_diagnostics::WRITE_DIAGNOSTIC_FORMAT
        );
        assert_eq!(finding.code, "html_undefined_identifier");
        assert_eq!(finding.severity, "warning");
        assert_eq!(finding.name.as_deref(), Some("taskClientNames"));
        assert_eq!(
            finding.message,
            "`taskClientNames` is not defined in this document"
        );
        let line = source.lines().nth(finding.line - 1).expect("line exists");
        assert!(
            line.contains("taskClientNames"),
            "points at the identifier: {line}"
        );
        assert_eq!(finding.column, line.find("taskClientNames").unwrap() + 1);
    }

    #[test]
    fn write_diagnostics_subtract_browser_and_ecmascript_globals() {
        let source = document(
            "<script>\n  var map = new Map();\n  var text = JSON.stringify(Object.keys({a: 1}));\n  var t = Promise.resolve(requestAnimationFrame).then(function () { return document.title; });\n  window.__probe = { map: map, text: text, t: t, crypto: crypto, url: new URL(\"about:blank\") };\n</script>",
        );
        let manifest = validate(&source).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "a browser or ECMAScript global is not a finding: {:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_flag_an_undeclared_input_port_read() {
        let source = named_document(
            json!({
                "records": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
            }),
            json!([{ "capability": "input.read", "scope": { "port": "records" } }]),
        );
        let source = source.replace(
            "</main>",
            "<script>window.nativeArtifact.ready.then(function (delivery) { return delivery.input.inputs.archive; });</script></main>",
        );
        let manifest = validate(&source).expect("document validates");
        let ports: Vec<_> = manifest
            .diagnostics
            .iter()
            .filter(|finding| finding.code == "html_unknown_input_port")
            .collect();
        assert_eq!(ports.len(), 1, "{:?}", manifest.diagnostics);
        assert_eq!(ports[0].severity, "warning");
        assert_eq!(ports[0].name.as_deref(), Some("archive"));
        assert_eq!(ports[0].message, "No input port named `archive` is bound");

        // A declared port is not a finding.
        let declared = source.replace("inputs.archive", "inputs.records");
        let manifest = validate(&declared).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_flag_an_undeclared_interaction_entry() {
        let declaration = json!({
            "schema": INTERACTIVE_MANIFEST_SCHEMA,
            "inputs": {"rows":{"envelope":COLLECTION_ENVELOPE,"required":true,"expose_to_root":true}},
            "capability_requests":[{"capability":"input.read","scope":{"port":"rows"}}],
            "interactions":[{"id":"triage","label":"Triage","effect":"facet.set",
                "slots":{"record":{"domain":{"kind":"bound_input","port":"rows"}}},
                "facet":"triage","value":{"from":"literal","value":"done"}}],
        });
        let source = document(&format!(
            "<script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script><script>window.nativeArtifact.propose({{request_id:\"r1\",entry_id:\"missing\",slots:{{}},values:{{}}}});</script>"
        ));
        let manifest = validate(&source).expect("document validates");
        let entries: Vec<_> = manifest
            .diagnostics
            .iter()
            .filter(|finding| finding.code == "html_unknown_interaction_entry")
            .collect();
        assert_eq!(entries.len(), 1, "{:?}", manifest.diagnostics);
        assert_eq!(entries[0].name.as_deref(), Some("missing"));
        assert_eq!(
            entries[0].message,
            "No interaction entry named `missing` is declared in this document"
        );

        // The declared entry id is not a finding.
        let declared = source.replace("entry_id:\"missing\"", "entry_id:\"triage\"");
        let manifest = validate(&declared).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_pass_is_cached_and_skipped_for_scriptless_bodies() {
        let source =
            document("<script>window.__cache_probe_marker = Object.keys({a: 1});</script>");
        let digest = digest_of(&source);
        let first = validate_cached(&source).expect("document validates");
        let second = validate_cached(&source).expect("document validates");
        assert_eq!(
            crate::write_diagnostics::test_probe::runs_for(&digest),
            1,
            "the same body digest must not re-run the pass"
        );
        assert_eq!(first.diagnostics, second.diagnostics);

        let scriptless = document("<p>no script here</p>");
        let scriptless_digest = digest_of(&scriptless);
        let _ = validate_cached(&scriptless).expect("document validates");
        assert_eq!(
            crate::write_diagnostics::test_probe::runs_for(&scriptless_digest),
            0,
            "a body with no inline script must not run the pass"
        );
    }

    fn digest_of(source: &str) -> String {
        hex::encode(Sha256::digest(source.as_bytes()))
    }

    #[test]
    fn write_diagnostics_share_top_level_declarations_across_script_blocks() {
        // Classic scripts run in one shared global scope, so a top-level
        // declaration in one block is defined in every later block. Splitting
        // bootstrap from app code is ordinary authoring and must not be noisy.
        for body in [
            "<script>function helper(){return 1;}</script><script>window.__x = helper();</script>",
            "<script>var shared = 1;</script><script>window.__x = shared + 1;</script>",
            "<script>let lexical = 1;</script><script>window.__x = lexical + 1;</script>",
            "<script>if (true) { var hoisted = 1; }</script><script>window.__x = hoisted;</script>",
        ] {
            let manifest = validate(&document(body)).expect("document validates");
            assert!(
                manifest.diagnostics.is_empty(),
                "{body} produced {:?}",
                manifest.diagnostics
            );
        }
        // A name declared only inside a function is still not defined outside.
        let nested = document(
            "<script>function outer(){ var inner = 1; }</script><script>window.__x = inner;</script>",
        );
        let manifest = validate(&nested).expect("document validates");
        assert_eq!(manifest.diagnostics.len(), 1, "{:?}", manifest.diagnostics);
        assert_eq!(manifest.diagnostics[0].name.as_deref(), Some("inner"));
    }

    #[test]
    fn write_diagnostics_exempt_the_typeof_operand() {
        let source = document(
            "<script>if (typeof analytics !== \"undefined\") { window.__x = analytics; }</script>",
        );
        let manifest = validate(&source).expect("document validates");
        let findings: Vec<_> = manifest
            .diagnostics
            .iter()
            .filter(|finding| finding.code == "html_undefined_identifier")
            .collect();
        assert_eq!(findings.len(), 1, "{:?}", manifest.diagnostics);
        assert_eq!(findings[0].name.as_deref(), Some("analytics"));
        // The survivor is the guarded use, not the `typeof` operand.
        let line = source.lines().nth(findings[0].line - 1).expect("line");
        assert!(
            findings[0].column - 1 > line.find("analytics").unwrap(),
            "finding {} should be the later occurrence on {line:?}",
            findings[0].column
        );
    }

    #[test]
    fn write_diagnostics_map_positions_for_crlf_authored_bodies() {
        let lf = document("<script>\n  const names = taskClientNames();\n</script>");
        let crlf = lf.replace('\n', "\r\n");
        let lf_manifest = validate(&lf).expect("LF document validates");
        let crlf_manifest = validate(&crlf).expect("CRLF document validates");
        assert_eq!(
            lf_manifest.diagnostics.len(),
            1,
            "{:?}",
            lf_manifest.diagnostics
        );
        assert_eq!(
            crlf_manifest.diagnostics.len(),
            1,
            "a CRLF body must not silently disable the pass: {:?}",
            crlf_manifest.diagnostics
        );
        assert_eq!(
            lf_manifest.diagnostics[0].line,
            crlf_manifest.diagnostics[0].line
        );
        assert_eq!(
            lf_manifest.diagnostics[0].column,
            crlf_manifest.diagnostics[0].column
        );
    }

    #[test]
    fn write_diagnostics_place_findings_at_the_script_body_not_an_earlier_comment() {
        let source =
            document("<!-- window.__x = nosuch4(); --><script>window.__x = nosuch4();</script>");
        let manifest = validate(&source).expect("document validates");
        assert_eq!(manifest.diagnostics.len(), 1, "{:?}", manifest.diagnostics);
        let finding = &manifest.diagnostics[0];
        let line = source.lines().nth(finding.line - 1).expect("line");
        let real = line.rfind("nosuch4").expect("real call") + 1;
        assert_eq!(
            finding.column, real,
            "finding must point at the script body"
        );
    }

    #[test]
    fn write_diagnostics_do_not_take_offsets_from_a_commented_out_script() {
        // Two raw bodies with byte-identical text: the commented-out copy and
        // the live script. The finding must point at the live one.
        let source = document(
            "<!-- <script>window.__x = nosuch5();</script> --><script>window.__x = nosuch5();</script>",
        );
        let manifest = validate(&source).expect("document validates");
        assert_eq!(manifest.diagnostics.len(), 1, "{:?}", manifest.diagnostics);
        let finding = &manifest.diagnostics[0];
        let line = source.lines().nth(finding.line - 1).expect("line");
        let calls: Vec<usize> = line
            .match_indices("nosuch5")
            .map(|(index, _)| index + 1)
            .collect();
        assert_eq!(calls.len(), 2, "{line:?}");
        assert_eq!(
            finding.column, calls[1],
            "the live script's offset, not the comment's"
        );
    }

    #[test]
    fn write_diagnostics_cross_script_union_is_order_insensitive() {
        // Documented warning-only trade: a call in an earlier block to a
        // function declared in a later block is not reported, though it throws
        // at runtime. Step 4 must revisit this before promoting to rejection.
        let source = document(
            "<script>window.__a = laterDef();</script><script>function laterDef(){}</script>",
        );
        let manifest = validate(&source).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_ignore_a_reassigned_port_map_alias() {
        let source = named_document(
            json!({
                "records": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
            }),
            json!([{ "capability": "input.read", "scope": { "port": "records" } }]),
        )
        .replace(
            "</main>",
            "<script>var d = { input: { inputs: {} } }; var m = d.input.inputs; m = {}; window.__x = m.anything;</script></main>",
        );
        let manifest = validate(&source).expect("document validates");
        assert!(
            manifest
                .diagnostics
                .iter()
                .all(|finding| finding.code != "html_unknown_input_port"),
            "a reassigned alias is not the port map: {:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_do_not_treat_an_arbitrary_object_as_the_bridge() {
        let source = document(
            "<script>var o = {}; o.nativeArtifact = { propose: function () {} }; o.nativeArtifact.propose({ entry_id: \"ghost\" });</script>",
        );
        let manifest = validate(&source).expect("document validates");
        assert!(
            manifest
                .diagnostics
                .iter()
                .all(|finding| finding.code != "html_unknown_interaction_entry"),
            "only the real bridge is policed: {:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_do_not_report_port_map_prototype_members() {
        let source = named_document(
            json!({
                "records": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
            }),
            json!([{ "capability": "input.read", "scope": { "port": "records" } }]),
        )
        .replace(
            "</main>",
            "<script>window.nativeArtifact.ready.then(function (delivery) { var inputs = delivery.input.inputs; inputs.forEach(function () {}); Object.keys(inputs); });</script></main>",
        );
        let manifest = validate(&source).expect("document validates");
        assert!(
            manifest
                .diagnostics
                .iter()
                .all(|finding| finding.code != "html_unknown_input_port"),
            "Object/Map prototype members are not ports: {:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn write_diagnostics_allow_element_id_globals_and_suppress_with() {
        let ids = document("<div id=\"panel\"></div><script>panel.innerHTML = \"\";</script>");
        let manifest = validate(&ids).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "{:?}",
            manifest.diagnostics
        );

        // `with` makes static scope unsound, so the script gets no undefined
        // findings rather than a stream of false positives.
        let with = document("<script>with (document) { window.__x = title; }</script>");
        let manifest = validate(&with).expect("document validates");
        assert_eq!(
            manifest.diagnostics,
            Vec::new(),
            "{:?}",
            manifest.diagnostics
        );
    }

    /// Every real `native.html.v1` artifact checked into the repository, plus
    /// the HTML documents in the authoring guide. The test prints every finding
    /// so the pull request can carry the corpus list verbatim, and fails if a
    /// known-good artifact is flagged at all: a false positive is a bug in the
    /// allowlist or a rule, not an accepted warning.
    #[test]
    fn checked_in_html_corpus_reports_its_write_diagnostics() {
        let mut corpus: Vec<(String, String)> = vec![
            (
                "tests/fixtures/native-html-v1-document.html".into(),
                include_str!("../../../tests/fixtures/native-html-v1-document.html").into(),
            ),
            (
                "tests/fixtures/native-html-v1-slides.html".into(),
                include_str!("../../../tests/fixtures/native-html-v1-slides.html").into(),
            ),
            (
                "tests/fixtures/native-html-v1-named-input.html".into(),
                include_str!("../../../tests/fixtures/native-html-v1-named-input.html").into(),
            ),
            (
                "tests/fixtures/native-html-v1-live-input.html".into(),
                include_str!("../../../tests/fixtures/native-html-v1-live-input.html").into(),
            ),
            (
                "tests/fixtures/native-html-v1-view-state.html".into(),
                include_str!("../../../tests/fixtures/native-html-v1-view-state.html").into(),
            ),
            (
                "crates/artifact-html/tests/fixtures/adversarial-native-html.html".into(),
                include_str!("../tests/fixtures/adversarial-native-html.html").into(),
            ),
        ];
        let guide = include_str!("../../../src/mcp/guides/compositions.md");
        for (index, block) in fenced_html_documents(guide).into_iter().enumerate() {
            corpus.push((format!("src/mcp/guides/compositions.md #{index}"), block));
        }
        // The guide's recommended authoring pattern, injected into its own
        // document: the JSDoc-typed plain-JS script the guide tells authors to
        // write. It must not be flagged, and its `inputs.nodes`/`inputs.edges`
        // reads must be recognised as declared ports.
        if let (Some(document), Some(script)) = (
            fenced_html_documents(guide).into_iter().next(),
            fenced_block(guide, "js"),
        ) {
            corpus.push((
                "src/mcp/guides/compositions.md JSDoc example".into(),
                document.replace("</body>", &format!("<script>\n{script}\n</script></body>")),
            ));
        }

        let mut false_positives = Vec::new();
        for (name, source) in &corpus {
            match validate(source) {
                Ok(manifest) => {
                    if manifest.diagnostics.is_empty() {
                        println!("== {name}: no findings");
                    } else {
                        for finding in &manifest.diagnostics {
                            println!(
                                "== {name}: {} [{}] line {} column {} name {:?}\n   {}",
                                finding.code,
                                finding.severity,
                                finding.line,
                                finding.column,
                                finding.name.as_deref().unwrap_or("-"),
                                finding.message
                            );
                        }
                        false_positives.push(name.clone());
                    }
                }
                Err(failure) => {
                    println!("== {name}: rejected [{}] {}", failure.code, failure.message);
                }
            }
        }
        assert!(
            false_positives.is_empty(),
            "in-repo artifacts must not be flagged: {false_positives:?}"
        );

        // The motivating case: exactly one finding, named and positioned.
        let motivating = document("<script>\n  const names = taskClientNames();\n</script>");
        let manifest = validate(&motivating).expect("document validates");
        assert_eq!(manifest.diagnostics.len(), 1, "{:?}", manifest.diagnostics);
        println!(
            "== reconstructed:taskClientNames(3c2461b): {} [{}] line {} column {} name {:?}\n   {}",
            manifest.diagnostics[0].code,
            manifest.diagnostics[0].severity,
            manifest.diagnostics[0].line,
            manifest.diagnostics[0].column,
            manifest.diagnostics[0].name.as_deref().unwrap_or("-"),
            manifest.diagnostics[0].message,
        );
    }

    fn fenced_html_documents(markdown: &str) -> Vec<String> {
        let mut documents = Vec::new();
        let mut remaining = markdown;
        while let Some(start) = remaining.find("```html") {
            let after = &remaining[start + "```html".len()..];
            let Some(end) = after.find("```") else {
                break;
            };
            let block = after[..end].trim_start_matches('\n');
            if block.trim_start().starts_with("<!doctype") {
                documents.push(block.to_owned());
            }
            remaining = &after[end + 3..];
        }
        documents
    }

    fn fenced_block(markdown: &str, tag: &str) -> Option<String> {
        let opener = format!("```{tag}\n");
        let start = markdown.find(&opener)? + opener.len();
        let after = &markdown[start..];
        let end = after.find("```")?;
        Some(after[..end].trim_end().to_owned())
    }

    #[test]
    fn named_declaration_is_exact_and_admits_relation_and_grouped_ports() {
        let relation_schema = "a".repeat(64);
        let source = named_document(
            json!({
                "rows": {
                    "envelope": RELATION_ENVELOPE,
                    "required": true,
                    "expose_to_root": true,
                    "schema_sha256": relation_schema,
                    "relations": {
                        "records": { "identity": "native.query-sql.records", "semantic_version": 1 }
                    }
                },
                "counts": {
                    "envelope": GROUPED_COUNT_ENVELOPE,
                    "required": false,
                    "expose_to_root": true,
                    "projection": {
                        "kind": "grouped_count",
                        "axis": { "kind": "facet", "key": "status" }
                    }
                }
            }),
            json!([
                { "capability": "input.read", "scope": { "port": "rows" } },
                { "capability": "input.read", "scope": { "port": "counts" } }
            ]),
        );
        let manifest = validate(&source).expect("named HTML declaration validates");
        assert!(manifest.named_inputs_declared);
        assert_eq!(manifest.artifact_ports.len(), 2);
        assert_eq!(
            manifest.artifact_ports["rows"]["envelope"],
            RELATION_ENVELOPE
        );
        assert_eq!(
            manifest.artifact_ports["counts"]["envelope"],
            GROUPED_COUNT_ENVELOPE
        );
        assert_eq!(manifest.capability_requests.len(), 2);
        assert_eq!(
            descriptor()["declaration_surface"]["schema"],
            MANIFEST_SCHEMA
        );
        assert_eq!(
            descriptor()["limits"]["named_input_safe_integer_min"],
            NAMED_INPUT_SAFE_INTEGER_MIN
        );
        assert_eq!(
            descriptor()["limits"]["named_input_safe_integer_max"],
            NAMED_INPUT_SAFE_INTEGER_MAX
        );
    }

    #[test]
    fn named_declaration_fails_closed_for_duplicates_unknown_capabilities_and_reserved_ports() {
        let base = json!({
            "schema": MANIFEST_SCHEMA,
            "inputs": {
                "rows": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
            },
            "capability_requests": [{ "capability": "input.read", "scope": { "port": "rows" } }]
        });
        let duplicate = document(&format!(
            "<meta name=\"native-artifact-manifest\" content='{}'><script type=\"application/json\" id=\"native-artifact-manifest\">{}</script>",
            serde_json::to_string(&base).unwrap(),
            serde_json::to_string(&base).unwrap()
        ));
        assert_eq!(
            validate(&duplicate).unwrap_err().code,
            "html_named_input_invalid"
        );

        let unknown_capability = json!({
            "rows": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
        });
        let failure = validate(&named_document(
            unknown_capability,
            json!([{ "capability": "database.read", "scope": { "port": "rows" } }]),
        ))
        .unwrap_err();
        assert_eq!(failure.code, "html_named_input_invalid");

        let unexposed = validate(&named_document(
            json!({
                "rows": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": false }
            }),
            json!([{ "capability": "input.read", "scope": { "port": "rows" } }]),
        ))
        .unwrap_err();
        assert_eq!(unexposed.code, "html_named_input_invalid");
        assert!(unexposed.message.contains("expose_to_root=true"));

        let reserved = validate(&named_document(
            json!({
                "default": { "envelope": COLLECTION_ENVELOPE, "required": true, "expose_to_root": true }
            }),
            json!([]),
        ))
        .unwrap_err();
        assert_eq!(reserved.code, "html_named_input_invalid");
    }

    #[test]
    fn body_set_html_uses_shared_closed_grammar_without_execution() {
        let mut declaration = json!({
            "schema": INTERACTIVE_MANIFEST_SCHEMA,
            "inputs":{"rows":{"envelope":COLLECTION_ENVELOPE,"required":true,"expose_to_root":true}},
            "capability_requests":[{"capability":"input.read","scope":{"port":"rows"}}],
            "interactions":[{"id":"save","label":"Save","effect":"body.set",
                "slots":{"page":{"domain":{"kind":"bound_input","port":"rows"}}},
                "body":{"max_bytes":32768}}]
        });
        let source = |v: &Value| {
            document(&format!(
                "<script type=\"application/json\" id=\"native-artifact-manifest\">{v}</script>"
            ))
        };
        let parsed = validate(&source(&declaration)).unwrap();
        assert_eq!(parsed.interactions[0].effect.as_str(), "body.set");
        declaration["interactions"][0]["body"]["max_bytes"] =
            json!(native_artifact_runtime::mdx_v2::BODY_SET_MAX_BODY_BYTES);
        assert!(validate(&source(&declaration)).is_ok());
        for cap in [
            json!(0),
            json!(native_artifact_runtime::mdx_v2::BODY_SET_MAX_BODY_BYTES + 1),
            json!(true),
            json!(1.5),
        ] {
            let mut bad = declaration.clone();
            bad["interactions"][0]["body"]["max_bytes"] = cap;
            assert!(validate(&source(&bad)).is_err());
        }
        declaration["interactions"][0]["body"]["extra"] = json!(1);
        assert!(validate(&source(&declaration)).is_err());
        declaration["interactions"][0]["body"]
            .as_object_mut()
            .unwrap()
            .remove("extra");
        declaration["interactions"][0]["effect"] = json!("title.set");
        declaration["interactions"][0]["title"] = json!({});
        assert_eq!(
            validate(&source(&declaration)).unwrap_err().code,
            "interaction_entry_invalid"
        );
    }

    #[test]
    fn interactive_declaration_reuses_closed_entries_and_keeps_v1_read_only() {
        let mut declaration = json!({
            "schema": INTERACTIVE_MANIFEST_SCHEMA,
            "inputs": {"rows":{"envelope":COLLECTION_ENVELOPE,"required":true,"expose_to_root":true}},
            "capability_requests":[{"capability":"input.read","scope":{"port":"rows"}}],
            "interactions":[{"id":"triage","label":"Triage","effect":"facet.set",
                "slots":{"record":{"domain":{"kind":"bound_input","port":"rows"}}},
                "facet":"triage","value":{"from":"literal","value":"done"}}],
        });
        let source = |value: &Value| {
            document(&format!("<script type=\"application/json\" id=\"native-artifact-manifest\">{value}</script>"))
        };
        let manifest = validate(&source(&declaration)).unwrap();
        assert_eq!(manifest.interactions.len(), 1);
        assert_eq!(
            manifest.interaction_manifest().interactions,
            manifest.interactions
        );
        for facet in ["runtime", "archived", "blob_ref"] {
            let mut invalid = declaration.clone();
            invalid["interactions"][0]["facet"] = json!(facet);
            assert_eq!(
                validate(&source(&invalid)).unwrap_err().code,
                "interaction_entry_invalid"
            );
        }
        let mut invalid = declaration.clone();
        invalid["interactions"][0]["actor"] = json!("forged");
        assert!(validate(&source(&invalid)).is_err());
        invalid = declaration.clone();
        invalid["interactions"][0]["slots"]["record"]["domain"]["port"] = json!("outside");
        assert_eq!(
            validate(&source(&invalid)).unwrap_err().code,
            "interaction_entry_invalid"
        );
        invalid = declaration.clone();
        invalid["interactions"]
            .as_array_mut()
            .unwrap()
            .push(declaration["interactions"][0].clone());
        assert_eq!(
            validate(&source(&invalid)).unwrap_err().code,
            "interaction_entry_invalid"
        );
        declaration["schema"] = json!(MANIFEST_SCHEMA);
        assert!(validate(&source(&declaration)).is_err());
        declaration.as_object_mut().unwrap().remove("interactions");
        assert!(validate(&source(&declaration))
            .unwrap()
            .interactions
            .is_empty());
    }

    #[test]
    fn bootstrap_offers_app_call_only_behind_the_host_feature() {
        // App contract v2: neither the method nor the alias exists unless the
        // host's init lists app.call.v2; there is no declared-need check.
        assert!(BOOTSTRAP.contains("get call(){return callFeature?callOperation:undefined}"));
        assert!(BOOTSTRAP.contains("else if(feature===CALL_FEATURE)callFeature=true;"));
        assert!(BOOTSTRAP.contains("const CALL_FEATURE=\"app.call.v2\""));
        assert!(BOOTSTRAP.contains(
            "if(callFeature||sessionFeature||subscribeFeature||agentsFeature||agentSessionsFeature||presentationFeature||skinFeature)exposeNative();"
        ));
        assert!(BOOTSTRAP.contains("freezeObject({...(callFeature?{call:callOperation}:{})"));
        assert!(!BOOTSTRAP.contains("apply(arrayIncludes,offeredNeeds,[operation])"));
        // Bounded: 8 in flight, 256 KiB of args, a 1 MiB answer, matched by id.
        assert!(BOOTSTRAP.contains("pendingCallCount>=8"));
        assert!(BOOTSTRAP.contains("encoded.length>262144"));
        assert!(BOOTSTRAP.contains(
            "answer=encoded.length>1048576?freezeObject({status:\"error\",code:\"too_large\"})"
        ));
        assert!(BOOTSTRAP.contains("commandData?.type===\"call-result\")settleCall(commandData)"));
        assert!(BOOTSTRAP.contains("own(pendingCalls,data.request_id)"));
        // Closing the port answers every pending call once, uncertain, and
        // frees the in-flight budget; args must still be an object after the
        // JSON round trip (a toJSON can make a scalar or array).
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",closeCalls)"));
        assert!(BOOTSTRAP.contains("listen(window,\"pagehide\",closeCalls,true)"));
        assert!(BOOTSTRAP.contains("callFailure(\"uncertain\",\"port_closed\""));
        assert!(BOOTSTRAP.contains("call args must serialize to an object"));
        assert!(BOOTSTRAP
            .contains("send({version:VERSION,type:\"call\",request_id,operation,args:payload})"));
    }

    #[test]
    fn bootstrap_offers_app_session_only_behind_the_host_feature() {
        // App contract v2 (live co-editing): neither nativeArtifact.session nor
        // window.native.session exists unless the host's init lists app.session.v2.
        assert!(BOOTSTRAP.contains("const SESSION_FEATURE=\"app.session.v2\""));
        assert!(BOOTSTRAP.contains("else if(feature===SESSION_FEATURE)sessionFeature=true;"));
        assert!(BOOTSTRAP.contains("get session(){return sessionFeature?sessionApi:undefined}"));
        assert!(BOOTSTRAP.contains("...(sessionFeature?{session:sessionApi}:{})"));
        assert!(BOOTSTRAP.contains("const sessionApi=freezeObject({open:openSession});"));
        // open validates the record id and mode, sends the frozen host shape and
        // returns the channel synchronously.
        assert!(BOOTSTRAP.contains(
            "value.length<=128&&apply(regExpExec,/[\\u0000-\\u001f\\u007f\\s]/,[value])===null"
        ));
        assert!(BOOTSTRAP.contains("session mode must be edit or view"));
        assert!(BOOTSTRAP.contains("const mode=given.mode===undefined?\"edit\":given.mode;"));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"session-open\",request_id,record_id:recordId,mode})"
        ));
        assert!(BOOTSTRAP.contains("const channel_=freezeObject({send:frame=>sessionSend(session,frame),onMessage:callback=>sessionSubscribe(session,callback),close:"));
        // Bounded: 16 open sessions, 1 MiB per frame either way, 64 queued
        // frames before the port arrives, frames are objects with a string op.
        assert!(BOOTSTRAP.contains("openSessionCount>=16"));
        assert!(BOOTSTRAP.contains(
            "const size=contextBytes(encoded,1048576);if(size>1048576)return\"too_large\""
        ));
        assert!(BOOTSTRAP.contains("typeof payload.op!==\"string\""));
        assert!(BOOTSTRAP.contains("session.queue.length>=64"));
        // Matched by request id; exactly one transferred port, else the port is
        // closed and the session errors. An unknown or closed session's port is
        // closed so the host sees it end.
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"session-opened\"||commandData?.type===\"session-refused\")settleSession(commandData,read(messagePorts,message))"
        ));
        assert!(BOOTSTRAP
            .contains("if(!session||session.done||session.port){releasePorts(ports);return}"));
        assert!(BOOTSTRAP.contains("if(!ports||ports.length!==1){releasePorts(ports);failSession("));
        assert!(BOOTSTRAP.contains("portClose=MessagePort.prototype.close"));
        // The host is told a session ended in-band, before the port closes.
        assert!(BOOTSTRAP.contains(
            "const endPort=(port,notify)=>{if(notify)try{post(port,{type:\"session-close\"})}catch{}try{apply(portClose,port,[])}catch{}};"
        ));
        // The same goodbye on a late or unknown session's port, so the host frees
        // the session it opened; a host-ended session closes without one.
        assert!(BOOTSTRAP.contains("endPort(ports[index],true)"));
        assert!(BOOTSTRAP.contains("session.hostEnded=true;endSession(session,false)"));
        assert!(BOOTSTRAP.contains("frame.op===\"session.refused\"&&typeof frame.key===\"string\""));
        assert!(BOOTSTRAP.contains("refuseSession(\"closed\",\"the host ended this session\")"));
        // Queued frames are bounded in total, across sessions, by bytes.
        assert!(BOOTSTRAP.contains("sessionQueuedBytes+size>4194304"));
        // A failure reaches subscribers once as session.error, then the channel
        // closes; the main port closing fails every open session.
        assert!(BOOTSTRAP
            .contains("freezeObject({op:\"session.error\",code,message:bounded(message)})"));
        assert!(BOOTSTRAP.contains("if(session.done)return;const frame="));
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",closeSessions)"));
        assert!(BOOTSTRAP.contains("listen(channel,\"messageerror\",closeSessions)"));
        assert!(BOOTSTRAP.contains("listen(window,\"pagehide\",closeSessions,true)"));
        assert!(BOOTSTRAP.contains("failSession(sessions[id],\"port_closed\""));
        // The sandbox, CSP and permissions are untouched: no new global but the
        // frozen aliases, and the port is only ever the transferred one.
        assert!(!BOOTSTRAP.contains("window.open"));
    }

    #[test]
    fn bootstrap_offers_app_query_and_subscribe_only_behind_the_host_feature() {
        // App contract v2 (instant reads): neither nativeArtifact.query/subscribe
        // nor window.native.query/subscribe exists unless the host's init lists
        // app.subscribe.v2.
        assert!(BOOTSTRAP.contains("const SUBSCRIBE_FEATURE=\"app.subscribe.v2\""));
        assert!(BOOTSTRAP.contains("else if(feature===SUBSCRIBE_FEATURE)subscribeFeature=true;"));
        assert!(BOOTSTRAP.contains("get query(){return subscribeFeature?queryOperation:undefined}"));
        assert!(BOOTSTRAP
            .contains("get subscribe(){return subscribeFeature?subscribeOperation:undefined}"));
        assert!(BOOTSTRAP.contains(
            "...(subscribeFeature?{query:queryOperation,subscribe:subscribeOperation}:{})"
        ));
        // The fixed wire shapes, frame to host. The frame's `params` travel as
        // the engine's positional `parameters`; no as_of sequence is exposed.
        assert!(BOOTSTRAP
            .contains("send({version:VERSION,type:\"query\",request_id,query:wire.query})"));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"subscribe\",subscription_id:subscription.id,query:wire.query})"
        ));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"unsubscribe\",subscription_id:subscription.id})"
        ));
        assert!(BOOTSTRAP.contains("parameters:given.params===undefined?[]:given.params"));
        assert!(!BOOTSTRAP.contains("as_of_seq"));
        // A structured query (R4) travels as query_record's own steps, order,
        // limit and offset; the two forms never mix.
        assert!(BOOTSTRAP.contains(
            "jsonStringify({steps:given.steps,order:given.order,limit:given.limit,offset:given.offset})"
        ));
        assert!(BOOTSTRAP.contains(
            "if(structured?!!own(given,\"sql\")||!!own(given,\"params\"):!!own(given,\"order\")||!!own(given,\"limit\")||!!own(given,\"offset\"))"
        ));
        assert!(BOOTSTRAP.contains(
            "if(structured){if(!query||!isArray(query.steps)||query.steps.length<1)return{code:\"malformed\""
        ));
        // Host to frame, matched by id; the port closing ends everything.
        assert!(BOOTSTRAP.contains("commandData?.type===\"query-result\")settleQuery(commandData)"));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"subscription-result\"||commandData?.type===\"subscription-error\")receiveSubscription(commandData)"
        ));
        assert!(BOOTSTRAP.contains("own(pendingQueries,data.request_id)"));
        assert!(BOOTSTRAP.contains("own(subscriptions,data.subscription_id)"));
        // Bounded: 8 queries in flight, 32 subscriptions, a 256 KiB query and a
        // 1 MiB result, with the argument rechecked after the JSON round trip.
        assert!(BOOTSTRAP.contains("pendingQueryCount>=8)return refuseQuery(\"busy\""));
        assert!(
            BOOTSTRAP.contains("openSubscriptionCount>=32)return refuse(\"subscription_limit\"")
        );
        assert!(BOOTSTRAP.contains("encoded.length>262144)return{code:\"too_large\""));
        assert!(BOOTSTRAP.contains("encoded.length>1048576)return\"too_large\""));
        assert!(BOOTSTRAP.contains(
            "if(!query||typeof query.sql!==\"string\"||query.sql.length<1||!isArray(query.parameters))"
        ));
        // A delivery that is not newer than the last one is dropped.
        assert!(BOOTSTRAP.contains("delivery<=subscription.delivery"));
        // Closing the port rejects every pending query and ends every
        // subscription with a terminal port_closed error. An error callback
        // that unsubscribes mid-loop deletes its entry, so the loop skips
        // dead entries rather than throwing on them.
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",closeSubscriptions)"));
        assert!(BOOTSTRAP.contains("listen(channel,\"messageerror\",closeSubscriptions)"));
        assert!(BOOTSTRAP.contains("listen(window,\"pagehide\",closeSubscriptions,true)"));
        assert!(BOOTSTRAP.contains("for(const id of objectKeys(subscriptions)){const subscription=subscriptions[id];if(subscription)failSubscription(subscription,\"port_closed\",\"the host port closed\")}"));
        // unsubscribe tells the host once and is idempotent.
        assert!(BOOTSTRAP.contains(
            "const endSubscription=(subscription,notify)=>{if(subscription.done)return;"
        ));
        // The query's shape is probed inside the try, so a hostile Proxy is a
        // refusal rather than a throw; a refusal outlives a synchronous
        // unsubscribe; port_closed is an error, never a refusal, in both paths.
        assert!(BOOTSTRAP.contains(
            "let encoded,structured;try{if(!given||typeof given!==\"object\"||isArray(given)||objectKeys(given).some("
        ));
        assert!(BOOTSTRAP.contains("if(subscription.silenced&&!refusal)return;"));
        assert!(BOOTSTRAP.contains("deliverSubscription(subscription,frame,true)"));
        assert!(BOOTSTRAP
            .contains("refuseQuery(\"port_closed\",\"the host port is closed\",\"error\")"));
    }

    #[test]
    fn bootstrap_offers_app_agents_only_behind_the_host_feature() {
        // App contract v2 (ask an agent, Shapes bf7cfa5): neither
        // nativeArtifact.agents nor window.native.agents exists unless the
        // host's init lists app.agents.v2.
        assert!(BOOTSTRAP.contains("const AGENTS_FEATURE=\"app.agents.v2\""));
        assert!(BOOTSTRAP.contains("else if(feature===AGENTS_FEATURE)agentsFeature=true;"));
        assert!(BOOTSTRAP.contains("get agents(){return agentsFeature?agentsApi:undefined}"));
        assert!(BOOTSTRAP.contains("...(agentsFeature?{agents:agentsApi}:{})"));
        assert!(BOOTSTRAP.contains(
            "const agentsApi=freezeObject({list:listAgents,ask:askAgent,onStatus:onAgentStatus});"
        ));
        // The fixed wire shapes: the app sends only an agent id and a comment
        // id, never text, and there is no gesture mark on the ask.
        assert!(BOOTSTRAP.contains("send({version:VERSION,type:\"agents-list\",request_id})"));
        assert!(BOOTSTRAP
            .contains("send({version:VERSION,type:\"agents-ask\",request_id,to,comment_id})"));
        assert!(BOOTSTRAP
            .contains("commandData?.type===\"agents-list-result\")settleAgentList(commandData)"));
        assert!(
            BOOTSTRAP.contains("commandData?.type===\"agents-ask-result\")settleAsk(commandData)")
        );
        assert!(BOOTSTRAP
            .contains("commandData?.type===\"agents-status\")deliverAgentStatus(commandData)"));
        assert!(BOOTSTRAP.contains("own(pendingAsks,data.request_id)"));
        // Bounded: 4 asks in flight (a fifth resolves busy, never throws), the
        // ids, the list, each result and each status.
        assert!(BOOTSTRAP.contains(
            "pendingAskCount>=4){reportBoundedRefusal(\"html_ask_refused\",\"busy\");return NativePromise.resolve(askRefusal(\"busy\""
        ));
        assert!(BOOTSTRAP.contains("if(!agentId(to,64)||!agentId(comment_id,128))"));
        assert!(BOOTSTRAP.contains("const list=agentsJson(value,65536)"));
        assert!(BOOTSTRAP.contains("const result=agentsJson(value,4096)"));
        assert!(BOOTSTRAP.contains("const status=agentsJson(data.status,4096)"));
        assert!(BOOTSTRAP.contains(
            "ASK_CODES=[\"unavailable\",\"not_ready\",\"invalid\",\"duplicate\",\"refused\",\"busy\"]"
        ));
        // Closing the port answers every pending ask and the pending list,
        // and ends every status subscription.
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",closeAgents)"));
        assert!(BOOTSTRAP.contains("listen(channel,\"messageerror\",closeAgents)"));
        assert!(BOOTSTRAP.contains("listen(window,\"pagehide\",closeAgents,true)"));
        assert!(BOOTSTRAP.contains("pendingAskCount=0;agentStatusSubscribers.length=0"));
    }

    #[test]
    fn bootstrap_offers_adopted_session_controls_only_behind_their_own_host_feature() {
        // Slices C1/C2 (design 86a586b sections 2.4 and 3.6): createStatus, cancel and quoted exist
        // only when the init lists app.agent-sessions.adopted.v1, which the host does only for a
        // Desktop that listed agent-access.v3. Without it the frame is what it was.
        assert!(
            BOOTSTRAP.contains("AGENT_SESSIONS_ADOPTED_FEATURE=\"app.agent-sessions.adopted.v1\"")
        );
        assert!(BOOTSTRAP.contains(
            "else if(feature===AGENT_SESSIONS_ADOPTED_FEATURE)agentSessionsAdoptedFeature=true;"
        ));
        assert!(BOOTSTRAP.contains(
            "const agentSessionsAdoptedApi=freezeObject({...agentSessionsCreateApi,createStatus:input=>requestAgentSessionStartControl(\"createStatus\",input),cancel:input=>requestAgentSessionStartControl(\"cancel\",input)});"
        ));
        assert!(BOOTSTRAP.contains(
            "const agentSessionsBaseSurface=()=>{const api=agentSessionsCreateFeature?(agentSessionsAdoptedFeature?agentSessionsAdoptedApi:agentSessionsCreateApi):agentSessionsApi;return agentSessionsOpenConversationFeature?freezeObject({...api,openConversation:(input,options)=>requestAgentSessionOpenConversation(input,options)}):api;};"
        ));
        for name in ["createStatus", "cancel", "quoted"] {
            let base = BOOTSTRAP
                .split("const agentSessionsApi=freezeObject({")
                .nth(1)
                .and_then(|rest| rest.split("});").next())
                .expect("the base agentSessionsApi literal");
            assert!(
                !base.contains(name),
                "{name} must not be on the base surface"
            );
        }
        // Wire: a fresh id beside the create's requestId; a quoted send posts only the keys it
        // always had when the app gave none.
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:kind===\"cancel\"?\"agent-sessions-cancel\":\"agent-sessions-create-status\",request_id,create_request_id})"
        ));
        assert!(BOOTSTRAP.contains(
            "nextAgentSessionsId(kind===\"cancel\"?\"agent-sessions-cancel-\":\"agent-sessions-status-\")"
        ));
        assert!(BOOTSTRAP.contains(
            "||commandData?.type===\"agent-sessions-cancel-result\")settleAgentSessionsStartControl(commandData)"
        ));
        assert!(BOOTSTRAP.contains("...(quoted===undefined?{}:{quoted})})}catch{"));
        // Quoted is validated to the Desktop's bounds before anything is posted, and is refused
        // (unavailable for a send, create_unsupported for a start) without the adopted feature.
        assert!(BOOTSTRAP.contains("const sessionQuotedOf=value=>{const items=sessionJson(value,262144);if(!isArray(items)||items.length>8)return null;"));
        assert!(BOOTSTRAP.contains("item.from.length>32"));
        assert!(BOOTSTRAP.contains("item.text.length>12288"));
        assert!(BOOTSTRAP.contains(
            "if(!agentSessionsAdoptedFeature)return NativePromise.resolve(sessionRefusal(\"unavailable\"))"
        ));
        assert!(BOOTSTRAP.contains(
            "if(!agentSessionsAdoptedFeature)return NativePromise.resolve(createFailure(\"create_unsupported\",\"Quoted words are not available here\"))"
        ));
        // One start chain for every launch (design section 3.5): create 205 s, send 145 s (a
        // first-send dialog), status and cancel 50 s. They are written as products so the
        // numeric-literal guards elsewhere keep counting what they count.
        assert!(BOOTSTRAP.contains(
            "AGENT_SESSIONS_CREATE_TIMEOUT_MS=205*1000,AGENT_SESSIONS_SEND_TIMEOUT_MS=145*1000,AGENT_SESSIONS_STATUS_TIMEOUT_MS=50*1000;"
        ));
        assert!(BOOTSTRAP.contains("},AGENT_SESSIONS_SEND_TIMEOUT_MS);"));
        assert!(BOOTSTRAP.contains("},AGENT_SESSIONS_STATUS_TIMEOUT_MS);"));
        // The status answers are read as strictly as a create reply: a state this frame cannot read is not one.
        assert!(BOOTSTRAP.contains("const SESSION_CREATE_STATES=[\"unknown_request\",\"preparing\",\"confirming\",\"dispatching\",\"dispatched\",\"settled\",\"cancelled\",\"terminal_mismatch\",\"refused_retryable\"];"));
        assert!(BOOTSTRAP.contains(
            "if(withAcknowledged){if(typeof value.acknowledged!==\"boolean\")return null;"
        ));
    }

    #[test]
    fn bootstrap_offers_open_conversation_only_behind_its_own_host_feature() {
        // Opening a conversation (quick side pane, full Agent HQ window) is a
        // host feature of its own: without app.agent-sessions.open-conversation.v1
        // in the init the frame exposes no openConversation, so an app falls back
        // to openInPaseo, and the open-in-paseo message is untouched.
        assert!(BOOTSTRAP.contains(
            "AGENT_SESSIONS_OPEN_CONVERSATION_FEATURE=\"app.agent-sessions.open-conversation.v1\""
        ));
        assert!(BOOTSTRAP.contains("agentSessionsOpenConversationFeature=false"));
        assert!(BOOTSTRAP.contains(
            "else if(feature===AGENT_SESSIONS_OPEN_CONVERSATION_FEATURE)agentSessionsOpenConversationFeature=true;"
        ));
        assert!(BOOTSTRAP.contains(
            "openConversation:(input,options)=>requestAgentSessionOpenConversation(input,options)"
        ));
        let base = BOOTSTRAP
            .split("const agentSessionsApi=freezeObject({")
            .nth(1)
            .and_then(|rest| rest.split("});").next())
            .expect("the base agentSessionsApi literal");
        assert!(
            !base.contains("openConversation") && !base.contains("open-conversation"),
            "openConversation must not be on the base surface"
        );
        // Depth is strict: absent, quick or full posts; anything else resolves
        // invalid in the frame, before anything is posted.
        assert!(BOOTSTRAP.contains("depth=options===undefined?input.depth:options.depth"));
        assert!(BOOTSTRAP.contains("(depth!==undefined&&!(typeof depth===\"string\"&&(depth===\"quick\"||depth===\"full\")))"));
        // The guard coerces nothing: an array or object depth fails typeof, and a
        // throwing toString is never invoked on the validation path, so neither
        // reaches the wire nor escapes synchronously; both resolve invalid.
        assert!(
            BOOTSTRAP.contains("type:\"agent-sessions-open-conversation\",request_id,...target")
        );
        assert!(BOOTSTRAP.contains("if(depth!==undefined)wire.depth=depth;send(wire)"));
        assert!(BOOTSTRAP.contains("const pending={kind:\"openConversation\",resolve,timer:0}"));
        // The same answer shape as openInPaseo: an empty-object success, else a
        // typed code, settled off its own result message.
        assert!(BOOTSTRAP
            .contains("pending.kind===\"openInPaseo\"||pending.kind===\"openConversation\""));
        assert!(BOOTSTRAP.contains(
            "data.type===\"agent-sessions-open-conversation-result\"?\"openConversation\""
        ));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"agent-sessions-open-conversation-result\"||commandData"
        ));
        // The open-in-paseo message keeps its exact wire shape: no depth key.
        assert!(BOOTSTRAP.contains("type:kind===\"openInPaseo\"?\"agent-sessions-open-in-paseo\""));
    }

    #[test]
    fn bootstrap_offers_followup_only_behind_its_own_host_feature() {
        // Attention's follow-up controls (status, continue, settings get/set) are a host
        // feature of their own: without app.agent-sessions.followup.v1 in the init the
        // frame exposes no agentSessions.followup, and every other message is untouched.
        assert!(BOOTSTRAP
            .contains("AGENT_SESSIONS_FOLLOWUP_FEATURE=\"app.agent-sessions.followup.v1\""));
        assert!(BOOTSTRAP.contains("agentSessionsFollowupFeature=false"));
        assert!(BOOTSTRAP.contains(
            "else if(feature===AGENT_SESSIONS_FOLLOWUP_FEATURE)agentSessionsFollowupFeature=true;"
        ));
        assert!(BOOTSTRAP.contains(
            "const agentSessionsSurface=()=>{const api=agentSessionsSavedSurface();return agentSessionsFollowupFeature?freezeObject({...api,followup:agentSessionsFollowupApi}):api;};"
        ));
        let base = BOOTSTRAP
            .split("const agentSessionsApi=freezeObject({")
            .nth(1)
            .and_then(|rest| rest.split("});").next())
            .expect("the base agentSessionsApi literal");
        assert!(
            !base.contains("followup"),
            "followup must not be on the base surface"
        );
        // The four calls, their wire names and result messages.
        assert!(BOOTSTRAP.contains(
            "const followupWire=freezeObject({status:\"status\",continue:\"continue\",getSettings:\"settings-get\",setSettings:\"settings-set\"});"
        ));
        assert!(BOOTSTRAP.contains(
            "const agentSessionsFollowupApi=freezeObject({status:()=>requestAgentSessionFollowup(\"status\"),continue:()=>requestAgentSessionFollowup(\"continue\"),getSettings:()=>requestAgentSessionFollowup(\"getSettings\"),setSettings:input=>requestAgentSessionFollowup(\"setSettings\",input)});"
        ));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"agent-sessions-followup-\"+followupWire[kind],request_id,...fields})"
        ));
        for message in ["status", "continue", "settings-get", "settings-set"] {
            assert!(
                BOOTSTRAP.contains(&format!(
                    "commandData?.type===\"agent-sessions-followup-{message}-result\""
                )),
                "{message} result is dispatched to the follow-up settle"
            );
        }
        // A change needs at least one of enabled/provider/model and nothing else; the
        // frame refuses anything else invalid before it posts.
        assert!(BOOTSTRAP.contains(
            "!permissionKeys(given,[\"enabled\",\"provider\",\"model\"],[])||objectKeys(given).length===0"
        ));
        assert!(BOOTSTRAP.contains("(own(given,\"enabled\")&&typeof given.enabled!==\"boolean\")"));
        // Without the feature, a closed port or a missing channel nothing is posted;
        // the same 16-in-flight cap and 30 s deadline as the other session calls.
        assert!(BOOTSTRAP.contains(
            "if(!agentSessionsFollowupFeature||agentSessionsClosed||!channel)return NativePromise.resolve(sessionRefusal(\"unavailable\"));if(agentSessionsInflight>=16)return NativePromise.resolve(sessionRefusal(\"busy\"));"
        ));
        assert!(BOOTSTRAP.contains(
            "const pending={kind,resolve,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(sessionRefusal(\"unavailable\"))},AGENT_SESSIONS_TIMEOUT_MS);"
        ));
        // Answers are checked strictly against the Desktop contract, including the
        // settings results `saved` (written, not yet applied) and a refusal as a value.
        assert!(BOOTSTRAP.contains(
            "apply(arrayIncludes,[\"applied\",\"saved\",\"unchanged\",\"refused\"],[v.result])"
        ));
        assert!(BOOTSTRAP.contains(
            "(v.result===\"refused\"?!own(v,\"settings\"):followupSettingsOk(v.settings))"
        ));
        assert!(BOOTSTRAP.contains(
            "apply(arrayIncludes,[\"enabled\",\"disabled\",\"paused\",\"limit_reached\",\"unavailable\"],[v.state])"
        ));
        // A workspace id may be up to 512 characters (the Desktop and the launcher allow that); every other name 256.
        assert!(BOOTSTRAP.contains("followupWorkspaceId=value=>permissionText(value,512,1)"));
        assert!(BOOTSTRAP.contains("followupWorkspaceId(w.workspaceId)"));
        assert!(BOOTSTRAP.contains("v.options.length>16"));
        assert!(BOOTSTRAP.contains("o.models.length<=64"));
        // A reply settles only the request of the same kind and result type.
        assert!(BOOTSTRAP.contains(
            "if(!own(followupWire,pending.kind)||data.type!==\"agent-sessions-followup-\"+followupWire[pending.kind]+\"-result\")return;"
        ));
        // The other messages keep their exact wire shape.
        assert!(BOOTSTRAP.contains("type:kind===\"openInPaseo\"?\"agent-sessions-open-in-paseo\""));
    }

    #[test]
    fn bootstrap_offers_agent_sessions_only_behind_the_host_feature() {
        // App contract v2 (Paseo agent sessions, app.agent-sessions.v2): neither
        // nativeArtifact.agentSessions nor window.native.agentSessions exists
        // unless the host's init lists app.agent-sessions.v2.
        assert!(BOOTSTRAP.contains("const AGENT_SESSIONS_FEATURE=\"app.agent-sessions.v2\""));
        assert!(BOOTSTRAP
            .contains("else if(feature===AGENT_SESSIONS_FEATURE)agentSessionsFeature=true;else if(feature===AGENT_SESSIONS_CREATE_FEATURE)agentSessionsCreateFeature=true;"));
        assert!(BOOTSTRAP.contains(
            "get agentSessions(){return agentSessionsFeature?agentSessionsSurface():undefined}"
        ));
        assert!(BOOTSTRAP
            .contains("...(agentSessionsFeature?{agentSessions:agentSessionsSurface()}:{})"));
        assert!(BOOTSTRAP.contains(
            "const agentSessionsApi=freezeObject({protocolVersion:2,list:listAgentSessions,follow:followAgentSession,send:sendAgentSession,markRead:markAgentSessionRead,watchList:watchAgentSessionList,openInPaseo:input=>requestAgentSessionPermission(\"openInPaseo\",input),getPermissionForm:input=>requestAgentSessionPermission(\"getPermissionForm\",input),respondToPermission:input=>requestAgentSessionPermission(\"respondToPermission\",input)});"
        ));
        // Starting sessions (app.agent-sessions.create.v1): catalog and create exist only when the
        // host offers that feature beside sessions, capabilities.create passes through, the public
        // requestId is the wire request_id untouched, and nothing but a typed Desktop code or a
        // success for the requested host is ever a definite answer.
        assert!(
            BOOTSTRAP.contains("AGENT_SESSIONS_CREATE_FEATURE=\"app.agent-sessions.create.v1\"")
        );
        assert!(BOOTSTRAP.contains(
            "const agentSessionsCreateApi=freezeObject({...agentSessionsApi,catalog:catalogAgentSessions,chooseFolder:chooseFolderAgentSessions,create:createAgentSession});"
        ));
        assert!(BOOTSTRAP.contains("if(value.create===true)out.create=true;if(value.chooseFolder===true)out.chooseFolder=true;"));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"agent-sessions-create\",request_id:requestId,host_id:hostId,host_epoch:hostEpoch,provider,model,"
        ));
        assert!(BOOTSTRAP
            .contains("send({version:VERSION,type:\"agent-sessions-catalog\",request_id})"));
        assert!(BOOTSTRAP.contains(
            "clearTimer(pending.timer);delete agentSessionsPending[requestId];agentSessionsInflight-=1;resolve(createUnknown())"
        ));
        assert!(BOOTSTRAP
            .contains("else if(pending.kind===\"create\")pending.resolve(createUnknown());"));
        assert!(BOOTSTRAP.contains("summary.hostId===pending.host_id"));
        assert!(BOOTSTRAP.contains("sessionText(result.error.message,500)"));
        assert!(!BOOTSTRAP.contains("idempotencyKey"));
        // The fixed wire shapes: list carries only an optional cursor, follow a
        // fresh correlation id plus session and subscription ids, unsubscribe only
        // its subscription id, and send the public requestId as request_id with
        // only session_id and text beside it.
        assert!(BOOTSTRAP.contains(
            "type:\"agent-sessions-list\",request_id};if(cursor!==undefined)wire.cursor=cursor"
        ));
        assert!(BOOTSTRAP.contains(
            "send({version:VERSION,type:\"agent-sessions-follow\",request_id,host_id,host_epoch,session_id,subscription_id})"
        ));
        assert!(BOOTSTRAP
            .contains("send({version:VERSION,type:\"agent-sessions-unsubscribe\",subscription_id"));
        assert!(BOOTSTRAP.contains(
            "const wire={version:VERSION,type:\"agent-sessions-send\",request_id:requestId,host_id,host_epoch,session_id,text};if(quoted!==undefined)wire.quoted=quoted;send(wire)"
        ));
        assert!(BOOTSTRAP.contains("type:\"agent-sessions-mark-read\",request_id,read_request_id,host_id,host_epoch,session_id"));
        assert!(BOOTSTRAP.contains("type:\"agent-sessions-watch-list\",request_id,subscription_id"));
        assert!(BOOTSTRAP.contains("type:\"agent-sessions-unwatch-list\",subscription_id"));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"agent-sessions-list-result\")settleAgentSessionsList(commandData)"
        ));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"agent-sessions-follow-result\")settleAgentSessionsFollow(commandData)"
        ));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"agent-sessions-send-result\")settleAgentSessionsSend(commandData)"
        ));
        assert!(BOOTSTRAP.contains("commandData?.type===\"agent-sessions-mark-read-result\")settleAgentSessionsMarkRead(commandData)"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"agent-sessions-watch-list-result\")settleAgentSessionsWatchList(commandData)"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"agent-sessions-list-changed\")deliverAgentSessionListChanged(commandData)"));
        assert!(BOOTSTRAP.contains(
            "commandData?.type===\"agent-sessions-event\")deliverAgentSessionEvent(commandData)"
        ));
        // The follow reserves its callback slot before posting, so a synchronous
        // initial snapshot still finds it; a terminal ended event removes its slot
        // before delivery, and a late follow result unsubscribes instead of
        // resurrecting.
        assert!(BOOTSTRAP.contains(
            "agentSessionFollows[subscription_id]={host_id,host_epoch,session_id,callback,request_id};const pending={kind:\"follow\",resolve,subscription_id,timer:0}"
        ));
        assert!(BOOTSTRAP.contains(
            "if(event.kind===\"ended\")delete agentSessionFollows[data.subscription_id]"
        ));
        assert!(BOOTSTRAP.contains(
            "pending.resolve(freezeObject({ok:true,value:freezeObject({dispose:()=>{}})}))"
        ));
        assert!(BOOTSTRAP.contains("dispose:disposeAgentSessionFollow(pending.subscription_id)"));
        // Bounded: 4 follows and 16 results in flight (more resolve busy, never
        // throw), the ids, cursor, text, pages, timelines and results.
        assert!(BOOTSTRAP.contains(
            "objectKeys(agentSessionFollows).length>=4){reportBoundedRefusal(\"html_agent_sessions_refused\",\"busy\")"
        ));
        assert!(BOOTSTRAP.contains(
            "agentSessionsInflight>=16){reportBoundedRefusal(\"html_agent_sessions_refused\",\"busy\")"
        ));
        assert!(
            BOOTSTRAP.contains("value.length<=128&&apply(regExpExec,/^[A-Za-z0-9:_-]+$/,[value])")
        );
        assert!(BOOTSTRAP.contains("cursor.length<1||cursor.length>4096"));
        assert!(BOOTSTRAP.contains("sessionUtf8Bytes(text)>16384"));
        assert!(BOOTSTRAP.contains("page.sessions.length>100||page.hosts.length>32"));
        assert!(BOOTSTRAP.contains("event.items.length>100"));
        assert!(BOOTSTRAP.contains("sessionJson(value,262144)"));
        assert!(BOOTSTRAP.contains(
            "SESSION_RESULT_CODES=[\"refused\",\"invalid\",\"unavailable\",\"gone\",\"busy\"]"
        ));
        // A send refused before dispatch resolves unavailable, while a post that throws
        // with the channel open, a rejection after posting, an own-deadline expiry, or a
        // close with the send pending all resolve delivery unknown, never re-sent; a receipt
        // naming another request id resolves unknown too. List and follow deadlines free
        // their pending slots (a follow deadline also drops its reservation and
        // unsubscribes). Closing the port answers every pending list and follow
        // unavailable, every pending send and permission response unknown, and
        // drops every callback.
        assert!(BOOTSTRAP.contains("value:freezeObject({requestId,delivery:\"unknown\"})"));
        assert!(BOOTSTRAP.contains("const AGENT_SESSIONS_TIMEOUT_MS=30000"));
        assert_eq!(
            BOOTSTRAP.matches("},AGENT_SESSIONS_TIMEOUT_MS);").count(),
            7
        );
        assert!(BOOTSTRAP.contains("while(own(agentSessionsPending,id)){agentSessionsSeq+=1;"));
        assert!(BOOTSTRAP.contains("if(!sessionIdOk(requestId))"));
        assert!(BOOTSTRAP.contains("if(result.value.requestId===requestId&&(result.value.delivery"));
        assert!(BOOTSTRAP.contains("if(sessionUtf8Bytes(jsonStringify(framed))>262144)return null"));
        // Bounded Desktop read-model additions: optional unread/request summaries
        // and typed tool detail flow through the allowlisted projections with
        // absent-unknown/null-known-none preserved and malformed descriptors
        // omitted. Producer widths match Desktop (host label 256, model 256,
        // status 128, workspace 500); title 512 and timeline envelopes unchanged.
        // Host capabilities stay informational; optional routes are gated by the host.
        assert!(BOOTSTRAP.contains("const sessionAttentionOf="));
        assert!(BOOTSTRAP.contains("const sessionPermissionOf="));
        assert!(BOOTSTRAP.contains("const sessionCapabilitiesOf="));
        assert!(BOOTSTRAP.contains("sessionToolDetailOk(item.detail)"));
        assert!(BOOTSTRAP.contains("sessionText(item.hostLabel,256)"));
        assert!(BOOTSTRAP.contains("sessionText(item.model,256)"));
        assert!(BOOTSTRAP.contains("sessionText(item.status,128)"));
        assert!(BOOTSTRAP.contains("sessionText(workspace.name,500)"));
        assert!(BOOTSTRAP.contains("sessionText(host.label,256)"));
        assert!(BOOTSTRAP.contains("sessionTimelineIdOk(item.id)"));
        assert!(BOOTSTRAP.contains("typeof item.unread===\"boolean\"?{unread:item.unread}:{}"));
        assert!(
            BOOTSTRAP.contains("clearTimer(pending.timer);delete agentSessionsPending[requestId]")
        );
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",closeAgentSessions)"));
        assert!(BOOTSTRAP.contains("listen(channel,\"messageerror\",closeAgentSessions)"));
        assert!(BOOTSTRAP.contains("listen(window,\"pagehide\",closeAgentSessions,true)"));
        assert!(BOOTSTRAP.contains(
            "agentSessionsInflight=0;for(const id of objectKeys(agentSessionFollows))delete agentSessionFollows[id]"
        ));
    }

    #[test]
    fn bootstrap_correlates_bounded_proposals_and_settlements() {
        assert!(BOOTSTRAP.contains("[\"request_id\",\"entry_id\",\"slots\",\"values\"]"));
        assert!(BOOTSTRAP.contains("pendingIntentCount>=32"));
        assert!(BOOTSTRAP.contains("encoded.length>65536"));
        assert!(
            BOOTSTRAP.contains("commandData?.type===\"intent-result\")settleIntent(commandData)")
        );
        assert!(BOOTSTRAP.contains("own(pendingIntents,data.request_id)"));
        // On-request reads: offered only for needs listed in the host's
        // init, bounded in flight and in size, settled only by request id.
        assert!(BOOTSTRAP.contains("read:readNeed"));
        assert!(BOOTSTRAP.contains("apply(arrayIncludes,offeredNeeds,[need])"));
        assert!(BOOTSTRAP.contains("pendingReadCount>=8"));
        assert!(BOOTSTRAP.contains("encoded.length>4096"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"read-result\")settleRead(commandData)"));
        assert!(BOOTSTRAP.contains("own(pendingReads,data.request_id)"));
        // Keyed reads: the host's opaque variant/eviction metadata rides the
        // same bounded clone/freeze/size cap as the rows, so packages can map
        // later keyed hints. Absent metadata serializes away (old-host shape).
        assert!(BOOTSTRAP.contains("result:data.result,keyed_freshness:data.keyed_freshness}"));
        assert!(BOOTSTRAP.contains("if(isArray(data.needs))"));
        assert!(BOOTSTRAP.contains("pending.resolve(result)"));
    }

    #[test]
    fn bootstrap_forwards_a_body_submit_with_its_gesture_mark_and_click_count() {
        // The frame cannot know whether the person consented to autosave, so it
        // no longer refuses a click-less Body submit itself: the host decides
        // and answers `gesture_required` when neither a click nor consent holds.
        assert!(!BOOTSTRAP.contains("bodyAttemptRefused(\"gesture_required\")"));
        assert!(BOOTSTRAP.contains(
            "if(type===\"body-attempt-submit\"){backed=gestureArmed&&!gestureUsed;if(backed)gestureUsed=true;}"
        ));
        // The click count only moves on a trusted completing gesture, and the
        // frame reports it so the host can keep autosave on the open record.
        assert!(BOOTSTRAP.contains("gestureArmed=true;gestureUsed=false;gestureEpoch++;"));
        assert!(BOOTSTRAP.contains("{gesture_backed:backed,gesture_epoch:gestureEpoch}"));
    }

    #[test]
    fn bootstrap_admits_a_proposal_only_for_the_event_that_completes_a_gesture() {
        // Layer 1 of the activation gate, mirroring navigation's trusted-click
        // runtime. A proposal made outside a completed gesture is not refused:
        // it is sent marked as not gesture-backed and the host routes it to the
        // tray, so the old no_gesture refusal is gone entirely.
        assert!(!BOOTSTRAP.contains("no_gesture"));
        assert!(BOOTSTRAP.contains("const backed=gestureArmed&&!gestureUsed;"));
        assert!(BOOTSTRAP.contains("if(backed)gestureUsed=true;"));
        assert!(BOOTSTRAP.contains("gesture_backed:backed"));
        assert!(BOOTSTRAP.contains("gestureUsed=true"));
        // Only genuine refusals report a diagnostic, with a bounded reason code
        // throttled so a loop cannot flood the host.
        assert!(BOOTSTRAP.contains("refuseProposal(\"malformed\""));
        assert!(BOOTSTRAP.contains("refuseProposal(\"duplicate\""));
        assert!(BOOTSTRAP.contains("refuseProposal(\"too_large\""));
        assert!(BOOTSTRAP.contains("reportBoundedRefusal(\"html_intent_refused\",reason)"));
        assert!(BOOTSTRAP.contains("refusalReports>=16"));
        assert!(BOOTSTRAP.contains("setTimer(()=>{refusalReported=false},250)"));
        // Disarm on a macrotask. A microtask checkpoint runs between a capture
        // listener and the target listener, so a microtask disarm would clear
        // the flag before the author's own handler ran.
        assert!(BOOTSTRAP.contains("setTimer(releaseGesture,0)"));
        assert!(!BOOTSTRAP.contains("microtask(releaseGesture)"));
        // The event type, trust bit and key repeat flag are read through
        // pristine getters, so author code cannot shadow what the gate reads.
        assert!(BOOTSTRAP.contains("eventType=getter(Event.prototype,\"type\")"));
        assert!(BOOTSTRAP.contains("keyRepeat=getter(KeyboardEvent.prototype,\"repeat\")"));
        assert!(BOOTSTRAP.contains("Array.prototype.includes"));
        // Only the terminal event of a gesture arms. Arming on the whole
        // pointer/mouse sequence admitted five proposals for one physical click.
        assert!(BOOTSTRAP.contains(r#"const gestureEvents=["click","drop"];"#));
        // A held key autorepeats trusted keydown, and on a control each repeat
        // also dispatches a trusted click; the repeat state suppresses that
        // click so one sustained keypress admits one proposal.
        assert!(BOOTSTRAP.contains("if(type===\"click\"&&keyRepeating)return;"));
        // A label click also synthesises a trusted click on its control in the
        // same task; the armed flag is not reset until its release, so the pair
        // admits one proposal.
        assert!(BOOTSTRAP.contains("if(gestureArmed)return;"));
        assert!(BOOTSTRAP.contains("trackKeyRepeat"));
        assert!(BOOTSTRAP.contains("clearKeyRepeat"));
        // Everything that completes a gesture exactly once is admitted; every
        // other event, and every trusted event author code can cause, is not.
        let list_start =
            BOOTSTRAP.find("gestureEvents=[").expect("gesture set") + "gestureEvents=[".len();
        let list_end = BOOTSTRAP[list_start..].find("];").expect("gesture set end") + list_start;
        let gesture_list = &BOOTSTRAP[list_start..list_end];
        for excluded in [
            "\"message\"",
            "\"submit\"",
            "\"focus\"",
            "\"load\"",
            "\"scroll\"",
            "\"pointerdown\"",
            "\"mousedown\"",
            "\"pointerup\"",
            "\"mouseup\"",
            "\"pointercancel\"",
            "\"touchstart\"",
            "\"touchend\"",
            "\"keydown\"",
            "\"keyup\"",
            "\"dblclick\"",
            "\"contextmenu\"",
            "\"auxclick\"",
        ] {
            assert!(
                !gesture_list.contains(excluded),
                "gestureEvents must not admit {excluded}"
            );
        }
    }

    #[test]
    fn validates_complete_self_contained_documents_and_rejects_authority() {
        let valid = validate(&document(
            "<img alt=\"\" src=\"data:image/png;base64,aQ==\">",
        ))
        .unwrap();
        assert_eq!(valid.profile, Profile::Document);
        assert!(validate(&document(
            "<button data-native-external-url=\"https://example.test/path\">Open</button>",
        ))
        .is_ok());
        for bad in [
            document("<script src=\"https://evil.test/x.js\"></script>"),
            document("<iframe src=\"data:text/html,x\"></iframe>"),
            document("<a href=\"https://evil.test\">leave</a>"),
            document("<button data-native-external-url=\"https://user:secret@example.test/path\">Open</button>"),
            document("<button data-native-record-id=\"one\" data-native-external-url=\"https://example.test/path\">Open</button>"),
        ] {
            assert_eq!(validate(&bad).unwrap_err().code, "html_policy_violation");
        }
        let located = document("\n<script src=\"https://evil.test/x.js\"></script>")
            .replace("<main>", "<main>\n");
        let failure = validate(&located).unwrap_err();
        assert!(failure.details["line"].as_u64().unwrap() > 1);
        assert!(failure.details["column"].as_u64().unwrap() > 0);
    }

    #[test]
    fn bootstrap_carries_the_in_place_input_update_surface() {
        // String-level, like `bootstrap_order_...`: the bridge keeps every
        // existing message untouched and only adds the subscriber API plus
        // the additive input delivery acknowledgements.
        assert!(BOOTSTRAP.contains("onInput"));
        assert!(BOOTSTRAP.contains("get input()"));
        assert!(BOOTSTRAP.contains("input-unhandled"));
        assert!(BOOTSTRAP.contains("input-applied"));
        assert!(BOOTSTRAP.contains("no-subscriber"));
        assert!(BOOTSTRAP.contains("subscriber-threw"));
        assert!(BOOTSTRAP.contains("html_input_update_failed"));
        assert!(BOOTSTRAP.contains("input_digest"));
        assert!(BOOTSTRAP.contains("content_event_seq"));
        assert!(BOOTSTRAP.contains("stale"));
        assert!(BOOTSTRAP.contains("freeze-failed"));
        assert!(BOOTSTRAP.contains("Array.prototype.push"));
        assert!(BOOTSTRAP.contains("Array.prototype.indexOf"));
        assert!(BOOTSTRAP.contains("Array.prototype.splice"));
        assert!(BOOTSTRAP.contains("native-html-init"));
        assert!(BOOTSTRAP.contains("VERSION"));
        // Readiness is announced before queued proposals are delivered, so a
        // proposal made on load is not refused as not-ready.
        let ready = BOOTSTRAP.find("type:\"ready\"").expect("ready message");
        let flush = BOOTSTRAP
            .find("for(const item of queued)")
            .expect("queue flush");
        assert!(ready < flush, "ready must precede the queued flush");
    }

    #[test]
    fn bootstrap_carries_the_reveal_surface() {
        // Task fb8564c: inbound reveal is additive throughout. A document
        // that never calls the new API sees no behavioural change; the
        // transport version is untouched.
        assert!(BOOTSTRAP.contains("onReveal"));
        assert!(BOOTSTRAP.contains("reveal subscriber must be a function"));
        assert!(BOOTSTRAP.contains("surface.reveal.v1"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"reveal\")deliverReveal(commandData)"));
        assert!(BOOTSTRAP.contains("commandData?.type===\"reveal-clear\")pendingReveal=null"));
        assert!(BOOTSTRAP
            .contains("features:[REVEAL_FEATURE,...(contextFeature?[CONTEXT_FEATURE]:[]),...(locationFeature?[LOCATION_FEATURE]:[]),...(unsavedFeature?[UNSAVED_FEATURE]:[]),...(bodyLane.api.offering?[\"records.body.read.v1\"]:[]),...(skinFeature?[SKIN_FEATURE]:[])]"));
        assert!(BOOTSTRAP.contains("CONTEXT_FEATURE=\"app-view-report.v1\""));
        assert!(BOOTSTRAP.contains("if(contextFeature&&!contextClosed)send("));
        assert!(BOOTSTRAP.contains("if(!contextFeature||contextClosed||"));
        // No ack or effect authority on this path: delivery reports only
        // bounded diagnostics, and the retained slot clears before replay.
        assert!(BOOTSTRAP.contains("html_reveal_failed"));
        assert!(BOOTSTRAP.contains("html_reveal_dropped"));
        assert!(!BOOTSTRAP.contains("reveal-applied"));
        assert!(!BOOTSTRAP.contains("reveal-unhandled"));
        assert!(BOOTSTRAP.contains("pendingReveal=null;deliverRevealTo(retained)"));
        // Unsupported payload fields never reach the callback: only the
        // validated record id is frozen into the delivery.
        assert!(BOOTSTRAP.contains("freezeObject({record_id})"));
        // The id shape is the exact backend alphabet, pinned literally,
        // checked through the captured pristine exec rather than any
        // prototype method author code could replace.
        assert!(BOOTSTRAP.contains("revealPattern=/^[A-Za-z0-9._:-]{1,128}$/"));
        assert!(BOOTSTRAP.contains("regExpExec=RegExp.prototype.exec"));
        assert!(BOOTSTRAP.contains("apply(regExpExec,revealPattern,[value])!==null"));
        assert!(!BOOTSTRAP.contains("[\\x20-\\x7E]"));
        // The retained target clears on teardown as well as on replay.
        assert!(BOOTSTRAP.contains("listen(channel,\"messageerror\",clearReveal)"));
        assert!(BOOTSTRAP.contains("listen(channel,\"close\",clearReveal)"));
        assert!(BOOTSTRAP.contains("listen(window,\"unload\",clearReveal,true)"));
    }

    #[test]
    fn bootstrap_location_is_scalar_negotiated_and_closed_with_document() {
        assert!(BOOTSTRAP.contains("surface.location.v1"));
        assert!(BOOTSTRAP.contains("publishLocation=recordId=>{if(contextClosed)throw"));
        assert!(BOOTSTRAP.contains("apply(locationTest,locationPattern,[recordId])"));
        assert!(BOOTSTRAP.contains("if(locationFeature)send({type:\"location\""));
        assert!(BOOTSTRAP.contains("else if(feature===LOCATION_FEATURE)locationFeature=true"));
    }

    #[test]
    fn bootstrap_unsaved_is_negotiated_and_closed_with_document() {
        assert!(BOOTSTRAP.contains("surface.unsaved.v1"));
        assert!(BOOTSTRAP.contains("publishUnsaved=state=>{if(contextClosed)throw"));
        assert!(BOOTSTRAP.contains("unsavedPattern=/^[^\\0-\\x1f\\x7f]{1,200}$/"));
        assert!(BOOTSTRAP.contains("apply(locationTest,unsavedPattern,[state.reason])"));
        assert!(BOOTSTRAP.contains("if(unsavedFeature)send({type:\"unsaved\""));
        assert!(BOOTSTRAP.contains("else if(feature===UNSAVED_FEATURE)unsavedFeature=true"));
    }

    #[test]
    fn bootstrap_carries_the_view_state_handoff() {
        // Eager publish, boot-time delivery: the frame hands its own view
        // state to the host, which holds the opaque blob and delivers it in
        // the successor's init before first paint. Additive throughout: a
        // document that never calls the new API sees no behavioural change.
        assert!(BOOTSTRAP.contains("setViewState"));
        assert!(BOOTSTRAP.contains("get viewState"));
        assert!(BOOTSTRAP.contains("type:\"view-state\""));
        assert!(BOOTSTRAP.contains("view_state"));
        assert!(BOOTSTRAP.contains("from_body_digest"));
        assert!(BOOTSTRAP.contains("viewState:heldViewState"));
        assert!(BOOTSTRAP.contains("data.view_state"));
        // Synchronous TypeErrors at the call site, mirroring propose(): the
        // value must survive a pristine JSON round-trip inside the same
        // 65536 bound, and the advisory schema is intentId-shaped.
        assert!(BOOTSTRAP.contains("refuseViewState(\"malformed\""));
        assert!(BOOTSTRAP.contains("refuseViewState(\"too_large\""));
        assert!(BOOTSTRAP.contains("view state exceeds bridge limit"));
        // Refusals share propose()'s single throttled refusal budget rather
        // than standing up a second timer: one budget for artifact
        // misbehaviour, with the view-state diagnostic code on it.
        assert!(BOOTSTRAP.contains("reportBoundedRefusal(\"html_view_state_refused\",reason)"));
        assert!(!BOOTSTRAP.contains("viewStateReported"));
        assert_eq!(
            BOOTSTRAP.matches("setTimer(").count(),
            18,
            "only gesture release, shared refusal throttle, feature-gated pre-ACK ARM wait, negotiated context deadline, bounded Body attempt deadline, eight bounded agent-session deadlines, and the catalog, folder choice, start, start-control and saved-session deadlines arm wall clocks"
        );
        // The read, watch and scoped-permission deadlines belong to tracked finite
        // operations. Each releases its pending
        // slot on expiry, settle once on a matching answer, and are cleared
        // with the other session timers when the document closes.
        assert_eq!(
            BOOTSTRAP.matches("},AGENT_SESSIONS_TIMEOUT_MS);").count(),
            7
        );
        assert!(BOOTSTRAP.contains("const pending={kind:\"markRead\",resolve,read_request_id,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(freezeObject({ok:true,value:freezeObject({requestId:read_request_id,delivery:\"unknown\"})}))},AGENT_SESSIONS_TIMEOUT_MS)"));
        assert!(BOOTSTRAP.contains("const pending={kind:\"watchList\",resolve,slot,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;stopAgentSessionListWatch(slot);resolve(sessionRefusal(\"unavailable\"))},AGENT_SESSIONS_TIMEOUT_MS)"));
        assert!(BOOTSTRAP.contains("const pending={kind,resolve,permission_request_id,timer:0};pending.timer=setTimer(()=>{if(agentSessionsPending[request_id]!==pending)return;delete agentSessionsPending[request_id];agentSessionsInflight-=1;resolve(kind===\"respondToPermission\"?permissionUnknown:sessionRefusal(\"unavailable\"))},AGENT_SESSIONS_TIMEOUT_MS)"));
        assert!(BOOTSTRAP.contains("const settleAgentSessionsPermission=data=>{if(typeof data.request_id!==\"string\"||!own(agentSessionsPending,data.request_id))return;"));
        assert!(BOOTSTRAP.contains("if(pending.kind!==\"markRead\")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);pending.resolve(sendReceiptOf(data.result,pending.read_request_id))"));
        assert!(BOOTSTRAP.contains("if(pending.kind!==\"watchList\")return;delete agentSessionsPending[data.request_id];agentSessionsInflight-=1;clearTimer(pending.timer);const result=sessionFollowResultOf(data.result)"));
        assert!(BOOTSTRAP.contains("delete agentSessionsPending[id];clearTimer(pending.timer);if(pending.kind===\"send\"||pending.kind===\"markRead\")"));
        assert!(BOOTSTRAP.contains("timer:setTimer(()=>cancelContext(id),remaining)"));
        // Body requests get one exact 45-second deadline through captured
        // timers, above the host's 30-second save window (BODY_SAVE_TIMEOUT_MS).
        // The host runs a frame's Body requests one at a time, so a prepare can
        // queue behind a slow save: every request type waits the same long
        // enough for it. Expiry clears only this pending request; submit stays
        // uncertain while preparation reports its bounded timeout.
        assert!(BOOTSTRAP.contains("pending.timer=setTimer(()=>{if(bodyAttemptPending[request_id]!==pending)return;delete bodyAttemptPending[request_id];resolve(type===\"body-attempt-submit\"?bodyAttemptUncertain():bodyAttemptRefused(\"prepare_timeout\"))},45000)"));
        assert_eq!(BOOTSTRAP.matches("45000").count(), 1);
        assert!(!BOOTSTRAP.contains("40000"));
        assert_eq!(
            BOOTSTRAP.matches("15000").count(),
            2,
            "only the pre-ACK ARM wait comment and constant keep 15 s"
        );
        assert!(BOOTSTRAP.contains(
            "const setTimer=setTimeout,clearTimer=clearTimeout,requestFrame=requestAnimationFrame;"
        ));
        assert!(BOOTSTRAP.contains("clearTimer(pending.timer)"));
        assert!(
            BOOTSTRAP.find("const setTimer=setTimeout").unwrap()
                < BOOTSTRAP.find("const bodyAttemptRequest=").unwrap()
        );
        // The additional context deadline uses primitives captured before
        // authored scripts execute, rather than looking up mutable clocks
        // when a private-port request arrives.
        assert_eq!(BOOTSTRAP.matches("Date.now").count(), 1);
        assert_eq!(BOOTSTRAP.matches("performance.now").count(), 1);
        assert!(BOOTSTRAP
            .contains("contextNow=Date.now,contextClock=performance.now.bind(performance)"));
        assert!(BOOTSTRAP.contains("data.deadline_ms-contextNow()"));
        assert!(BOOTSTRAP.contains("contextClock()>=deadline"));
        assert!(
            BOOTSTRAP.find("contextNow=Date.now").unwrap()
                < BOOTSTRAP.find("define(window,\"nativeArtifact\"").unwrap()
        );
        // The advisory schema is read once into a local, so a getter cannot
        // pass validation and then return something else.
        assert!(BOOTSTRAP.contains("const givenSchema=options.schema;"));
        // At most one posted message per animation frame, latest wins. The
        // delivery path itself arms no clock at all: no acknowledgement and
        // no bounded wait, so no host decision ever waits on a timer here.
        // The only reachable wall-clock arm is the shared refusal throttle
        // counted above, which nothing waits on.
        assert!(BOOTSTRAP.contains("requestAnimationFrame"));
        assert!(BOOTSTRAP.contains("pendingViewState"));
        assert!(BOOTSTRAP.contains("viewStateScheduled"));
        assert!(!BOOTSTRAP.contains("setInterval"));
        // One reserved slot before the port opens: a waiting view state
        // collapses onto itself instead of exhausting the 32-slot buffer.
        assert!(BOOTSTRAP.contains("queued[index].type===\"view-state\""));
        assert!(BOOTSTRAP.contains("if(queued.length<32)pushValue(queued,value)"));
        // The successor's evidence travels in the init envelope and is frozen
        // with the same freeze used for input; without it the frame cold-boots.
        assert!(BOOTSTRAP.contains("heldViewState=freeze(envelope)"));
        assert!(BOOTSTRAP.contains("heldViewState===undefined?freezeObject({input})"));
    }

    #[test]
    fn bootstrap_carries_new_tab_disposition_from_trusted_gestures() {
        // Ctrl/Cmd-click sends the navigation with `newTab: true`;
        // middle-click arrives as `auxclick` with button 1. Both read through
        // pristine `MouseEvent` getters so authored code cannot forge them.
        assert!(BOOTSTRAP.contains("newTab"));
        assert!(BOOTSTRAP.contains("auxclick"));
        assert!(BOOTSTRAP.contains("MouseEvent.prototype,\"ctrlKey\""));
        assert!(BOOTSTRAP.contains("MouseEvent.prototype,\"metaKey\""));
        assert!(BOOTSTRAP.contains("MouseEvent.prototype,\"button\""));
    }

    #[test]
    fn bootstrap_order_rejects_quoted_head_delimiters_and_pre_head_execution() {
        let attributed = document("").replacen("<head>", "<head data-x=\">\">", 1);
        let failure = validate(&attributed).unwrap_err();
        assert_eq!(failure.details["rule"], "bootstrap-order");
        assert!(failure.details["line"].as_u64().unwrap() > 0);

        let pre_head = document("").replacen(
            "<head>",
            "<script>window.ranBeforeBootstrap=true</script><head>",
            1,
        );
        let failure = validate(&pre_head).unwrap_err();
        assert_eq!(failure.details["rule"], "bootstrap-order");
    }

    #[test]
    fn host_matching_normalizes_dns_ipv6_and_default_ports_but_rejects_ambiguity() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("ARTIFACT.EXAMPLE.TEST:443"));
        assert!(host_matches_origin(
            &headers,
            "https://artifact.example.test"
        ));
        headers.insert(HOST, HeaderValue::from_static("artifact.example.test"));
        assert!(host_matches_origin(
            &headers,
            "https://artifact.example.test:443"
        ));
        headers.insert(HOST, HeaderValue::from_static("[::1]:4175"));
        assert!(host_matches_origin(&headers, "http://[::1]:4175"));
        headers.append(HOST, HeaderValue::from_static("attacker.example.test"));
        assert!(!host_matches_origin(
            &headers,
            "https://artifact.example.test"
        ));
    }

    fn launch_delivery_fixture() -> (LaunchDelivery, String, Manifest) {
        let delivery = LaunchDelivery::isolated_fixture(
            RuntimeConfig::new("https://workbench.test", "https://artifacts.test").unwrap(),
        );
        let source = document("");
        let manifest = validate(&source).unwrap();
        (delivery, source, manifest)
    }

    #[derive(Clone)]
    struct OrdinaryLaunchFixture {
        config: Arc<RuntimeConfig>,
        tickets: Arc<Mutex<TicketStore<Ticket>>>,
    }

    impl OrdinaryLaunchFixture {
        fn new(config: RuntimeConfig) -> Self {
            Self {
                config: Arc::new(config),
                tickets: Arc::new(Mutex::new(TicketStore::default())),
            }
        }
    }

    fn ordinary_launch_fixture() -> (OrdinaryLaunchFixture, String, Manifest) {
        let delivery = OrdinaryLaunchFixture::new(
            RuntimeConfig::new("https://workbench.test", "https://artifacts.test").unwrap(),
        );
        let source = document("");
        let manifest = validate(&source).unwrap();
        (delivery, source, manifest)
    }

    fn issue_at(
        delivery: &OrdinaryLaunchFixture,
        source: &str,
        manifest: &Manifest,
        principal: &str,
        now: Instant,
    ) -> Launch {
        issue_launch_in_store(
            source,
            manifest,
            principal,
            Some("db:test"),
            "artifact",
            &delivery.config,
            None,
            None,
            &delivery.tickets,
            Some(now),
        )
        .unwrap()
    }

    fn redeem_at(delivery: &OrdinaryLaunchFixture, issued: &Launch, now: Instant) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("artifacts.test"));
        launch_response(
            &delivery.config,
            &delivery.tickets,
            issued.url.rsplit('/').next().unwrap(),
            &headers,
            Some(now),
        )
    }

    #[tokio::test]
    async fn launch_global_pressure_is_instance_scoped_and_oldest_first_at_real_cap() {
        let (target, source, manifest) = ordinary_launch_fixture();
        let pressure = OrdinaryLaunchFixture::new((*target.config).clone());
        let now = Instant::now();
        let victim = issue_at(&target, &source, &manifest, "victim", now);
        let other_victim = issue_at(&pressure, &source, &manifest, "victim", now);
        let mut newest = None;
        for index in 0..LAUNCH_TICKET_MAX_COUNT {
            newest = Some(issue_at(
                &pressure,
                &source,
                &manifest,
                &format!("distinct-owner-{index}"),
                now,
            ));
        }
        {
            let store = pressure.tickets.lock().unwrap();
            assert_eq!(store.entries.len(), 128);
            assert_eq!(store.oldest.len(), 128);
            assert!(store.bytes < LAUNCH_TICKET_MAX_BYTES);
            assert_eq!(
                store.bytes,
                store.entries.values().map(|t| t.html.len()).sum::<usize>()
            );
            assert!(store
                .entries
                .values()
                .all(|t| t.expires == now + TICKET_TTL));
        }
        assert_eq!(
            redeem_at(&pressure, &other_victim, now).status(),
            StatusCode::GONE
        );
        assert_eq!(
            redeem_at(&pressure, &newest.unwrap(), now).status(),
            StatusCode::OK
        );
        let response = redeem_at(&target.clone(), &victim, now);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
        assert!(response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors https://workbench.test;"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        for marker in [
            "setViewState",
            "viewState",
            "view_state",
            "from_body_digest",
            "native-html-init",
        ] {
            assert!(
                body.contains(marker),
                "isolated launch lost bridge marker: {marker}"
            );
        }
        assert_eq!(redeem_at(&target, &victim, now).status(), StatusCode::GONE);
    }

    #[test]
    fn launch_per_principal_pressure_preserves_other_owners_below_global_cap() {
        let (delivery, source, manifest) = ordinary_launch_fixture();
        let now = Instant::now();
        let victim = issue_at(&delivery, &source, &manifest, "same-owner", now);
        let unrelated = issue_at(&delivery, &source, &manifest, "other-owner", now);
        for _ in 0..LAUNCH_TICKET_MAX_PER_PRINCIPAL {
            issue_at(&delivery, &source, &manifest, "same-owner", now);
        }
        let store = delivery.tickets.lock().unwrap();
        assert_eq!(store.entries.len(), 33);
        assert!(store.bytes < LAUNCH_TICKET_MAX_BYTES);
        assert!(store
            .entries
            .values()
            .all(|t| t.expires == now + TICKET_TTL));
        drop(store);
        assert_eq!(
            redeem_at(&delivery, &victim, now).status(),
            StatusCode::GONE
        );
        assert_eq!(
            redeem_at(&delivery, &unrelated, now).status(),
            StatusCode::OK
        );
    }

    #[test]
    fn launch_ttl_boundary_and_issuance_cleanup_use_fixed_time() {
        let (delivery, source, manifest) = ordinary_launch_fixture();
        let now = Instant::now();
        assert_eq!(TICKET_TTL, Duration::from_secs(30));
        let before = issue_at(&delivery, &source, &manifest, "owner", now);
        let exact = issue_at(&delivery, &source, &manifest, "owner", now);
        assert_eq!(before.expires_in_ms, 30_000);
        assert_eq!(
            redeem_at(
                &delivery,
                &before,
                now + TICKET_TTL - Duration::from_nanos(1)
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            redeem_at(&delivery, &exact, now + TICKET_TTL).status(),
            StatusCode::GONE
        );
        let expired = issue_at(&delivery, &source, &manifest, "owner", now);
        let fresh = issue_at(&delivery, &source, &manifest, "owner", now + TICKET_TTL);
        assert_eq!(delivery.tickets.lock().unwrap().entries.len(), 1);
        assert_eq!(
            redeem_at(&delivery, &expired, now + TICKET_TTL).status(),
            StatusCode::GONE
        );
        assert_eq!(
            redeem_at(&delivery, &fresh, now + TICKET_TTL).status(),
            StatusCode::OK
        );
    }

    #[test]
    fn ticket_store_real_byte_cap_evicts_without_count_principal_or_ttl_pressure() {
        struct Item {
            expires: Instant,
            principal: &'static str,
            bytes: usize,
        }
        let now = Instant::now();
        let mut store = TicketStore::<Item>::default();
        assert_eq!(LAUNCH_TICKET_MAX_BYTES, 64 * 1024 * 1024);
        let item_bytes = LAUNCH_TICKET_MAX_BYTES / 2 + 1;
        // Model payload sizes rather than allocate 64MiB of HTML. The same
        // production make_room implementation receives the real launch caps.
        for (token, principal) in [("old", "p"), ("new", "q")] {
            make_room(
                &mut store,
                now,
                principal,
                item_bytes,
                LAUNCH_TICKET_MAX_COUNT,
                LAUNCH_TICKET_MAX_PER_PRINCIPAL,
                LAUNCH_TICKET_MAX_BYTES,
                |item| item.expires,
                |item| item.principal,
                |item| item.bytes,
            )
            .unwrap();
            store.bytes += item_bytes;
            store.oldest.push_back(token.into());
            store.entries.insert(
                token.into(),
                Item {
                    expires: now + TICKET_TTL,
                    principal,
                    bytes: item_bytes,
                },
            );
        }
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.oldest, VecDeque::from(["new".to_string()]));
        assert_eq!(store.bytes, item_bytes);
        assert!(make_room(
            &mut store,
            now,
            "r",
            LAUNCH_TICKET_MAX_BYTES + 1,
            LAUNCH_TICKET_MAX_COUNT,
            LAUNCH_TICKET_MAX_PER_PRINCIPAL,
            LAUNCH_TICKET_MAX_BYTES,
            |item| item.expires,
            |item| item.principal,
            |item| item.bytes,
        )
        .is_err());
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.bytes, item_bytes);
    }

    #[tokio::test]
    async fn launch_configuration_interleaving_rejects_host_without_consuming_ticket() {
        let (delivery, source, manifest) = launch_delivery_fixture();
        let issued = delivery
            .issue_launch(&source, &manifest, "owner", None, "artifact")
            .unwrap();
        // Deterministically construct the legacy interleaving: the test writes
        // *.test, a competing artifacts.rs test overwrites it with localhost,
        // then the test snapshots config for its router. A LOCAL slot avoids
        // racing actual global configuration or unrelated tests. Both routers
        // share the same ticket, just as legacy routers share the default store.
        let slot = RwLock::new((*delivery.config).clone());
        *slot.write().unwrap() =
            RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080").unwrap();
        let stale_router = LaunchDelivery {
            kit: delivery.kit.clone(),
            config: Arc::new(slot.read().unwrap().clone()),
            ..delivery.clone()
        }
        .router();
        let request = || {
            Request::builder()
                .uri(Url::parse(&issued.url).unwrap().path())
                .header(HOST, "artifacts.test")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            stale_router.oneshot(request()).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(delivery.sample_counts().0, 1);
        let app = delivery.router();
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
        assert!(response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors https://workbench.test;"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("native.html.bridge.v1"));
        assert!(body.contains("setViewState"));
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn launch_delivery_router_excludes_harness_and_owns_store_lifetime() {
        let (delivery, source, manifest) = launch_delivery_fixture();
        let weak = Arc::downgrade(&delivery.tickets);
        let issued = delivery
            .issue_launch(&source, &manifest, "owner", None, "artifact")
            .unwrap();
        let app = delivery.clone().router();
        drop(delivery);
        assert!(weak.upgrade().is_some());
        let harness = Request::builder()
            .uri("/internal/artifacts/verification/unused")
            .header(HOST, "workbench.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(harness).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let request = Request::builder()
            .uri(Url::parse(&issued.url).unwrap().path())
            .header(HOST, "artifacts.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
        drop(app);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn ticket_store_bounds_bytes_count_and_principal_with_oldest_first_eviction() {
        struct Item {
            expires: Instant,
            principal: String,
            bytes: usize,
        }
        let now = Instant::now();
        let mut store = TicketStore::<Item>::default();
        assert!(make_room(
            &mut store,
            now,
            "p",
            11,
            2,
            1,
            10,
            |item| item.expires,
            |item| item.principal.as_str(),
            |item| item.bytes,
        )
        .is_err());

        for (token, principal, bytes) in [("old", "p", 4), ("other", "q", 4)] {
            make_room(
                &mut store,
                now,
                principal,
                bytes,
                2,
                1,
                10,
                |item| item.expires,
                |item| item.principal.as_str(),
                |item| item.bytes,
            )
            .unwrap();
            store.bytes += bytes;
            store.oldest.push_back(token.into());
            store.entries.insert(
                token.into(),
                Item {
                    expires: now + TICKET_TTL,
                    principal: principal.into(),
                    bytes,
                },
            );
        }
        make_room(
            &mut store,
            now,
            "p",
            5,
            2,
            1,
            10,
            |item| item.expires,
            |item| item.principal.as_str(),
            |item| item.bytes,
        )
        .unwrap();
        assert!(!store.entries.contains_key("old"));
        assert!(store.entries.contains_key("other"));
        assert_eq!(store.oldest, VecDeque::from(["other".to_string()]));
        assert_eq!(store.bytes, 4);
    }

    #[test]
    fn view_state_tabs_fixture_validates_for_the_handoff_journey() {
        // The real-server journey opens this document, switches to the
        // non-default tab, and rewrites the body out of band. Both revisions
        // must validate: the journey can only prove the handoff if the only
        // thing changing is authored text.
        let first = include_str!("../../../tests/fixtures/native-html-v1-view-state.html");
        assert_eq!(validate(first).unwrap().profile, Profile::Document);
        let second = first
            .replace("Workspace tabs</h1>", "Workspace tabs revised</h1>")
            .replace("data-body-revision=\"1\"", "data-body-revision=\"2\"");
        assert_ne!(second, first);
        assert_eq!(validate(&second).unwrap().profile, Profile::Document);
    }

    #[test]
    fn checked_in_document_slides_and_malicious_corpus_define_the_policy_boundary() {
        let document = include_str!("../../../tests/fixtures/native-html-v1-document.html");
        let slides = include_str!("../../../tests/fixtures/native-html-v1-slides.html");
        assert_eq!(validate(document).unwrap().profile, Profile::Document);
        let deck = validate(slides).unwrap();
        assert_eq!(deck.profile, Profile::Slides);
        assert_eq!(deck.slides, 4);
        let corpus: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native-html-v1-malicious.json"
        ))
        .unwrap();
        for probe in corpus.as_array().unwrap() {
            let source = document.replace(
                "</main>",
                &format!("{}</main>", probe["source"].as_str().unwrap()),
            );
            assert!(
                validate(&source).is_err(),
                "malicious fixture unexpectedly passed: {}",
                probe["name"]
            );
        }
    }

    #[tokio::test]
    async fn launch_is_host_scoped_single_use_and_carries_exact_policy() {
        let config =
            RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080").unwrap();
        configure(config.clone());
        let source = document("");
        let manifest = validate(&source).unwrap();
        let issued = issue_launch(&source, &manifest, "principal", Some("db"), "artifact").unwrap();
        let token = issued.url.rsplit('/').next().unwrap();
        let app = router(config);
        let request = || {
            Request::builder()
                .uri(format!("/artifact-runtime/v1/launch/{token}"))
                .header("host", "artifact.localhost:8080")
                .body(Body::empty())
                .unwrap()
        };
        let wrong = Request::builder()
            .uri(format!("/artifact-runtime/v1/launch/{token}"))
            .header("host", "localhost:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(wrong).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
        assert!(response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox allow-scripts"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("native.html.bridge.v1"));
        assert!(body.contains("nativeArtifact"));
        assert!(body.contains("propose"));
        assert!(descriptor()["requested_capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("host-mediated-write-proposal")));
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn launch_parent_is_immutable_per_ticket_and_rejection_mints_nothing() {
        let config = RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080")
            .unwrap()
            .with_parent_origins([
                "http://127.0.0.1:4319",
                "https://shell.example",
                "native-ui://app",
            ])
            .unwrap();
        let source = document("");
        let manifest = validate(&source).unwrap();
        let mut issued = Vec::new();
        for parent in [
            None,
            Some("http://127.0.0.1:4319/"),
            Some("https://SHELL.example:443"),
            Some("native-ui://app"),
        ] {
            let launch = issue_launch_with_attestation(
                &source,
                &manifest,
                "parent-binding-fixture",
                None,
                "artifact",
                &config,
                parent,
                None,
            )
            .unwrap();
            issued.push((launch, config.resolve_parent_origin(parent).unwrap()));
        }
        for parent in [
            "https://unlisted.example",
            "http://127.0.0.1:4320",
            "https://*.example",
            "null",
            "https://shell.example/path",
            "http://artifact.localhost:8080",
            "native-ui://other",
            "native-ui://app/",
        ] {
            let failure = issue_launch_with_attestation(
                &source,
                &manifest,
                "parent-binding-denied",
                None,
                "artifact",
                &config,
                Some(parent),
                None,
            )
            .err()
            .unwrap();
            assert_eq!(failure.code, "html_parent_origin_denied");
        }
        assert!(tickets()
            .lock()
            .unwrap()
            .entries
            .values()
            .all(|ticket| ticket.principal != "parent-binding-denied"));
        // The router has a different workbench origin from issuance. Delivered
        // policies must come from each already-issued ticket, including default.
        let app = router(
            RuntimeConfig::new("https://changed.example", "http://artifact.localhost:8080")
                .unwrap(),
        );
        for (launch, parent) in issued {
            let url = Url::parse(&launch.url).unwrap();
            let request = |host: &str| {
                Request::builder()
                    .uri(url.path())
                    .header("host", host)
                    .body(Body::empty())
                    .unwrap()
            };
            assert_eq!(
                app.clone()
                    .oneshot(request("localhost:8080"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            let response = app
                .clone()
                .oneshot(request("artifact.localhost:8080"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[CONTENT_SECURITY_POLICY], csp(&parent));
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
            assert_eq!(response.headers()[REFERRER_POLICY], "no-referrer");
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(
                body.as_ref(),
                inject(&source, &parent, &validate(&source).unwrap())
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(
                app.clone()
                    .oneshot(request("artifact.localhost:8080"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::GONE
            );
        }
        assert_eq!(
            descriptor()["delivery_transform"]["digest"],
            bootstrap_digest()
        );
        // Pin the template bytes independently of the descriptor. The default
        // rendered-text reporter changes delivery bytes. Install/source pins
        // are unaffected: alpha-tab-digest.v1
        // binds bundle, declaration and runtime only, never bootstrap bytes.
        // This current pin covers the composed body reader, default text
        // reporter, bounded Body-attempt negotiation, multi-host agent sessions v2,
        // floating-chat presentation, bounded session unread/request/detail
        // projections, synchronous admitted kit delivery, bounded app
        // close-risk reports, reentrancy-safe port-closed teardown,
        // host-injected app skins, and the Desktop-owned folder chooser.
        assert_eq!(
            bootstrap_digest(),
            "949dd85a45308648b938ba716f39a0c72c545a78a3c617390c04015639f5d1fa"
        );
    }

    #[tokio::test]
    async fn verification_harness_and_its_child_are_single_use_and_child_is_attested() {
        let config = RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080")
            .unwrap()
            .with_parent_origins(["http://127.0.0.1:4319", "https://shell.example"])
            .unwrap();
        configure(config.clone());
        let source = document("");
        let manifest = validate(&source).unwrap();
        let issued = issue_verification_harness(VerificationHarnessRequest {
            source: &source,
            manifest: &manifest,
            input: &json!({"version":"native.artifact-input.v1","mode":"standalone","collection":null,"records":[]}),
            input_digest: &"1".repeat(64),
            artifact_digest: &"2".repeat(64),
            adapter_digest: &"3".repeat(64),
            bootstrap_digest: &bootstrap_digest(),
            csp_digest: &content_security_policy_digest("http://localhost:8080").unwrap(),
            input_mode: "standalone",
            input_count: 0,
            principal: "principal",
            database: Some("db"),
            artifact_id: "artifact",
        })
        .unwrap();
        let token = issued.url.rsplit('/').next().unwrap();
        let app = router(config);
        let request = || {
            Request::builder()
                .uri(format!("/internal/artifacts/verification/{token}"))
                .header("host", "localhost:8080")
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-native-artifact-id"], "artifact");
        assert_eq!(response.headers()["x-native-input-mode"], "standalone");
        assert_eq!(response.headers()["x-native-input-count"], "0");
        assert_eq!(
            response.headers()["x-native-input-abi"],
            "native.artifact-input.v1"
        );
        assert_eq!(response.headers()["x-native-input-ports"], "[]");
        assert_eq!(response.headers()["x-native-runtime-id"], RUNTIME_ID);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store, private");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("MessageChannel"));
        assert!(body.contains("native-html-init"));
        let launch_url = Regex::new(r#"id="artifact" src="([^"]+)""#)
            .unwrap()
            .captures(&body)
            .unwrap()[1]
            .to_string();
        let launch_path = Url::parse(&launch_url).unwrap().path().to_string();
        let child_request = || {
            Request::builder()
                .uri(&launch_path)
                .header("host", "artifact.localhost:8080")
                .body(Body::empty())
                .unwrap()
        };
        let child = app.clone().oneshot(child_request()).await.unwrap();
        assert_eq!(child.status(), StatusCode::OK);
        assert_eq!(child.headers()["x-native-artifact-id"], "artifact");
        assert_eq!(child.headers()["x-native-artifact-digest"], &"2".repeat(64));
        assert_eq!(child.headers()["x-native-input-digest"], &"1".repeat(64));
        assert_eq!(child.headers()["x-native-adapter-digest"], &"3".repeat(64));
        assert_eq!(
            child.headers()["x-native-bootstrap-digest"],
            bootstrap_digest()
        );
        assert_eq!(
            child.headers()["x-native-csp-digest"],
            content_security_policy_digest("http://localhost:8080").unwrap()
        );
        assert_eq!(
            child.headers()["x-native-adapter-revision"],
            ADAPTER_REVISION.to_string()
        );
        assert_eq!(child.headers()["x-native-runtime-id"], RUNTIME_ID);
        assert_eq!(child.headers()["x-native-input-mode"], "standalone");
        assert_eq!(child.headers()["x-native-input-count"], "0");
        let child_csp = child.headers()[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert_eq!(
            child_csp,
            content_security_policy("http://localhost:8080").unwrap()
        );
        assert_eq!(
            hex::encode(Sha256::digest(child_csp.as_bytes())),
            child.headers()["x-native-csp-digest"]
        );
        let child_body = to_bytes(child.into_body(), usize::MAX).await.unwrap();
        assert!(
            String::from_utf8_lossy(&child_body).contains("const HOST=\"http://localhost:8080\"")
        );
        assert_eq!(
            app.clone().oneshot(child_request()).await.unwrap().status(),
            StatusCode::GONE
        );
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::GONE
        );
    }

    #[test]
    fn parent_allowlist_resolves_default_canonical_and_rejects_other() {
        let config = RuntimeConfig::new("https://app.test", "https://artifact.test")
            .unwrap()
            .with_parent_origins(["http://127.0.0.1:4319"])
            .unwrap();
        assert_eq!(
            config.resolve_parent_origin(None).unwrap(),
            "https://app.test"
        );
        assert_eq!(
            config
                .resolve_parent_origin(Some("https://app.test"))
                .unwrap(),
            "https://app.test"
        );
        assert_eq!(
            config
                .resolve_parent_origin(Some("http://127.0.0.1:4319"))
                .unwrap(),
            "http://127.0.0.1:4319"
        );
        assert_eq!(
            config
                .resolve_parent_origin(Some("HTTP://127.0.0.1:4319"))
                .unwrap(),
            "http://127.0.0.1:4319"
        );
        assert!(config
            .resolve_parent_origin(Some("https://evil.test"))
            .is_err());
        assert!(config
            .resolve_parent_origin(Some("https://artifact.test"))
            .is_err());
        assert!(config.resolve_parent_origin(Some("http://*.test")).is_err());
        assert!(config
            .resolve_parent_origin(Some("http://example.com"))
            .is_err());
    }

    #[test]
    fn parent_allowlist_canonicalizes_loopback_and_rejects_controls_and_partial_origins() {
        let base = || RuntimeConfig::new("https://app.test", "https://artifact.test").unwrap();
        let config = base()
            .with_parent_origins([
                "http://SHELL.localhost:80/",
                "http://[::1]:4319",
                "https://SHELL.test:443/",
                "https://bücher.test",
                "native-ui://app",
            ])
            .unwrap();
        for (raw, canonical) in [
            ("native-ui://app", "native-ui://app"),
            ("http://shell.localhost", "http://shell.localhost"),
            ("http://[0:0:0:0:0:0:0:1]:4319/", "http://[::1]:4319"),
            ("https://shell.test", "https://shell.test"),
            (
                "https://xn--bcher-kva.test:443",
                "https://xn--bcher-kva.test",
            ),
        ] {
            assert_eq!(config.resolve_parent_origin(Some(raw)).unwrap(), canonical);
        }
        for raw in [
            "",
            " ",
            "null",
            "https://shell.te\nst",
            "https://shell.test\t",
            " https://shell.test",
            "https://shell.test/path",
            "https://shell.test/..",
            "https://@shell.test",
            "https://shell.test\\",
            "https://shell.test?q=1",
            "https://shell.test#x",
            "https://user:password@shell.test",
            "https://%2A.test",
            "https://shell.localhost",
            "http://shell.localhost:81",
            "http://[::1]:4320",
            "http://remote.test",
            "native-ui://other",
            "native-ui://app/",
            "native-ui://APP",
            "NATIVE-UI://app",
            "native-ui://app:80",
            "native-ui://user@app",
            "native-ui://app/path",
            "native-ui://app?x=1",
            "native-ui://app#x",
        ] {
            assert!(config.resolve_parent_origin(Some(raw)).is_err(), "{raw:?}");
        }
        for raw in [
            "",
            " ",
            "null",
            "https://shell.te\nst",
            "https://shell.test\t",
            " https://shell.test",
            "https://shell.test/path",
            "https://shell.test/..",
            "https://@shell.test",
            "https://shell.test\\",
            "https://shell.test?q=1",
            "https://shell.test#x",
            "https://user:password@shell.test",
            "https://%2A.test",
        ] {
            assert!(base().with_parent_origins([raw]).is_err(), "{raw:?}");
        }
        let mut invalid = base();
        invalid.workbench_origin = invalid.artifact_origin.clone();
        assert!(invalid.resolve_parent_origin(None).is_err());
        assert!(base()
            .resolve_parent_origin(Some("native-ui://app"))
            .is_err());
        assert!(RuntimeConfig::new("native-ui://app", "https://artifact.test").is_err());
        assert!(RuntimeConfig::new("https://app.test", "native-ui://app").is_err());
    }

    #[test]
    fn parent_allowlist_builder_rejects_wildcard_artifact_and_plain_http() {
        let base = || RuntimeConfig::new("https://app.test", "https://artifact.test").unwrap();
        assert!(base().with_parent_origins(["https://*.test"]).is_err());
        assert!(base()
            .with_parent_origins(["https://artifact.test"])
            .is_err());
        assert!(base().with_parent_origins(["http://example.com"]).is_err());
        assert!(base().with_parent_origins(["not-an-origin"]).is_err());
        assert!(base()
            .with_parent_origins(["https://shell.test", "https://shell.test"])
            .is_ok());
    }
}

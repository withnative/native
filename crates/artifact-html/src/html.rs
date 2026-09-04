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
pub const ADAPTER_REVISION: u64 = 1;
pub const BRIDGE_VERSION: &str = "native.html.bridge.v1";
/// The static declaration contract embedded in an authored HTML document.
///
/// HTML intentionally does not grow a JavaScript module/import surface. A
/// declaration is inert JSON in one well-known element and is parsed before
/// delivery; the host later turns the same values into the shared named-input
/// envelopes used by native.mdx.v2.
pub const MANIFEST_SCHEMA: &str = "native.html.artifact.v1";
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
pub const DATA_ASSET_EACH_LIMIT: usize = 262_144;
pub const DATA_ASSET_TOTAL_LIMIT: usize = 393_216;
pub const DOM_NODE_LIMIT: usize = 10_000;
pub const CSS_RULE_LIMIT: usize = 5_000;
pub const SLIDE_LIMIT: usize = 200;
pub const INPUT_RECORD_LIMIT: usize = 5_000;
pub const INPUT_JSON_LIMIT: usize = 4_194_304;
pub const BRIDGE_MESSAGE_LIMIT: usize = 4_194_304;
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
const apply=Reflect.apply,own=Object.getOwnPropertyDescriptor,parentOf=Object.getPrototypeOf,define=Object.defineProperty,freezeObject=Object.freeze,objectKeys=Object.keys,isFrozen=Object.isFrozen,NativeString=String,nativeSetInterval=setInterval;
const getter=(proto,name)=>{for(let current=proto;current;current=parentOf(current)){const descriptor=own(current,name);if(descriptor?.get)return descriptor.get}};
const read=(nativeGetter,value)=>apply(nativeGetter,value,[]),eventAdd=EventTarget.prototype.addEventListener,eventRemove=EventTarget.prototype.removeEventListener,eventPrevent=Event.prototype.preventDefault,eventStop=Event.prototype.stopImmediatePropagation,portPost=MessagePort.prototype.postMessage,portStart=MessagePort.prototype.start,elementClosest=Element.prototype.closest,elementAttribute=Element.prototype.getAttribute;
const pristineEvent=new Event("native-html-bootstrap"),messageData=getter(MessageEvent.prototype,"data"),messageSource=getter(MessageEvent.prototype,"source"),messageOrigin=getter(MessageEvent.prototype,"origin"),messagePorts=getter(MessageEvent.prototype,"ports"),eventTarget=getter(Event.prototype,"target"),eventTrusted=own(pristineEvent,"isTrusted")?.get||getter(Event.prototype,"isTrusted"),eventPrevented=getter(Event.prototype,"defaultPrevented"),nodeType=getter(Node.prototype,"nodeType"),keyValue=getter(KeyboardEvent.prototype,"key"),shiftValue=getter(KeyboardEvent.prototype,"shiftKey");
const listen=(target,type,listener,options)=>apply(eventAdd,target,[type,listener,options]),unlisten=(target,type,listener,options)=>apply(eventRemove,target,[type,listener,options]),prevent=event=>apply(eventPrevent,event,[]),stop=event=>apply(eventStop,event,[]),post=(port,value,transfer)=>apply(portPost,port,transfer?[value,transfer]:[value]),start=port=>apply(portStart,port,[]),isElement=value=>!!value&&read(nodeType,value)===1,attribute=(element,name)=>apply(elementAttribute,element,[name]),closest=(element,selector)=>apply(elementClosest,element,[selector]),trusted=event=>!!eventTrusted&&read(eventTrusted,event)===true,prevented=event=>!!eventPrevented&&read(eventPrevented,event)===true;
let channel=null, initialized=false, current=0, slides=[], queued=[];
let resolveReady, rejectReady;
const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject});
const propose=intent=>{if(!intent||typeof intent!=="object"||Array.isArray(intent))throw new TypeError("artifact intent must be an object");send({version:VERSION,type:"intent",intent});};
define(window,"nativeArtifact",{value:freezeObject({ready,propose}),writable:false,configurable:false});
const bounded=value=>NativeString(value??"").slice(0,512);
const send=value=>{if(channel)post(channel,value);else if(queued.length<32)queued.push(value)};
const report=(code,detail={})=>send({version:VERSION,type:"diagnostic",code,detail});
const freeze=value=>{if(value&&typeof value==="object"&&!isFrozen(value)){freezeObject(value);for(const key of objectKeys(value))freeze(value[key])}return value};
for(const name of ["RTCPeerConnection","webkitRTCPeerConnection","mozRTCPeerConnection"]){try{define(globalThis,name,{value:undefined,writable:false,configurable:false})}catch{}}
listen(window,"error",event=>report("html_runtime_error",{message:bounded(event.message),line:event.lineno||0,column:event.colno||0}),true);
listen(window,"unhandledrejection",event=>report("html_runtime_error",{message:bounded(event.reason)}),true);
listen(window,"securitypolicyviolation",event=>report("html_csp_violation",{directive:bounded(event.effectiveDirective),blocked:bounded(event.blockedURI).split(/[?#]/)[0]}),true);
function interactive(target){return isElement(target)&&!!closest(target,"input,textarea,select,button,a,[contenteditable]:not([contenteditable=false])")}
function show(index){if(!slides.length)return;current=Math.max(0,Math.min(index,slides.length-1));slides.forEach((slide,i)=>{slide.hidden=i!==current;slide.setAttribute("aria-hidden",NativeString(i!==current))});let live=document.getElementById("native-slide-status");if(!live){live=document.createElement("div");live.id="native-slide-status";live.setAttribute("role","status");live.setAttribute("aria-live","polite");live.style.cssText="position:fixed;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)";document.body.append(live)}live.textContent=`Slide ${current+1} of ${slides.length}`;dispatchEvent(new CustomEvent("native:slidechange",{detail:freezeObject({index:current,number:current+1,total:slides.length,id:slides[current].id})}));send({version:VERSION,type:"slidechange",index:current,total:slides.length})}
function command(action){if(action==="first")show(0);else if(action==="previous")show(current-1);else if(action==="next")show(current+1);else if(action==="last")show(slides.length-1)}
function setupSlides(){const deck=document.querySelector("main[data-native-deck]");if(!deck)return;slides=[...deck.children].filter(node=>node.matches("section[data-native-slide]"));show(0);listen(window,"keydown",event=>{const target=read(eventTarget,event),key=read(keyValue,event),shift=read(shiftValue,event);if(prevented(event)||interactive(target))return;const backwards=key==="ArrowLeft"||key==="PageUp"||(key===" "&&shift);const forwards=key==="ArrowRight"||key==="PageDown"||(key===" "&&!shift);if(backwards||forwards||key==="Home"||key==="End"){prevent(event);command(key==="Home"?"first":key==="End"?"last":backwards?"previous":"next")}},true)}
listen(window,"click",event=>{if(!trusted(event)||prevented(event))return;const target=read(eventTarget,event),link=isElement(target)?closest(target,"[data-native-record-id],[data-native-external-url]"):null;if(!link)return;prevent(event);send({version:VERSION,type:"navigation",recordId:attribute(link,"data-native-record-id"),href:attribute(link,"data-native-external-url")})},true);
function receive(event){const data=read(messageData,event),ports=read(messagePorts,event);if(initialized||read(messageSource,event)!==parent||read(messageOrigin,event)!==HOST||data?.type!=="native-html-init"||data?.version!==VERSION||ports.length!==1)return;stop(event);initialized=true;unlisten(window,"message",receive,true);channel=ports[0];listen(channel,"message",message=>{const commandData=read(messageData,message);if(commandData?.version===VERSION&&commandData?.type==="command"&&["first","previous","next","last"].includes(commandData.action))command(commandData.action)});start(channel);for(const item of queued)post(channel,item);queued=[];try{const input=freeze(data.input);setupSlides();resolveReady(freezeObject({input}));send({version:VERSION,type:"ready",profile:slides.length?"slides":"document",slides:slides.length});nativeSetInterval(()=>send({version:VERSION,type:"heartbeat"}),500)}catch(error){rejectReady(error);report("html_delivery_failed",{message:bounded(error)})}}
listen(window,"message",receive,true);
const hostPost=parent.postMessage;apply(hostPost,parent,[{type:"native-html-bootstrap",version:VERSION},HOST]);
})();"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub workbench_origin: String,
    pub artifact_origin: String,
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
        })
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

#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
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
    /// True when the author supplied the declaration surface, including an
    /// explicitly empty manifest. It is intentionally omitted from the
    /// serialized validation manifest because it is an implementation detail,
    /// not source data.
    #[serde(skip)]
    pub named_inputs_declared: bool,
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
    headings: Vec<u8>,
    css: Vec<String>,
    assets: Vec<String>,
    deck_slides: Vec<(String, String, bool)>,
    deck_count: usize,
    declaration_values: Vec<String>,
}

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

type ParsedNamedDeclaration = (BTreeMap<String, Value>, Vec<Value>, bool);

fn parse_named_declaration(
    values: &[String],
) -> std::result::Result<ParsedNamedDeclaration, ValidationFailure> {
    if values.is_empty() {
        return Ok((BTreeMap::new(), Vec::new(), false));
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
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "schema" | "inputs" | "capability_requests"))
        || object.len() != 3
    {
        return Err(declaration_failure(
            "native HTML input declaration has unknown or missing fields",
            "declaration-fields",
        ));
    }
    if object.get("schema").and_then(Value::as_str) != Some(MANIFEST_SCHEMA) {
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
    Ok((inputs, normalized_requests, true))
}

fn source_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let before = &source[..byte_offset.min(source.len())];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = before.rsplit_once('\n').map_or_else(
        || before.chars().count() + 1,
        |(_, tail)| tail.chars().count() + 1,
    );
    (line, column)
}

fn attach_source_location(source: &str, failure: &mut ValidationFailure) {
    let rule = failure
        .details
        .get("rule")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let lower = source.to_ascii_lowercase();
    let needle = match rule {
        "external-script" | "import-map" => Some("<script"),
        "external-link-resource" => Some("<link"),
        "meta-http-equiv" => Some("<meta"),
        "forbidden-element" => [
            "<iframe",
            "<frame",
            "<fencedframe",
            "<portal",
            "<object",
            "<embed",
        ]
        .into_iter()
        .find(|needle| lower.contains(needle)),
        "form-action" => Some("<form"),
        "host-navigation" => Some("data-native-"),
        _ => None,
    };
    let Some(offset) = needle.and_then(|needle| lower.find(needle)) else {
        return;
    };
    let (line, column) = source_position(source, offset);
    if let Some(details) = failure.details.as_object_mut() {
        details.insert("line".into(), json!(line));
        details.insert("column".into(), json!(column));
    }
}

fn tag_end(source: &str, start: usize) -> Option<usize> {
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
            "h1" => {
                inspection.h1 += 1;
                inspection.headings.push(1);
            }
            "h2" | "h3" | "h4" | "h5" | "h6" => inspection.headings.push(tag.as_bytes()[1] - b'0'),
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
                        return Err(policy(
                            "profile meta must occur at most once",
                            "profile-count",
                        ));
                    }
                    inspection.profile = attributes
                        .get("content")
                        .map(|v| v.trim().to_ascii_lowercase());
                }
                if meta_name.as_deref() == Some("native-artifact-manifest") {
                    let Some(value) = attributes.get("content") else {
                        return Err(declaration_failure(
                            "native-artifact-manifest meta requires a content attribute",
                            "declaration-content",
                        ));
                    };
                    inspection.declaration_values.push(value.clone());
                }
                if matches!(
                    http_equiv.as_deref(),
                    Some("content-security-policy" | "refresh")
                ) {
                    return Err(policy(
                        "authored CSP and refresh meta are forbidden",
                        "meta-http-equiv",
                    ));
                }
            }
            "base" | "iframe" | "frame" | "fencedframe" | "portal" | "object" | "embed" => {
                return Err(policy(format!("<{tag}> is forbidden"), "forbidden-element"))
            }
            "script" => {
                if attributes.contains_key("src") {
                    return Err(policy("script[src] is forbidden", "external-script"));
                }
                if attributes
                    .get("type")
                    .is_some_and(|v| v.eq_ignore_ascii_case("importmap"))
                {
                    return Err(policy("import maps are forbidden", "import-map"));
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
            }
            "link" => {
                return Err(policy(
                    "link elements are forbidden; artifacts are self-contained",
                    "external-link-resource",
                ))
            }
            "form" if attributes.contains_key("action") => {
                return Err(policy("form[action] is forbidden", "form-action"))
            }
            "img" if !attributes.contains_key("alt") => {
                return Err(policy(
                    "every image must carry alt (empty for decorative images)",
                    "image-alt",
                ));
            }
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
            .and_then(|v| v.parse::<i32>().ok())
            .is_some_and(|v| v > 0)
        {
            return Err(policy(
                "positive tabindex is forbidden",
                "positive-tabindex",
            ));
        }
        if let Some(style) = attributes.get("style") {
            inspection.css.push(style.clone());
        }
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
            ) {
                return Err(policy(
                    format!("URL-bearing attribute {key} on <{tag}> is forbidden"),
                    "url-attribute",
                ));
            }
        }
        if let Some(record_id) = attributes.get("data-native-record-id") {
            if record_id.trim().is_empty() || attributes.contains_key("data-native-external-url") {
                return Err(policy(
                    "host-mediated navigation must name exactly one non-empty destination",
                    "host-navigation",
                ));
            }
        }
        if let Some(href) = attributes.get("data-native-external-url") {
            let parsed = Url::parse(href).map_err(|_| {
                policy(
                    "data-native-external-url must be an absolute http(s) URL",
                    "host-navigation",
                )
            })?;
            if !matches!(parsed.scheme(), "http" | "https")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(policy(
                    "data-native-external-url must be an absolute http(s) URL without credentials",
                    "host-navigation",
                ));
            }
        }
    }
    for child in node.children.borrow().iter() {
        inspect_node(child, inspection, children_in_deck)?;
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
    let bytes = source.len();
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    if bytes > BODY_LIMIT {
        return Err(ValidationFailure::new(
            "html_source_too_large",
            "HTML source exceeds the UTF-8 body limit",
            json!({"phase":"validation","limit":"body_utf8_bytes","maximum":BODY_LIMIT,"actual":bytes,"body_digest":digest}),
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
    if let Err(mut failure) = inspect_node(&dom.document, &mut inspection, false) {
        attach_source_location(source, &mut failure);
        return Err(failure);
    }
    if inspection.html != 1
        || inspection.head != 1
        || inspection.body != 1
        || !inspection.lang
        || !inspection.charset
        || !inspection.viewport
        || inspection.title.len() != 1
        || inspection.title[0].trim().is_empty()
    {
        return Err(ValidationFailure::new("html_invalid_document", "document requires one html[lang], head, body, non-empty title, UTF-8 charset and responsive viewport", json!({"phase":"validation","rule":"document-envelope","body_digest":digest})));
    }
    let profile = match inspection.profile.as_deref() {
        None | Some("document") => Profile::Document,
        Some("slides") => Profile::Slides,
        Some(other) => {
            return Err(policy(
                format!("unknown native artifact profile '{other}'"),
                "profile",
            ))
        }
    };
    if inspection.mains != 1 || inspection.h1 != 1 {
        return Err(policy(
            "artifact requires exactly one main landmark and one H1",
            "landmarks-headings",
        ));
    }
    for pair in inspection.headings.windows(2) {
        if pair[1] > pair[0] + 1 {
            return Err(policy("heading levels must not skip", "heading-order"));
        }
    }
    let mut css_rules = 0usize;
    let css_url = Regex::new(r#"(?is)url\(\s*['\"]?([^'\")]+)['\"]?\s*\)"#).expect("CSS URL regex");
    let mut assets = inspection.assets;
    let css_comments = Regex::new(r"(?s)/\*.*?\*/").expect("CSS comment regex");
    for css in &inspection.css {
        let normalized = css_comments.replace_all(css, "").to_ascii_lowercase();
        if normalized.contains("@import") {
            return Err(policy("CSS @import is forbidden", "css-import"));
        }
        if normalized.contains("image-set(") || normalized.contains("-webkit-image-set(") {
            return Err(policy(
                "CSS image-set is forbidden; use a single quota-checked data URL",
                "css-image-set",
            ));
        }
        if normalized.contains("http:")
            || normalized.contains("https:")
            || normalized.contains("url(//")
        {
            return Err(policy("external CSS authority is forbidden", "css-url"));
        }
        css_rules += css.bytes().filter(|b| *b == b'{').count();
        for capture in css_url.captures_iter(css) {
            let value = capture.get(1).map(|v| v.as_str().trim()).unwrap_or("");
            if value.starts_with("data:") {
                assets.push(value.to_string());
            } else if !value.starts_with('#') {
                return Err(policy(
                    "CSS URLs must be permitted data assets or fragments",
                    "css-url",
                ));
            }
        }
    }
    if css_rules > CSS_RULE_LIMIT {
        return Err(policy("CSS rule limit exceeded", "css-rules"));
    }
    let mut asset_total = 0usize;
    for asset in assets {
        asset_total += decode_data_url(&asset)?;
        if asset_total > DATA_ASSET_TOTAL_LIMIT {
            return Err(ValidationFailure::new(
                "html_asset_too_large",
                "decoded data assets exceed aggregate limit",
                json!({"phase":"validation","limit":"data_asset_decoded_bytes_total","maximum":DATA_ASSET_TOTAL_LIMIT,"actual":asset_total}),
            ));
        }
    }
    let slides = if profile == Profile::Slides {
        if inspection.deck_count != 1 || !(2..=SLIDE_LIMIT).contains(&inspection.deck_slides.len())
        {
            return Err(policy(
                "slides require one main[data-native-deck] with 2–200 direct slides",
                "slides-structure",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for (id, labelled, heading) in &inspection.deck_slides {
            if id.is_empty() || labelled.is_empty() || !heading || !ids.insert(id) {
                return Err(policy(
                    "every slide needs a unique id, aria-labelledby, and visible heading",
                    "slide-accessible-name",
                ));
            }
        }
        inspection.deck_slides.len()
    } else {
        if inspection.deck_count != 0 {
            return Err(policy(
                "document profile cannot declare a slide deck",
                "profile-structure",
            ));
        }
        0
    };
    let (artifact_ports, capability_requests, named_inputs_declared) =
        parse_named_declaration(&inspection.declaration_values)?;
    Ok(Manifest {
        profile,
        body_digest: digest,
        body_utf8_bytes: bytes,
        static_dom_nodes: inspection.nodes,
        css_rules,
        data_asset_decoded_bytes_total: asset_total,
        slides,
        artifact_ports,
        capability_requests,
        named_inputs_declared,
    })
}

fn validation_cache() -> &'static Mutex<HashMap<String, Manifest>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Manifest>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cache_key(source: &str) -> String {
    let body_digest = Sha256::digest(source.as_bytes());
    let bootstrap_digest = Sha256::digest(BOOTSTRAP.as_bytes());
    let adapter_revision = ADAPTER_REVISION.to_be_bytes();
    let limits = format!(
        "{BODY_LIMIT}:{DATA_ASSET_EACH_LIMIT}:{DATA_ASSET_TOTAL_LIMIT}:{DOM_NODE_LIMIT}:{CSS_RULE_LIMIT}:{SLIDE_LIMIT}"
    );
    let parts: [&[u8]; 9] = [
        b"native.artifact-html-cache.v1",
        &body_digest,
        RUNTIME_ID.as_bytes(),
        b"native-ce.html-policy@1",
        &adapter_revision,
        &bootstrap_digest,
        b"native-ce.html-csp@1",
        limits.as_bytes(),
        b"html5ever@0.39.0",
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
    let key = cache_key(source);
    if let Some(manifest) = validation_cache()
        .lock()
        .expect("HTML validation cache poisoned")
        .get(&key)
        .cloned()
    {
        return Ok(manifest);
    }
    let manifest = validate(source)?;
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
        "validator":{"id":"native-ce.html-policy","version":1,"html_parser":"html5ever@0.39.0"},
        "delivery_transform":{"id":"native-ce.html-bootstrap","version":1,"digest":bootstrap_digest},
        "input_envelope_version":"native.artifact-input.v1","named_input_envelope_version":NAMED_INPUT_ABI,
        "collection_envelope_version":COLLECTION_ENVELOPE,"relation_envelope_version":RELATION_ENVELOPE,
        "bridge_version":BRIDGE_VERSION,
        "declaration_surface":{"schema":MANIFEST_SCHEMA,"element":"script[type=application/json][id=native-artifact-manifest] or meta[name=native-artifact-manifest]","exact_source":true,"capability":"input.read"},
        "execution_profile":"sandboxed-browser","profiles":["document","slides"],
        "requested_capabilities":["inline-script","inline-style","data-image","data-font","exact-input-read","host-mediated-navigation","host-mediated-write-proposal","host-fullscreen","ephemeral-render-verification"],
        "output_surface":"workbench.isolated-html-frame","diagnostic_format":"native.artifact-diagnostic.v1",
        "limits":{"body_utf8_bytes":BODY_LIMIT,"data_asset_decoded_bytes_each":DATA_ASSET_EACH_LIMIT,"data_asset_decoded_bytes_total":DATA_ASSET_TOTAL_LIMIT,"static_dom_nodes":DOM_NODE_LIMIT,"css_rules":CSS_RULE_LIMIT,"slides":SLIDE_LIMIT,"input_records":INPUT_RECORD_LIMIT,"input_json_bytes":INPUT_JSON_LIMIT,"bridge_message_bytes":BRIDGE_MESSAGE_LIMIT,"named_input_safe_integer_min":NAMED_INPUT_SAFE_INTEGER_MIN,"named_input_safe_integer_max":NAMED_INPUT_SAFE_INTEGER_MAX,"ready_timeout_ms":2000,"heartbeat_interval_ms":500,"heartbeat_misses":4}
    })
}

fn inject(source: &str, workbench_origin: &str) -> std::result::Result<String, ValidationFailure> {
    let insertion = bootstrap_insertion_offset(source)?;
    let bootstrap = BOOTSTRAP.replace(
        "__NATIVE_WORKBENCH_ORIGIN__",
        &serde_json::to_string(workbench_origin).expect("origin JSON"),
    );
    let mut delivered = String::with_capacity(source.len() + bootstrap.len() + 17);
    delivered.push_str(&source[..insertion]);
    delivered.push_str("<script>");
    delivered.push_str(&bootstrap);
    delivered.push_str("</script>");
    delivered.push_str(&source[insertion..]);
    Ok(delivered)
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
    _workbench_origin: String,
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
    pub url: String,
    pub expires_in_ms: u64,
}

pub fn issue_launch(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
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
        None,
    )
}

fn issue_launch_with_attestation(
    source: &str,
    manifest: &Manifest,
    principal: &str,
    database: Option<&str>,
    artifact_id: &str,
    config: &RuntimeConfig,
    attestation: Option<Attestation>,
) -> std::result::Result<Launch, ValidationFailure> {
    let html = inject(source, &config.workbench_origin)?;
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = hex::encode(random);
    let now = Instant::now();
    let mut store = tickets().lock().expect("ticket store poisoned");
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
            _workbench_origin: config.workbench_origin.clone(),
            attestation,
        },
    );
    Ok(Launch {
        url: format!(
            "{}/artifact-runtime/v1/launch/{token}",
            config.artifact_origin
        ),
        expires_in_ms: TICKET_TTL.as_millis() as u64,
    })
}

pub struct VerificationHarness {
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
    if !host_matches_origin(&headers, &config.artifact_origin) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let ticket = take_launch_ticket(&token);
    let Some(ticket) = ticket else {
        return StatusCode::GONE.into_response();
    };
    if ticket.expires <= Instant::now() {
        return StatusCode::GONE.into_response();
    }
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
        HeaderValue::from_str(&csp(&config.workbench_origin)).expect("validated CSP origin"),
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
    async fn verification_harness_and_its_child_are_single_use_and_child_is_attested() {
        let config =
            RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080").unwrap();
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
        assert_eq!(child.headers()["x-native-adapter-revision"], "1");
        assert_eq!(child.headers()["x-native-runtime-id"], RUNTIME_ID);
        assert_eq!(child.headers()["x-native-input-mode"], "standalone");
        assert_eq!(child.headers()["x-native-input-count"], "0");
        let child_csp = child.headers()[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(child_csp.as_bytes())),
            child.headers()["x-native-csp-digest"]
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
}

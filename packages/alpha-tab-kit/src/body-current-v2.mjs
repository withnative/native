// Inactive pure-data candidate. No host, transport, writer or authority discovery.
// Structural results are UNQUALIFIED. Only actual SHA256 verification promotes bytes.
// Capture before caller work; never freeze or replace shared globals/prototypes.
const apply = Reflect.apply, own = Object.getOwnPropertyDescriptor, names = Reflect.ownKeys;
const proto = Object.getPrototypeOf, create = Object.create, define = Object.defineProperty;
const setProto = Object.setPrototypeOf, objectProto = Object.prototype, nativeFreeze = Object.freeze;
const array = Array.isArray, integer = Number.isSafeInteger, hasOwn = Object.hasOwn;
const charCode = String.prototype.charCodeAt, slice = String.prototype.slice;
const parseJSON = JSON.parse, quoteJSON = JSON.stringify, numberText = Number.prototype.toString;
const Bytes = Uint8Array, Words = Uint32Array, Decoder = TextDecoder, Encoder = TextEncoder;
const typed = proto(Bytes.prototype), byteLength = own(typed, 'byteLength').get;
const typedName = own(typed, Symbol.toStringTag).get, setBytes = Bytes.prototype.set;
const bufferLength = own(ArrayBuffer.prototype, 'byteLength').get;
const decode = Decoder.prototype.decode, encoder = new Encoder(), encode = Encoder.prototype.encode;
const weakAdd = WeakSet.prototype.add, weakHas = WeakSet.prototype.has, verified = new WeakSet();
const addEvent = EventTarget.prototype.addEventListener, removeEvent = EventTarget.prototype.removeEventListener;
const signalAborted = own(AbortSignal.prototype, 'aborted').get;
const NativePromise = Promise, nativeThen = NativePromise.prototype.then;
const P = class extends NativePromise {};
const descriptor = value => { const d = create(null); d.value = value; return d; };
define(P, Symbol.species, descriptor(P));
const securedPromises = new WeakSet();
// Only promises created by this implementation (or its own crypto call) may be hardened.
const secureOwned = p => {
  if (apply(weakHas, securedPromises, [p])) return p;
  define(p, 'constructor', descriptor(P));
  define(p, 'then', descriptor(function(yes, no) { return apply(nativeThen, this, [yes, no]); }));
  apply(weakAdd, securedPromises, [p]); return p;
};
// Own safe constructor/then avoid mutable Promise.prototype and species lookups.
const promise = executor => secureOwned(new P(executor));
const then = (p, yes, no) => secureOwned(apply(nativeThen, secureOwned(p), [yes, no]));
const settle = p => then(p, value => value, error => { throw error; });
const race = (a, b) => promise((yes, no) => { then(a, yes, no); then(b, yes, no); });
const resolved = value => promise(yes => yes(value));
// Caller observation is deliberately NON-MUTATING. Native then ignores own .then,
// but necessarily reads constructor/species before installing its handlers.
// A throwing/invalid species (including later prototype sabotage) may prevent
// observing the producer's rejection: producer responsibility, not universal custody.
// Refuse safely through our own operation promise; never mutate foreign promises.
// Benign frozen/nonconfigurable native promises remain supported.
const observeCaller = p => promise(resolve => {
  try {
    apply(nativeThen, p, [value => { resolve(freeze({status:'fulfilled', value})); },
      () => { resolve(freeze({status:'rejected'})); }]);
  } catch { resolve(freeze({status:'unobservable'})); }
});
nativeFreeze(P.prototype); nativeFreeze(P);
const includes = (list, value) => { for (let i = 0; i < list.length; i++) if (list[i] === value) return true; return false; };
const cc = (s, at) => apply(charCode, s, [at]);
const cut = (s, start, end) => apply(slice, s, [start, end]);
const starts = (s, prefix, at = 0) => cut(s, at, at + prefix.length) === prefix;
const has = (o, k) => hasOwn(o, k);
const freeze = value => {
  // Only owned records reach here. Null prototypes prevent inherited then/toJSON.
  if (value && typeof value === 'object' && !array(value)) setProto(value, null);
  return nativeFreeze(value);
};
const byteCount = value => apply(byteLength, value, []);
const encoding = text => apply(encode, encoder, [text]);
const decoding = (decoder, bytes, stream) => apply(decode, decoder, [bytes, {stream}]);
const abort = signal => signal !== undefined && apply(signalAborted, signal, []) === true;
const listen = (signal, listener) => { if (signal !== undefined) apply(addEvent, signal, ['abort', listener, {once:true}]); };
const unlisten = (signal, listener) => { if (signal !== undefined) apply(removeEvent, signal, ['abort', listener]); };
// Internal canonical JSON: never looks up toJSON, iterators or authored methods.
function json(value, depth = 0) {
  if (depth > 10) throw 0;
  if (value === null) return 'null';
  if (typeof value === 'string') return quoteJSON(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number' && integer(value)) return apply(numberText, value, [10]);
  if (!value || typeof value !== 'object') throw 0;
  let out = '', keys = names(value), count = 0;
  if (array(value)) {
    for (let i = 0; i < value.length; i++) {
      const d = own(value, apply(numberText, i, [10])); if (!d || !has(d, 'value')) throw 0;
      out += (i ? ',' : '') + json(d.value, depth + 1);
    }
    return '[' + out + ']';
  }
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i], d = own(value, key);
    if (typeof key !== 'string' || !d?.enumerable || !has(d, 'value')) throw 0;
    out += (count++ ? ',' : '') + quoteJSON(key) + ':' + json(d.value, depth + 1);
  }
  return '{' + out + '}';
}
// Private sibling implementation plumbing; no package export/host grant.
export const bodyV2Internals = nativeFreeze({apply, own, names, proto, create, objectProto, array, integer, has,
  freeze, includes, cc, cut, starts, json, parseJSON, Bytes, Decoder, byteLength, typedName, setBytes,
  byteCount, encoding, decoding, abort, listen, unlisten, promise, then, settle, secureOwned, race, resolved, observeCaller});
const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const MAX = '9223372036854775807';
const BODY = 16777216;
let subtle, digest;
try { subtle = globalThis.crypto.subtle; digest = subtle.digest; } catch { /* no crypto: refusal */ }
const refusal = (code, reason) => freeze({ status: 'refused', code, reason });
const invalid = () => refusal('protocol_error', 'invalid_data');
const parsed = value => freeze({ status: 'parsed', qualification: 'unqualified', value: freeze(value) });

// Snapshot only declared own enumerable DATA fields; never read original accessors.
function data(value, required, optional = [], open = false) {
  if (!value || typeof value !== 'object' || array(value) || proto(value) !== null && proto(value) !== objectProto) throw 0;
  const keys = names(value);
  if (!open && (keys.length < required.length || keys.length > required.length + optional.length)) throw 0;
  const out = create(null);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (!includes(required, key) && !includes(optional, key)) { if (open) continue; throw 0; }
    const descriptor = own(value, key);
    if (!descriptor || !descriptor.enumerable || !has(descriptor, 'value')) throw 0;
    out[key] = descriptor.value;
  }
  for (let i = 0; i < required.length; i++) if (!has(out, required[i])) throw 0;
  return out;
}
function graphic(value, cap = 128) {
  if (typeof value !== 'string' || value.length < 1 || value.length > cap) throw 0;
  for (let i = 0; i < value.length; i++) if (cc(value, i) < 33 || cc(value, i) > 126) throw 0;
  return value;
}
function hex(value) {
  if (typeof value !== 'string' || value.length !== 64) throw 0;
  for (let i = 0; i < 64; i++) { const c = cc(value, i); if (!(c >= 48 && c <= 57 || c >= 97 && c <= 102)) throw 0; }
  return value;
}
function decimal(value, zero = false) {
  if (typeof value !== 'string' || !value.length || value.length > 19
    || (value[0] === '0' && (value.length !== 1 || !zero))
    || value.length === 19 && value > MAX) throw 0;
  for (let i = 0; i < value.length; i++) if (cc(value, i) < 48 || cc(value, i) > 57) throw 0;
  return value;
}
function recordVersion(value) {
  if (typeof value !== 'string' || !starts(value, 'rec:')) throw 0;
  return decimal(cut(value, 4), true);
}
function revision(value, state) {
  if (typeof value !== 'string' || value.length !== 74 || !starts(value, `body:v1:${state === 'live' ? 'l' : 'd'}:`)) throw 0;
  hex(cut(value, 10)); return value;
}
function bytes(text) {
  if (typeof text !== 'string' || text.length > BODY) throw 0;
  for (let i = 0; i < text.length; i++) {
    const c = cc(text, i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const low = cc(text, ++i); if (!(low >= 0xdc00 && low <= 0xdfff)) throw 0;
    } else if (c >= 0xdc00 && c <= 0xdfff) throw 0;
  }
  const encoded = encoding(text); if (byteCount(encoded) > BODY) throw 0;
  return encoded;
}
function size(value, cap = BODY) { if (!integer(value) || value < 0 || value > cap) throw 0; return value; }
function committed(value, version, withVersion = false) {
  const c = data(value, withVersion ? ['record_version', 'body_present', 'body_digest', 'body_event'] : ['body_present', 'body_digest', 'body_event']);
  const seq = recordVersion(version);
  if (withVersion && c.record_version !== version || typeof c.body_present !== 'boolean') throw 0;
  hex(c.body_digest);
  if (c.body_event === null) {
    if (c.body_present || c.body_digest !== EMPTY) throw 0;
  } else {
    if (!c.body_present) throw 0;
    const event = data(c.body_event, ['id', 'seq']); graphic(event.id); decimal(event.seq);
    if (event.seq.length > seq.length || event.seq.length === seq.length && event.seq > seq) throw 0;
    c.body_event = freeze(event);
  }
  return freeze(c);
}
function sameCommitted(a, b) {
  return a.body_present === b.body_present && a.body_digest === b.body_digest
    && (a.body_event === null ? b.body_event === null : b.body_event !== null
      && a.body_event.id === b.body_event.id && a.body_event.seq === b.body_event.seq);
}
function evidence(value) {
  const e = data(value, ['state', 'record_version', 'committed', 'live']);
  if (!includes(['durable', 'live'], e.state)) throw 0;
  recordVersion(e.record_version); e.committed = committed(e.committed, e.record_version);
  if (e.state === 'durable') { if (e.live !== null) throw 0; }
  else {
    const live = data(e.live, ['room_state', 'dirty']);
    if (!includes(['active', 'grace'], live.room_state) || typeof live.dirty !== 'boolean') throw 0;
    e.live = freeze(live);
  }
  return freeze(e);
}
function selected(value, e, text) {
  revision(value.revision, e.state); hex(value.body_digest);
  if (typeof value.body_present !== 'boolean') throw 0;
  size(value.total_bytes);
  if (!value.body_present && (text !== null || value.total_bytes !== 0 || value.body_digest !== EMPTY)) throw 0;
  if (value.body_present && typeof text !== 'string') throw 0;
  if (byteCount(bytes(text ?? '')) !== value.total_bytes) throw 0;
  if (value.total_bytes === 0 && value.body_digest !== EMPTY) throw 0;
  if (e.state === 'durable') {
    if (value.body_present !== e.committed.body_present || value.body_digest !== e.committed.body_digest) throw 0;
  } else if (!value.body_present || !e.live.dirty && value.body_digest !== e.committed.body_digest) throw 0;
}

export function validateBodyEvidenceV2(value) {
  try { return parsed(evidence(value)); } catch { return invalid(); }
}

/** A single already-selected record, not a singleton-envelope/authority check. */
export function validateCurrentBodyRecordV2(value, expectedRecordId) {
  try {
    graphic(expectedRecordId);
    const r = data(value, ['id', 'status', 'body', 'body_digest', 'version', 'record_version', 'body_read_contract', 'body_basis', 'live_body'], [], true);
    if (r.id !== expectedRecordId || r.status !== 'found' || r.body_read_contract !== 'native.current-body.v1'
      || r.version !== r.record_version || r.body !== null && typeof r.body !== 'string') throw 0;
    recordVersion(r.version); hex(r.body_digest);
    const basis = data(r.body_basis, ['revision', 'record_version', 'body_present', 'body_digest', 'body_event']);
    revision(basis.revision, 'durable');
    const base = committed({ record_version: basis.record_version, body_present: basis.body_present, body_digest: basis.body_digest, body_event: basis.body_event }, r.version, true);
    if (base.body_present !== (r.body !== null) || base.body_digest !== r.body_digest) throw 0;
    const durableBytes = bytes(r.body ?? '');
    if (!byteCount(durableBytes) && r.body_digest !== EMPTY) throw 0;
    // Keep only the owned materialization needed for later hashing/selection.
    const durable = freeze({ body: r.body, body_digest: r.body_digest, body_present: base.body_present,
      total_bytes: byteCount(durableBytes), revision: basis.revision, record_version: r.version, committed: base });
    let body = r.body, rev = basis.revision, present = base.body_present, hash = r.body_digest, count = byteCount(durableBytes);
    let e = freeze({ state: 'durable', record_version: r.version,
      committed: committed({ body_present: base.body_present, body_digest: base.body_digest, body_event: base.body_event }, r.version), live: null });
    if (r.live_body !== null) {
      const l = data(r.live_body, ['contract', 'state', 'revision', 'body', 'body_present', 'body_digest', 'total_bytes', 'room_state', 'dirty', 'committed']);
      if (l.contract !== 'native.live-body.v1' || l.state !== 'live' || l.body_present !== true || typeof l.body !== 'string') throw 0;
      const c = committed(l.committed, r.version, true);
      if (!sameCommitted(c, base)) throw 0;
      e = evidence({ state: 'live', record_version: r.version,
        committed: { body_present: c.body_present, body_digest: c.body_digest, body_event: c.body_event },
        live: { room_state: l.room_state, dirty: l.dirty } });
      selected(l, e, l.body);
      if (!l.dirty && l.body !== (r.body ?? '')) throw 0;
      body = l.body; rev = l.revision; present = true; hash = l.body_digest; count = l.total_bytes;
    }
    return parsed(freeze({ durable, selected: freeze({ contract: 'records.body.complete.v2', record_id: r.id,
      body, body_present: present, body_digest: hash, revision: rev, total_bytes: count, evidence: e }) }));
  } catch { return invalid(); }
}

const PAIRS = {
  invalid_params: ['request'], invalid_cursor: ['cursor'], cursor_expired: ['cursor'],
  resource_exhausted: ['result_budget', 'process_busy', 'source_work_limit', 'provenance_work_limit', 'vm_work_limit'],
  unsupported_profile: ['primary_sqlite_required'], unsupported_capability: ['portability_policy'],
  source_integrity: ['source'], undeclared_read: ['descriptor'], adoption_required: ['source'],
  record_unavailable: ['target'], access_lost: ['target'], scope_denied: ['scope'],
  revision_changed: ['incarnation'], too_large: ['body_read_work_limit'], timeout: ['request'], engine: ['integrity_or_execution'],
  // Proposed v2-only data vocabulary, not an installed host mapping.
  current_body_unavailable: ['sealed', 'quarantined', 'basis_changed'],
};
export function validateBodyPageV2(value, expected) {
  try {
    const required = ['contract', 'record_id', 'revision', 'body_digest', 'body_present', 'encoding', 'start_byte', 'end_byte', 'total_bytes', 'text', 'complete', 'next_cursor', 'limits', 'evidence'];
    // Inspect exactly once before selecting the closed variant.
    const top = data(value, ['contract'], ['record_id', 'revision', 'body_digest', 'body_present', 'encoding', 'start_byte', 'end_byte', 'total_bytes', 'text', 'complete', 'next_cursor', 'limits', 'evidence', 'error']);
    if (top.contract !== 'records.body.read.v2') throw 0;
    if (has(top, 'error')) {
      if (names(top).length !== 2) throw 0;
      const error = data(top.error, ['code', 'reason']);
      if (typeof error.code !== 'string' || typeof error.reason !== 'string' || !has(PAIRS, error.code) || !includes(PAIRS[error.code], error.reason)) return refusal('remote_refusal', 'unknown_refusal');
      return parsed(freeze({ contract: top.contract, error: freeze(error) }));
    }
    if (names(top).length !== required.length) throw 0;
    for (let i = 0; i < required.length; i++) if (!has(top, required[i])) throw 0;
    const p = top; graphic(p.record_id); hex(p.body_digest);
    if (expected !== undefined) {
      const x = data(expected, ['recordId', 'pageBytes']); graphic(x.recordId); size(x.pageBytes, 32768);
      if (x.pageBytes < 4 || p.record_id !== x.recordId || byteCount(bytes(p.text)) > x.pageBytes) throw 0;
    }
    p.evidence = evidence(p.evidence); revision(p.revision, p.evidence.state);
    if (p.encoding !== 'utf-8' || typeof p.body_present !== 'boolean' || typeof p.complete !== 'boolean') throw 0;
    size(p.start_byte); size(p.end_byte); size(p.total_bytes);
    const n = byteCount(bytes(p.text));
    if (p.start_byte > p.end_byte || p.end_byte > p.total_bytes || n > 32768 || p.end_byte - p.start_byte !== n) throw 0;
    if (p.complete ? p.end_byte !== p.total_bytes || p.next_cursor !== null : p.end_byte >= p.total_bytes || n === 0) throw 0;
    if (!p.complete) graphic(p.next_cursor, 1024);
    if (!p.body_present && (!p.complete || p.total_bytes !== 0 || p.text !== '')) throw 0;
    if (p.total_bytes === 0 && p.body_digest !== EMPTY) throw 0;
    const e = p.evidence;
    if (e.state === 'durable' ? p.body_present !== e.committed.body_present || p.body_digest !== e.committed.body_digest
      : !p.body_present || !e.live.dirty && p.body_digest !== e.committed.body_digest) throw 0;
    const optional = ['max_body_bytes', 'max_source_bytes', 'max_provenance_payload_bytes', 'max_provenance_events', 'request_timeout_ms'];
    const limits = data(p.limits, ['max_page_bytes', 'max_response_bytes'], optional);
    size(limits.max_page_bytes, 32768); size(limits.max_response_bytes, 262144);
    if (limits.max_page_bytes < 4 || limits.max_response_bytes < 1 || n > limits.max_page_bytes) throw 0;
    for (let i = 0; i < optional.length; i++) { const key = optional[i]; if (has(limits, key) && (!integer(limits[key]) || limits[key] < 1)) throw 0; }
    if (has(limits, 'max_body_bytes') && p.total_bytes > limits.max_body_bytes
      || has(limits, 'max_source_bytes') && p.total_bytes > limits.max_source_bytes) throw 0;
    p.limits = freeze(limits);
    if (byteCount(bytes(json(p))) > limits.max_response_bytes) throw 0;
    return parsed(freeze(p));
  } catch { return invalid(); }
}

export function validateCompleteBodyV2(value) {
  try {
    const c = data(value, ['contract', 'record_id', 'body', 'body_present', 'body_digest', 'revision', 'total_bytes', 'evidence']);
    if (c.contract !== 'records.body.complete.v2') throw 0;
    graphic(c.record_id); c.evidence = evidence(c.evidence); selected(c, c.evidence, c.body);
    return parsed(freeze(c));
  } catch { return invalid(); }
}
// Private independent SHA256 guard, adapted from kit/coedit/sha256.ts rounds.
// Algorithm reference: FIPS180-4 sections4.1.2/4.2.2,5.1.1/5.3.3,6.2.2.
// Fixed64-word schedule +8 hash words; virtual padding, no whole-body padded copy.
// Both this guard and REQUIRED WebCrypto consume the same private UTF8 input.
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function independentSha256(input) {
  const length = byteCount(input), bitLength = length * 8;
  // Input<=16MiB, hence its bit count fits in32 bits; the high length word is0.
  const paddedLength = ((length + 9 + 63) >>> 6) << 6;
  const w = new Words(64), h = new Words(8);
  h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
  h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
  const rotr = (x,n) => (x >>> n) | (x << (32-n));
  for(let offset=0;offset<paddedLength;offset+=64){
    for(let i=0;i<16;i++){
      let word=0;
      for(let j=0;j<4;j++){
        const at=offset+i*4+j;
        const value=at<length?input[at]:at===length?0x80:at<paddedLength-4?0:(bitLength >>> ((paddedLength-1-at)*8))&255;
        word=(word<<8)|value;
      }
      w[i]=word;
    }
    for(let i=16;i<64;i++){
      const x=w[i-15],y=w[i-2];
      w[i]=(w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>>10)))>>>0;
    }
    let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(let i=0;i<64;i++){
      const t1=(hh+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+K[i]+w[i])>>>0;
      const t2=((rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
      hh=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    h[0]=(h[0]+a)>>>0;h[1]=(h[1]+b)>>>0;h[2]=(h[2]+c)>>>0;h[3]=(h[3]+d)>>>0;
    h[4]=(h[4]+e)>>>0;h[5]=(h[5]+f)>>>0;h[6]=(h[6]+g)>>>0;h[7]=(h[7]+hh)>>>0;
  }
  const digits='0123456789abcdef';let out='';
  for(let i=0;i<8;i++)for(let shift=28;shift>=0;shift-=4)out+=digits[(h[i]>>>shift)&15];
  return out;
}

async function hash(text, signal) {
  if (abort(signal)) throw 'aborted';
  if (typeof digest !== 'function' || !subtle) throw 'crypto_unavailable';
  const input = bytes(text);
  const independent = independentSha256(input);
  let result, listener;
  const cancelled = promise((_, reject) => {
    listener = () => reject('aborted'); listen(signal, listener);
  });
  try {
    if (abort(signal)) throw 'aborted';
    result = await settle(race(secureOwned(apply(digest, subtle, ['SHA-256', input])), cancelled));
  } catch { if (abort(signal)) throw 'aborted'; throw 'crypto_failed'; }
  finally { unlisten(signal, listener); }
  if (abort(signal)) throw 'aborted';
  try {
    if (apply(bufferLength, result, []) !== 32) throw 0;
    const view = new Bytes(result), digits = '0123456789abcdef'; let out = '';
    for (let i = 0; i < 32; i++) out += digits[view[i] >>> 4] + digits[view[i] & 15];
    if (out !== independent) throw 'digest_mismatch';
    return out;
  } catch (error) { throw error === 'digest_mismatch' ? error : 'crypto_failed'; }
}

function hashFailure(error) { return error === 'aborted' ? refusal('cancelled', 'aborted') : refusal('source_integrity', includes(['crypto_unavailable', 'crypto_failed', 'digest_mismatch'], error) ? error : 'crypto_failed'); }
function promote(value) {
  const result = freeze({ status: 'verified', qualification: 'sha256-verified', value }); apply(weakAdd, verified, [result]); return result;
}
export function isVerifiedBodyV2(value) { return apply(weakHas, verified, [value]); }
async function verifyComplete(value, options) {
  const p = validateCompleteBodyV2(value); if (p.status !== 'parsed') return p;
  try {
    const o = data(options, [], ['signal']);
    const actual = await settle(hash(p.value.body ?? '', o.signal));
    if (abort(o.signal)) throw 'aborted';
    if (actual !== p.value.body_digest) throw 'digest_mismatch';
    if (abort(o.signal)) throw 'aborted';
    return promote(p.value);
  } catch (error) { return hashFailure(error); }
}
async function verifyCurrent(value, expectedRecordId, options) {
  const p = validateCurrentBodyRecordV2(value, expectedRecordId); if (p.status !== 'parsed') return p;
  try {
    const o = data(options, [], ['signal']);
    const durableHash = await settle(hash(p.value.durable.body ?? '', o.signal));
    if (abort(o.signal)) throw 'aborted';
    if (durableHash !== p.value.durable.body_digest) throw 'digest_mismatch';
    const selectedHash = await settle(hash(p.value.selected.body ?? '', o.signal));
    if (abort(o.signal)) throw 'aborted';
    if (selectedHash !== p.value.selected.body_digest) throw 'digest_mismatch';
    if (abort(o.signal)) throw 'aborted';
    return promote(p.value.selected);
  } catch (error) { return hashFailure(error); }
}

export function verifyCompleteBodyV2(value, options = {}) { return secureOwned(verifyComplete(value, options)); }
export function verifyCurrentBodyRecordV2(value, expectedRecordId, options = {}) { return secureOwned(verifyCurrent(value, expectedRecordId, options)); }

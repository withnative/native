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

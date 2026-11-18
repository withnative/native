// Inactive data codec. Does not register a transport/channel, offering or namespace.
import { validateBodyPageV2, bodyV2Internals as I } from './body-current-v2.mjs';
const {freeze, apply, own, names, proto, create, objectProto, array, integer, has, includes, cc, cut, starts,
  json, parseJSON, Bytes, Decoder, byteLength, typedName, setBytes, byteCount, encoding, decoding} = I;
const invalid = freeze({ kind: 'invalid', reason: 'protocol' });
const badRequest = freeze({ kind: 'invalid', reason: 'invalid_message' });
const HTTP = ['invalid_message', 'busy', 'mount_unavailable', 'timeout', 'cancelled', 'protocol'];
const pageKeys = ['contract', 'record_id', 'revision', 'body_digest', 'body_present', 'encoding', 'start_byte', 'end_byte', 'total_bytes', 'text', 'complete', 'next_cursor', 'limits', 'evidence', 'error'];
const grammars = {
  response: pageKeys,
  request: ['contract', 'record_id', 'page_bytes', 'revision', 'cursor'],
  evidence: ['state', 'record_version', 'committed', 'live'],
  committed: ['body_present', 'body_digest', 'body_event'],
  body_event: ['id', 'seq'], live: ['room_state', 'dirty'], error: ['code', 'reason'],
  limits: ['max_page_bytes', 'max_response_bytes', 'max_body_bytes', 'max_source_bytes', 'max_provenance_payload_bytes', 'max_provenance_events', 'request_timeout_ms'],
};
function shape(value, required, optional = []) {
  if (!value || typeof value !== 'object' || array(value) || proto(value) !== null && proto(value) !== objectProto) throw 0;
  const keys = names(value); if (keys.length < required.length || keys.length > required.length + optional.length) throw 0;
  const out = create(null);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (!includes(required, key) && !includes(optional, key)) throw 0;
    const d = own(value, key); if (!d?.enumerable || !has(d, 'value')) throw 0;
    out[key] = d.value;
  }
  for (let i = 0; i < required.length; i++) if (!has(out, required[i])) throw 0;
  return out;
}
function ascii(s, cap) { if (typeof s !== 'string' || s.length < 1 || s.length > cap) return false;
  for (let i = 0; i < s.length; i++) if (cc(s, i) < 33 || cc(s, i) > 126) return false; return true; }
const digit = (s, zero) => typeof s === 'string' && s.length === 1 && cc(s, 0) >= (zero ? 48 : 49) && cc(s, 0) <= 57;
const hexChar = s => digit(s, true) || typeof s === 'string' && s.length === 1 && (cc(s, 0) >= 65 && cc(s, 0) <= 70 || cc(s, 0) >= 97 && cc(s, 0) <= 102);
const digestHex = s => { if (s.length !== 64) return false; for (let i = 0; i < 64; i++) if (!(digit(s[i], true) || cc(s, i) >= 97 && cc(s, i) <= 102)) return false; return true; };
function scalar(s) {
  if (typeof s !== 'string') throw 0;
  for (let i = 0; i < s.length; i++) {
    const c = cc(s, i);
    if (c >= 0xd800 && c <= 0xdbff) { const n = cc(s, ++i); if (!(n >= 0xdc00 && n <= 0xdfff)) throw 0; }
    else if (c >= 0xdc00 && c <= 0xdfff) throw 0;
  }
  return s;
}
function bounded(text, cap) {
  if (typeof text !== 'string' || text.length > cap || byteCount(encoding(scalar(text))) > cap) throw 0;
  return text;
}
// Scan BEFORE JSON.parse. At most five fixed-schema object frames, <=16 keys each.
// Decoded keys alone are retained; payload strings are scanned without allocation.
function scan(text, root) {
  let at = 0;
  const ws = () => { while (at < text.length && includes([' ', '\r', '\n', '\t'], text[at])) at++; };
  function string(key) {
    const start = at;
    if (text[at++] !== '"') throw 0;
    let done = false;
    while (at < text.length) {
      const c = cc(text, at++);
      if (c === 34) { done = true; break; }
      if (c < 32) throw 0;
      if (c === 92) {
        const escape = text[at++];
        if (escape === 'u') { for (let n = 0; n < 4; n++) { const h = text[at++]; if (!h || !hexChar(h)) throw 0; } }
        else if (!escape || !includes(['"', '\\', '/', 'b', 'f', 'n', 'r', 't'], escape)) throw 0;
      }
      if (key && at - start > 400) throw 0;
    }
    if (!done) throw 0;
    if (!key) return;
    const value = parseJSON(cut(text, start, at));
    if (!ascii(value, 64)) throw 0;
    return value;
  }
  function object(grammar, depth) {
    if (depth > 5 || text[at++] !== '{') throw 0;
    const seen = create(null); seen.length = 0; ws(); if (text[at] === '}') { at++; return; }
    for (;;) {
      ws(); const key = string(true);
      if (!includes(grammars[grammar], key) || includes(seen, key)) throw 0;
      seen[seen.length++] = key; ws(); if (text[at++] !== ':') throw 0; ws();
      const c = text[at];
      if (c === '{') {
        const child = includes(['evidence', 'committed', 'body_event', 'live', 'limits', 'error'], key) ? key : null;
        if (!child) throw 0; object(child, depth + 1);
      } else if (c === '"') string(false);
      else if (starts(text, 'true', at)) at += 4;
      else if (starts(text, 'false', at)) at += 5;
      else if (starts(text, 'null', at)) at += 4;
      else {
        const start = at;
        if (text[at] === '-') at++;
        if (text[at] === '0') at++;
        else { if (!digit(text[at], false)) throw 0; while (digit(text[at], true)) at++; }
        if (text[at] === '.') { at++; const a = at; while (digit(text[at], true)) at++; if (at === a) throw 0; }
        if (text[at] === 'e' || text[at] === 'E') { at++; if (text[at] === '+' || text[at] === '-') at++; const a = at; while (digit(text[at], true)) at++; if (at === a) throw 0; }
        if (start === at) throw 0;
      }
      ws(); const next = text[at++]; if (next === '}') return; if (next !== ',') throw 0;
    }
  }
  ws(); object(root, 1); ws(); if (at !== text.length) throw 0;
}
function request(value) {
  const r = shape(value, ['contract', 'record_id'], ['page_bytes', 'revision', 'cursor']);
  if (r.contract !== 'records.body.read.v2' || !ascii(r.record_id, 128)
    || has(r, 'page_bytes') && (!integer(r.page_bytes) || r.page_bytes < 4 || r.page_bytes > 32768)
    || has(r, 'revision') !== has(r, 'cursor')) throw 0;
  if (has(r, 'revision') && (typeof r.revision !== 'string' || r.revision.length !== 74
    || !(starts(r.revision, 'body:v1:d:') || starts(r.revision, 'body:v1:l:')) || !digestHex(cut(r.revision, 10)) || !ascii(r.cursor, 1024))) throw 0;
  return freeze({ kind: 'request', qualification: 'unqualified', request_json: bounded(json(r), 4096), request: freeze(r) });
}
export function createBodyWireV2() {
  return freeze({
    validateTypedRequest(value) { try { return request(value); } catch { return badRequest; } },
    validateRawRequest(text) {
      try { bounded(text, 4096); scan(text, 'request'); return request(parseJSON(text)); } catch { return badRequest; }
    },
    validateBody(value, expected) { return validateBodyPageV2(value, expected); },
    decodeHttp(bytes, expected) {
      try {
        if (expected !== undefined) {
          const e = shape(expected, ['recordId', 'pageBytes']);
          if (!ascii(e.recordId, 128) || !integer(e.pageBytes) || e.pageBytes < 4 || e.pageBytes > 32768) return invalid;
          expected = freeze(e);
        }
        if (apply(typedName, bytes, []) !== 'Uint8Array') return invalid;
        const length = apply(byteLength, bytes, []);
        if (length < 1 || length > 262144) return invalid;
        const copy = new Bytes(length); apply(setBytes, copy, [bytes]);
        const text = decoding(new Decoder('utf-8', {fatal:true, ignoreBOM:true}), copy, false);
        // HTTP transport has a separate tiny closed grammar, never engine success.
        if (text.length <= 512) {
          try {
            // Same duplicate-aware pass, then exact shape. No pre-parse inspection.
            scan(text, 'responseTransport');
            const t = shape(parseJSON(text), ['contract', 'reason']);
            if (t.contract === 'records.body.transport.v2' && includes(HTTP, t.reason)) return freeze({ kind: 'transport', reason: t.reason });
          } catch { /* try the selected page/refusal variant */ }
        }
        scan(text, 'response');
        return validateBodyPageV2(parseJSON(text), expected);
      } catch { return invalid; }
    },
  });
}
grammars.responseTransport = ['contract', 'reason'];

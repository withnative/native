// Inactive assembler: explicit page callback only, no discovery or legacy fallback.
import { validateBodyPageV2, verifyCompleteBodyV2, bodyV2Internals as I } from './body-current-v2.mjs';
const {freeze, own, names, proto, create, objectProto, has, integer, includes, cc, json,
  encoding, decoding, Decoder, byteCount, abort, listen, unlisten, promise, then, settle, secureOwned, race, resolved, observeCaller} = I;
const refusal = (code, reason) => freeze({ status: 'refused', code, reason });
const data = (o, keys) => {
  if (!o || typeof o !== 'object' || proto(o) !== null && proto(o) !== objectProto) throw 0;
  const out = create(null), list = names(o);
  for (let i = 0; i < list.length; i++) {
    const key = list[i]; if (!includes(keys, key)) throw 0;
    const d = own(o, key); if (!d?.enumerable || !has(d, 'value')) throw 0;
    out[key] = d.value;
  }
  return out;
};
const canonical = p => {
  const e = p.evidence, c = e.committed, limits = p.limits;
  return json([p.revision, p.body_digest, p.body_present, p.total_bytes, p.encoding,
    [e.state, e.record_version, c.body_present, c.body_digest,
      c.body_event === null ? null : [c.body_event.id, c.body_event.seq],
      e.live === null ? null : [e.live.room_state, e.live.dirty]],
    [limits.max_page_bytes, limits.max_response_bytes, limits.max_body_bytes ?? null, limits.max_source_bytes ?? null,
      limits.max_provenance_payload_bytes ?? null, limits.max_provenance_events ?? null, limits.request_timeout_ms ?? null]]);
};
async function fetchPage(callback, request, signal) {
  if (abort(signal)) return refusal('cancelled', 'aborted');
  let listener;
  const cancelled = promise(resolve => {
    listener = () => resolve(refusal('cancelled', 'aborted')); listen(signal, listener);
  });
  // Use captured native promise observation; never look up caller-mutated .then.
  const response = then(resolved(undefined), () => {
    if (abort(signal)) return refusal('cancelled', 'aborted');
    const result = callback(freeze(request), freeze({signal}));
    // The declared callback returns a genuine Promise. Non-promises are a failure.
    return then(observeCaller(result), observation => observation.status === 'fulfilled'
      ? freeze({status:'page', value:observation.value}) : refusal('transport_error', 'read_page_failed'));
  }, () => refusal('transport_error', 'read_page_failed'));
  const sanitized = then(response, value => value, () => refusal('transport_error', 'read_page_failed'));
  try { return await settle(race(sanitized, cancelled)); }
  finally { unlisten(signal, listener); }
}
async function read(options) {
  let o;
  try {
    o = data(options, ['recordId', 'readPage', 'pageBytes', 'maxBodyBytes', 'signal', 'onProgress']);
    if (typeof o.recordId !== 'string' || o.recordId.length < 1 || o.recordId.length > 128
      || typeof o.readPage !== 'function' || o.onProgress !== undefined && typeof o.onProgress !== 'function') throw 0;
    for (let i = 0; i < o.recordId.length; i++) if (cc(o.recordId, i) < 33 || cc(o.recordId, i) > 126) throw 0;
    o.pageBytes ??= 32768; o.maxBodyBytes ??= 16777216;
    if (!integer(o.pageBytes) || o.pageBytes < 4 || o.pageBytes > 32768
      || !integer(o.maxBodyBytes) || o.maxBodyBytes < 0 || o.maxBodyBytes > 16777216) throw 0;
    abort(o.signal); // brand-check actual AbortSignal with the captured accessor
  } catch { return refusal('client_error', 'invalid_options'); }
  let first, signature, end = 0, count = 0, cursor;
  let chunks = create(null);
  try {
    for (;;) {
      if (abort(o.signal)) return refusal('cancelled', 'aborted');
      const request = create(null); request.contract = 'records.body.read.v2'; request.record_id = o.recordId; request.page_bytes = o.pageBytes;
      if (first) { request.revision = first.revision; request.cursor = cursor; }
      if (byteCount(encoding(json(request))) > 4096) return refusal('client_error', 'request_budget');
      const reply = await settle(fetchPage(o.readPage, request, o.signal));
      if (abort(o.signal)) return refusal('cancelled', 'aborted');
      if (reply.status !== 'page') return reply;
      const checked = validateBodyPageV2(reply.value, {recordId:o.recordId, pageBytes:o.pageBytes});
      if (checked.status !== 'parsed') return checked;
      const page = checked.value;
      if (has(page, 'error')) return refusal(page.error.code, page.error.reason);
      if (page.start_byte !== end) return refusal('protocol_error', 'noncontiguous_page');
      if (first && signature !== canonical(page)) return refusal('protocol_error', 'assembly_changed');
      if (page.total_bytes > o.maxBodyBytes) return refusal('client_limit', 'body_memory_limit');
      if (!first) { first = page; signature = canonical(page); }
      if (page.end_byte === end && !(count === 0 && page.complete && page.total_bytes === 0)) return refusal('protocol_error', 'nonprogress');
      chunks[count] = encoding(page.text); end = page.end_byte; count++;
      if (o.onProgress) {
        try {
          const pending = o.onProgress(freeze({receivedBytes:end, totalBytes:first.total_bytes, pages:count}));
          if (pending && (typeof pending === 'object' || typeof pending === 'function')) {
            observeCaller(pending); // Attach rejection handling without redefining caller properties.
            return refusal('client_error', 'progress_failed');
          }
        } catch { return refusal('client_error', 'progress_failed'); }
      }
      if (abort(o.signal)) return refusal('cancelled', 'aborted');
      if (page.complete) {
        const d = new Decoder('utf-8', {fatal:true, ignoreBOM:true}); let text = '';
        for (let i = 0; i < count; i++) text += decoding(d, chunks[i], i !== count - 1);
        const result = await settle(verifyCompleteBodyV2({contract:'records.body.complete.v2', record_id:o.recordId,
          body:first.body_present ? text : null, body_present:first.body_present, body_digest:first.body_digest,
          revision:first.revision, total_bytes:first.total_bytes, evidence:first.evidence}, {signal:o.signal}));
        if (abort(o.signal)) return refusal('cancelled', 'aborted');
        return result;
      }
      cursor = page.next_cursor;
    }
  } catch { return abort(o.signal) ? refusal('cancelled', 'aborted') : refusal('protocol_error', 'invalid_data'); }
  finally { chunks = null; }
}
export function readBodyV2(options) { return secureOwned(read(options)); }

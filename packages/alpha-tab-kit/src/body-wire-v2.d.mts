import type {BodyFailureV2,ParsedV2,BodyPageV2,BodyRefusalV2} from './body-current-v2.mjs';
import type {BodyRequestV2} from './body-reader-v2.mjs';
export type BodyWireInvalidV2 = Readonly<{kind:'invalid';reason:'protocol'|'invalid_message'}>;
export type BodyWireRequestV2 = Readonly<{kind:'request';qualification:'unqualified';request_json:string;request:BodyRequestV2}>|BodyWireInvalidV2;
export type BodyWireResultV2 = ParsedV2<BodyPageV2|BodyRefusalV2>|BodyFailureV2|BodyWireInvalidV2|
  Readonly<{kind:'transport';reason:'invalid_message'|'busy'|'mount_unavailable'|'timeout'|'cancelled'|'protocol'}>;
export interface BodyWireV2 {
  validateTypedRequest(value:unknown):BodyWireRequestV2;
  validateRawRequest(text:unknown):BodyWireRequestV2;
  validateBody(value:unknown,expected?:Readonly<{recordId:string;pageBytes:number}>):ParsedV2<BodyPageV2|BodyRefusalV2>|BodyFailureV2;
  decodeHttp(bytes:Uint8Array,expected?:Readonly<{recordId:string;pageBytes:number}>):BodyWireResultV2;
}
/** Pure request/HTTP codec; channel/offer/host names remain deferred. */
export function createBodyWireV2():BodyWireV2;

import type { BodyPage, BodyRefusal } from './body-reader.mjs';
export type HttpBodyTransportReason = 'invalid_message' | 'busy' | 'mount_unavailable' | 'timeout' | 'cancelled' | 'protocol';
export type BodyTransportReason = HttpBodyTransportReason | 'not_offered' | 'closed' | 'network';
export interface BodyWireExpected { readonly recordId: string; readonly pageBytes: number }
export type BodyWirePage = Readonly<Omit<BodyPage, 'limits'>> & { readonly limits: Readonly<BodyPage['limits']> };
export type BodyWireRefusal = Readonly<Omit<BodyRefusal, 'error'>> & { readonly error: Readonly<BodyRefusal['error']> };
export type BodyWireResult =
  | { readonly kind: 'body'; readonly response: BodyWirePage | BodyWireRefusal }
  | { readonly kind: 'transport'; readonly reason: HttpBodyTransportReason }
  | { readonly kind: 'invalid'; readonly reason: 'protocol' };
export type BodyWireRequest =
  | { readonly kind: 'request'; readonly request_json: string }
  | { readonly kind: 'invalid'; readonly reason: 'invalid_message' };
export type BodyChannelKind = 'request' | 'cancel' | 'transport' | 'result' | 'offering';
export interface BodyWire {
  decodeHttp(bytes: Uint8Array, expected?: BodyWireExpected): BodyWireResult;
  validateBody(value: unknown, expected?: BodyWireExpected): Exclude<BodyWireResult, { kind: 'transport' }>;
  validateTypedRequest(value: unknown): BodyWireRequest;
  validateRawRequest(value: unknown): BodyWireRequest;
  encodeChannel(value: unknown, kind: BodyChannelKind):
    | { readonly kind: 'encoded'; readonly data: Readonly<Record<string, unknown>>; readonly utf8Bytes: number }
    | { readonly kind: 'invalid'; readonly reason: 'protocol' };
  /** Literal page Reply mapping only; not an authenticated server adapter. */
  mapHostRefusal(variant: unknown): HttpBodyTransportReason;
}
/** Pure codec, not a host/transport/grant. Capture-before-author is a host obligation. */
export function createBodyWire(): BodyWire;

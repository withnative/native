import type { BodyPage, BodyRefusal } from './body-reader.mjs';
import type { BodyTransportReason } from './body-wire.mjs';
export type BodyTransportRequest = { record_id: string; page_bytes?: number } &
  ({ revision?: never; cursor?: never } | { revision: string; cursor: string });
export interface BodyOffering {
  readonly contract: 'records.body.read.v1'; readonly scope: 'viewer-visible-current-bodies';
  readonly max_request_bytes: 4096; readonly max_response_bytes: 262144; readonly max_page_bytes: 32768;
  readonly max_body_bytes: 16777216; readonly request_timeout_ms: 5000; readonly max_inflight: 1;
}
export interface BodyTransportError { readonly name: 'BodyTransportError'; readonly reason: BodyTransportReason }
export interface BodyTransport {
  readonly offering: BodyOffering | null;
  readPage(request: BodyTransportRequest, options?: { readonly signal?: AbortSignal }): Promise<BodyPage | BodyRefusal>;
  readPageRaw(requestJson: string, options?: { readonly signal?: AbortSignal }): Promise<BodyPage | BodyRefusal>;
  /** Stops this wrapper; mounted holder teardown owns remote cancellation. */
  dispose(): void;
}
export interface NativeBodyApi { readonly body: Omit<BodyTransport, 'dispose'> }
/** Bind after pristine module capture. Supplied API wiring is trusted, not admission. */
export function createBodyTransport(api?: NativeBodyApi): BodyTransport;

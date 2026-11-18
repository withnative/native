/** Candidate data only. IDs accept a bounded graphic-ASCII subset, not all native IDs. */
export type BodyRevisionV2 = `body:v1:${'d'|'l'}:${string}`;
export type RecordVersionV2 = `rec:${string}`;
export interface BodyEventV2 { readonly id: string; readonly seq: string }
export interface CommittedBodyV2 {
  readonly body_present: boolean; readonly body_digest: string; readonly body_event: BodyEventV2|null;
}
export type EvidenceV2 = Readonly<{
  state: 'durable'; record_version: RecordVersionV2; committed: CommittedBodyV2; live: null;
}> | Readonly<{
  state: 'live'; record_version: RecordVersionV2; committed: CommittedBodyV2;
  /** room_state is a T3 diagnostic; text/authority are T2 snapshot observations. */
  live: Readonly<{room_state:'active'|'grace';dirty:boolean}>;
}>;
export interface BodyLimitsV2 {
  readonly max_page_bytes:number; readonly max_response_bytes:number; readonly max_body_bytes?:number;
  readonly max_source_bytes?:number; readonly max_provenance_payload_bytes?:number;
  readonly max_provenance_events?:number; readonly request_timeout_ms?:number;
}
export interface BodyPageV2 {
  readonly contract:'records.body.read.v2'; readonly record_id:string; readonly revision:BodyRevisionV2;
  readonly body_digest:string; readonly body_present:boolean; readonly encoding:'utf-8';
  readonly start_byte:number; readonly end_byte:number; readonly total_bytes:number; readonly text:string;
  readonly complete:boolean; readonly next_cursor:string|null; readonly limits:BodyLimitsV2; readonly evidence:EvidenceV2;
}
export interface BodyRefusalV2 { readonly contract:'records.body.read.v2'; readonly error:Readonly<{code:string;reason:string}> }
/** Data shape alone is neither SHA verification, authority nor a committed BodyReceipt. */
export interface CompleteBodyDataV2 {
  readonly contract:'records.body.complete.v2'; readonly record_id:string; readonly body:string|null;
  readonly body_present:boolean; readonly body_digest:string; readonly revision:BodyRevisionV2;
  readonly total_bytes:number; readonly evidence:EvidenceV2;
}
export interface BodyFailureV2 { readonly status:'refused'; readonly code:string; readonly reason:string }
export interface ParsedV2<T> { readonly status:'parsed'; readonly qualification:'unqualified'; readonly value:T }
declare const verifiedBytes: unique symbol;
export interface VerifiedBodyV2 {
  readonly status:'verified'; readonly qualification:'sha256-verified'; readonly value:CompleteBodyDataV2;
  readonly [verifiedBytes]:true;
}
export type VerifiedDurableBodyV2 = VerifiedBodyV2 & {readonly value:CompleteBodyDataV2 & {readonly evidence:Extract<EvidenceV2,{state:'durable'}>}};
export type VerifiedLiveBodyV2 = VerifiedBodyV2 & {readonly value:CompleteBodyDataV2 & {readonly evidence:Extract<EvidenceV2,{state:'live'}>}};
export interface CurrentRecordDataV2 {
  readonly durable:Readonly<{body:string|null;body_digest:string;body_present:boolean;total_bytes:number;
    revision:BodyRevisionV2;record_version:RecordVersionV2;committed:CommittedBodyV2 & {readonly record_version:RecordVersionV2}}>;
  readonly selected:CompleteBodyDataV2;
}
export function validateBodyEvidenceV2(value:unknown):ParsedV2<EvidenceV2>|BodyFailureV2;
/** Takes an already-selected single record, not its outer envelope. */
export function validateCurrentBodyRecordV2(value:unknown,expectedRecordId:string):ParsedV2<CurrentRecordDataV2>|BodyFailureV2;
export function validateBodyPageV2(value:unknown,expected?:Readonly<{recordId:string;pageBytes:number}>):ParsedV2<BodyPageV2|BodyRefusalV2>|BodyFailureV2;
export function validateCompleteBodyV2(value:unknown):ParsedV2<CompleteBodyDataV2>|BodyFailureV2;
/** Actual captured platform crypto only; no hash callback accepted. */
export function verifyCompleteBodyV2(value:unknown,options?:Readonly<{signal?:AbortSignal}>):Promise<VerifiedBodyV2|BodyFailureV2>;
/** Hashes BOTH durable top-level body and selected observed bytes. */
export function verifyCurrentBodyRecordV2(value:unknown,expectedRecordId:string,options?:Readonly<{signal?:AbortSignal}>):Promise<VerifiedBodyV2|BodyFailureV2>;
/** Runtime provenance check: forged tags/structural server claims return false. */
export function isVerifiedBodyV2(value:unknown):value is VerifiedBodyV2;

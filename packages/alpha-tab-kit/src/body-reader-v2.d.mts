import type {BodyRevisionV2,BodyPageV2,BodyRefusalV2,VerifiedBodyV2,BodyFailureV2} from './body-current-v2.mjs';
export type BodyRequestV2 = Readonly<{contract:'records.body.read.v2';record_id:string;page_bytes?:number} &
  ({revision?:never;cursor?:never}|{revision:BodyRevisionV2;cursor:string})>;
export interface BodyReadOptionsV2 {
  readonly recordId:string;
  readonly readPage:(request:BodyRequestV2,options:Readonly<{signal?:AbortSignal}>)=>Promise<BodyPageV2|BodyRefusalV2>;
  readonly pageBytes?:number;readonly maxBodyBytes?:number;readonly signal?:AbortSignal;
  readonly onProgress?:(progress:Readonly<{receivedBytes:number;totalBytes:number;pages:number}>)=>void;
}
/** No discovery, offered transport, legacy fallback or caller-provided hash implementation. */
export function readBodyV2(options:BodyReadOptionsV2):Promise<VerifiedBodyV2|BodyFailureV2>;

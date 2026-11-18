import {validateCurrentBodyRecordV2,verifyCurrentBodyRecordV2,isVerifiedBodyV2,
  type VerifiedBodyV2,type VerifiedLiveBodyV2,type VerifiedDurableBodyV2} from '../src/body-current-v2.mjs';
import {readBodyV2} from '../src/body-reader-v2.mjs';
import {createBodyWireV2} from '../src/body-wire-v2.mjs';
import type {BodyReceipt} from '../../../web/apps/src/port/bodyAttempt.js';
const parsed=validateCurrentBodyRecordV2({},'task');
if(parsed.status==='parsed') {
  // @ts-expect-error structural parsing is not verified provenance
  const verified:VerifiedBodyV2=parsed;
  // @ts-expect-error selected raw data is not a save receipt
  const saved:BodyReceipt=parsed.value.selected;
  // @ts-expect-error owned evidence is deeply readonly
  parsed.value.selected.evidence.committed.body_digest='changed';
}
const result=await verifyCurrentBodyRecordV2({},'task');
if(result.status==='verified') {
  // @ts-expect-error SHA qualification is not committed save evidence
  const saved:BodyReceipt=result;
  // @ts-expect-error unknown selection state is not necessarily durable
  const durable:VerifiedDurableBodyV2=result;
  // @ts-expect-error unknown selection state is not necessarily live
  const live:VerifiedLiveBodyV2=result;
}
const forged={status:'verified' as const,qualification:'sha256-verified' as const,value:{} };
// @ts-expect-error missing module-private verified brand
const verified:VerifiedBodyV2=forged;
if(isVerifiedBodyV2(forged)){const narrowed:VerifiedBodyV2=forged;void narrowed;}
await readBodyV2({recordId:'task',readPage:async()=>{throw Error('unavailable');},
  // @ts-expect-error no fake hashing callback or discovery option
  hash:()=> 'declared digest'});
const wire=createBodyWireV2();wire.validateTypedRequest({});wire.decodeHttp(new Uint8Array());
// @ts-expect-error no offered transport/channel registration API
wire.offering;
// @ts-expect-error no page callback discovery
await readBodyV2({recordId:'task'});

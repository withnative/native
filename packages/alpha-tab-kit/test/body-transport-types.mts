import { createBodyTransport, type BodyTransportRequest } from '../src/body-transport.mjs';
import { readBody } from '../src/body-reader.mjs';
const transport=createBodyTransport();
const first:BodyTransportRequest={record_id:'document'};
void transport.readPage(first,{signal:new AbortController().signal});
void transport.readPage({record_id:'document',revision:'revision',cursor:'cursor',page_bytes:4});
void transport.readPageRaw('{"record_id":"document"}');
void readBody({recordId:'document',readPage:transport.readPage});
// @ts-expect-error paired continuation fields are required
void transport.readPage({record_id:'document',revision:'revision'});
// @ts-expect-error descriptor/offering is never a selector or grant input
void transport.readPage({record_id:'document',scope:'viewer-visible-current-bodies'});
transport.dispose();

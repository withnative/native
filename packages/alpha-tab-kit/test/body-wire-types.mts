// Compile-only public-subpath consumer. No host/transport authority parameters.
import { createBodyWire, type BodyWireResult } from '@withnative/alpha-tab-kit/body-wire';
const wire = createBodyWire();
const result: BodyWireResult = wire.decodeHttp(new Uint8Array(), {recordId:'doc',pageBytes:4});
if (result.kind === 'body') {
  if ('limits' in result.response) {
    // @ts-expect-error validated nested data is readonly
    result.response.limits.max_page_bytes = 1;
  } else {
    // @ts-expect-error validated error data is readonly
    result.response.error.reason = 'diagnostic';
  }
}
wire.validateRawRequest('[]');
wire.validateTypedRequest({record_id:'doc'});
wire.encodeChannel({}, 'cancel');
// @ts-expect-error only closed channel kinds are allowed
wire.encodeChannel({}, 'grant');

import { createBodyParentController } from '../src/body-parent-controller.mjs';
const c = createBodyParentController({ token: 'host-only', endpoint: '/body', retireEndpoint: '/retire', isCurrent: () => true });
const closed: Promise<void> = c.closed;
const outcome: 'ignored' | 'consumed' | 'ready' | 'closed' = c.receive(new MessageEvent('message'), { port: new MessageChannel().port1, epoch: 1 });
void [closed, outcome];
// @ts-expect-error readonly logical notification
c.closed = Promise.resolve();
// @ts-expect-error no teardown authority callback constructor
createBodyParentController({ token: '', endpoint: '', retireEndpoint: '', isCurrent: () => true, onClose: () => {} });
const mixed = createBodyParentController({ token: 'host-only', endpoint: '/body', retireEndpoint: '/retire',
  isCurrent: () => true, composition: { kind: 'ordinary-mixed.v1' } });
mixed.attach({ port: new MessageChannel().port1, epoch: 1, window,
  composition: { kind: 'ordinary-mixed.v1', contextOffered: true } });
// @ts-expect-error constructor cannot select attach-time context
createBodyParentController({ token: '', endpoint: '', retireEndpoint: '', isCurrent: () => true, composition: { kind: 'ordinary-mixed.v1', contextOffered: true } });
// @ts-expect-error closed attachment kind
mixed.attach({ port: new MessageChannel().port1, epoch: 1, window, composition: { kind: 'other', contextOffered: false } });
// @ts-expect-error context must be literal boolean data, no authority function
mixed.attach({ port: new MessageChannel().port1, epoch: 1, window, composition: { kind: 'ordinary-mixed.v1', contextOffered: () => true } });

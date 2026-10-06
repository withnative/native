import type { BodyOffering } from './body-transport.mjs';
export interface BodyMixedComposition { readonly kind: 'ordinary-mixed.v1'; }
export interface BodyMixedAttachmentComposition { readonly kind: 'ordinary-mixed.v1'; readonly contextOffered: boolean; }
/** Internal trusted owner API. No account/Db/package or launch selection. */
export interface BodyParentController {
  attach(attachment: { readonly port: MessagePort; readonly epoch: number; readonly window: Window; readonly composition?: BodyMixedAttachmentComposition }): BodyOffering;
  receive(event: MessageEvent, context: { readonly port: MessagePort; readonly epoch: number }): 'ignored' | 'consumed' | 'ready' | 'closed';
  close(): void;
  /** Logical closure only, no value/error. NOT retirement/settlement/physical ACK. */
  readonly closed: Promise<void>;
}
/** Capture this module before authored execution; host-only, not a kit export. */
export function createBodyParentController(configuration: {
  readonly token: string; readonly endpoint: string; readonly retireEndpoint: string; readonly isCurrent: () => boolean; readonly composition?: BodyMixedComposition;
}): BodyParentController;

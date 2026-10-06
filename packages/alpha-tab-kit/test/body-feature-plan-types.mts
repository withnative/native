import { planBodyFeatureInstall, type BodyFeaturePlan, type BodyFeatureInstallResult } from '@withnative/alpha-tab-kit/body-feature-plan';
const p: BodyFeaturePlan = planBodyFeatureInstall({
  descriptor: { package: 'example.reader', version: '1.0.0', runtime: 'native.html.v1',
    declaration: { needs: [{ need: 'records.body.read.v1', scope: 'viewer-visible-current-bodies' },
      { need: 'sql.snapshot.v1', key: 'rows', label: 'Rows', sql: 'SELECT id FROM records', params: [{ name: 'id', type: 'text' }] }],
      effects: [{ effect: 'records.title-set.v1', target: { need: 'rows' } }],
      sessions: [{ session: 'session.body.v1', key: 'doc', scope: { type: 'Document', kind: '*' }, mode: 'view', presence: false }] } },
  html: '<!doctype html><html><head></head><body></body></html>', homeId: 'home', reason: 'Prepare source',
});
const action: 'install' = p.hostInstall.arguments.action;
const withheld: false = p.hostAvailability.sessions;
const ack: BodyFeatureInstallResult = { event_id: 'event', event_type: 'alpha_tab.installed', changed: true };
void [action, withheld, ack];
// @ts-expect-error host plan is an immutable intent
p.hostInstall.arguments.idempotency_key = 'reset';
// @ts-expect-error no cookie or executor is accepted
planBodyFeatureInstall({ descriptor: {} as never, html: '', homeId: 'home', reason: 'r', cookie: 'secret' });
// @ts-expect-error request is not part of this authoring contract
planBodyFeatureInstall({ descriptor: {} as never, html: '', homeId: 'home', reason: 'r', request: null });
// @ts-expect-error acknowledgement is not a mount
ack.mount_token;

/** Pure author planning only. No Cookie transport, server admission or offering. */
export interface BodyReadDescriptor {
  readonly need: 'records.body.read.v1'; readonly scope: 'viewer-visible-current-bodies';
}
export type SqlParam = { readonly name: string; readonly required?: boolean } &
  ({ readonly type: 'text'; readonly max_len?: number } | { readonly type: 'integer' | 'timestamp_ms'; readonly max_len?: never });
export interface SqlNeed {
  readonly need: 'sql.snapshot.v1'; readonly key: string; readonly label: string;
  readonly sql: string; readonly params?: readonly SqlParam[];
}
export type EffectBound =
  { readonly effect: 'records.facet-set.v1'; readonly key: string; readonly values: readonly string[]; readonly target: { readonly need: string } } |
  { readonly effect: 'comment.create.v1'; readonly positions: readonly ('root' | 'reply')[]; readonly max_body_bytes: number; readonly target: { readonly need: string } } |
  { readonly effect: 'message.react.v1'; readonly emoji: readonly string[]; readonly target: { readonly need: string } } |
  { readonly effect: 'records.title-set.v1'; readonly target: { readonly need: string } };
export interface BodySession {
  readonly session: 'session.body.v1'; readonly key: string;
  readonly scope: { readonly type: string; readonly kind: string };
  readonly mode: 'edit' | 'view'; readonly presence: boolean;
}
export interface FeatureDeclaration {
  readonly needs: readonly (string | BodyReadDescriptor | SqlNeed)[];
  readonly effects: readonly (string | EffectBound)[];
  /** Absence, explicit empty, order and duplicates are retained in author intent. */
  readonly sessions?: readonly BodySession[];
}
export interface FeatureDescriptor {
  readonly package: string; readonly version: string; readonly runtime: 'native.html.v1';
  readonly declaration: FeatureDeclaration; readonly bundle?: string;
  readonly digest?: string; readonly bundle_sha256?: string; readonly declaration_digest?: string;
  readonly digest_version?: 'alpha-tab-digest.v1';
}
export interface BodyFeatureInstallParameters {
  readonly descriptor: FeatureDescriptor; readonly html: string; readonly homeId: string; readonly reason: string;
  readonly name?: string; readonly summary?: string;
  readonly sources?: readonly { readonly record_id: string; readonly reason: string }[];
  readonly chunkBytes?: number;
  readonly completenessBudget?: { readonly scriptBytes?: number; readonly tokens?: number; readonly steps?: number };
  readonly replaceInstallEventId?: string;
}
export type JsonData = null | boolean | number | string | readonly JsonData[] | { readonly [key: string]: JsonData };
export interface SourceStep {
  readonly step: string; readonly executor: 'records_write' | 'sql_read' | 'artifacts_write';
  readonly operation: 'create_record' | 'update_record' | 'query_sql' | 'manage_alpha_tabs.remove';
  readonly arguments: { readonly [key: string]: JsonData };
  readonly expect?: { readonly body_digest: string; readonly body_bytes?: number };
  readonly capture?: { readonly source_revision: 'rows[0].id' };
  readonly note?: string;
}
export interface BodyFeatureInstallArguments {
  readonly action: 'install'; readonly package: string; readonly version: string; readonly digest: string;
  readonly artifact_id: '{{record_id}}'; readonly source_revision: '{{source_revision}}';
  readonly declaration: FeatureDeclaration; readonly reason: string; readonly idempotency_key: string;
  readonly expected_install_event_id?: '{{removed_event_id}}';
}
/** An acknowledgement only; never a mount, source proof or admission grant. */
export interface BodyFeatureInstallResult {
  readonly event_id: string; readonly event_type: 'alpha_tab.installed'; readonly changed: boolean;
}
export interface BodyFeaturePlan {
  readonly kind: 'alpha-tab.body-feature-plan.v1'; readonly package: string; readonly version: string;
  readonly digests: { readonly digest_version: 'alpha-tab-digest.v1'; readonly bundle_sha256: string; readonly declaration_digest: string; readonly digest: string };
  readonly sourceSteps: readonly SourceStep[];
  readonly hostInstall: { readonly operation: 'alpha-tabs.body-feature'; readonly method: 'POST';
    readonly pathTemplate: '/databases/{db_id}/alpha-tabs/body-feature'; readonly arguments: BodyFeatureInstallArguments };
  readonly hostAvailability: { readonly body: 'viewer-visible-current-bodies'; readonly otherReads: false; readonly effects: false; readonly sessions: false };
}
/** Throws on malformed author data/structure/lint. Frozen plan, one new UUID
 * intent per call; explicit retry must reuse the original plan and raw request.
 * The separate selected-Db Cookie host executor/production lane is not supplied.
 */
export function planBodyFeatureInstall(parameters: BodyFeatureInstallParameters): BodyFeaturePlan;

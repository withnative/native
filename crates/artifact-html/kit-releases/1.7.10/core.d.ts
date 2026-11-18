// Native core app kit — AGPL-3.0-only; Copyright Native contributors.
// Release 1.7.10; major 1; native.app-kit.core.factory.v1; native.html.bridge.v1
declare namespace NativeAppKit {
  interface KitRelease {
      readonly version: string;
      readonly major: number;
      readonly layer: "core";
      readonly factory: "native.app-kit.core.factory.v1";
      readonly bridge: "native.html.bridge.v1";
      readonly js_sha256: string;
      readonly types_sha256: string;
  }

  /** One result row, keyed by output column name. */
  type Row = Readonly<Record<string, unknown>>;

  /**
   * One capped answer. `rows` is what was delivered; `truncated` says the
   * answer is a prefix. `rowCount` is a total only while `rowCountComplete` is
   * true, otherwise it is a floor ("more than N"). An app must show both.
   */
  interface QueryResult {
      readonly label: string;
      readonly columns: readonly string[];
      readonly rows: readonly Row[];
      readonly rowCount: number;
      readonly rowCountComplete: boolean;
      readonly truncated: boolean;
      /**
       * Set only on a result the host served from its cache, ahead of the
       * revalidation that follows it (a remount). It clears on the next uncached
       * delivery, even if the rows are equal. The host sends nothing for a
       * revalidation that finds equal rows, so then the flag stays set: do not
       * treat it as proof the rows are stale, only as "served from cache".
       */
      readonly cached?: boolean;
      /**
       * Set only while the host cannot confirm these rows right now: saved or first-paint rows awaiting its
       * answer, or its event stream is down. The rows are still the best known; keep showing them and say only
       * that they are being updated. Clears on the next delivery the host stands behind, even if the rows are equal.
       */
      readonly behind?: boolean;
      /**
       * Set only on the `last` rows of an error feed whose subscription has ended
       * for good (a terminal error): nothing will refresh them, so they may be out
       * of date. They are kept for display; do not present them as current.
       */
      readonly stale?: boolean;
      /**
       * Only for the host-pushed keyed needs (`HOST_PUSHED_KEYED_NEEDS`): the
       * opaque handle the host minted for this parameter variant. The host names
       * it in `keyed_freshness.changed` when the variant's rows move.
       */
      readonly variant?: string;
  }

  /** Why a port call failed. Stable, app-facing; adapters map their transport onto it. */
  type PortErrorCode = "busy" | "timeout" | "undeclared" | "refused" | "unavailable" | "malformed" | "closed";

  /** Stable diagnostic shape; no transport or write capability. */
  interface KitError extends Error {
      readonly code: PortErrorCode;
      readonly detail?: string;
  }

  /** What a live subscription is showing right now. Errors keep the last good result. */
  type Feed<T> = {
      readonly status: "loading";
  } | {
      readonly status: "ready";
      readonly result: T;
  } | {
      readonly status: "error";
      readonly error: KitError;
      readonly last?: T;
  };

  /** Apps own DOM and CSS; all data comes from their declared snapshots. */
  interface CoreKitBase {
      readonly release: KitRelease;
      readonly ready: Promise<void>;
      read(key: string): Promise<QueryResult>;
      subscribe(key: string, listener: (feed: Feed<QueryResult>) => void): () => void;
      countLabel(result: QueryResult): string;
      /** Object rows from an app-v2 result of either shape (1.7.0): `{sql}` rows are already objects, `{steps}` rows are arrays aligned to `columns`. */
      rowsOf(result: {
          readonly rows?: readonly unknown[];
          readonly columns?: readonly unknown[];
      } | null | undefined): Record<string, unknown>[];
      errorText(error: Pick<KitError, "code">): string;
      recordLink(id: string): {
          readonly "data-native-record-id": string;
      };
      externalLink(url: string): {
          readonly "data-native-external-url": string;
      };
  }

  /** Structural UI types: source apps need no npm declarations. */
  type UiChild = object | string | number | bigint | boolean | null | undefined | readonly UiChild[];

  type UiComponent<P = {}> = (props: P & {
      children?: UiChild;
  }) => UiChild;

  interface UiElement {
      readonly type: string | Function;
      readonly props: object;
      readonly key: string | number | null;
  }

  interface UiContext<T> {
      Provider: UiComponent<{
          value: T;
      }>;
      Consumer: UiComponent<{
          children: (value: T) => UiChild;
      }>;
  }

  type StateUpdate<T> = T | ((previous: T) => T);

  interface UiRef<T> {
      current: T;
  }

  type Effect = () => void | (() => void);

  interface AppQuery {
      readonly sql: string;
      readonly params?: readonly unknown[];
  }

  interface StepsQuery {
      readonly steps: readonly unknown[];
      readonly order?: string;
      readonly limit?: number;
      readonly offset?: number;
  }

  interface QueryFeedOptions {
      /** Waits before each quiet resubscribe after a transient terminal error; default 1, 2, 4, 8 s. */
      readonly retryDelaysMs?: readonly number[];
      /** How long a read may be in trouble before "Reconnecting…" shows; default 4 s. */
      readonly noticeDelayMs?: number;
      /** How long a recovery subscription may stay silent before "Couldn't refresh"; default 10 s. */
      readonly resubscribeDeadlineMs?: number;
  }

  interface AppQueryResult {
      readonly rows: readonly unknown[];
      readonly columns: readonly unknown[];
      readonly truncated: boolean;
      readonly cached?: boolean;
      readonly behind?: boolean;
      /** The act these rows reflect, when the host said (a node copy's head act, or hosted's own); absent when unknown. Never inside `rows`. */
      readonly act?: number;
  }

  interface QueryFeedError {
      readonly code: string;
      readonly message: string;
      readonly terminal: boolean;
      /** Present while the kit is still recovering on its own: `quiet` inside the notice delay, `reconnecting` after it. Absent once recovery is over or cannot help. */
      readonly retrying?: 'quiet' | 'reconnecting';
  }

  type QueryFeedState = {
      readonly status: 'loading';
      readonly last?: AppQueryResult;
      readonly deliveredAt?: number;
  } | {
      readonly status: 'unsupported';
      readonly message: string;
  } | {
      readonly status: 'ready';
      readonly result: AppQueryResult;
      readonly deliveredAt: number;
  } | {
      readonly status: 'error';
      readonly error: QueryFeedError;
      readonly last?: AppQueryResult;
      readonly deliveredAt?: number;
  };

  /** What a person should be told about a failing read; never an internal outcome word. */
  type FeedNoticeKind = 'none' | 'reconnecting' | 'failed';

  /**
   * How much to trust what a read is showing, in one word. Data is never dropped while it is held.
   * `none`: nothing is known yet (the only "nothing here" state). `current`: the host answered and stands behind it.
   * `refreshing`: rows are held and a confirmation is on its way. `behind`: the host cannot confirm right now
   * (offline, reconnecting, catching up): keep showing the rows and let the cue say they are being updated.
   */
  type Freshness = 'current' | 'refreshing' | 'behind' | 'none';

  type QueryFeed = QueryFeedState & {
      readonly retry: () => void;
      /** True when the rows shown (current or last good) are only part of the result. */
      readonly truncated: boolean;
      /** Quiet by design: `reconnecting` only after a delay, `failed` once retries are used up or cannot help. */
      readonly notice: FeedNoticeKind;
      /** The rows to show (current or last good), or undefined when `freshness` is `none`. Same object as `result` / `last`. */
      readonly data: AppQueryResult | undefined;
      readonly freshness: Freshness;
      /** The act the rows reflect; null while unknown (hosted reads carry none yet). */
      readonly act: number | null;
  };

  /**
   * Record-aware reads (1.7.0) are built on `useQueryFeed`, so they need app-v2 and inherit its quiet recovery.
   * Not deleted, not archived, and only readable pages: `types` defaults to Document, Collection, Resolution, WorkItem and Outcome,
   * and attachments, saved queries and selections, and artifacts are never returned.
   */
  interface RecordTypeOptions {
      /** Record types to accept, replacing the defaults. */
      readonly types?: readonly string[];
  }

  interface UseRecordOptions extends RecordTypeOptions, QueryFeedOptions {
      /** Characters of body to read (default 120,000, at most 262,142), or `false` to skip the body. */
      readonly body?: number | false;
  }

  /** One record's standard metadata, keyed by column: id, name, type, kind, lifecycle, summary, home_id, created_at, updated_at, updated_at_ms, is_current. */
  type RecordRow = Readonly<Record<string, unknown>>;

  /**
   * Edits made through `useWrite({ operation: 'update_record' })` (a name, summary, maturity or lifecycle set, or plain-text facets)
   * show on the record hooks at once and stay marked until Native confirms them. Memory only: they do not survive a reload.
   */
  /** The person's values from a refused edit, kept so nothing they typed is lost. */
  interface EditDraft {
      readonly fields: Readonly<Record<string, string | null>>;
      readonly facets: Readonly<Record<string, string | null>>;
  }

  /** What one record's pending edits come to: the worst state among them, and a way forward. */
  interface PendingEdit {
      /** `saving`: on its way. `unsure`: it may not have been saved. `refused`: it was not saved. `saved`: the host confirmed it. */
      readonly status: 'saving' | 'unsure' | 'refused' | 'saved';
      /** Plain wording for `status`. Render this rather than your own copy. */
      readonly label: string;
      /** What the edit changes: `name`, `summary`, `maturity`, `lifecycle`, `facet:<key>`. */
      readonly changes: readonly string[];
      /** The person's values, when an edit was refused; null otherwise. */
      readonly draft: EditDraft | null;
      readonly canRetry: boolean;
      readonly canDiscard: boolean;
      /** Send an unsaved edit again (the same request, under the same key while it may have applied). */
      retry(): void;
      /** Forget a refused edit. The row keeps showing what the host has. */
      discard(): void;
  }

  interface UseRecord {
      /**
       * `idle`: no usable id, nothing is read. `loading`: nothing to show yet. `ready`: `record` is the requested one, fresh or kept
       * through a reload or a transient failure (see `refreshing`, `notice`). `missing`: the read succeeded and no row came back, because
       * the record is deleted, archived, outside this app's scope or not visible to this person; the app cannot and need not tell which.
       * `unsupported`: the host has no app-v2 subscriptions. `error`: the read failed and there is nothing to show.
       */
      readonly status: 'idle' | 'loading' | 'ready' | 'missing' | 'unsupported' | 'error';
      /** Metadata of the record asked for, never another record's. Null until there is one. */
      readonly record: RecordRow | null;
      /** The body prefix read, or null (no record, or `body: false`). */
      readonly body: string | null;
      /** `length(body)` in characters: the whole body's length, not the prefix's. */
      readonly bodyLength: number | null;
      /** True when `body` is only the first part of the record's body. */
      readonly bodyTruncated: boolean;
      /** True when the rows shown were served from the host's cache ahead of revalidation. */
      readonly cached: boolean;
      /** True while a read is under way and `record` is the previous answer for this same id. */
      readonly refreshing: boolean;
      /** The record (`null`: the read succeeded and found none; `undefined`: nothing known yet, `freshness` is `none`). */
      readonly data: RecordRow | null | undefined;
      readonly freshness: Freshness;
      readonly act: number | null;
      /** This record's unconfirmed edits, or null. `record` and `data` already show them laid over what Native has; render `EditStatus` beside them. */
      readonly edit: PendingEdit | null;
      readonly retry: () => void;
      readonly notice: FeedNoticeKind;
      /** The read's failure, as `useQueryFeed` reports it; present beside a kept `record` while it recovers. */
      readonly error: QueryFeedError | undefined;
  }

  /** A folder's children (by `home_id`) or an ordered set of record ids. */
  type RecordListSource = {
      readonly folder: string | null | undefined;
  } | {
      readonly ids: readonly string[];
  };

  interface UseRecordListOptions extends RecordTypeOptions, QueryFeedOptions {
      /** Rows per page (default 50, at most 200). `loadMore` adds one page. */
      readonly limit?: number;
      /** Folder ordering: `updated` (newest first, the default) or `name`. An id set keeps the order given. */
      readonly order?: 'updated' | 'name';
  }

  interface UseRecordList {
      /** `idle`: no usable folder id, nothing is read. Otherwise as `useQueryFeed`; `ready` also while a bigger page loads or a refresh fails and `rows` are kept. An empty id set is `ready` and empty. */
      readonly status: 'idle' | 'loading' | 'ready' | 'unsupported' | 'error';
      /** Rows of the current source only, never a previous folder's or id set's. For `ids`, in the order given. */
      readonly rows: readonly RecordRow[];
      /** For `ids`: the ids on this page that came back with no row (deleted, archived, not visible, or not a readable type). */
      readonly missing: readonly string[];
      /** True when the folder has more children than `rows`, or the id set has more ids than the page. */
      readonly more: boolean;
      /** True when `more` is true but `loadMore` cannot help: the 200-row ceiling is reached. Use raw SQL to go further. */
      readonly capped: boolean;
      /** For `ids`: usable ids past the first 200, which are never read. */
      readonly omitted: number;
      /** Shows one more page while keeping the current `rows`. Does nothing when `more` is false, a read is under way, or the ceiling is reached. */
      readonly loadMore: () => void;
      /** True while a read is under way and `rows` are the previous answer for this same source. */
      readonly refreshing: boolean;
      readonly cached: boolean;
      /** The same rows as `rows`, or `undefined` while nothing is known yet (`freshness` is `none`); an empty list is `[]`. */
      readonly data: readonly RecordRow[] | undefined;
      readonly freshness: Freshness;
      readonly act: number | null;
      /** Unconfirmed edits by record id, for the rows shown. `rows` and `data` already show them, in the rows' own places. */
      readonly edits: Readonly<Record<string, PendingEdit>>;
      readonly retry: () => void;
      readonly notice: FeedNoticeKind;
      readonly error: QueryFeedError | undefined;
  }

  interface DispatchContext {
      /** Use as the idempotency key. */
      readonly key: string;
      /** 1 for the first dispatch of this write, then counting every retry. */
      readonly attempt: number;
  }

  interface WriteFailure {
      readonly status?: string;
      readonly code?: string;
      readonly message?: string;
  }

  /** An unfinished write as saved by `export` and given back to `restore`: plain and frozen. */
  interface ExportedWrite<Request = unknown> {
      /** The frozen request as submitted. */
      readonly request: Request;
      /** The idempotency key. Save it as it is. */
      readonly key: string;
      /** When the person made the change (ms since epoch). */
      readonly madeAt: number;
      readonly status: "uncertain" | "failed";
      readonly attempts: number;
      /** The key MAY have been applied: true for `uncertain`, false for `failed`. */
      readonly exposed: boolean;
      /** Status, code and message, each cut to a fixed length. */
      readonly error?: WriteFailure;
  }

  /** Options for `useWrite`. Give `operation` for an ordinary Native call, or `dispatch` to send it yourself. */
  interface UseWriteOptions<Request extends object = Record<string, unknown>, Result = unknown> {
      /** A Native operation such as `create_record`. The kit calls it with the frozen request plus the write's `idempotency_key`. */
      readonly operation?: string;
      /** Sends the request yourself and resolves when Native confirms. Use `context.key` as the idempotency key. Wins over `operation`. */
      readonly dispatch?: (request: Request, context: DispatchContext) => Promise<Result>;
      /** Extra tries after a `busy` refusal, spaced by these delays; default 300 ms then 600 ms. */
      readonly busyDelaysMs?: readonly number[];
      readonly checkpoint?: (entries: readonly ExportedWrite<Request>[]) => Promise<{
          readonly status: 'ok' | 'error';
          readonly keys?: readonly string[];
          readonly code?: string;
      }>;
      /** Any value that identifies the account or workspace the writes belong to. When it changes, every entry is dropped. */
      readonly scope?: unknown;
  }

  /** Where a write stands. A durable layer may add detail through `custody`, never new statuses. */
  type WriteStatus = "pending" | "sent" | "uncertain" | "failed";

  /** Who holds the request: `memory` is this page only. A durable layer may add values, so do not switch exhaustively. */
  type WriteCustody = "memory" | (string & {});

  /** A frozen snapshot of one logical write. A new snapshot replaces it on every change. */
  interface WriteEntry<Request = unknown, Result = unknown> {
      /** Stable for the life of the write, across retries and key changes. */
      readonly id: string;
      readonly status: WriteStatus;
      readonly custody: WriteCustody;
      /** Plain wording for `status`, honest about `custody`. Render this rather than your own copy. */
      readonly label: string;
      readonly custodyLabel?: string;
      readonly storageError?: string;
      /** The person's request exactly as frozen at submit; a retry sends this, never a re-read of the form. */
      readonly request: Request;
      /** The idempotency key the next (or current) dispatch uses. Changes only after a definite failure. */
      readonly key: string;
      readonly attempts: number;
      /** When the person made the change (ms since epoch). Provenance only; never used for ordering. */
      readonly madeAt: number;
      /** Why a write is `failed`, `uncertain` or applied with a pending receipt. */
      readonly error?: WriteFailure;
      /** What `dispatch` resolved with, once `sent`. */
      readonly result?: Result;
      readonly canRetry: boolean;
      readonly canDiscard: boolean;
      /** Refused again in this page under its permanent key: the person may send it as a new write (it may send twice). */
      readonly canSendAsNew: boolean;
  }

  /** Returned at once; `done` settles when this attempt ends. It never rejects. */
  interface WriteTicket<Request = unknown, Result = unknown> {
      readonly id: string;
      readonly done: Promise<WriteEntry<Request, Result>>;
  }

  /** Says the person has been told the write may already have been sent. */
  interface SendAsNewOptions {
      readonly acknowledgeMaySendTwice: true;
  }

  /** What `restore` takes: an `ExportedWrite`, or older state without `attempts` or `exposed`. */
  interface RestorableWrite<Request = unknown> {
      readonly request: Request;
      readonly key: string;
      readonly madeAt: number;
      /** Never `pending` or `sent`. */
      readonly status: "uncertain" | "failed";
      /** Default 1. */
      readonly attempts?: number;
      /** Default true, even for `failed`; true restores as `uncertain`. */
      readonly exposed?: boolean;
      readonly error?: WriteFailure;
  }

  type RestoreRefusalCode = "closed" | "invalid_status" | "invalid_key" | "invalid_request" | "invalid_entry" | "duplicate_key" | "superseded" | "scope_changed" | "too_many" | "no_dispatch";

  /** When `ok` is false nothing was kept and nothing was sent. */
  type RestoreResult<Request = unknown, Result = unknown> = {
      readonly ok: true;
      readonly entry: WriteEntry<Request, Result>;
  } | {
      readonly ok: false;
      readonly code: RestoreRefusalCode;
      readonly message: string;
  };

  interface UseWrite<Request extends object = Record<string, unknown>, Result = unknown> {
      /** Every write still on screen, oldest first. Render each with `WriteStatus`. */
      readonly entries: readonly WriteEntry<Request, Result>[];
      /** True while any write is being sent. */
      readonly pending: boolean;
      /** Freezes the request, mints its key and sends it in this task (call it from the click). Throws only if closed or 256 writes are unresolved. */
      submit(request: Request): WriteTicket<Request, Result>;
      /** Sends the same frozen request again, under the same key (a new key only for a failed write that was never exported). */
      retry(id: string): WriteTicket<Request, Result> | undefined;
      /** Removes a `failed` or `sent` entry; an uncertain one stays until it resolves. */
      discard(id: string): boolean;
      /** As `WriteHelper.sendAsNew`: may send twice; requires acknowledgement. */
      sendAsNew(id: string, acknowledgement: SendAsNewOptions): WriteTicket<Request, Result> | undefined;
      /** As `WriteHelper.restore` (1.4.0). */
      restore(saved: RestorableWrite<Request>): RestoreResult<Request, Result>;
      /** As `WriteHelper.export`: permanently pins the keys it returns. */
      export(): readonly ExportedWrite<Request>[];
  }

  interface AgentSessionsOptions {
      /** How long a list may be in trouble before "Reconnecting…" shows; default 4 s. */
      readonly noticeDelayMs?: number;
  }

  /** What an agent asks of the person. `done` is the agent saying it has finished something to look at. */
  type AttentionRequestKind = "blocked" | "decision" | "review" | "done";

  interface SessionAttentionRequest {
      readonly kind: AttentionRequestKind;
      readonly message: string;
  }

  type PendingPermissionKind = "question" | "plan" | "tool" | "mode" | "other";

  /** An advisory only: `requestId` is an opaque identifier and there is no description, only a kind and an optional title. */
  interface SessionPendingPermission {
      readonly requestId: string;
      readonly kind: PendingPermissionKind;
      readonly title?: string;
  }

  interface SessionSummary {
      readonly id: string;
      readonly hostId: string;
      readonly hostLabel: string;
      readonly hostEpoch: string;
      readonly title: string | null;
      readonly provider: string;
      readonly model: string | null;
      readonly status: string;
      /** Daemon timestamp string (ISO 8601 in practice). */
      readonly lastActivity: string;
      readonly workspace: {
          readonly id: string | null;
          readonly name: string | null;
      };
      readonly createdAt?: string;
      readonly parentId?: string;
      /** Who started the session, when the host stamps it. Absent means unknown. */
      readonly startedBy?: "user" | "agent" | "schedule";
      /** Absent means unknown. */
      readonly unread?: boolean;
      /** Absent means unknown; null means none. */
      readonly attentionRequest?: SessionAttentionRequest | null;
      readonly pendingPermission?: SessionPendingPermission | null;
  }

  /** Optional, positive-only host advertisements: a missing flag means "not offered", never "unknown". */
  interface SessionHostCapabilities {
      readonly markRead?: true;
      readonly listChanged?: true;
      /** The daemon serves app approvals (permission forms and responses). Opening a conversation does not need it. */
      readonly scopedPermissions?: true;
      readonly create?: true;
      readonly chooseFolder?: true;
      /** The host stamps new session summaries with who started them. */
      readonly startedBy?: true;
  }

  interface SessionHost {
      readonly id: string;
      readonly label: string;
      readonly status: "reachable" | "unreachable";
      /** Null only while unreachable. A new epoch means the host's sessions were re-established. */
      readonly epoch: string | null;
      readonly capabilities?: SessionHostCapabilities;
  }

  /**
   * Paseo agent sessions as an app sees them (app contract v2 `native.agentSessions`, Desktop only).
   *
   * The shapes are the host's, taken from the launcher's bounded projection
   * (`packages/native-launcher/src/appAgentSessions.mjs`) and the bridge
   * (`packages/alpha-tab-kit/src/fake-host/bridge-bootstrap.js`), not invented here. The host offers the API
   * as `app.agent-sessions.v2` after Desktop admits the launch (legacy first-party allowlist or adopted-app
   * admission with `app.agent-sessions.adopted.v1`); everywhere
   * else `native.agentSessions` is absent and an app must carry on without it.
   *
   * Calls resolve rather than reject. Ordinary refusals carry `code`; creation has its own
   * `{error: {code, message}}` result and preserves uncertain outcomes. Optional bridge features
   * answer unavailable when absent (create: create_unsupported). No method grants host authority.
   */
  type SessionRefusal = "refused" | "invalid" | "unavailable" | "gone" | "busy";

  interface AgentSessionsError {
      readonly code: SessionRefusal;
      /** Present while the kit is still reading the list again by itself: `quiet` inside the notice delay, `reconnecting` after it. */
      readonly retrying?: 'quiet' | 'reconnecting';
  }

  /** What a person should be told about the session list; the same shape of answer `useQueryFeed` gives for a read. */
  type AgentSessionsState = {
      readonly status: 'loading';
      readonly sessions: readonly SessionSummary[];
      readonly hosts: readonly SessionHost[];
      readonly notice: FeedNoticeKind;
      readonly listedAt: number | null;
  }
  /** The host does not offer `agentSessions` (only Native Desktop does, to an app it has admitted). Nothing else will happen. */
   | {
      readonly status: 'unsupported';
      readonly message: string;
      readonly sessions: readonly SessionSummary[];
      readonly hosts: readonly SessionHost[];
      readonly notice: FeedNoticeKind;
      readonly listedAt: number | null;
  } | {
      readonly status: 'ready';
      readonly sessions: readonly SessionSummary[];
      readonly hosts: readonly SessionHost[];
      readonly notice: FeedNoticeKind;
      readonly listedAt: number | null;
  }
  /** `sessions` are the last good list, kept through a transient failure and cleared by an access refusal. */
   | {
      readonly status: 'error';
      readonly error: AgentSessionsError;
      readonly sessions: readonly SessionSummary[];
      readonly hosts: readonly SessionHost[];
      readonly notice: FeedNoticeKind;
      readonly listedAt: number | null;
  };

  /** A session is addressed by host, host epoch and id together. */
  interface SessionTarget {
      readonly hostId: string;
      readonly hostEpoch: string;
      readonly sessionId: string;
  }

  type SessionResult<T> = {
      readonly ok: true;
      readonly value: T;
  } | {
      readonly ok: false;
      readonly code: SessionRefusal;
  };

  interface SessionCatalogModel {
      readonly id: string;
      readonly label: string;
      readonly description?: string;
      readonly featured?: boolean;
      readonly isDefault?: boolean;
      readonly thinkingOptions: readonly {
          readonly id: string;
          readonly label: string;
      }[];
      readonly defaultThinkingOptionId?: string;
  }

  interface SessionCatalogProvider {
      readonly id: string;
      readonly label: string;
      readonly available: boolean;
      readonly unavailableReason?: string;
      readonly models: readonly SessionCatalogModel[];
      readonly modes: readonly {
          readonly id: string;
          readonly label: string;
          readonly description?: string;
      }[];
      readonly defaultModeId?: string;
  }

  interface SessionCatalogWorkspace {
      readonly id: string;
      readonly name: string;
      readonly path: string;
      readonly projectName?: string;
      readonly isGitRepo?: boolean;
      readonly kind?: "ordinary" | "folder" | "worktree";
  }

  interface SessionCatalogHost {
      readonly hostId: string;
      readonly hostLabel: string;
      readonly hostEpoch: string | null;
      readonly status: "reachable" | "unreachable";
      readonly providers: readonly SessionCatalogProvider[];
      readonly workspaces: readonly SessionCatalogWorkspace[];
      readonly workspacesTruncated?: true;
  }

  interface SessionCatalog {
      readonly hosts: readonly SessionCatalogHost[];
  }

  /** What choosing a folder came to. */
  type FolderChoice = {
      readonly status: "chosen";
      readonly hostId: string;
      readonly hostEpoch: string;
      readonly folder: SessionCatalogWorkspace;
  } | {
      readonly status: "cancelled";
  }
  /** The machine reconnected while the person was choosing: the choice belongs to a world that no longer exists. Choose again. */
   | {
      readonly status: "stale";
      readonly message: string;
  } | {
      readonly status: "unavailable";
      readonly message: string;
  };

  /** Projected timeline only: messages contain at most 16 Ki UTF-16 code units, no raw tool payloads. */
  type SessionTimelineItem = {
      readonly id: string;
      readonly kind: "message";
      readonly role: "user" | "assistant";
      readonly text: string;
      readonly truncated?: true;
  } | {
      readonly id: string;
      readonly kind: "tool";
      readonly title: string;
      readonly status: string;
      readonly detail?: string;
  } | {
      readonly id: string;
      readonly kind: "status";
      readonly status: string;
  };

  /** Snapshot replaces the view; updates contain changed items; resync asks the app to re-follow. */
  type SessionEvent = SessionTarget & ({
      readonly kind: "snapshot" | "update";
      readonly items: readonly SessionTimelineItem[];
      readonly historyTruncated?: true;
  } | {
      readonly kind: "resync";
  } | {
      readonly kind: "ended";
      readonly code: SessionRefusal;
  });

  interface SessionSubscription {
      readonly dispose: () => void;
  }

  type SessionCreateState = "unknown_request" | "preparing" | "confirming" | "dispatching" | "dispatched" | "settled" | "cancelled" | "terminal_mismatch" | "refused_retryable";

  type SessionCreateErrorCode = "invalid_request" | "refused" | "busy" | "host_unreachable" | "host_epoch_changed" | "create_unsupported" | "provider_unavailable" | "model_unavailable" | "workspace_not_found" | "worktree_unsupported" | "create_failed" | "outcome_unknown";

  type SessionCreateResult = {
      readonly ok: true;
      readonly value: SessionSummary;
  } | {
      readonly ok: false;
      readonly error: {
          readonly code: SessionCreateErrorCode;
          readonly message: string;
      };
  };

  interface SessionCreateStatus {
      readonly state: SessionCreateState;
      readonly result?: SessionCreateResult;
  }

  /** Everything but the list. Targets come from the list's own sessions and hosts. */
  interface AgentSessionsActions {
      /** Whether this machine is still the one the list showed, at the same epoch. A target that is not current is dead: do not send to it. */
      isCurrent(target: Pick<SessionTarget, 'hostId' | 'hostEpoch'>): boolean;
      /** The machines, agents, models and folders a session can be started with. */
      catalog(): Promise<SessionResult<SessionCatalog>>;
      /**
       * Open Desktop's folder chooser on a machine. Call it directly from the click. Resolves with the folder, `cancelled`, `stale`
       * (the machine reconnected while the person was choosing, so the choice is dropped) or `unavailable`.
       */
      chooseFolder(host: Pick<SessionTarget, 'hostId' | 'hostEpoch'>): Promise<FolderChoice>;
      /** Follow a session's timeline. Ends with an `ended` event if its machine reconnects. Dispose when leaving the view. */
      follow(target: SessionTarget, onEvent: (event: SessionEvent) => void): Promise<SessionResult<SessionSubscription>>;
      /** Open the conversation in Desktop: `quick` in the side pane (default), `full` in the Agent HQ window. */
      openConversation(target: SessionTarget, options?: {
          readonly depth?: 'quick' | 'full';
      }): Promise<SessionResult<Record<string, never>>>;
      /** What became of a start whose outcome is unknown; pass the write entry's `key`. Needs a Desktop that offers it. */
      createStatus(requestId: string): Promise<SessionResult<SessionCreateStatus>>;
  }

  /**
   * Words that came from someone else, sent beside the person's own `text` so the Desktop can frame them as data rather
   * than as the person's instruction (design 86a586b section 8). At most 8 items; `from` 1..32 characters, `text` 1..12288
   * non-blank. `sourceMessageId`, when present, is an owner-claimed reference to the quoted message
   * (design f38936b §7.3, Desktop S5i contract.ts): canonical lowercase UUID, never authenticated authorship
   * nor a read grant. Only a host that offers `app.agent-sessions.adopted.v1` takes them; elsewhere a send that carries any
   * resolves `unavailable` and sends nothing, so put quoted words in `text` only if you accept that they read as the person's.
   */
  interface SessionQuoted {
      readonly from: string;
      readonly text: string;
      readonly sourceMessageId?: string;
  }

  interface SessionSendRequest extends SessionTarget {
      readonly text: string;
      readonly contentOrigin?: "typed" | "generated";
      readonly quoted?: readonly SessionQuoted[];
  }

  /** `acknowledged`: Desktop took it. `unknown`: it may have arrived; never assume either way. */
  interface SessionReceipt {
      readonly requestId: string;
      readonly delivery: "acknowledged" | "unknown";
  }

  interface SessionCreateInput {
      readonly requestId: string;
      readonly hostId: string;
      readonly hostEpoch: string;
      readonly provider: string;
      readonly model: string;
      readonly workspaceId: string;
      readonly modeId?: string;
      readonly thinkingOptionId?: string;
      readonly newWorktree?: {
          readonly baseBranch: string;
      };
      /** Non-blank, at most 16 KiB UTF-8. */
      readonly initialPrompt: string;
      readonly contentOrigin?: "typed" | "generated";
      readonly quoted?: readonly SessionQuoted[];
  }

  type SessionCreateRequest = Omit<SessionCreateInput, "requestId">;

  type SessionPermissionAction = {
      readonly kind: "tool_decision";
      readonly behavior: "allow" | "deny";
  } | {
      readonly kind: "plan_action";
      readonly actionId: string;
  } | {
      readonly kind: "question_dismiss";
  } | {
      readonly kind: "question_answers";
      readonly answers: readonly {
          readonly questionIndex: number;
          readonly optionIndexes?: readonly number[];
          readonly text?: string;
      }[];
  };

  interface SessionPermissionRequest extends SessionTarget {
      /** The pending permission's `requestId`, from the session summary. */
      readonly permissionRequestId: string;
      readonly action: SessionPermissionAction;
  }

  /** What the host said about a permission response. Only `acknowledged` resolves a write. */
  interface SessionPermissionAnswer {
      readonly status: "acknowledged";
  }

  /**
   * The Paseo agent sessions `useAgentSessions` reads and acts on (1.3.0). `status` is `unsupported` when the host does not offer
   * `agentSessions`; the rest follows `useQueryFeed`: `sessions` is the last good list, kept through a transient failure and
   * cleared by an access refusal, and `notice` says when to speak.
   */
  type UseAgentSessions = AgentSessionsState & AgentSessionsActions & {
      /** Read the list now. */
      readonly retry: () => void;
      /** Send a message into a session (`submit` from the click). Render each entry with `WriteStatus`. */
      readonly send: Omit<UseWrite<SessionSendRequest, SessionReceipt>, 'restore' | 'export'>;
      /** Start a session (`submit` from the click). The entry's `key` is the start's request id, for `createStatus`. */
      readonly create: Omit<UseWrite<SessionCreateRequest, SessionSummary>, 'restore' | 'export'>;
      /** Answer a session's pending permission (`submit` from the click). */
      readonly respond: Omit<UseWrite<SessionPermissionRequest, SessionPermissionAnswer>, 'restore' | 'export'>;
  };

  interface PreactKit {
      h<P>(type: string | UiComponent<P>, props: P | null, ...children: UiChild[]): UiElement;
      render(child: UiChild, parent: Element | Document | ShadowRoot): void;
      readonly Fragment: UiComponent;
      createContext<T>(value: T): UiContext<T>;
      html(strings: TemplateStringsArray, ...values: unknown[]): UiChild;
      useState<T>(initial: T | (() => T)): [
          T,
          (value: StateUpdate<T>) => void
      ];
      useState<T = undefined>(): [
          T | undefined,
          (value: StateUpdate<T | undefined>) => void
      ];
      useReducer<S, A>(reducer: (state: S, action: A) => S, initial: S): [
          S,
          (action: A) => void
      ];
      useReducer<S, A, I>(reducer: (state: S, action: A) => S, initial: I, init: (initial: I) => S): [
          S,
          (action: A) => void
      ];
      useRef<T>(initial: T): UiRef<T>;
      useRef<T>(initial: T | null): UiRef<T | null>;
      useRef<T = undefined>(): UiRef<T | undefined>;
      useEffect(effect: Effect, dependencies?: readonly unknown[]): void;
      useLayoutEffect(effect: Effect, dependencies?: readonly unknown[]): void;
      useMemo<T>(factory: () => T, dependencies: readonly unknown[]): T;
      useCallback<T extends Function>(callback: T, dependencies: readonly unknown[]): T;
      useContext<T>(context: UiContext<T>): T;
      useImperativeHandle<T>(ref: UiRef<T> | ((value: T | null) => void) | null, create: () => T, dependencies?: readonly unknown[]): void;
      useDebugValue<T>(value: T, format?: (value: T) => unknown): void;
      useErrorBoundary(callback?: (error: unknown, info: unknown) => void): [
          unknown,
          () => void
      ];
      useId(): string;
      useFeed(key: string): Feed<QueryResult>;
      /** Query must be JSON serializable; equivalent values share a subscription. */
      useQueryFeed(query: AppQuery | StepsQuery, options?: QueryFeedOptions): QueryFeed;
      /** Object rows from an app-v2 result of either shape (1.7.0); the same function as `kit.rowsOf`. */
      rowsOf(result: {
          readonly rows?: readonly unknown[];
          readonly columns?: readonly unknown[];
      } | null | undefined): Record<string, unknown>[];
      /**
       * One record by id (1.7.0), without writing SQL. Reads need app-v2, which runs as the adopted person with their full read and write
       * authority (a v1 declared read is the narrower grant). It never returns another id's record: on a change of id nothing shows until
       * the new one arrives.
       */
      useRecord(id: string | null | undefined, options?: UseRecordOptions): UseRecord;
      /**
       * A bounded list (1.7.0): a folder's children, or an ordered set of up to 200 ids. Same access as `useRecord`.
       * Changing the folder or id set shows nothing of the old one. `loadMore` keeps the rows on screen while the next page loads.
       */
      useRecordList(source: RecordListSource | null | undefined, options?: UseRecordListOptions): UseRecordList;
      /**
       * Renders `feed.notice` ("Reconnecting…", or "Couldn't refresh" with Try again), a partial-results line, and, when `freshness` is
       * given and no notice is showing, one quiet "Updating…" cue while rows are `refreshing` or `behind` (after a few seconds of `behind`
       * it says the last copy is showing and will update when back online). The rows themselves are never hidden.
       */
      readonly FeedNotice: UiComponent<{
          feed: Pick<QueryFeed, 'notice' | 'retry'> & {
              readonly freshness?: Freshness;
              readonly truncated?: boolean;
              readonly error?: {
                  readonly code: string;
                  readonly terminal?: boolean;
              };
          };
      }>;
      /**
       * Safe writes (1.2.0). Freezes each request, mints its idempotency key before anything is sent, retries `busy`
       * a bounded number of times, and tracks `pending | sent | uncertain | failed`. Memory only: nothing survives a reload.
       * Entries are dropped when the app's account or workspace changes (`scope_changed` on any `useQueryFeed`, or `scope`).
       * With `operation: 'update_record'`, a name, summary, maturity, lifecycle or plain-text facet set is also an edit: `useRecord` and
       * `useRecordList` show it at once (`edit`, `edits`) and render it with `EditStatus` until Native confirms it. Body text is not.
       */
      useWrite<Request extends object = Record<string, unknown>, Result = unknown>(options: UseWriteOptions<Request, Result>): UseWrite<Request, Result>;
      /** "Sending…", "Sent", "May not have sent" with Retry, or "Not sent" with Retry and Discard. */
      readonly WriteStatus: UiComponent<{
          entry: Pick<WriteEntry, 'status' | 'label' | 'canRetry' | 'canDiscard'> & {
              canSendAsNew?: boolean;
              id?: string;
              key?: string;
              custodyLabel?: string;
              storageError?: string;
          };
          onRetry?: () => void;
          onDiscard?: () => void;
          onSendAsNew?: () => void;
          className?: string;
      }>;
      /**
       * "Saving…", "Not saved yet" with Try again, "Not saved" with the person's text and Try again, Edit again and Discard, or "Saved"
       * (only once Native confirmed it). Renders nothing for null. `onRestore` receives the draft of a refused edit (to put the text
       * back in the app's own field), and the edit is then discarded.
       */
      readonly EditStatus: UiComponent<{
          edit: PendingEdit | null | undefined;
          onRestore?: (draft: EditDraft) => void;
          className?: string;
      }>;
      /**
       * Paseo agent sessions (1.3.0, Native Desktop only): the live list, the folder chooser, and start/send/answer-a-permission as safe writes.
       * Reports `unsupported` when the host does not offer `agentSessions`. Needs `useQueryFeed`'s account boundary too: a `scope_changed` on any
       * feed forgets the list and drops every write. Render `FeedNotice` with it.
       */
      useAgentSessions(options?: AgentSessionsOptions): UseAgentSessions;
      /** Calm first paint: four static skeleton bars with self-contained inline styles (no host CSS needed); the real loading text is clipped to a status. */
      readonly Loading: UiComponent<{
          what?: string;
      }>;
      readonly Empty: UiComponent;
      /** Renders nothing while `error.retrying` is `quiet`, "Reconnecting…" while it is `reconnecting`, otherwise the full error with Try again. */
      readonly ErrorState: UiComponent<{
          error: Pick<KitError, 'code'> & {
              message?: string;
              retrying?: 'quiet' | 'reconnecting';
          };
          onRetry?: () => void;
      }>;
      /** Mount only when the host explicitly identifies sample/preview mode. */
      readonly PreviewBanner: UiComponent;
      readonly Markdown: UiComponent<{
          source: string;
          className?: string;
      }>;
      readonly Avatar: UiComponent<{
          name?: string;
          initials?: string;
          title?: string;
          className?: string;
      }>;
      readonly IconSvg: UiComponent<{
          children?: UiChild;
          title?: string;
          viewBox?: string;
          className?: string;
      }>;
      readonly RecordLink: UiComponent<{
          id: string;
          children?: UiChild;
          className?: string;
      }>;
  }

  /** A bounded, acknowledged device snapshot. Entries merge by permanent key. */
  interface AppStateEntry {
      readonly key: string;
      readonly exposed?: boolean;
      readonly status?: string;
      readonly state?: string;
      readonly attempts?: number;
      readonly madeAt?: number;
      readonly at?: string;
  }

  interface AppStateValue<Entry extends AppStateEntry = AppStateEntry, Data = unknown> {
      readonly entries: readonly Entry[];
      readonly data?: Data;
  }

  interface AppStateOptions<Entry extends AppStateEntry, Data> {
      readonly schema: string;
      readonly initial?: AppStateValue<Entry, Data>;
      /** Merge application data (for example drafts) from recovered sources. */
      readonly mergeData?: (current: Data | undefined, incoming: Data | undefined) => Data | undefined;
  }

  interface AppStateSaveResult {
      readonly status: 'ok' | 'error';
      readonly code?: string;
      /** Only these keys were in the acknowledged successor. */
      readonly keys: readonly string[];
      readonly deferred: number;
  }

  interface AppState<Entry extends AppStateEntry = AppStateEntry, Data = unknown> {
      /** Merge own and recovered values, never sending. Null never erases this page's memory. */
      load(): Promise<AppStateValue<Entry, Data>>;
      /** Save a complete live value; retain overflow sources until room frees. */
      save(value: AppStateValue<Entry, Data>): Promise<AppStateSaveResult>;
      value(): AppStateValue<Entry, Data>;
      result(): AppStateSaveResult;
      /** Retire this slot only, keeping unadopted source snapshots; then dispose. */
      retire(): Promise<AppStateSaveResult>;
      dispose(): void;
  }

  interface WriteHelperOptions<Request, Result> {
      /** Await a device checkpoint before dispatch. Refusal still sends, with memory custody. */
      checkpoint?(entries: readonly ExportedWrite<Request>[]): Promise<{
          readonly status: 'ok' | 'error';
          readonly keys?: readonly string[];
          readonly code?: string;
      }>;
      /** Send the request; resolve when Native confirms, reject with the host's error. `SubmitOptions.dispatch` wins. */
      dispatch?(request: Request, context: DispatchContext): Promise<Result>;
      /** Delays before each extra try after a `busy` refusal. Default 300, 600 ms; `[]` for none. */
      busyDelaysMs?: readonly number[];
      /** Unresolved writes to keep; the oldest `sent` entries are forgotten first. Default and largest 256. */
      maxEntries?: number;
      /** Subscribe to account/workspace changes; call the callback to drop everything. Returns the unsubscribe. */
      onScopeChange?(drop: () => void): () => void;
      /** The account/workspace the writes belong to now (compared with `Object.is`). */
      scope?: unknown;
      /** Injectable for tests. */
      now?(): number;
  }

  interface SubmitOptions {
      /** Use this idempotency key for the first dispatch (it was minted by the caller before the request was built). */
      readonly key?: string;
      /** Sends this write, and every retry of it, even if the helper's own `dispatch` or the app's options change later. */
      readonly dispatch?: (request: never, context: DispatchContext) => Promise<unknown>;
      /** The scope this write is made in; default the current one. A UI passes its render's scope. */
      readonly scope?: unknown;
      /** The render generation of the handler (see `commit`). A newer one than committed is staged until it commits. Omit outside UI hooks. */
      readonly generation?: number;
      /**
       * For the kit's own hooks: called once, synchronously, with the frozen request (the one object every dispatch and retry will be
       * given) in the same task as the call to `submit`, so a hook can take a note about it without reading the app's object a second
       * time. It cannot change the request, and nothing it throws touches the write.
       */
      readonly onFrozen?: (frozen: never) => void;
  }

  interface RestoreOptions {
      /** Sends the write on retry; default the helper's `dispatch`. */
      readonly dispatch?: (request: never, context: DispatchContext) => Promise<unknown>;
      /** The scope the state belongs to; default the current one. */
      readonly scope?: unknown;
      /** As `SubmitOptions.generation`; until it commits the entry cannot be retried. */
      readonly generation?: number;
  }

  interface WriteHelper<Request = unknown, Result = unknown> {
      /** Freeze, key and dispatch in the caller's task, so a host that ties a write to a click still sees one. */
      submit(request: Request, options?: SubmitOptions): WriteTicket<Request, Result>;
      /** Send the same frozen request again. No-op while pending or after `sent`. Undefined for an unknown id. */
      retry(id: string): WriteTicket<Request, Result> | undefined;
      /** Forget a `failed` or `sent` entry. An `uncertain` one cannot be: its key protects against a duplicate. */
      discard(id: string): boolean;
      get(id: string): WriteEntry<Request, Result> | undefined;
      entries(): readonly WriteEntry<Request, Result>[];
      subscribe(listener: (entries: readonly WriteEntry<Request, Result>[]) => void): () => void;
      /** An account or workspace change: forget everything, send nothing more for it, ignore late answers. */
      dropAll(code?: string): void;
      /** Tell the helper which account/workspace is current. A different value drops every entry; nothing is sent under another scope. */
      setScope(scope: unknown): void;
      /** Publish a render generation and scope, from a layout effect (never while rendering). Staged writes go out if their scope is committed, else are dropped. */
      commit(generation: number, scope: unknown): void;
      /** Put a saved write back (1.4.0). It never sends: only `retry` does, under the saved key. Refuses with a code; never throws. */
      restore(saved: RestorableWrite<Request>, options?: RestoreOptions): RestoreResult<Request, Result>;
      /** The unfinished entries of this scope to save (in flight is `uncertain`, staged is `failed`). Permanently pins the keys it returns. */
      export(): readonly ExportedWrite<Request>[];
      /** May send twice; requires acknowledgement. Replaces a `canSendAsNew` write with the same request under a new key. */
      sendAsNew(id: string, acknowledgement: SendAsNewOptions): WriteTicket<Request, Result> | undefined;
      /** Cancel timers, ignore late answers, send nothing more. Idempotent. */
      dispose(): void;
  }

  /** The framework-free sessions surface. Writes use the same lifecycle as `createWriteHelper`: render `entry.label`, switch on `entry.status`. */
  interface AgentSessionsClient extends AgentSessionsActions {
      state(): AgentSessionsState;
      subscribe(listener: (state: AgentSessionsState) => void): () => void;
      /** Read the list now ("Try again"). */
      retry(): void;
      /** Send a message into a session. Call `submit` from the click. */
      readonly send: Omit<WriteHelper<SessionSendRequest, SessionReceipt>, 'restore' | 'export'>;
      /** Start a session. Call `submit` from the click. */
      readonly create: Omit<WriteHelper<SessionCreateRequest, SessionSummary>, 'restore' | 'export'>;
      /** Answer a session's pending permission. Call `submit` from the click. */
      readonly respond: Omit<WriteHelper<SessionPermissionRequest, SessionPermissionAnswer>, 'restore' | 'export'>;
      /** Stop reading and drop every write. Call when the page closes. */
      dispose(): void;
  }

  interface CoreKit extends CoreKitBase {
      readonly preact: PreactKit;
      /** Device snapshots with revision tracking and selective whole-source recovery (1.5.0). */
      createAppState<Entry extends AppStateEntry, Data = unknown>(options: AppStateOptions<Entry, Data>): AppState<Entry, Data>;
      /**
       * Safe writes without a UI framework (1.2.0): see `preact.useWrite` for what it does. You send the request
       * (`dispatch`), and call `dropAll()` yourself when your account or workspace changes; the kit does that for
       * you when a `useQueryFeed` hears `scope_changed`. Call `dispose()` when the page closes.
       */
      createWriteHelper<Request extends object = Record<string, unknown>, Result = unknown>(options: Omit<WriteHelperOptions<Request, Result>, 'onScopeChange' | 'now'>): WriteHelper<Request, Result>;
      /**
       * Paseo agent sessions without a UI framework (1.3.0; see `preact.useAgentSessions`): the live list, `chooseFolder`, and start/send/answer
       * as safe writes. Its `state().status` is `unsupported` when the host does not offer `agentSessions`. The kit forgets the list and drops
       * every write when a `useQueryFeed` hears `scope_changed`. Call `dispose()` when the page closes.
       */
      createAgentSessions(options?: AgentSessionsOptions): AgentSessionsClient;
  }

  interface AppStateEnvelope<Entry extends AppStateEntry, Data> {
      readonly value: AppStateValue<Entry, Data>;
      readonly source?: string;
  }

  interface AppStateHost {
      get(options: {
          schema: string;
      }): Promise<{
          status: 'ok';
          revision: number;
          snapshot: AppStateEnvelope<AppStateEntry, unknown> | null;
          recovered: readonly AppStateEnvelope<AppStateEntry, unknown>[];
      } | {
          status: 'error';
          code: string;
      }>;
      clear?(options: {
          expectedRevision: number;
          consume: readonly string[];
      }): Promise<{
          status: 'ok';
          revision: number;
      } | {
          status: 'error';
          code: string;
      }>;
      set(value: unknown, options: {
          schema: string;
          expectedRevision: number;
          consume: readonly string[];
      }): Promise<{
          status: 'ok';
          revision: number;
      } | {
          status: 'error';
          code: string;
      }>;
  }

  type QueryDelivery = (AppQueryResult & {
      readonly status: 'ready';
  }) | {
      readonly status: 'error';
      readonly code: string;
      readonly message: string;
      readonly terminal: boolean;
  };

  /** What a view had in front of it when a write was made. `rendered`: the highest act among the results on screen; `delivered`: an act the page was told of but did not show (a receipt); `none`: nothing to go on. */
  type ObservedBasis = 'rendered' | 'delivered' | 'none';

  interface Observed {
      readonly act: number | null;
      readonly basis: ObservedBasis;
  }

  /** Options of `call`. `observed` is the claim taken at the click: the host clamps it to what this frame was given and records it with the write. */
  interface CallOptions {
      readonly observed?: Observed;
  }

  interface AppCall {
      readonly request_id: string;
      readonly confirmed: Promise<unknown>;
  }

  /** Data methods exist only after app-v2 negotiation; kit policy grants no data authority. */
  interface Host {
      readonly appState?: AppStateHost;
      readonly kit?: CoreKit;
      query?(query: AppQuery | StepsQuery): Promise<AppQueryResult>;
      subscribe?(query: AppQuery | StepsQuery, listener: (delivery: QueryDelivery) => void): () => void;
      call?(operation: string, args?: Record<string, unknown>, options?: CallOptions): AppCall;
  }
}
interface Window { readonly native?: NativeAppKit.Host }

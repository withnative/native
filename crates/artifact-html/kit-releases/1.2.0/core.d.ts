// Native core app kit — AGPL-3.0-only; Copyright Native contributors.
// Release 1.2.0; major 1; native.app-kit.core.factory.v1; native.html.bridge.v1
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

  type QueryFeed = QueryFeedState & {
      readonly retry: () => void;
      /** True when the rows shown (current or last good) are only part of the result. */
      readonly truncated: boolean;
      /** Quiet by design: `reconnecting` only after a delay, `failed` once retries are used up or cannot help. */
      readonly notice: FeedNoticeKind;
  };

  interface DispatchContext {
      /** Use as the idempotency key. */
      readonly key: string;
      /** 1 for the first dispatch of this write, then counting every retry. */
      readonly attempt: number;
  }

  /** Options for `useWrite`. Give `operation` for an ordinary Native call, or `dispatch` to send it yourself. */
  interface UseWriteOptions<Request extends object = Record<string, unknown>, Result = unknown> {
      /** A Native operation such as `create_record`. The kit calls it with the frozen request plus the write's `idempotency_key`. */
      readonly operation?: string;
      /** Sends the request yourself and resolves when Native confirms. Use `context.key` as the idempotency key. Wins over `operation`. */
      readonly dispatch?: (request: Request, context: DispatchContext) => Promise<Result>;
      /** Extra tries after a `busy` refusal, spaced by these delays; default 300 ms then 600 ms. */
      readonly busyDelaysMs?: readonly number[];
      /** Any value that identifies the account or workspace the writes belong to. When it changes, every entry is dropped. */
      readonly scope?: unknown;
  }

  /** Where a write stands. A durable layer may add detail through `custody`, never new statuses. */
  type WriteStatus = "pending" | "sent" | "uncertain" | "failed";

  /**
   * Who holds the request right now. `memory` is this page only. A later durable
   * layer reports `device`, `native` and the like here, with its own `label`, so
   * apps that render `label` and switch on `status` keep working. Do not
   * exhaustively switch on this.
   */
  type WriteCustody = "memory" | (string & {});

  interface WriteFailure {
      readonly status?: string;
      readonly code?: string;
      readonly message?: string;
  }

  /** A frozen snapshot of one logical write. A new snapshot replaces it on every change. */
  interface WriteEntry<Request = unknown, Result = unknown> {
      /** Stable for the life of the write, across retries and key changes. */
      readonly id: string;
      readonly status: WriteStatus;
      readonly custody: WriteCustody;
      /** Plain wording for `status`, honest about `custody`. Render this rather than your own copy. */
      readonly label: string;
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
  }

  /** Returned at once; `done` settles when this attempt ends. It never rejects. */
  interface WriteTicket<Request = unknown, Result = unknown> {
      readonly id: string;
      readonly done: Promise<WriteEntry<Request, Result>>;
  }

  interface UseWrite<Request extends object = Record<string, unknown>, Result = unknown> {
      /** Every write still on screen, oldest first. Render each with `WriteStatus`. */
      readonly entries: readonly WriteEntry<Request, Result>[];
      /** True while any write is being sent. */
      readonly pending: boolean;
      /** Freezes the request, mints its key, and sends it in this task (call it from the click). Throws only if the page is closed or too many writes are unresolved. */
      submit(request: Request): WriteTicket<Request, Result>;
      /** Sends the same frozen request again: the same key if it may have been applied, a new one if it was not sent. */
      retry(id: string): WriteTicket<Request, Result> | undefined;
      /** Removes a `failed` or `sent` entry; an uncertain one stays until it resolves. */
      discard(id: string): boolean;
  }

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
      /** Renders `feed.notice` ("Reconnecting…", or "Couldn't refresh" with Try again) and a partial-results line. */
      readonly FeedNotice: UiComponent<{
          feed: Pick<QueryFeed, 'notice' | 'truncated' | 'retry'> & {
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
       */
      useWrite<Request extends object = Record<string, unknown>, Result = unknown>(options: UseWriteOptions<Request, Result>): UseWrite<Request, Result>;
      /** "Sending…", "Sent", "May not have sent" with Retry, or "Not sent" with Retry and Discard. */
      readonly WriteStatus: UiComponent<{
          entry: Pick<WriteEntry, 'status' | 'label' | 'canRetry' | 'canDiscard'>;
          onRetry?: () => void;
          onDiscard?: () => void;
          className?: string;
      }>;
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

  interface WriteHelperOptions<Request, Result> {
      /** Send the request. Resolve when Native confirms; reject with the host's error otherwise. A write's `SubmitOptions.dispatch` wins; one of the two is required. */
      dispatch?(request: Request, context: DispatchContext): Promise<Result>;
      /** Extra tries after a `busy` refusal, spaced by these delays. Default 300 ms, 600 ms. `[]` when the transport already retries. */
      busyDelaysMs?: readonly number[];
      /** Unresolved writes to keep; the oldest `sent` entries are forgotten first. Default 256. */
      maxEntries?: number;
      /** Subscribe to account/workspace changes; the helper calls the callback to drop everything. Returns the unsubscribe. */
      onScopeChange?(drop: () => void): () => void;
      /** The account/workspace identity the writes belong to now (compared with `Object.is`). Each write records it at submit; see `setScope`. */
      scope?: unknown;
      /** Injectable for tests. */
      now?(): number;
  }

  interface SubmitOptions {
      /** Use this idempotency key for the first dispatch (it was minted by the caller before the request was built). */
      readonly key?: string;
      /** Sends this write, and every retry of it, even if the helper's own `dispatch` or the app's options change later. */
      readonly dispatch?: (request: never, context: DispatchContext) => Promise<unknown>;
      /**
       * The scope this write is made in; default the helper's current scope. A UI passes the scope of the render that produced
       * the handler, so a write made from a still-visible old scope is recorded (and fenced) under that scope, never the next one.
       */
      readonly scope?: unknown;
      /**
       * The render generation of the handler making this write (see `commit`). A generation newer than the committed one is
       * staged: shown as "Sending…", kept, and sent only when that generation (or a later one with the same scope) commits.
       * Omit it outside UI hooks.
       */
      readonly generation?: number;
  }

  interface WriteHelper<Request = unknown, Result = unknown> {
      /** Freeze, key and dispatch in the caller's task, so a host that ties a write to a click still sees one. */
      submit(request: Request, options?: SubmitOptions): WriteTicket<Request, Result>;
      /** Send the same frozen request again. No-op while pending or after `sent`. Undefined for an unknown id. */
      retry(id: string): WriteTicket<Request, Result> | undefined;
      /** Forget a `failed` or `sent` entry. An `uncertain` one cannot be discarded: its key is the only protection against a duplicate. */
      discard(id: string): boolean;
      get(id: string): WriteEntry<Request, Result> | undefined;
      entries(): readonly WriteEntry<Request, Result>[];
      subscribe(listener: (entries: readonly WriteEntry<Request, Result>[]) => void): () => void;
      /** An account or workspace change: forget everything, send nothing more for it, ignore late answers. */
      dropAll(code?: string): void;
      /**
       * Tell the helper which account/workspace is current. A different value drops every entry at once, and a write is only
       * ever sent or retried while its recorded scope is the current one, so a retry cannot slip into another account
       * between the change and any deferred cleanup.
       */
      setScope(scope: unknown): void;
      /**
       * Publish a render generation and its scope, from the hook's layout effect (never while rendering). Older generations are
       * ignored. A changed scope retires every entry made under another one. Writes staged by handlers of this generation or
       * earlier are sent if their scope is the committed one, and dropped as "Not sent" (`scope_changed`) if it is not.
       */
      commit(generation: number, scope: unknown): void;
      /** Cancel timers, ignore late answers, send nothing more. Idempotent. */
      dispose(): void;
  }

  interface CoreKit extends CoreKitBase {
      readonly preact: PreactKit;
      /**
       * Safe writes without a UI framework (1.2.0): see `preact.useWrite` for what it does. You send the request
       * (`dispatch`), and call `dropAll()` yourself when your account or workspace changes; the kit does that for
       * you when a `useQueryFeed` hears `scope_changed`. Call `dispose()` when the page closes.
       */
      createWriteHelper<Request extends object = Record<string, unknown>, Result = unknown>(options: Omit<WriteHelperOptions<Request, Result>, 'onScopeChange' | 'now'>): WriteHelper<Request, Result>;
  }

  type QueryDelivery = (AppQueryResult & {
      readonly status: 'ready';
  }) | {
      readonly status: 'error';
      readonly code: string;
      readonly message: string;
      readonly terminal: boolean;
  };

  interface AppCall {
      readonly request_id: string;
      readonly confirmed: Promise<unknown>;
  }

  /** Data methods exist only after app-v2 negotiation; kit policy grants no data authority. */
  interface Host {
      readonly kit?: CoreKit;
      query?(query: AppQuery | StepsQuery): Promise<AppQueryResult>;
      subscribe?(query: AppQuery | StepsQuery, listener: (delivery: QueryDelivery) => void): () => void;
      call?(operation: string, args?: Record<string, unknown>): AppCall;
  }
}
interface Window { readonly native?: NativeAppKit.Host }

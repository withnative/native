// Native core app kit — AGPL-3.0-only; Copyright Native contributors.
// Release 1.1.0; major 1; native.app-kit.core.factory.v1; native.html.bridge.v1
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

  interface AppQueryResult {
      readonly rows: readonly unknown[];
      readonly columns: readonly unknown[];
      readonly truncated: boolean;
      readonly cached?: boolean;
  }

  type QueryFeedState = {
      readonly status: 'loading';
  } | {
      readonly status: 'unsupported';
      readonly message: string;
  } | {
      readonly status: 'ready';
      readonly result: AppQueryResult;
      readonly deliveredAt: number;
  } | {
      readonly status: 'error';
      readonly error: {
          readonly code: string;
          readonly message: string;
          readonly terminal: boolean;
      };
      readonly last?: AppQueryResult;
      readonly deliveredAt?: number;
  };

  type QueryFeed = QueryFeedState & {
      readonly retry: () => void;
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
      useQueryFeed(query: AppQuery | StepsQuery): QueryFeed;
      readonly Loading: UiComponent<{
          what?: string;
      }>;
      readonly Empty: UiComponent;
      readonly ErrorState: UiComponent<{
          error: Pick<KitError, 'code'> & {
              message?: string;
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

  interface CoreKit extends CoreKitBase {
      readonly preact: PreactKit;
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

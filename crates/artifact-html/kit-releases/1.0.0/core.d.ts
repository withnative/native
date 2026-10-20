// Native core app kit — AGPL-3.0-only; Copyright Native contributors.
// Release 1.0.0; major 1; native.app-kit.core.factory.v1; native.html.bridge.v1
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
  interface CoreKit {
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

  /** Optional because hosted delivery of this release is not available yet. */
  interface Host {
      readonly kit?: CoreKit;
  }
}
interface Window { readonly native?: NativeAppKit.Host }

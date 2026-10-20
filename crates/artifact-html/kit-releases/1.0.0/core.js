/* Native core app kit — AGPL-3.0-only; Copyright Native contributors. */
(function () {
var CoreFactoryExports = (function(exports) {
  "use strict";
  class PortError extends Error {
    constructor(code, message, detail) {
      super(message ?? code);
      this.code = code;
      this.detail = detail;
      this.name = "PortError";
    }
    code;
    detail;
  }
  const isObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);
  function toQueryResult(raw, variant) {
    if (!isObject(raw) || !Array.isArray(raw.rows)) throw new PortError("malformed", "the host's answer has no rows");
    const rows = raw.rows;
    return {
      label: typeof raw.label === "string" ? raw.label : "",
      columns: Array.isArray(raw.columns) ? raw.columns : [],
      rows,
      rowCount: typeof raw.row_count === "number" ? raw.row_count : rows.length,
      rowCountComplete: raw.row_count_complete !== false,
      truncated: raw.truncated === true,
      ...{}
    };
  }
  const inputOf = (delivery) => {
    const input = delivery?.input;
    return input && typeof input === "object" && !Array.isArray(input) ? input : void 0;
  };
  const failureOf = (error) => error instanceof PortError ? error : new PortError("unavailable", String(error));
  function createSnapshotClient(bridge2) {
    let disposed = false;
    let input;
    let started = false;
    let pushed = false;
    const feeds = /* @__PURE__ */ new Set();
    const snapshot = (key) => {
      if (disposed) throw new PortError("closed");
      const sql = input?.sql;
      if (!sql || typeof sql !== "object" || Array.isArray(sql) || !Object.hasOwn(sql, key)) {
        throw new PortError("undeclared", `the snapshot "${key}" was not delivered: declare it as a param-less sql.snapshot.v1 need`);
      }
      return toQueryResult(sql[key]);
    };
    const ready = bridge2.ready.then((delivery) => {
      if (!disposed && !pushed) input = inputOf(delivery);
      started = true;
    }, (error) => {
      throw failureOf(error);
    });
    void ready.catch(() => {
    });
    const stopInput = bridge2.onInput((delivery) => {
      if (disposed) return;
      const next = inputOf(delivery);
      if (!next) return;
      pushed = true;
      input = next;
      if (started) for (const feed of [...feeds]) feed.update();
    });
    return {
      ready,
      async read(key) {
        if (disposed) throw new PortError("closed");
        await ready;
        return snapshot(key);
      },
      subscribe(key, listener) {
        if (disposed) throw new PortError("closed");
        let alive = true;
        let last;
        const feed = {
          update() {
            if (!alive || disposed) return;
            let value;
            try {
              last = snapshot(key);
              value = { status: "ready", result: last };
            } catch (error) {
              value = { status: "error", error: failureOf(error), ...last ? { last } : {} };
            }
            deliver(value);
          },
          close() {
            alive = false;
            feeds.delete(feed);
          }
        };
        const deliver = (value) => {
          if (!alive || disposed) return;
          try {
            listener(value);
          } catch {
            feed.close();
          }
        };
        feeds.add(feed);
        try {
          listener({ status: "loading" });
        } catch (error) {
          feed.close();
          throw error;
        }
        void ready.then(() => feed.update(), (error) => {
          deliver({ status: "error", error: failureOf(error) });
        }).catch(() => {
          feed.close();
        });
        return feed.close;
      },
      dispose() {
        if (disposed) return;
        disposed = true;
        for (const feed of [...feeds]) feed.close();
        stopInput();
        input = void 0;
      }
    };
  }
  const ERROR_COPY = {
    busy: "Native is busy right now.",
    timeout: "Native took too long to answer.",
    undeclared: "This app was not given access to that data.",
    refused: "Native refused that request.",
    unavailable: "That data is not available right now.",
    malformed: "Native's answer was not in the expected shape.",
    closed: "This app was closed."
  };
  function errorText(error) {
    return ERROR_COPY[error.code];
  }
  function countLabel(result) {
    const shown = result.rows.length;
    if (!result.truncated) return `${shown}`;
    const total = result.rowCount.toLocaleString("en-US");
    return result.rowCountComplete ? `${shown} of ${total}` : `${shown} of more than ${total}`;
  }
  function recordLink(recordId) {
    return { "data-native-record-id": recordId };
  }
  function externalLink(url) {
    return { "data-native-external-url": url };
  }
  const version = "1.0.0";
  const major = 1;
  const layer = "core";
  const factory = "native.app-kit.core.factory.v1";
  const bridge = "native.html.bridge.v1";
  const identity = {
    version,
    major,
    layer,
    factory,
    bridge
  };
  function createCoreKit(bridge2, release) {
    if (Object.keys(release).sort().join(",") !== "bridge,factory,js_sha256,layer,major,types_sha256,version" || release.version !== identity.version || release.major !== identity.major || release.layer !== identity.layer || release.factory !== identity.factory || release.bridge !== identity.bridge || !/^[a-f0-9]{64}$/.test(release.js_sha256) || !/^[a-f0-9]{64}$/.test(release.types_sha256)) {
      throw new Error("incompatible core kit release metadata");
    }
    const client = createSnapshotClient(bridge2);
    const kit = Object.freeze({
      release: Object.freeze({ ...release }),
      ready: client.ready,
      read: client.read,
      subscribe: client.subscribe,
      countLabel,
      errorText,
      recordLink,
      externalLink
    });
    return Object.freeze({ kit, dispose: client.dispose });
  }
  exports.createCoreKit = createCoreKit;
  Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
  return exports;
})({});

return CoreFactoryExports.createCoreKit;
})()

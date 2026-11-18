/** Bounded device custody. No network, timers, eviction, or app-owned scope. */
export const APP_STATE_FEATURE = 'app.state.v1';
export const APP_STATE_PREFIX = 'native:app-state:v1:';
const GLOBAL_GENERATION_KEY = 'native:app-state-generation:all:v1';
const CONSUMED_PREFIX = 'native:app-state-consumed:v1:';
const ADMISSION_PREFIX = 'native:app-state-admission:v1:';
const WIPE_RESERVE_KEY = 'native:app-state-wipe-reserve:v1';
const PACKAGE_INDEX_PREFIX = 'native:app-state-package-index:v1:';
const GENERATION_PREFIX = 'native:app-state-generation:v1:';
const PACKAGE_GENERATION_PREFIX = 'native:app-state-package-generation:v1:';
export const APP_STATE_VALUE_CHARS = 65_536;
export const APP_STATE_ENVELOPE_BYTES = 256 * 1024;
export const APP_STATE_ACCOUNT_BYTES = 1024 * 1024;
const bytes = text => new TextEncoder().encode(text).length;
const encoded = value => encodeURIComponent(value);
const failure = code => ({ status: 'error', code });
const keys = storage => Array.from({ length: storage.length }, (_, i) => storage.key(i)).filter(key => typeof key === 'string');
const accountPrefix = account => APP_STATE_PREFIX + encoded(account) + ':';
// Record custody never shares installed-package prefixes or reconciliation indexes.
const scopeKey = scope => (scope.record === undefined ? '' : '@record:' + encoded(scope.record) + ':') + [scope.database, scope.workspace ?? '', scope.package].map(encoded).join(':') + ':';
const generationKey = account => GENERATION_PREFIX + encoded(account);
const packageGenerationKey = scope => PACKAGE_GENERATION_PREFIX + encoded(scope.account) + ':' + scopeKey(scope);
const stamp = (storage, key) => storage.getItem(key) ?? '0';
const nonce = () => globalThis.crypto.randomUUID();
function parse(raw) {
  if (!raw) return null;
  const row = JSON.parse(raw);
  if (row?.version !== 1 || !Number.isSafeInteger(row.revision) || row.revision < 0
    || !row.scope || typeof row.owner !== 'string' || !Object.hasOwn(row, 'snapshot')) throw new Error('invalid saved state');
  return row;
}
const consumedPrefix = account => CONSUMED_PREFIX + encoded(account) + ':';
const consumedKey = (key, row) => consumedPrefix(row.scope.account) + encoded(key) + ':' + row.owner + ':' + row.revision;
const consumed = (storage, key, row) => !!row && storage.getItem(consumedKey(key, row)) === '1';
function rows(storage, prefix) {
  return keys(storage).filter(key => key.startsWith(prefix)).map(key => ({ key, raw: storage.getItem(key) }));
}
const rowCurrent = (storage, row) => !!row
  && row.globalGeneration === stamp(storage, GLOBAL_GENERATION_KEY)
  && row.generation === stamp(storage, generationKey(row.scope.account))
  && row.packageGeneration === stamp(storage, packageGenerationKey(row.scope));

/** Capture once at authenticated account admission, not on frame/reload creation. */
export function captureAppStateGeneration(storage, account) {
  // A wipe can race another page's last commit or stop partway through its
  // deletions. Fences make those rows unreadable; admission also reclaims them.
  for (const { key, raw } of rows(storage, accountPrefix(account))) {
    let valid = false;
    try { valid = rowCurrent(storage, parse(raw)); } catch { /* malformed row */ }
    if (!valid && storage.getItem(key) === raw) storage.removeItem(key);
  }
  // Reserve space, never initialize generation keys: two simultaneous first
  // tabs must not invalidate each other's admitted generation. Only wipes
  // write generation keys, so late initialization cannot undo a tombstone.
  try { if (storage.getItem(WIPE_RESERVE_KEY) === null) storage.setItem(WIPE_RESERVE_KEY, '0'.repeat(65_536)); } catch { /* reads still work when full */ }
  // A per-admission lease also fences Clear-Site-Data/storage.clear, which
  // removes generation tombstones. Never recreate it when opening a frame.
  let leaseKey = ADMISSION_PREFIX + encoded(account) + ':' + nonce();
  try { storage.setItem(leaseKey, '1'); } catch { leaseKey = null; }
  return Object.freeze({ account, leaseKey, global: stamp(storage, GLOBAL_GENERATION_KEY), accountGeneration: stamp(storage, generationKey(account)) });
}

function writeFence(storage, key, doomed) {
  const value = nonce();
  try { storage.setItem(key, value); return; } catch (error) {
    if (error?.name !== 'QuotaExceededError') throw error;
  }
  // A full origin can spend its reserve on the fence. If no reserve could be
  // made, delete only rows already authorized for this wipe to free space.
  storage.removeItem(WIPE_RESERVE_KEY);
  for (const candidate of [null, ...doomed]) {
    if (candidate) storage.removeItem(candidate);
    try { storage.setItem(key, value); return; } catch (error) {
      if (error?.name !== 'QuotaExceededError') throw error;
    }
  }
  throw Object.assign(new Error('app state wipe fence unavailable'), { name: 'QuotaExceededError' });
}
/** Tombstones are deliberately retained. Old page sessions can never re-create wiped rows. */
export function wipeAppStateAccount(storage, account) {
  const doomed = keys(storage).filter(key => key.startsWith(account ? accountPrefix(account) : APP_STATE_PREFIX)
    || key.startsWith(account ? consumedPrefix(account) : CONSUMED_PREFIX)
    || key.startsWith(PACKAGE_INDEX_PREFIX + (account ? encoded(account) + ':' : ''))
    || key.startsWith(ADMISSION_PREFIX + (account ? encoded(account) + ':' : '')));
  writeFence(storage, account ? generationKey(account) : GLOBAL_GENERATION_KEY, doomed);
  for (const key of doomed) storage.removeItem(key);
}
export function wipeAppStatePackage(storage, scope) {
  const prefix = accountPrefix(scope.account) + scopeKey(scope);
  const index = PACKAGE_INDEX_PREFIX + encoded(scope.account) + ':' + scopeKey(scope);
  const doomed = keys(storage).filter(key => key.startsWith(prefix)
    || key.startsWith(consumedPrefix(scope.account) + encoded(prefix)) || key === index);
  writeFence(storage, packageGenerationKey(scope), doomed);
  for (const key of doomed) storage.removeItem(key);
}
/** Reconcile only a confirmed, complete install list; broken/disabled entries still count as present. */
export function reconcileAppStatePackages(storage, scope, installs) {
  const present = new Set(installs.filter(row => row?.status !== 'removed').map(row => row?.package));
  const markerPrefix = PACKAGE_INDEX_PREFIX + encoded(scope.account) + ':' + [scope.database, scope.workspace ?? ''].map(encoded).join(':') + ':';
  const knownPackages = keys(storage).filter(key => key.startsWith(markerPrefix)).map(key => decodeURIComponent(key.slice(markerPrefix.length, -1)));
  const packages = new Set(rows(storage, accountPrefix(scope.account)).map(({ raw }) => parse(raw)?.scope)
    .filter(row => row?.record === undefined && row?.database === scope.database && (row.workspace ?? '') === (scope.workspace ?? ''))
    .map(row => row.package).concat(knownPackages));
  for (const pkg of packages) if (!present.has(pkg)) wipeAppStatePackage(storage, { ...scope, package: pkg });
}
export function listAppStateForAccount(storage, account) {
  if (!account) return [];
  return rows(storage, accountPrefix(account)).flatMap(({ key, raw }) => {
    let row;
    try { row = parse(raw); } catch { return []; }
    if (!row?.snapshot || consumed(storage, key, row) || !rowCurrent(storage, row)) return [];
    const value = row.snapshot.value;
    const count = Array.isArray(value) ? value.length : value && typeof value === 'object' ? Object.keys(value).length : 1;
    return [{ key, recordId: row.scope.record, databaseId: row.scope.database, package: row.scope.package,
      appName: row.appName, count, snapshot: row.snapshot }];
  });
}

/**
 * One page/tab owns one fresh slot per mounted package. get returns its snapshot
 * and orphan snapshots. The app MUST merge recovered values before set: set is a
 * complete replacement of the returned state. Adoption never dispatches writes.
 * With Web Locks, live slots are skipped and orphan locks retained until close.
 * Without locks, recovery is conservative (may include another live tab). Each
 * writer still writes only its unique slot; revision-specific consumption receipts
 * leave newer source saves visible, so double adoption cannot lose entries.
 */
export function createAppStateStore({ storage, scope, appName = scope.package, bodyDigest, slot = nonce(),
  generation: admittedGeneration, locks = globalThis.navigator?.locks, now = () => new Date().toISOString(), isCurrent = () => true }) {
  for (const field of ['account', 'database', 'package']) {
    if (typeof scope[field] !== 'string' || !scope[field] || scope[field].length > 512) throw new Error(`invalid app state ${field}`);
  }
  scope = { account: scope.account, database: scope.database, workspace: scope.workspace ?? '', package: scope.package, ...(scope.record === undefined ? {} : { record: scope.record }) };
  if (scope.record !== undefined && (typeof scope.record !== 'string' || !scope.record || scope.record.length > 512)) throw new Error('invalid app state record');
  if (typeof scope.workspace !== 'string' || scope.workspace.length > 512) throw new Error('invalid app state workspace');
  const prefix = accountPrefix(scope.account) + scopeKey(scope);
  const key = prefix + encoded(slot);
  const owner = nonce();
  const admitted = admittedGeneration ?? captureAppStateGeneration(storage, scope.account);
  if (admitted.account !== scope.account) throw new Error('app state admission account mismatch');
  const globalGeneration = admitted.global;
  const generation = admitted.accountGeneration;
  const packageMarker = packageGenerationKey(scope);
  const packageIndex = PACKAGE_INDEX_PREFIX + encoded(scope.account) + ':' + scopeKey(scope);
  if (admitted.leaseKey && storage.getItem(admitted.leaseKey) === '1'
    && globalGeneration === stamp(storage, GLOBAL_GENERATION_KEY) && generation === stamp(storage, generationKey(scope.account))) {
    try { if (storage.getItem(packageIndex) === null) storage.setItem(packageIndex, '0'.repeat(64)); } catch { /* a full origin must still restore */ }
  }
  const packageGeneration = stamp(storage, packageMarker);
  let closed = false, chain = Promise.resolve(), recovered = new Map(), releases = [];
  const current = () => !closed && isCurrent() && (!admitted.leaseKey || storage.getItem(admitted.leaseKey) === '1') && globalGeneration === stamp(storage, GLOBAL_GENERATION_KEY) && generation === stamp(storage, generationKey(scope.account))
    && packageGeneration === stamp(storage, packageGenerationKey(scope));
  // Held lock promises are released on close, including acquisition racing close.
  async function acquire(rowKey) {
    if (!locks?.request) return true;
    return new Promise((resolve, reject) => {
      locks.request('native-app-state-owner:' + rowKey, { ifAvailable: true }, lock => {
        if (!lock || closed) { resolve(false); return; }
        return new Promise(release => { releases.push(release); resolve(true); });
      }).catch(reject);
    });
  }
  const ownLock = acquire(key);
  const serial = operation => {
    const result = chain.then(async () => {
      try {
        if (!await ownLock) return failure('unavailable');
        if (!current()) return failure('unavailable');
        const run = () => current() ? operation() : failure('unavailable');
        return locks?.request ? await locks.request('native-app-state-account:' + scope.account, run) : await run();
      } catch (error) { return failure(error?.name === 'QuotaExceededError' ? 'quota' : 'unavailable'); }
    });
    chain = result.then(() => undefined, () => undefined);
    return result;
  };
  const readOwn = () => {
    const row = parse(storage.getItem(key));
    if (row && row.owner !== owner) throw new Error('slot ownership changed');
    return rowCurrent(storage, row) ? row : null;
  };
  function commit(snapshot, revision, selected) {
    const row = { version: 1, scope, appName: String(appName).slice(0, 256), owner, globalGeneration, generation, packageGeneration, revision, snapshot };
    const raw = JSON.stringify(row);
    const usage = rows(storage, accountPrefix(scope.account)).reduce((sum, item) => sum + (item.key === key || selected.some(([source, saved]) => source === item.key && saved.raw === item.raw) || consumed(storage, item.key, parse(item.raw)) ? 0 : bytes(item.raw ?? '')), 0)
      + keys(storage).filter(key => key.startsWith(consumedPrefix(scope.account))).reduce((sum, key) => sum + bytes(key) + 1, 0);
    const receiptBytes = locks?.request ? 0 : selected.reduce((sum, [source, item]) => sum + (storage.getItem(consumedKey(source, item.row)) === null ? bytes(consumedKey(source, item.row)) + 1 : 0), 0);
    if (usage + receiptBytes + bytes(raw) > APP_STATE_ACCOUNT_BYTES) return failure('quota');
    if (!current()) return failure('unavailable');
    if (!admitted.leaseKey) return failure('unavailable');
    storage.setItem(key, raw); // Acknowledgement follows the successful storage commit.
    if (!current()) { if (storage.getItem(key) === raw) storage.removeItem(key); return failure('unavailable'); }
    return { status: 'ok', revision, snapshot };
  }
  function selection(consume) {
    if (consume !== 'all' && (!Array.isArray(consume) || consume.some(token => typeof token !== 'string' || token.length > 128))) return failure('malformed');
    const selected = consume === 'all' ? [...recovered] : [];
    if (consume !== 'all') for (const token of new Set(consume)) {
      const found = [...recovered].find(([, item]) => item.source === token);
      if (!found) return failure('stale_revision');
      selected.push(found);
    }
    if (consume !== 'all' && selected.some(([source, item]) => storage.getItem(source) !== item.raw || consumed(storage, source, item.row))) return failure('stale_revision');
    return selected;
  }
  function consumeRecovered(selected) {
    // Never delete a mutable slot owned by an uncoordinated tab. A receipt
    // consumes exactly the revision we returned, leaving every newer save
    // visible. Crash before this receipt may duplicate restore, never lose it.
    for (const [source, item] of selected) {
      try {
        if (locks?.request) { if (storage.getItem(source) === item.raw) storage.removeItem(source); }
        else storage.setItem(consumedKey(source, item.row), '1');
      } catch { /* successor committed; retain duplicate sources on cleanup failure */ }
    }
    for (const [source] of selected) recovered.delete(source);
  }
  return {
    get(options = {}) {
      const schema = options.schema;
      return serial(async () => {
        const own = readOwn();
        // Refresh changed/unavailable revisions before issuing this get's tokens.
        const previouslyClaimed = new Set(recovered.keys());
        for (const [source, item] of recovered) if (storage.getItem(source) !== item.raw || consumed(storage, source, item.row)) recovered.delete(source);
        for (const item of rows(storage, prefix)) {
          if (item.key === key || recovered.has(item.key)) continue;
          if (!previouslyClaimed.has(item.key) && !await acquire(item.key)) continue;
          if (!current()) return failure('unavailable');
          const raw = storage.getItem(item.key), row = parse(raw);
          if (row?.snapshot && !consumed(storage, item.key, row) && row.globalGeneration === globalGeneration
            && row.generation === generation && row.packageGeneration === packageGeneration) recovered.set(item.key, { raw, row });
        }
        const decorate = snapshot => snapshot && ({ ...snapshot, bodyChanged: snapshot.from_body_digest !== bodyDigest,
          schemaChanged: schema !== undefined && snapshot.schema !== schema });
        for (const item of recovered.values()) item.source = nonce();
        return { status: 'ok', revision: own?.revision ?? 0, snapshot: decorate(own && !consumed(storage, key, own) ? own.snapshot : null),
          recovered: [...recovered.values()].map(item => ({ ...decorate(item.row.snapshot), source: item.source })) };
      });
    },
    set(value, options = {}) {
      // Clone BEFORE queueing, so later app mutations cannot change the acknowledged value.
      let json;
      try { json = JSON.stringify(value); } catch { return Promise.resolve(failure('malformed')); }
      if (typeof json !== 'string') return Promise.resolve(failure('malformed'));
      if (json.length > APP_STATE_VALUE_CHARS) return Promise.resolve(failure('too_large'));
      const schema = options.schema ?? null, expectedRevision = options.expectedRevision;
      const consume = Array.isArray(options.consume) ? [...options.consume] : (options.consume === undefined ? 'all' : options.consume);
      if ((schema !== null && (typeof schema !== 'string' || !schema || schema.length > 128))
        || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) return Promise.resolve(failure('malformed'));
      return serial(() => {
        const selected = selection(consume);
        if (!Array.isArray(selected)) return selected;
        const prior = readOwn();
        if ((prior?.revision ?? 0) !== expectedRevision) return failure('stale_revision');
        const snapshot = { version: 1, schema, from_body_digest: bodyDigest, revision: expectedRevision + 1, savedAt: now(), value: JSON.parse(json) };
        if (bytes(JSON.stringify(snapshot)) > APP_STATE_ENVELOPE_BYTES) return failure('too_large');
        const answer = commit(snapshot, expectedRevision + 1, selected);
        if (answer.status === 'ok') consumeRecovered(selected);
        return answer;
      });
    },
    clear(options = {}) {
      const expectedRevision = options.expectedRevision;
      const consume = Array.isArray(options.consume) ? [...options.consume] : (options.consume === undefined ? 'all' : options.consume);
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) return Promise.resolve(failure('malformed'));
      return serial(() => {
        const selected = selection(consume);
        if (!Array.isArray(selected)) return selected;
        const prior = readOwn();
        if ((prior?.revision ?? 0) !== expectedRevision) return failure('stale_revision');
        const answer = commit(null, expectedRevision + 1, selected);
        if (answer.status === 'ok') consumeRecovered(selected);
        return answer;
      });
    },
    close() { closed = true; for (const release of releases) release(); releases = []; },
  };
}

/** The router accepts data only; identity, storage and body digest were bound by the host. */
export async function handleAppStateMessage(store, message) {
  if (!message || message.version !== 'native.html.bridge.v1' || message.type !== 'app-state'
    || typeof message.request_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(message.request_id)
    || !['get', 'set', 'clear'].includes(message.action)
    || Object.keys(message).some(key => !['version', 'type', 'request_id', 'action', 'value', 'options'].includes(key))) return failure('malformed');
  const options = message.options ?? {};
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || Object.keys(options).some(key => !(message.action === 'get' ? ['schema'] : message.action === 'clear' ? ['expectedRevision', 'consume'] : ['schema', 'expectedRevision', 'consume']).includes(key))
    || (options.schema !== undefined && (typeof options.schema !== 'string' || !options.schema || options.schema.length > 128))) return failure('malformed');
  return message.action === 'set' ? store.set(message.value, options) : store[message.action](options);
}

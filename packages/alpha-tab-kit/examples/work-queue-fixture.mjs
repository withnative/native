// Fixture backend + real supplied kit/bridge. No real agents, Native writes or external effects.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { injectBridge } from '../src/fake-host/server.mjs';

export const folderId = '10000000-0000-4000-8000-000000000001';
export const taskId = '10000000-0000-4000-8000-000000000002';
const source = readFileSync(new URL('./work-queue.html', import.meta.url), 'utf8');
const body = '# Why this is worth doing\n\nGeorge’s CRM separates proposals, exact approved wording and execution.\n\n- [Today cards specification](https://n8v.to/53839614)\n- [Lessons for the app kit](https://n8v.to/a6119828)\n\nWe want to learn which part of that loop still needs the most app-specific code. This is a fixture proposal, not a new product decision.';
const row = (id, name, text, type = 'Document', summary = null) => ({ id, name, body: text, body_length: text.length, summary, type, kind: type === 'WorkItem' ? 'task' : 'note', home_id: folderId, lifecycle: type === 'WorkItem' ? 'open' : null, created_at: '2026-11-13T10:00:00.000Z', updated_at: '2026-11-13T10:00:00.000Z', updated_at_ms: 1, is_current: 1, archived: false });
export const fixtureHost = { id: 'fixture', label: 'Demo machine', status: 'reachable', epoch: 'e1', capabilities: { create: true, chooseFolder: true } };
export const fixtureCatalog = { hosts: [{ hostId: 'fixture', hostLabel: 'Demo machine', hostEpoch: 'e1', status: 'reachable',
  providers: [{ id: 'claude', label: 'Claude Code (demo)', available: true, defaultModeId: 'default', modes: [{ id: 'default', label: 'Ask for permissions' }], models: [{ id: 'demo-model', label: 'Demo model', isDefault: true, thinkingOptions: [] }] }],
  workspaces: [{ id: 'ordinary', name: 'Research chat', path: '/fixture/research', kind: 'ordinary' }] }] };
const summary = id => ({ id, hostId: 'fixture', hostLabel: 'Demo machine', hostEpoch: 'e1', title: 'Compare the work-loop glue', provider: 'claude', model: 'demo-model', status: 'running', lastActivity: '2026-11-13T10:01:00.000Z', workspace: { id: 'ordinary', name: 'Research chat' } });
const parent = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Work queue · fixture preview</title><style>html,body{margin:0;height:100%;font:14px system-ui;background:#f7f8f3}#banner{padding:10px 20px;background:#e4ecd9;color:#27412b}iframe{width:100%;height:calc(100% - 40px);border:0}</style></head><body>
<div id="banner">Fixture preview · agent runs and returned results are simulated · nothing is sent externally</div><iframe id="app-frame" sandbox="allow-scripts"></iframe>
<script type="module">
import { createAppStateStore, handleAppStateMessage } from '/app-state.mjs';
const version = 'native.html.bridge.v1', options = new URLSearchParams(location.search);
const state = options.get('state') === 'off' ? null : createAppStateStore({ storage: localStorage, locks: navigator.locks, scope: { account: 'fixture-user', database: 'fixture-db', package: 'agent.work-queue' }, bodyDigest: 'fixture-source' });
let port; const subscriptions = new Map(), received = [], deliveries = new Map();
const send = message => port?.postMessage({ version, ...message });
const request = async message => (await fetch('/rpc', { method: 'POST', body: JSON.stringify(message) })).json();
async function push() {
  for (const [id, query] of subscriptions) {
    const result = await request({ type: 'query', query });
    if (result.status !== 'ok') { send({ type: 'subscription-error', subscription_id: id, code: result.code, message: result.message, terminal: result.terminal !== false }); continue; }
    send({ type: 'subscription-result', subscription_id: id, delivery: (deliveries.get(id) || 0) + 1, result: result.result, cached: false });
    deliveries.set(id, (deliveries.get(id) || 0) + 1);
  }
}
window.addEventListener('message', event => {
  if (event.source !== document.getElementById('app-frame').contentWindow || event.data?.type !== 'native-html-bootstrap') return;
  const channel = new MessageChannel(); port = channel.port1;
  port.onmessage = async ({ data: m }) => {
    received.push(m);
    if (m.type === 'subscribe') { subscriptions.set(m.subscription_id, m.query); await push(); return; }
    if (m.type === 'unsubscribe') { subscriptions.delete(m.subscription_id); return; }
    if (m.type === 'app-state' && state) { send({ type: 'app-state-result', request_id: m.request_id, ...await handleAppStateMessage(state, m) }); return; }
    if (m.type === 'call' || m.type.startsWith('agent-sessions-')) {
      const result = await request(m);
      send({ type: m.type === 'call' ? 'call-result' : m.type + '-result', request_id: m.request_id, ...result });
      if (m.type === 'call') await push();
    }
  };
  port.start();
  const features = ['app.subscribe.v2','app.call.v2', ...(state ? ['app.state.v1'] : []), ...(options.get('agents') === 'off' ? [] : ['app.agent-sessions.v2','app.agent-sessions.create.v1','app.agent-sessions.adopted.v1','app.agent-sessions.open-conversation.v1'])];
  event.source.postMessage({ type: 'native-html-init', version, input: {}, host_features: features }, '*', [channel.port2]);
});
window.fixture = { received: () => received, push, failScope() { for (const id of subscriptions.keys()) send({ type: 'subscription-error', subscription_id: id, code: 'scope_changed', message: 'Workspace changed', terminal: true }); subscriptions.clear(); } };
document.getElementById('app-frame').src = '/frame';
setInterval(push, 1000);
</script></body></html>`;

export async function startWorkQueueFixture({ port = 0, loseFirstLaunch = false, refuseApproval = false, listUnavailable = false, emptyListHosts = false, catalogFailures = 0 } = {}) {
  const tasks = [row(taskId, 'Find the most useful next kit improvement', body, 'WorkItem', 'Compare the proposal-to-result flow in George’s apps. Recommend one small app-kit improvement, with concrete evidence and a useful example.')];
  const records = [], links = [], calls = [], launches = [], sends = [], sessions = new Map(), receipts = new Map();
  let lost = false, catalogReads = 0;
  let delayLists = false, delayTask = false;
  let failTask = false, failApprovals = false, transientReads = false;
  const pendingReads = new Set();
  function query(q) {
    const first = q.parameters?.[0], id = first?.value ?? first;
    const rows = q.sql.includes('JOIN links') ? records.filter(r => links.some(l => l.source_id === r.id && l.target_id === id))
      : q.sql.includes('home_id =') ? tasks.filter(r => r.home_id === id)
      : tasks.filter(r => r.id === id);
    const cap = Number(/substr\((?:r\.)?body,\s*1,\s*(\d+)\)/.exec(q.sql)?.[1] || 24000);
    const delivered = [...rows].reverse().slice(0, 5).map(r => ({ ...r, body: r.body.slice(0, cap), body_length: r.body.length, ...(q.sql.includes('JOIN links') ? { approval_id: id } : {}) }));
    return { columns: Object.keys(delivered[0] || { id: null }), rows: delivered, truncated: false };
  }
  function addResult(approvalId) {
    if (links.some(l => l.target_id === approvalId)) return;
    const result = row(randomUUID(), 'Result: a reusable agent task handoff', '## Recommendation\n\nMake the source record, approved brief and return destination one reusable handoff recipe.\n\nThe existing kit handles records and sessions separately. This example still assembles the return instructions and preserves a launch key itself.\n\n### Suggested next step\n\nTry this with a real research task before extracting an API.\n\n*Fixture result. No actual agent performed this research.*');
    records.push(result); links.push({ source_id: result.id, target_id: approvalId });
  }
  async function rpc(m) {
    if (m.type === 'query') {
      const list = m.query.sql.includes('home_id =');
      const detail = m.query.sql.includes('WHERE id =');
      const approval = m.query.sql.includes('JOIN links') && m.query.parameters[0]?.value === taskId;
      if ((detail && failTask) || (approval && failApprovals)) return { status: transientReads ? 'error' : 'refused', code: transientReads ? 'network_lost' : 'query_refused', message: 'Fixture read unavailable', terminal: !transientReads };
      if ((list && delayLists) || (detail && delayTask)) await new Promise(resolve => pendingReads.add(resolve));
      return { status: 'ok', result: query(m.query) };
    }
    if (m.type === 'call') {
      calls.push(m);
      if (refuseApproval) return { status: 'refused', code: 'permission_denied', message: 'Demo refusal: brief not saved.' };
      const old = receipts.get(m.args.idempotency_key);
      if (old) return { status: 'ok', result: old };
      const rec = row(randomUUID(), m.args.name, m.args.body); records.push(rec);
      for (const link of m.args.links || []) links.push({ source_id: rec.id, target_id: link.target_id });
      const result = { id: rec.id }; receipts.set(m.args.idempotency_key, result);
      return { status: 'ok', result };
    }
    if (m.type === 'agent-sessions-list') return { result: listUnavailable ? { ok: false, code: 'unavailable' } : { ok: true, value: { hosts: emptyListHosts ? [] : [fixtureHost], sessions: emptyListHosts ? [] : [...sessions.values()] } } };
    if (m.type === 'agent-sessions-catalog') { catalogReads++; return { result: catalogReads <= catalogFailures ? { ok: false, code: 'unavailable' } : { ok: true, value: fixtureCatalog } }; }
    if (m.type === 'agent-sessions-create') {
      launches.push(m);
      if (!sessions.has(m.request_id)) {
        sessions.set(m.request_id, summary('session-' + sessions.size));
        const approved = records.find(r => { try { return JSON.parse(r.body).requestKey === m.request_id; } catch { return false; } });
        if (approved) setTimeout(() => addResult(approved.id), 600);
      }
      if (loseFirstLaunch && !lost) { lost = true; return { result: { ok: false, error: { code: 'outcome_unknown', message: 'Demo lost launch answer.' } } }; }
      return { result: { ok: true, value: sessions.get(m.request_id) } };
    }
    if (m.type === 'agent-sessions-create-status') {
      const found = sessions.get(m.create_request_id);
      return { result: { ok: true, value: found ? { state: 'settled', result: { ok: true, value: found } } : { state: 'unknown_request' } } };
    }
    if (m.type === 'agent-sessions-send') { sends.push(m); return { result: { ok: true, value: { requestId: m.request_id, delivery: 'acknowledged' } } }; }
    if (m.type === 'agent-sessions-open-conversation') return { result: { ok: true, value: {} } };
    return { result: { ok: false, code: 'unavailable' } };
  }
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    try {
      if (url.pathname === '/rpc' && req.method === 'POST') {
        let body = ''; for await (const chunk of req) { body += chunk; if (body.length > 1000000) throw new Error('Fixture request too large'); }
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(await rpc(JSON.parse(body)))); return;
      }
      if (url.pathname === '/app-state.mjs') { res.writeHead(200, { 'content-type': 'text/javascript' }); res.end(readFileSync(new URL('../src/fake-host/app-state.mjs', import.meta.url))); return; }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(url.pathname === '/frame' ? injectBridge(source.replace("const DEFAULT_FOLDER = '';", 'const DEFAULT_FOLDER = ' + JSON.stringify(folderId) + ';'), 'http://' + req.headers.host) : parent);
    } catch (error) { res.writeHead(500); res.end(String(error)); }
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, tasks, records, calls, launches, sends, sessions, links, addResult,
    failReads: ({ task = false, approvals = false, transient = false } = {}) => { failTask = task; failApprovals = approvals; transientReads = transient; },
    holdReads: ({ lists = true, task = false } = {}) => { delayLists = lists; delayTask = task; },
    releaseReads: () => { delayLists = false; delayTask = false; for (const resolve of pendingReads) resolve(); pendingReads.clear(); },
    close: () => new Promise(resolve => { for (const done of pendingReads) done(); pendingReads.clear(); server.close(resolve); server.closeAllConnections(); }) };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const fixture = await startWorkQueueFixture({ port: Number(process.env.PORT || 4319) });
  console.log('Work queue fixture: ' + fixture.url + '\nSimulated agents and data only. Press Ctrl-C to stop.');
  process.once('SIGINT', async () => { await fixture.close(); process.exit(0); });
}

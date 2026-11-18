// The meeting-notes starter against real reads and writes (task 85dedf2).
//
// The fake host only carries the frame; every query goes through the real
// launcher read hub (packages/native-launcher/src/readHub.mjs, as the hosted
// shell uses it) to a real `mcp-stdio` engine on a fresh SQLite file, and
// every create goes to that engine. So the rows the starter sees have the
// engine's own `query_sql` shape, which is what run set 3 (c904228) met live.
//
// Needs a built engine and Chromium, so it is a local check, not a CI gate:
//
//   cargo build --bin mcp-stdio
//   node packages/alpha-tab-kit/test/source-starters-real-engine.mjs [path/to/mcp-stdio]
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadChromium, openFakeHost } from '../src/fake-host/playwright.mjs';
import { createReadHub } from '../../native-launcher/src/readHub.mjs';
import { starters } from './helpers/source-starters.mjs';

const binary = process.argv[2] ?? process.env.NATIVE_MCP_STDIO
  ?? fileURLToPath(new URL('../../../target/debug/mcp-stdio', import.meta.url));
if (!existsSync(binary)) {
  console.log(`SKIPPED: no mcp-stdio binary at ${binary} (cargo build --bin mcp-stdio)`);
  process.exit(0);
}

const dir = mkdtempSync(join(tmpdir(), 'starter-real-'));
const child = spawn(binary, [join(dir, 'engine.db')], {
  stdio: ['pipe', 'pipe', 'ignore'],
  env: { ...process.env, NATIVE_CE_MCP_SURFACE: 'legacy', NATIVE_CE_MCP_TOOL_PROFILE: 'complete' },
});
let buffered = '';
let nextId = 0;
const waiting = new Map();
child.stdout.on('data', (chunk) => {
  buffered += chunk;
  for (let end; (end = buffered.indexOf('\n')) >= 0;) {
    const line = buffered.slice(0, end).trim();
    buffered = buffered.slice(end + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    waiting.get(message.id)?.(message);
    waiting.delete(message.id);
  }
});
const rpc = (method, params) => new Promise((resolve) => {
  nextId += 1;
  waiting.set(nextId, resolve);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: nextId, method, params })}\n`);
});
let runKey = 'new';
async function engine(name, args) {
  const answer = await rpc('tools/call', { name, arguments: { format: 'json', run_key: runKey, ...args } });
  if (answer.error) throw new Error(answer.error.message);
  const result = answer.result;
  const text = result.content?.map((part) => part.text ?? '').join('') ?? '';
  if (result.isError) throw Object.assign(new Error(result.structuredContent?.error ?? text), { status: 'refused' });
  return result.structuredContent ?? JSON.parse(text);
}

const chromium = await loadChromium();
assert.ok(chromium, 'Playwright required');
const browser = await chromium.launch({ headless: true, ...(process.env.ALPHA_TAB_KIT_CHROMIUM ? { executablePath: process.env.ALPHA_TAB_KIT_CHROMIUM } : {}) });
const inbox = starters[1];
try {
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'source-starters-real-engine', version: '0' } });
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  runKey = (await engine('set_intent', { intent: 'Check the meeting-notes starter against real rows' })).run_context.run_key;
  const saved = await engine('create_record', { type: 'Document', kind: 'note', name: 'Weekly planning',
    body: 'Agenda first.\n\n**Decide** owners', home_id: 'native:unfiled', reason: 'fixture' });
  const savedId = saved.id ?? saved.record?.id;
  assert.equal(typeof savedId, 'string');

  const hub = createReadHub({ callTool: (operation, args) => engine(operation, args), scope: () => 'starter-check' });
  const delivered = [];
  const page = await browser.newPage();
  const tab = await openFakeHost(page, { ...inbox,
    queries: async (query) => {
      const answer = await hub.query(query);
      if (answer.status !== 'ok') throw Object.assign(new Error(answer.message), { status: answer.status, code: answer.code });
      delivered.push(answer.result);
      return answer.result;
    },
    // As the hosted shell does, a confirmed write revalidates the hub's cached reads.
    calls: async (operation, args) => { const result = await engine(operation, args); hub.revalidate(); return result; } });
  const frame = page.frames().find((f) => f.url().includes('/frame'));

  // The real engine answers named objects, and this list reads metadata only.
  await frame.locator(`ul [data-native-record-id="${savedId}"]`).waitFor();
  const first = delivered[0].rows[0];
  assert.ok(first && !Array.isArray(first) && first.id === savedId && first.name === 'Weekly planning', JSON.stringify(first));
  assert.equal('body' in first, false);
  assert.equal('body_length' in first, false);
  assert.equal(await frame.locator(`ul [data-native-record-id="${savedId}"]`).textContent(), 'Weekly planning');

  // A note created through the starter persists and comes back through the same reads.
  await frame.locator('input[name="title"]').fill('Created in starter');
  await frame.locator('textarea[name="body"]').fill('Made by the app');
  await frame.getByRole('button', { name: 'Create note', exact: true }).click();
  // This fake host performs one-shot queries; forward the controlled host invalidation
  // to its subscriptions. The app itself never calls retry after writing.
  // The engine's receipt names the record, so the list shows it at once; the forwarded invalidation then brings the
  // list's own row, which replaces it. One record, one row.
  await frame.locator('ul [data-native-record-id]').filter({ hasText: 'Created in starter' }).waitFor();
  for (const sub of await tab.subscriptions()) await tab.pushSubscription(sub);
  await frame.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await frame.locator('ul [data-native-record-id]').filter({ hasText: 'Created in starter' }).waitFor();
  await frame.locator('section[aria-label="Note actions"] article').waitFor({ state: 'hidden' });
  assert.equal(await frame.locator('ul [data-native-record-id]').filter({ hasText: 'Created in starter' }).count(), 1);
  const stored = await engine('query_sql', { sql: "SELECT id, home_id FROM records WHERE name = 'Created in starter' AND kind = 'note' ORDER BY id LIMIT 2" });
  assert.equal(stored.rows.length, 1);
  assert.equal(stored.rows[0].home_id, 'native:unfiled');

  await tab.expectHealthy(); await tab.close(); await page.close();
  hub.dispose?.();
  console.log('Meeting-notes starter: real read hub and engine metadata rows display, reconcile and persist.');
} finally {
  await browser.close();
  child.kill();
  rmSync(dir, { recursive: true, force: true });
}

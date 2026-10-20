import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { starters } from './helpers/source-starters.mjs';
import { validateHtml } from '../src/html.mjs';
import { startFakeHost } from '../src/fake-host/server.mjs';

test('Native-readable complete starters pass package admission on their exact bytes', async () => {
  assert.equal(starters.length, 2);
  for (const { html, descriptor } of starters) {
    assert.equal(readFileSync(new URL(`../starters/${descriptor.package}.html`,import.meta.url),'utf8'),html);
    assert.deepEqual(JSON.parse(readFileSync(new URL(`../starters/${descriptor.package}.declaration.json`,import.meta.url),'utf8')),descriptor.declaration);
    assert.ok(Buffer.byteLength(html) < 15000);
    assert.equal((html.match(/<script type="module">/g) || []).length, 1);
    assert.doesNotMatch(html, /\bimport\s|<script[^>]+src=/);
    validateHtml(html);
    const host = await startFakeHost({ html, descriptor });
    await host.close();
  }
});

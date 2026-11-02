import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../backend/src/app.js';
import { scanStore } from '../backend/src/scanner.js';
import { demoArchive, demoFetcher } from '../scripts/demo-fixture.js';

test('real application rejects cross-site requests, malformed/oversized bodies and hostile inputs without leaking internals', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-security-'));
  let network = 0;
  const app = createApp({ store: scanStore(directory), fetcher: async (...args) => { network++; return demoFetcher(...args); }, frontendDirectory: false });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}/api/scans`;
  const post = (body: string, headers: Record<string, string> = {}) => fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });
  try {
    assert.equal((await post('{}', { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post('{')).status, 400);
    assert.equal((await post(JSON.stringify({ value: 'x'.repeat(101 * 1024) }))).status, 413);
    for (const body of [{ url: 'http://169.254.169.254/latest/meta-data' }, { url: 'https://github.com@127.0.0.1/a/b' }, { url: 'https://github.com/a/b', extra: true }, []]) assert.equal((await post(JSON.stringify(body))).status, 400);
    assert.equal(network, 0, 'hostile input must not initiate an outbound request');
    const error = await fetch(`${base}/not-a-uuid`); assert.equal(error.status, 400);
    const message = await error.text(); assert.doesNotMatch(message, /node_modules|Error:|scanner\.ts|stack/i);
    assert.equal(error.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(error.headers.get('x-powered-by'), null);
    const wrong = new FormData(); wrong.append('wrong', new Blob(['invalid']), 'bad.zip');
    assert.equal((await fetch(base, { method: 'POST', body: wrong })).status, 400);
    const valid = new FormData(); valid.append('archive', new Blob([new Uint8Array(await demoArchive())]), 'demo.zip');
    const response = await fetch(base, { method: 'POST', body: valid }); assert.equal(response.status, 201);
    const scan = await response.json(); assert.equal('sourceSnapshot' in scan, false);
    if (process.platform !== 'win32') assert.equal((await stat(join(directory, `${scan.id}.json`))).mode & 0o777, 0o600);
    const repeated = await post('{}'); assert.equal(repeated.status, 400);
    for (let i = 0; i < 3; i++) assert.equal((await post('{}')).status, 400);
    const limited = await post('{}'); assert.equal(limited.status, 429);
    assert.ok(limited.headers.get('retry-after'));
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

test('ingestion concurrency slots remain held until work completes and recover after failure', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-concurrency-'));
  const store = scanStore(directory); const original = store.create.bind(store);
  let entered = 0; let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  store.create = async (...args) => { entered++; await gate; return original(...args); };
  const server = createApp({ store, fetcher: demoFetcher, frontendDirectory: false }).listen(0, '127.0.0.1');
  await once(server, 'listening'); const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}/api/scans`;
  const send = () => fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://github.com/traceguard-demo/fixture' }) });
  try {
    const a = send(), b = send();
    const deadline = Date.now() + 5000;
    while (entered < 2 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(entered, 2); assert.equal((await send()).status, 503);
    release(); assert.equal((await a).status, 201); assert.equal((await b).status, 201);
    const invalid = new FormData(); invalid.append('archive', new Blob(['not zip']), 'bad.zip');
    assert.equal((await fetch(base, { method: 'POST', body: invalid })).status, 400);
    assert.equal((await send()).status, 201);
  } finally { release(); await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

test('GitHub archive rate limits reach the UI as HTTP 429 with Retry-After and no automatic retry', async () => {
  let calls = 0;
  const server = createApp({ fetcher: async () => { calls++; return new Response(null, { status: 429, headers: { 'Retry-After': '120' } }); }, frontendDirectory: false }).listen(0, '127.0.0.1');
  await once(server, 'listening'); const address = server.address(); assert.ok(address && typeof address !== 'string');
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/scans`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://github.com/example/repository' }) });
    assert.equal(response.status, 429); assert.equal(response.headers.get('retry-after'), '120');
    assert.match((await response.json()).error, /Retry in 120 seconds/); assert.equal(calls, 1);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});

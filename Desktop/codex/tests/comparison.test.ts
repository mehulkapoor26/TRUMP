import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import express from 'express';
import { ZipFile } from 'yazl';
import type { ScanResult, ScanComparison } from '@traceguard/shared';
import { scanStore, ScanError } from '../backend/src/scanner.js';
import { scanRouter } from '../backend/src/scans.js';
import { compareScans } from '../backend/src/comparison.js';

async function archive(side: string) {
  const zip = new ZipFile(); const chunks: Buffer[] = [];
  zip.outputStream.on('data', chunk => chunks.push(chunk));
  const end = once(zip.outputStream, 'end');
  for (const file of ['package.json', 'package-lock.json']) zip.addBuffer(await readFile(new URL(`./fixtures/rescan-${side}/${file}`, import.meta.url)), `${side}/${file}`);
  zip.end(); await end; return Buffer.concat(chunks);
}
const controlledOsv: typeof fetch = async (_input, options) => {
  const queries = JSON.parse(String(options?.body)).queries;
  return Response.json({ results: queries.map(({ package: pkg, version }: { package: { name: string }; version: string }) => {
    if (pkg.name === 'fixture-unknown' && version === '2.0.0') return { error: 'controlled outage' };
    const match = ['fixture-remaining', 'fixture-removed', 'fixture-unknown'].includes(pkg.name) || pkg.name === 'fixture-upgrade' && version === '1.0.0' || pkg.name === 'fixture-new' && version === '2.0.0';
    return match ? { vulns: [{ id: `TEST-${pkg.name}` }] } : {};
  }) });
};

test('controlled before/after repository ZIPs classify fixes, duplicates, removals, introductions and unknown checks without modification', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-compare-'));
  try {
    const fixturePaths = ['before', 'after'].flatMap(side => ['package.json', 'package-lock.json'].map(file => new URL(`./fixtures/rescan-${side}/${file}`, import.meta.url)));
    const fixtureContents = await Promise.all(fixturePaths.map(path => readFile(path, 'utf8')));
    const beforeArchive = await archive('before'), afterArchive = await archive('after');
    const store = scanStore(directory);
    const before = await store.create(beforeArchive, 'Controlled before repository');
    const after = await store.create(afterArchive, 'Controlled after repository');
    const original = JSON.stringify([before, after]);
    const result = await compareScans(before, after, controlledOsv);
    assert.deepEqual(result.counts, { resolved: 2, remaining: 1, newlyIntroduced: 1, unverifiable: 2 });
    assert.equal(result.issues.find(i => i.packageName === 'fixture-upgrade')!.status, 'resolved');
    assert.equal(result.issues.find(i => i.packageName === 'fixture-removed')!.status, 'resolved');
    const remaining = result.issues.find(i => i.packageName === 'fixture-remaining')!;
    assert.equal(remaining.before.length, 2); assert.equal(remaining.after.length, 1);
    assert.equal(result.issues.find(i => i.packageName === 'fixture-new')!.status, 'newlyIntroduced');
    assert.equal(result.issues.find(i => i.packageName === 'fixture-unknown')!.status, 'unverifiable');
    assert.equal(result.issues.find(i => i.packageName === 'fixture-upgrade')!.after[0].version, '2.0.0');
    assert.equal(JSON.stringify([before, after]), original);
    assert.deepEqual(await Promise.all(fixturePaths.map(path => readFile(path, 'utf8'))), fixtureContents);
    await store.saveComparison(result);
    assert.deepEqual(await scanStore(directory).getComparison(after.id), result);
    const incomplete = structuredClone(after); incomplete.graph!.warnings.push('missing lock context');
    const gaps = await compareScans(before, incomplete, controlledOsv);
    assert.equal(gaps.counts.resolved, 0);
    assert.ok(gaps.issues.some(i => i.packageName === '(inventory coverage)'));
    const offline = await compareScans(before, after, async () => { throw new Error('offline'); });
    assert.equal(offline.counts.resolved, 0); assert.equal(offline.counts.newlyIntroduced, 0);
    assert.ok(offline.counts.unverifiable > 0);
    const paginated = await compareScans(before, after, async (_input, options) => Response.json({ results: JSON.parse(String(options?.body)).queries.map(() => ({ vulns: [], next_page_token: 'more' })) }));
    assert.equal(paginated.counts.resolved, 0); assert.equal(paginated.counts.newlyIntroduced, 0);
    await assert.rejects(compareScans(before, before, controlledOsv), /distinct/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('HTTP workflow saves a comparison, validates identity declaration, downloads evidence, and includes it in reports', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-compare-api-'));
  const store = scanStore(directory);
  const app = express(); app.use(express.json());
  app.use('/api/scans', scanRouter(store, async (input, options) => String(input).endsWith('/querybatch') ? controlledOsv(input, options) : new Response(null, { status: 503 })));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(error instanceof ScanError ? error.status : 500).json({ error: String(error) }));
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}/api/scans`;
  async function upload(side: string): Promise<ScanResult> {
    const form = new FormData(); form.append('archive', new Blob([new Uint8Array(await archive(side))]), `${side}.zip`);
    const response = await fetch(base, { method: 'POST', body: form }); assert.equal(response.status, 201); return response.json();
  }
  try {
    const before = await upload('before'), after = await upload('after');
    const post = (body: unknown) => fetch(`${base}/${after.id}/comparison`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal((await post({ beforeScanId: before.id })).status, 400);
    const response = await post({ beforeScanId: before.id, sameProject: true });
    assert.equal(response.status, 201);
    const comparison: ScanComparison = await response.json();
    const download = await fetch(`${base}/${after.id}/comparison`);
    assert.match(download.headers.get('content-disposition')!, /attachment/);
    assert.deepEqual(await download.json(), comparison);
    const bundleResponse = await fetch(`${base}/${after.id}/reports`, { method: 'POST' });
    assert.equal(bundleResponse.status, 201);
    const bundle = await bundleResponse.json();
    assert.deepEqual(bundle.securityFindings.comparison, comparison);
    assert.deepEqual(bundle.remediationPlan.comparison, comparison);
    assert.deepEqual(await store.get(before.id), before); assert.deepEqual(await store.get(after.id), after);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

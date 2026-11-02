import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import express from 'express';
import { PDFDocument } from 'pdf-lib';
import { ZipFile } from 'yazl';
import { inspectArchive, githubRepository, downloadRepository, ScanError, scanStore, SCAN_LIMITS } from '../backend/src/scanner.js';
import { scanRouter } from '../backend/src/scans.js';
import { validateSbom } from '../backend/src/sbom.js';

async function zip(entries: [string, string, number?][]) {
  const archive = new ZipFile();
  const chunks: Buffer[] = [];
  archive.outputStream.on('data', chunk => chunks.push(chunk));
  const done = once(archive.outputStream, 'end');
  for (const [name, value, mode] of entries) archive.addBuffer(Buffer.from(value), name, { mode: mode ?? 0o100644 });
  archive.end({ comment: 'a'.repeat(40), forceZip64Format: false }); await done;
  return Buffer.concat(chunks);
}
const valid = () => zip([['project/package.json', '{"name":"fixture","dependencies":{"is-number":"7.0.0"},"scripts":{"preinstall":"touch /tmp/traceguard-never-execute"}}'], ['project/package-lock.json', '{"lockfileVersion":3,"packages":{"":{},"node_modules/is-number":{"version":"7.0.0"}}}'], ['project/packages/child/package.json', '{}'], ['project/main.js', "import isNumber from 'is-number';\nexport function handler() {\n  return isNumber(42);\n}"]]);

test('strict GitHub URL validation', () => {
  assert.equal(githubRepository('https://github.com/npm/cli.git').repo, 'cli');
  for (const value of ['http://github.com/a/b', 'https://github.com.evil/a/b', 'https://user@github.com/a/b', 'https://github.com/a/b?x=1', 'https://github.com/a/b/tree/main', 'https://127.0.0.1/a/b', 'https://github.com/a/..', null]) assert.throws(() => githubRepository(value));
});

test('archive inventories nested npm files and rejects hostile inputs', async () => {
  assert.equal((await inspectArchive(await valid())).length, 3);
  await assert.rejects(inspectArchive(Buffer.from('not zip')));
  await assert.rejects(inspectArchive(await zip([['package.json', 'broken']])));
  await assert.rejects(inspectArchive(await zip([['node_modules/package.json', '{}']])));
  await assert.rejects(inspectArchive(await zip([['package.json', '{}'], ['link', 'target', 0o120777]])));
  await assert.rejects(inspectArchive(await zip([['package.json', '{}'], ['PACKAGE.JSON', '{}']])));
  await assert.rejects(inspectArchive(await zip([['package.json', '{}'], ['bomb', 'a'.repeat(1024 * 1024)]])));
  const checksum = Buffer.from(await valid());
  const central = checksum.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  checksum.writeUInt32LE(0, central + 16);
  await assert.rejects(inspectArchive(checksum), /checksum/);
  const encrypted = Buffer.from(await valid());
  const encryptedCentral = encrypted.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  encrypted.writeUInt16LE(encrypted.readUInt16LE(encryptedCentral + 8) | 1, encryptedCentral + 8);
  await assert.rejects(inspectArchive(encrypted), /Encrypted/);
  await assert.rejects(inspectArchive(Buffer.alloc(10 * 1024 * 1024 + 1)), /10 MiB/);
  const traversal = await zip([['aa/package.json', '{}']]);
  // Equal-length mutation changes both central and local directory paths.
  await assert.rejects(inspectArchive(Buffer.from(traversal.toString('latin1').replaceAll('aa/package.json', '../package.json'), 'latin1')));
});

test('source-only repositories return explicit unsupported coverage instead of a clean result', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-unsupported-'));
  try {
    const scan = await scanStore(directory).create(await zip([['src/main.rs', 'fn main() {}']]), 'uploaded ZIP');
    assert.equal(scan.analysisStatus, 'unsupported');
    assert.equal(scan.evidence?.projects[0]?.status, 'unsupported');
    assert.equal(scan.counts?.dependencyInstances, 0);
    assert.match(scan.evidence?.projects[0]?.reasons.join(' ') ?? '', /no supported dependency manifest or lockfile/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('uncompressed oversized npm metadata is rejected before JSON parsing', async () => {
  const archive = new ZipFile(); const chunks: Buffer[] = [];
  archive.outputStream.on('data', chunk => chunks.push(chunk)); const end = once(archive.outputStream, 'end');
  archive.addBuffer(randomBytes(2 * 1024 * 1024 + 1), 'package.json', { compress: false });
  archive.end(); await end;
  await assert.rejects(inspectArchive(Buffer.concat(chunks)), error => error instanceof ScanError && error.status === 413 && /metadata file exceeds 2 MiB/.test(error.message));
});

test('GitHub retrieval uses one public HEAD archive request, bounded downloads and no redirects or credentials', async () => {
  const calls: string[] = [];
  const archive = await valid();
  const fetcher: typeof fetch = async (input, options) => {
    calls.push(String(input)); assert.equal(options?.redirect, 'error');
    assert.equal(new Headers(options?.headers).has('authorization'), false);
    return new Response(new Uint8Array(archive));
  };
  const result = await downloadRepository('https://github.com/example/project', fetcher);
  assert.equal((await inspectArchive(result.archive)).length, 3);
  assert.deepEqual(calls, ['https://codeload.github.com/example/project/zip/HEAD', `https://codeload.github.com/example/project/zip/${'a'.repeat(40)}`]);
  assert.equal(result.revision.commitSha, 'a'.repeat(40));
  await assert.rejects(downloadRepository('https://github.com/a/b', async () => new Response(null, { status: 302 })));
  await assert.rejects(downloadRepository('https://github.com/a/b', async () => new Response(null, { status: 404 })));
  await assert.rejects(downloadRepository('https://github.com/a/b', async () => new Response(null, { status: 403 })), /denied access/);
  let attempts = 0;
  await assert.rejects(downloadRepository('https://github.com/a/b', async () => { attempts++; return new Response(null, { status: 429, headers: { 'Retry-After': '120' } }); }), error => error instanceof ScanError && error.status === 429 && error.retryAfter === 120);
  assert.equal(attempts, 1, 'rate limits must not trigger alternate-host requests or retries');
  await assert.rejects(downloadRepository('https://github.com/a/b', async () => new Response(null, { status: 403, headers: { 'x-ratelimit-remaining': '0' } })), error => error instanceof ScanError && error.status === 429);
});

test('GitHub and ZIP scans of the same controlled revision have equivalent path-normalized inventory and saved OSV results', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-ingestion-equivalence-'));
  const commit = 'a'.repeat(40); const githubRoot = `equivalent-project-${commit}`;
  const projectEntries: [string, string][] = [
    ['package.json', JSON.stringify({ name: 'fixture', dependencies: { lodash: '4.17.19' }, peerDependencies: { optionalPeer: '^1' }, peerDependenciesMeta: { optionalPeer: { optional: true } } })],
    ['package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { lodash: '4.17.19' }, peerDependencies: { optionalPeer: '^1' }, peerDependenciesMeta: { optionalPeer: { optional: true } } }, 'node_modules/lodash': { version: '4.17.19' } } })],
    ['apps/child/package.json', JSON.stringify({ name: 'child', dependencies: { minimist: '0.0.8', requiredMissing: '^2' } })],
    ['apps/child/package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { minimist: '0.0.8', requiredMissing: '^2' } }, 'node_modules/minimist': { version: '0.0.8' } } })],
    ['apps/child/src/main.js', "import minimist from 'minimist';\nexport default minimist;"],
  ];
  const zipArchive = await zip(projectEntries);
  const githubArchive = await zip(projectEntries.map(([path, content]) => [`${githubRoot}/${path}`, content]));
  const store = scanStore(directory);
  const osvSnapshot = JSON.parse(await readFile('tests/fixtures/osv-ingestion-snapshot.json', 'utf8'));
  const fetcher: typeof fetch = async (input, options) => {
    const url = String(input);
    if (url.includes('/zip/')) return new Response(new Uint8Array(githubArchive));
    if (url.endsWith('/querybatch')) {
      const queries = JSON.parse(String(options?.body)).queries;
      const results = queries.map((query: { package: { name: string }; version: string }) => {
        if (query.package.name === osvSnapshot.query.package.name && query.version === osvSnapshot.query.version) return osvSnapshot.querybatch.results[0];
        return {};
      });
      return Response.json({ results });
    }
    if (url.includes('/vulns/')) return new Response(null, { status: 503 });
    if (url.startsWith('https://registry.npmjs.org/')) return Response.json({});
    throw new Error(`Unexpected integration-test request: ${url}`);
  };
  const app = express(); app.use(express.json()); app.use('/api/scans', scanRouter(store, fetcher));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(error instanceof ScanError ? error.status : 400).json({ error: String(error) }));
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}/api/scans`;
  try {
    assert.deepEqual(await (await fetch(`${base}/limits`)).json(), SCAN_LIMITS);
    const form = new FormData(); form.append('archive', new Blob([new Uint8Array(zipArchive)]), 'project.zip');
    const zipResponse = await fetch(base, { method: 'POST', body: form }); assert.equal(zipResponse.status, 201);
    const zipScan = await zipResponse.json();
    const githubResponse = await fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://github.com/example/equivalent-project' }) }); assert.equal(githubResponse.status, 201);
    const githubScan = await githubResponse.json();
    assert.deepEqual(githubScan.counts, zipScan.counts);
    assert.equal(githubScan.analysisStatus, zipScan.analysisStatus);
    assert.equal(githubScan.evidence.commitSha, commit);
    assert.equal(zipScan.evidence.revisionStatus, 'unknown');
    const canonicalInventory = (scan: any, root = '') => {
      const normalize = (value: string) => {
        const normalized = root ? (value === root ? '.' : value.startsWith(`${root}/`) ? value.slice(root.length + 1) : value) : value;
        return normalized === '.' ? '' : normalized;
      };
      const graph = scan.graph;
      const nodeKey = (node: any) => JSON.stringify([node.ecosystem, node.name, node.version ?? null, normalize(node.projectPath ?? '.'), node.installPath, node.isProject, node.direct, node.transitive]);
      return {
        nodes: graph.nodes.map(nodeKey).sort(),
        edges: graph.edges.map((edge: any) => JSON.stringify([nodeKey(graph.nodes.find((node: any) => node.id === edge.from)), nodeKey(graph.nodes.find((node: any) => node.id === edge.to)), edge.name, edge.requested, edge.kind, !!edge.optionalPeer])).sort(),
        unresolved: graph.unresolved.map((item: any) => JSON.stringify([nodeKey(graph.nodes.find((node: any) => node.id === item.from)), item.name, item.requested, item.kind, !!item.optionalPeer])).sort(),
      };
    };
    assert.deepEqual(canonicalInventory(githubScan, githubRoot), canonicalInventory(zipScan));
    assert.equal(zipScan.graph.unresolved.filter((item: { optionalPeer?: boolean }) => item.optionalPeer).length, 1);
    assert.equal(zipScan.graph.unresolved.filter((item: { optionalPeer?: boolean }) => !item.optionalPeer).length, 1);
    assert.deepEqual(githubScan.sbom.components.map((component: any) => [component.purl, component.name, component.version]).sort(), zipScan.sbom.components.map((component: any) => [component.purl, component.name, component.version]).sort());

    const checked = await Promise.all([zipScan, githubScan].map(async scan => {
      const response = await fetch(`${base}/${scan.id}/vulnerabilities`, { method: 'POST' }); assert.equal(response.status, 200);
      return response.json();
    }));
    assert.deepEqual(checked[0].counts, checked[1].counts);
    assert.deepEqual(checked[0].evidence.requests[0].results, checked[1].evidence.requests[0].results);
    const checkedCanonical = (scan: any, result: any, root = '') => result.checks.map((check: any) => {
      const node = scan.graph.nodes.find((item: any) => item.id === check.nodeId);
      const path = node.projectPath ?? '.';
      const projectPath = root ? (path === root ? '.' : path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path) : path;
      return JSON.stringify([[node.ecosystem, node.name, node.version ?? null, projectPath], check.status, check.complete, check.advisoryIds]);
    }).sort();
    assert.deepEqual(checkedCanonical(zipScan, checked[0]), checkedCanonical(githubScan, checked[1], githubRoot));
    assert.equal(checked[0].checks.find((check: { advisoryIds: string[] }) => check.advisoryIds.length)?.advisoryIds[0], 'GHSA-29mw-wpgm-hmr9');

    const bundles = [];
    for (const scan of [zipScan, githubScan]) {
      const response = await fetch(`${base}/${scan.id}/reports`, { method: 'POST' }); assert.equal(response.status, 201);
      bundles.push(await response.json());
    }
    for (const bundle of bundles) {
      assert.deepEqual(bundle.securityFindings.inventoryCounts, zipScan.counts);
      assert.deepEqual(bundle.remediationPlan.inventoryCounts, zipScan.counts);
      assert.equal(bundle.securityFindings.coverage.matched, 1);
      const pdf = await fetch(`${base}/${bundle.scanId}/reports/security-findings/pdf`);
      assert.equal(pdf.status, 200); assert.ok((await PDFDocument.load(await pdf.arrayBuffer())).getPageCount() > 0);
    }
    assert.deepEqual(bundles[0].securityFindings.inventoryCounts, bundles[1].securityFindings.inventoryCounts);
    assert.deepEqual(bundles[0].securityFindings.findings.map((finding: { package: { name: string; version?: string }; advisories: { id: string }[] }) => [finding.package.name, finding.package.version, finding.advisories.map(advisory => advisory.id)]), bundles[1].securityFindings.findings.map((finding: { package: { name: string; version?: string }; advisories: { id: string }[] }) => [finding.package.name, finding.package.version, finding.advisories.map(advisory => advisory.id)]));
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

test('multipart and GitHub HTTP scans return persisted IDs; bad uploads are rejected', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-test-'));
  const archive = await valid();
  const store = scanStore(directory);
  const app = express(); app.use(express.json());
  app.use('/api/scans', scanRouter(store, async input => String(input).includes('api.osv.dev') ? Response.json({ results: [{ vulns: [{ id: 'GHSA-test-fixture' }] }] }) : String(input).includes('api.github.com') ? Response.json({ private: false, default_branch: 'main' }) : new Response(new Uint8Array(archive))));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(error instanceof ScanError ? error.status : 400).json({ error: String(error) }));
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}/api/scans`;
  try {
    const form = new FormData(); form.append('archive', new Blob([new Uint8Array(archive)]), 'project.zip');
    const response = await fetch(base, { method: 'POST', body: form });
    assert.equal(response.status, 201);
    const result = await response.json(); assert.match(result.id, /^[a-f0-9-]{36}$/); assert.equal(result.files.length, 3);
    assert.deepEqual(await scanStore(directory).get(result.id), result);
    assert.ok(result.graph);
    validateSbom(result.sbom);
    const download = await fetch(`${base}/${result.id}/sbom`);
    assert.equal(download.status, 200);
    assert.match(download.headers.get('content-type')!, /application\/vnd\.cyclonedx\+json/);
    assert.equal(download.headers.get('content-disposition'), `attachment; filename="traceguard-${result.id}.cdx.json"`);
    assert.deepEqual(await download.json(), result.sbom);
    const advisoryResponse = await fetch(`${base}/${result.id}/vulnerabilities`, { method: 'POST' });
    assert.equal(advisoryResponse.status, 200);
    const report = await advisoryResponse.json();
    const packageNode = result.graph.nodes.find((node: { name: string }) => node.name === 'is-number');
    assert.ok(packageNode);
    assert.equal(report.checks.find((check: { nodeId: string }) => check.nodeId === packageNode.id).status, 'matched');
    assert.equal(report.source, 'OSV');
    assert.equal(result.sourceFiles.length, 1);
    assert.equal('sourceSnapshot' in result, false);
    const historyResponse = await fetch(base);
    assert.equal(historyResponse.status, 200);
    const history = await historyResponse.json();
    assert.equal(history.scans[0].id, result.id);
    assert.equal(history.scans[0].packages, 1);
    assert.equal('sourceSnapshot' in history.scans[0], false);
    assert.equal('graph' in history.scans[0], false);

    assert.match((await store.getSources(result.id))!.files[0].content, /isNumber/);
    const analysis = await fetch(`${base}/${result.id}/reachability`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entrypoints: [{ file: 'project/main.js', symbol: 'handler' }], target: { packageNodeId: packageNode.id, exportName: 'default' } }) });
    assert.equal(analysis.status, 200);
    const reachability = await analysis.json();
    assert.equal(reachability.status, 'REACHABLE', JSON.stringify(reachability));
    assert.ok(reachability.evidence.some((e: { file: string; line: number }) => e.file === 'project/main.js' && e.line === 3));
    const generated = await fetch(`${base}/${result.id}/reports`, { method: 'POST' });
    assert.equal(generated.status, 201);
    const bundle = await generated.json();
    assert.equal(bundle.securityFindings.findings[0].reachability.status, 'REACHABLE');
    assert.equal(bundle.remediationPlan.actions[0].status, 'MANUAL REVIEW');
    assert.equal(bundle.securityFindings.coverage.status, 'partial');
    assert.equal(bundle.securityFindings.packageRisk.coverage.total, 1);
    assert.deepEqual(bundle.securityFindings.packageRisk, bundle.remediationPlan.packageRisk);
    assert.deepEqual(await scanStore(directory).getReport(result.id), bundle);
    for (const [type, expected] of [['security-findings', bundle.securityFindings], ['remediation-plan', bundle.remediationPlan]] as const) {
      const json = await fetch(`${base}/${result.id}/reports/${type}/json`);
      assert.match(json.headers.get('content-disposition')!, /attachment/);
      assert.deepEqual(await json.json(), expected);
      const pdf = await fetch(`${base}/${result.id}/reports/${type}/pdf`);
      assert.equal(pdf.headers.get('content-type'), 'application/pdf');
      assert.ok((await PDFDocument.load(await pdf.arrayBuffer())).getPageCount() > 0);
    }
    assert.equal((await fetch(`${base}/${result.id}/reports/invalid/pdf`)).status, 404);
    const malformed = await fetch(`${base}/${result.id}/reachability`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entrypoints: [{ file: '../outside.js', symbol: '<module>' }], target: { packageNodeId: packageNode.id, exportName: 'default' } }) });
    assert.equal(malformed.status, 400);


    assert.deepEqual(await (await fetch(`${base}/${result.id}`)).json(), result);
    const github = await fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://github.com/example/project' }) });
    assert.equal(github.status, 201);
    const bad = new FormData(); bad.append('archive', new Blob(['bad']), 'bad.zip');
    assert.equal((await fetch(base, { method: 'POST', body: bad })).status, 400);
    assert.equal((await fetch(base, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://localhost/repo' }) })).status, 400);
    assert.equal((await fetch(`${base}/00000000-0000-4000-8000-000000000000`)).status, 404);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

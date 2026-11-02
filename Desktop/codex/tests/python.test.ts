import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import { ZipFile } from 'yazl';
import { PDFDocument } from 'pdf-lib';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { DependencyGraph, ScanResult, SourceSnapshot } from '@traceguard/shared';
import { parsePythonDependencies } from '../backend/src/python-dependencies.js';
import { pythonConstraint, pythonSatisfies, exactVersion } from '../backend/src/ecosystems.js';
import { checkVulnerabilities } from '../backend/src/vulnerabilities.js';
import { enrichVulnerabilityReport, generateReportBundle } from '../backend/src/reports.js';
import { generateSbom, validateSbom } from '../backend/src/sbom.js';
import { createApp } from '../backend/src/app.js';
import { scanStore } from '../backend/src/scanner.js';
import { analyzeReachability } from '../backend/src/reachability.js';
import { runReachability } from '../backend/src/reachability-runner.js';
import { ReachabilityPanel } from '../frontend/src/ReachabilityPanel.js';
import { compareEvidence } from '../backend/src/comparison.js';

const fixture = async (kind: string, name: string) => ({ path: name, content: await readFile(`tests/fixtures/python/${kind}/${name}`, 'utf8') });
async function poetry() { return parsePythonDependencies(await Promise.all(['pyproject.toml', 'poetry.lock'].map(name => fixture('poetry', name)))); }
async function archive(files: { path: string; content: string }[]) {
  const zip = new ZipFile(), chunks: Buffer[] = []; zip.outputStream.on('data', chunk => chunks.push(chunk)); const end = once(zip.outputStream, 'end');
  for (const file of files) zip.addBuffer(Buffer.from(file.content), file.path); zip.end(); await end; return Buffer.concat(chunks);
}
const scan = (graph: DependencyGraph): ScanResult => ({ id: '00000000-0000-4000-8000-000000000000', source: 'Controlled Python fixture', createdAt: new Date().toISOString(), status: 'completed', files: [], graph });
const pinned = () => parsePythonDependencies([{ path: 'requirements.txt', content: 'PyYAML==5.3.1' }]);
function sources(mode: 'ok' | 'yanked' | 'offline' | 'candidate-fails' | 'withdrawn' = 'ok'): typeof fetch {
  return async (input, options) => {
    const url = String(input);
    assert.ok(!url.includes('registry.npmjs.org'), 'Python must never use the npm registry');
    if (mode === 'offline') throw new Error('offline');
    if (url.includes('/vulns/')) return Response.json({ id: 'GHSA-python-fixture', ...(mode === 'withdrawn' ? { withdrawn: new Date().toISOString() } : {}), summary: 'Controlled Python advisory', aliases: ['CVE-2020-14343'], database_specific: { severity: 'CRITICAL' }, affected: [{ package: { name: 'PyYAML', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.4' }] }] }] });
    if (url.startsWith('https://pypi.org/')) { assert.equal(url, 'https://pypi.org/pypi/pyyaml/5.4/json'); return Response.json({ info: { name: 'PyYAML', version: '5.4' }, urls: [{ filename: 'PyYAML-5.4.tar.gz', yanked: mode === 'yanked', url: 'https://DO-NOT-DOWNLOAD.invalid/source.tar.gz' }] }); }
    assert.equal(url, 'https://api.osv.dev/v1/querybatch');
    const queries = JSON.parse(String(options?.body)).queries;
    for (const query of queries) assert.equal(query.package.ecosystem, 'PyPI');
    if (mode === 'candidate-fails' && queries[0].version === '5.4') throw new Error('candidate lookup failed');
    return Response.json({ results: queries.map((q: { package: { name: string }; version: string }) => q.package.name === 'pyyaml' && q.version === '5.3.1' ? { vulns: [{ id: 'GHSA-python-fixture' }] } : {}) });
  };
}

test('requirements pins use canonical PyPI names and PEP 440 versions; ranges/URLs remain UNKNOWN and relationships are not invented', async () => {
  const graph = parsePythonDependencies([await fixture('requirements', 'requirements.txt')]);
  const packages = graph.nodes.filter(n => !n.isProject); assert.equal(packages.length, 4);
  assert.equal(packages.find(n => n.name === 'pyyaml')?.version, '5.3.1'); assert.equal(packages.find(n => n.name === 'requests')?.version, undefined);
  assert.ok(packages.every(n => n.ecosystem === 'PyPI' && !n.direct && !n.transitive)); assert.equal(graph.edges.length, 0);
  let sent = 0;
  const report = await checkVulnerabilities(graph, async (_input, options) => { const queries = JSON.parse(String(options?.body)).queries; sent = queries.length; assert.ok(queries.every((q: { package: { ecosystem: string } }) => q.package.ecosystem === 'PyPI')); return Response.json({ results: queries.map(() => ({})) }); });
  assert.equal(sent, 2); assert.equal(report.checks.filter(c => c.status === 'unknown').length, 3); assert.equal(report.status, 'partial');
});

test('pyproject PEP 621 preserves direct declarations, exact pins, extras and marker coverage gaps', async () => {
  const graph = parsePythonDependencies([await fixture('pyproject', 'pyproject.toml')]);
  assert.equal(graph.nodes.find(n => n.name === 'typing-extensions')?.version, '4.0.0');
  assert.equal(graph.nodes.find(n => n.name === 'django')?.version, undefined);
  assert.ok(graph.nodes.filter(n => !n.isProject).every(n => n.direct));
  assert.ok(graph.warnings.some(w => w.includes('markers'))); assert.ok(graph.unresolved.some(d => d.name === 'django'));
});

test('Poetry locks derive direct/transitive relationships only from declared roots and unambiguous lock edges', async () => {
  const graph = await poetry(); const packages = graph.nodes.filter(n => !n.isProject);
  assert.equal(packages.length, 6); assert.equal(packages.filter(n => n.direct).length, 2); assert.equal(packages.filter(n => n.transitive).length, 4); assert.equal(graph.edges.length, 6);
  assert.deepEqual(graph.unresolved, []);
  const sbom = generateSbom(graph, scan(graph).id, new Date().toISOString()); validateSbom(sbom);
  assert.ok(sbom.components.some(c => c.purl === 'pkg:pypi/pyyaml@5.3.1')); assert.ok(sbom.components.every(c => !c.purl?.startsWith('pkg:npm/')));
});

test('Poetry 1.x/2.1 and legacy tool.poetry declarations support dev groups and safe version constraints', () => {
  for (const version of ['1.1', '2.1']) {
    const graph = parsePythonDependencies([{ path: 'pyproject.toml', content: '[tool.poetry]\nname="demo"\n[tool.poetry.dependencies]\npython=">=3.9"\nPyYAML="^5.3"\n[tool.poetry.group.test.dependencies]\npytest="~7.1"' }, { path: 'poetry.lock', content: `[[package]]\nname="PyYAML"\nversion="5.3.1"\n[[package]]\nname="pytest"\nversion="7.1.2"\n[metadata]\nlock-version="${version}"` }]);
    assert.equal(graph.nodes.filter(n => n.direct).length, 2); assert.ok(graph.edges.some(e => e.kind === 'dev'));
  }
  assert.equal(pythonConstraint('~1.2'), '>=1.2,<1.3'); assert.equal(pythonSatisfies('1.3.0', '~1.2'), false);
  assert.equal(pythonSatisfies('0.3.0', '^0.2.1'), false); assert.equal(pythonSatisfies('1.2.8', '1.2.*'), true);
  assert.ok(exactVersion('PyPI', '1!2.0.post1')); assert.ok(exactVersion('PyPI', '3.1.0rc1'));
});

test('malformed TOML/locks reject; ambiguous lock versions and missing roots do not invent relationships', () => {
  assert.throws(() => parsePythonDependencies([{ path: 'pyproject.toml', content: '[project\n' }]), /TOML/);
  assert.throws(() => parsePythonDependencies([{ path: 'poetry.lock', content: '[metadata]\nlock-version="9.0"' }]), /Unsupported/);
  const lock = '[[package]]\nname="x"\nversion="1.0"\n[[package]]\nname="x"\nversion="2.0"\n[metadata]\nlock-version="2.0"';
  const graph = parsePythonDependencies([{ path: 'pyproject.toml', content: '[project]\ndependencies=["x>=1"]' }, { path: 'poetry.lock', content: lock }]);
  assert.equal(graph.edges.length, 0); assert.equal(graph.unresolved.length, 1);
  const alone = parsePythonDependencies([{ path: 'poetry.lock', content: lock }]); assert.ok(alone.nodes.every(n => !n.direct && !n.transitive));
});

test('includes, indexes, VCS dependencies and external Poetry sources are never fetched or queried as public PyPI', async () => {
  const graph = parsePythonDependencies([{ path: 'requirements.txt', content: '--index-url https://private.invalid/simple\nPyYAML==5.3.1\n-r ../../secret.txt\n-e git+https://example.invalid/repo.git\nhttps://example.invalid/a.whl' }]);
  const report = await checkVulnerabilities(graph, async () => { assert.fail('Custom index names must not be queried'); });
  assert.equal(report.status, 'unavailable'); assert.equal(graph.nodes.filter(n => !n.isProject).length, 1);
  const privateGraph = parsePythonDependencies([{ path: 'poetry.lock', content: '[[package]]\nname="PyYAML"\nversion="5.3.1"\n[package.source]\ntype="git"\nurl="https://private.invalid/repo"\n[metadata]\nlock-version="2.0"' }]);
  await checkVulnerabilities(privateGraph, async () => { assert.fail('External source is not PyPI'); });
  const configured = parsePythonDependencies([{ path: 'pyproject.toml', content: '[project]\ndependencies=["PyYAML==5.3.1"]\n[[tool.poetry.source]]\nname="private"\nurl="https://private.invalid/simple"' }]);
  await checkVulnerabilities(configured, async () => { assert.fail('Private Poetry source is not public PyPI'); });
  const local = parsePythonDependencies([{ path: 'requirements.txt', content: 'example==1.0+custom' }]); assert.equal(local.nodes.find(n => n.name === 'example')?.version, '1.0+custom');
  await checkVulnerabilities(local, async () => { assert.fail('Local build identity is unverified'); });
});

test('npm/PyPI identities remain separate in OSV batching, details and before/after comparison', async () => {
  const graph = pinned(); const python = graph.nodes.find(n => !n.isProject)!;
  graph.nodes.push({ ...python, id: 'npm-pyyaml', ecosystem: 'npm', version: '5.3.1' });
  const report = await checkVulnerabilities(graph, async (_url, options) => { const queries = JSON.parse(String(options?.body)).queries; assert.equal(queries.length, 2); assert.deepEqual(new Set(queries.map((q: { package: { ecosystem: string } }) => q.package.ecosystem)), new Set(['npm', 'PyPI'])); return Response.json({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-shared' }] })) }); });
  const enriched = await enrichVulnerabilityReport(graph, report, async () => Response.json({ id: 'GHSA-shared', affected: [{ package: { name: 'PyYAML', ecosystem: 'PyPI' } }] }));
  assert.equal(enriched.advisories!['["GHSA-shared","pyyaml","PyPI"]'].verification, 'verified');
  assert.equal(enriched.advisories!['["GHSA-shared","pyyaml"]'].verification, 'package-mismatch');
  const before = scan({ ...graph, warnings: [], unresolved: [] }); const after = { ...before, id: 'after' };
  const comparison = compareEvidence(before, after, report, report); assert.equal(comparison.counts.remaining, 2);
});

test('Python reports verify non-yanked PyPI fixes against fresh OSV and leave unsafe/unverified candidates manual', async () => {
  const result = await generateReportBundle(scan(pinned()), [], sources());
  assert.equal(result.remediationPlan.actions[0].suggestedVersion, '5.4'); assert.equal(result.remediationPlan.actions[0].verification.compatibility, 'NOT TESTED');
  assert.equal(result.securityFindings.findings[0].reachability.status, 'UNKNOWN'); assert.equal(result.securityFindings.findings[0].advisories[0].severityLabel, 'CRITICAL');
  assert.ok(result.remediationPlan.actions[0].steps.every(step => !step.includes('package.json') && !step.includes('override')));
  assert.equal(result.securityFindings.packageRisk!.coverage.skipped, 1);
  const graph = pinned(); const target = graph.nodes.find(n => !n.isProject)!;
  const fakeReachable = { ...analyzeReachability(null, graph, { entrypoints: [], target: { packageNodeId: target.id, exportName: '' } }), status: 'REACHABLE' as const };
  const stale = await generateReportBundle(scan(graph), [fakeReachable], sources()); assert.equal(stale.securityFindings.findings[0].reachability.status, 'UNKNOWN');
  for (const mode of ['yanked', 'candidate-fails', 'withdrawn'] as const) {
    const bundle = await generateReportBundle(scan(pinned()), [], sources(mode)); assert.equal(bundle.remediationPlan.actions[0].status, 'MANUAL REVIEW'); assert.equal(bundle.remediationPlan.actions[0].suggestedVersion, undefined);
  }
  const offline = await generateReportBundle(scan(pinned()), [], sources('offline')); assert.equal(offline.securityFindings.coverage.status, 'unavailable');
});

test('Python reachability is UNKNOWN in API engine, runner and UI; Python source cannot enter JS analysis', async () => {
  const graph = pinned(); const node = graph.nodes.find(n => !n.isProject)!;
  const source: SourceSnapshot = { files: [{ path: 'app.py', content: 'raise RuntimeError("DO NOT EXECUTE")' }], skipped: [] };
  const request = { entrypoints: [{ file: 'app.py', symbol: '<module>' }], target: { packageNodeId: node.id, exportName: 'load' } };
  assert.equal(analyzeReachability(source, graph, request).status, 'UNKNOWN'); assert.equal((await runReachability(source, graph, request)).coverage.functionsVisited, 0);
  const html = renderToStaticMarkup(createElement(ReachabilityPanel, { scanId: 'id', node, sourceFiles: [], advisoryIds: [] })); assert.match(html, /UNKNOWN/); assert.match(html, /JavaScript AST/); assert.doesNotMatch(html, /<form/);
});

test('Python-only ZIP to persisted scan/SBOM/OSV/reachability and both PDF/JSON reports uses the existing real HTTP pipeline', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-python-')); const store = scanStore(directory);
  const server = createApp({ store, fetcher: sources(), frontendDirectory: false }).listen(0, '127.0.0.1'); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string'); const base = `http://127.0.0.1:${address.port}/api/scans`;
  try {
    const zip = await archive([await fixture('requirements', 'requirements.txt'), await fixture('requirements', 'app.py')]);
    const form = new FormData(); form.append('archive', new Blob([new Uint8Array(zip)]), 'python.zip');
    const response = await fetch(base, { method: 'POST', body: form }); assert.equal(response.status, 201); const result = await response.json();
    assert.deepEqual(result.ecosystems, ['PyPI']); assert.equal(result.sourceFiles[0].path, 'app.py'); assert.equal('sourceSnapshot' in result, false); validateSbom(result.sbom);
    const restarted = scanStore(directory); assert.deepEqual(await restarted.get(result.id), result);
    const checked = await fetch(`${base}/${result.id}/vulnerabilities`, { method: 'POST' }); assert.equal(checked.status, 200); const report = await checked.json(); assert.ok(report.checks.some((c: { status: string }) => c.status === 'matched'));
    const target = result.graph.nodes.find((n: { name: string }) => n.name === 'pyyaml');
    const reach = await fetch(`${base}/${result.id}/reachability`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entrypoints: [{ file: 'app.py', symbol: '<module>' }], target: { packageNodeId: target.id, exportName: 'load' } }) }); assert.equal((await reach.json()).status, 'UNKNOWN');
    const generated = await fetch(`${base}/${result.id}/reports`, { method: 'POST' }); assert.equal(generated.status, 201);
    for (const type of ['security-findings', 'remediation-plan']) for (const format of ['json', 'pdf']) {
      const download = await fetch(`${base}/${result.id}/reports/${type}/${format}`); assert.equal(download.status, 200);
      if (format === 'pdf') assert.ok((await PDFDocument.load(await download.arrayBuffer())).getPageCount() > 0); else assert.equal((await download.json()).scan.id, result.id);
    }
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

test('mixed npm/Python archives auto-detect both ecosystems without changing npm resolution', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'traceguard-mixed-'));
  try {
    const store = scanStore(directory);
    const zip = await archive([{ path: 'requirements.txt', content: 'PyYAML==5.3.1' }, { path: 'package.json', content: '{"name":"mixed","dependencies":{"lodash":"4.17.20"}}' }, { path: 'package-lock.json', content: '{"lockfileVersion":3,"packages":{"":{"name":"mixed","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}' }]);
    const result = await store.create(zip, 'Mixed controlled archive');
    assert.deepEqual(result.ecosystems, ['npm', 'PyPI']);
    assert.equal(result.graph!.nodes.find(n => n.name === 'lodash')?.direct, true);
    assert.equal(result.graph!.nodes.find(n => n.name === 'pyyaml')?.direct, false);
    assert.ok(result.sbom!.components.some(c => c.purl === 'pkg:npm/lodash@4.17.20'));
    assert.ok(result.sbom!.components.some(c => c.purl === 'pkg:pypi/pyyaml@5.3.1'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

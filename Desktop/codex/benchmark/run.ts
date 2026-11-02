import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { ZipFile } from 'yazl';
import type { DependencyGraph, Ecosystem, VulnerabilityReport } from '../shared/src/index.js';
import { scanStore } from '../backend/src/scanner.js';
import { checkVulnerabilities } from '../backend/src/vulnerabilities.js';

type Query = { ecosystem: Ecosystem; name: string; version: string; responseIndex?: number; responseFile?: string };
type Expected = { id: string; fixture: string; expectedScanStatus: string; osvMode?: 'failure' | 'incomplete'; dependencies: { ecosystem: Ecosystem; name: string; version: string | null; relationship: 'direct' | 'transitive' | 'unresolved' | 'unknown' }[]; advisories: { ecosystem: Ecosystem; name: string; version: string; label: string; expectedStatus: string; expectedAdvisoryIds: string[] }[] };
const dataset = resolve(import.meta.dirname);
const expected = JSON.parse(await readFile(join(dataset, 'expected-results.json'), 'utf8')) as { snapshotId: string; cases: Expected[] };
const manifest = JSON.parse(await readFile(join(dataset, 'snapshots/manifest.json'), 'utf8')) as { snapshotId: string; responseFile: string; responseSha256: string; additionalResponseHashes: Record<string, string>; queries: Query[] };
assert.equal(expected.snapshotId, manifest.snapshotId, 'expected results must identify their advisory snapshot');

const snapshotMap = new Map<string, unknown>();
const batchBytes = await readFile(join(dataset, 'snapshots', manifest.responseFile));
assert.equal(createHash('sha256').update(batchBytes).digest('hex'), manifest.responseSha256, 'frozen OSV batch response hash mismatch');
const batch = JSON.parse(batchBytes.toString('utf8')) as { results: unknown[] };
for (const query of manifest.queries) {
  let response: unknown;
  if (query.responseFile) {
    const bytes = await readFile(join(dataset, 'snapshots', query.responseFile));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), manifest.additionalResponseHashes[query.responseFile], `frozen OSV response hash mismatch: ${query.responseFile}`);
    response = JSON.parse(bytes.toString('utf8'));
  } else response = batch.results[query.responseIndex!];
  snapshotMap.set(JSON.stringify([query.ecosystem, query.name.toLowerCase(), query.version]), response);
}

async function zipFixture(fixture: string): Promise<Buffer> {
  const folder = join(dataset, fixture); const zip = new ZipFile(); const chunks: Buffer[] = [];
  zip.outputStream.on('data', chunk => chunks.push(chunk)); const ended = once(zip.outputStream, 'end');
  async function visit(directory: string) {
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const file = join(directory, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile()) zip.addBuffer(await readFile(file), relative(folder, file).split('\\').join('/'));
    }
  }
  await visit(folder); zip.end(); await ended; return Buffer.concat(chunks);
}

const live = process.argv.includes('--live');
const fetcher: typeof fetch = live ? fetch : async (_input, init) => {
  const queries = JSON.parse(String(init?.body)).queries as { package: { ecosystem: Ecosystem; name: string }; version: string }[];
  const results = queries.map(query => snapshotMap.get(JSON.stringify([query.package.ecosystem, query.package.name.toLowerCase(), query.version])));
  if (results.some(result => result === undefined)) throw new Error('Package/version is missing from the frozen OSV snapshot.');
  return Response.json({ results });
};

const temp = await mkdtemp(join(tmpdir(), 'traceguard-benchmark-'));
const extractionMismatches: unknown[] = []; const advisoryMismatches: unknown[] = [];
const observed = new Map<string, { status: string; ids: string[] }>();
const caseResults: unknown[] = [];
try {
  const store = scanStore(temp);
  for (const benchmarkCase of expected.cases) {
    let scan;
    try { scan = await store.create(await zipFixture(benchmarkCase.fixture), `benchmark:${benchmarkCase.id}`); }
    catch (error) {
      if (benchmarkCase.expectedScanStatus !== 'failed') extractionMismatches.push({ case: benchmarkCase.id, expected: benchmarkCase.expectedScanStatus, actual: 'failed', error: error instanceof Error ? error.message : String(error) });
      caseResults.push({ id: benchmarkCase.id, scanStatus: 'failed', error: error instanceof Error ? error.message : String(error) }); continue;
    }
    if (scan.analysisStatus !== benchmarkCase.expectedScanStatus) extractionMismatches.push({ case: benchmarkCase.id, field: 'analysisStatus', expected: benchmarkCase.expectedScanStatus, actual: scan.analysisStatus });
    const graph = scan.graph as DependencyGraph;
    for (const item of benchmarkCase.dependencies) {
      if (item.relationship === 'unresolved') {
        if (!graph.unresolved.some(declaration => declaration.name.toLowerCase() === item.name.toLowerCase())) extractionMismatches.push({ case: benchmarkCase.id, expectedPackage: item, actual: 'unresolved declaration missing' });
        continue;
      }
      const found = graph.nodes.filter(node => !node.isProject && (node.ecosystem ?? 'npm') === item.ecosystem && node.name.toLowerCase() === item.name.toLowerCase() && (node.version ?? null) === item.version);
      if (!found.length) extractionMismatches.push({ case: benchmarkCase.id, expectedPackage: item, actual: 'missing' });
      else if (item.relationship !== 'unknown') {
        const ok = found.some(node => item.relationship === 'direct' ? node.direct : item.relationship === 'transitive' ? node.transitive && !node.direct : item.relationship === 'unresolved' ? !node.version : true);
        if (!ok) extractionMismatches.push({ case: benchmarkCase.id, expectedPackage: item, actual: found.map(node => ({ version: node.version, direct: node.direct, transitive: node.transitive })) });
      }
    }
    let report: VulnerabilityReport | undefined;
    if (benchmarkCase.osvMode === 'failure') report = await checkVulnerabilities(graph, async () => { throw new Error('benchmark transport outage'); });
    else if (benchmarkCase.osvMode === 'incomplete') report = await checkVulnerabilities(graph, async () => Response.json({ results: [{ vulns: [], next_page_token: 'repeat-token' }] }));
    else if (benchmarkCase.advisories.length) report = await checkVulnerabilities(graph, fetcher);
    for (const item of benchmarkCase.advisories) {
      const nodes = graph.nodes.filter(node => !node.isProject && (node.ecosystem ?? 'npm') === item.ecosystem && node.name.toLowerCase() === item.name.toLowerCase() && node.version === item.version);
      const checks = nodes.flatMap(node => report?.checks.filter(check => check.nodeId === node.id) ?? []);
      const actualIds = [...new Set(checks.flatMap(check => check.advisoryIds))].sort();
      const actualStatus = checks.some(check => check.status === 'matched') ? 'matched' : checks.length && checks.every(check => check.status === 'no-known' && check.complete) ? 'no-known' : 'unknown';
      if (actualStatus !== item.expectedStatus || JSON.stringify(actualIds) !== JSON.stringify([...item.expectedAdvisoryIds].sort())) advisoryMismatches.push({ case: benchmarkCase.id, package: `${item.ecosystem}/${item.name}@${item.version}`, expected: { status: item.expectedStatus, advisoryIds: [...item.expectedAdvisoryIds].sort() }, actual: { status: actualStatus, advisoryIds: actualIds } });
      if (item.label === 'osv-match' || item.label === 'no-osv-match-at-snapshot') observed.set(JSON.stringify([item.ecosystem, item.name.toLowerCase(), item.version]), { status: actualStatus, ids: actualIds });
    }
    caseResults.push({ id: benchmarkCase.id, scanStatus: scan.analysisStatus, dependencyInstances: graph.nodes.filter(node => !node.isProject).length, counts: scan.counts, advisoryStatus: report?.status, warnings: report?.warnings });
  }
} finally { await rm(temp, { recursive: true, force: true }); }

let tp = 0, fp = 0, fn = 0, tn = 0, unscoredUnknown = 0;
const labelled = new Map<string, boolean>();
for (const benchmarkCase of expected.cases) for (const item of benchmarkCase.advisories) {
  if (item.label === 'osv-match' || item.label === 'no-osv-match-at-snapshot') labelled.set(JSON.stringify([item.ecosystem, item.name.toLowerCase(), item.version]), item.label === 'osv-match');
}
for (const [key, isVulnerable] of labelled) {
  const status = observed.get(key)?.status;
  if (status !== 'matched' && status !== 'no-known') { unscoredUnknown++; continue; }
  const predicted = status === 'matched';
  if (isVulnerable && predicted) tp++; else if (isVulnerable) fn++; else if (predicted) fp++; else tn++;
}
const ratio = (numerator: number, denominator: number) => denominator ? Number((numerator / denominator).toFixed(4)) : null;
const output = {
  mode: live ? 'live-osv' : 'frozen-osv-snapshot', snapshotId: manifest.snapshotId,
  evaluationScope: live ? 'Frozen labels compared with live responses; differences are database drift as well as scanner behavior and are not a historical-snapshot accuracy score.' : 'Same production parser and OSV matcher with saved OSV response bytes; no submitted project code is executed.',
  caseCount: expected.cases.length, labeledPackageVersionPairs: labelled.size,
  vulnerabilityMetrics: { TP: tp, FP: fp, FN: fn, TN: tn, unscoredUnknown, precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn), f1: ratio(2 * tp, 2 * tp + fp + fn) },
  extractionMismatchCount: extractionMismatches.length, extractionMismatches,
  advisoryMismatchCount: advisoryMismatches.length, advisoryMismatches, cases: caseResults,
};
console.log(JSON.stringify(output, null, 2));
if (!live && (extractionMismatches.length || advisoryMismatches.length)) process.exitCode = 1;

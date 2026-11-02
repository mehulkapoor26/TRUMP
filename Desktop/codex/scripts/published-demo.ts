import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import type { ScanResult, VulnerabilityReport, ReachabilityReport, ReportBundle } from '@traceguard/shared';
import { validateSbom } from '../backend/src/sbom.js';
import { publishedArchive } from './published-fixture.js';

const base = process.env.TRACEGUARD_URL ?? 'http://127.0.0.1:5173';
const directory = resolve('artifacts/published-demo'); await mkdir(directory, { recursive: true });
const incomplete: string[] = [];
const evidence: Record<string, unknown> = { mode: 'CONTROLLED INPUT + LIVE GitHub/OSV/npm. No mocked advisories. No downloaded code executed.', base, verifiedAt: new Date().toISOString(), incomplete };
const save = (name: string, value: unknown) => writeFile(join(directory, name), JSON.stringify(value, null, 2));
async function api(path: string, init: RequestInit = {}, status = 200) {
  const response = await fetch(`${base}${path}`, { ...init, signal: AbortSignal.timeout(120_000) });
  const value = await response.json(); assert.equal(response.status, status, JSON.stringify(value)); return value;
}
const post = (value?: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });

try {
  await api('/api/health');
  console.log('Checking real public GitHub repository archive…');
  try {
    const repository: ScanResult = await api('/api/scans', post({ url: 'https://github.com/expressjs/serve-static' }), 201);
    assert.ok(repository.files.some(file => file.kind === 'manifest'));
    evidence.github = { status: 'passed', scanId: repository.id, source: repository.source, metadataFiles: repository.files.length, inventoryWarnings: repository.graph?.warnings, note: 'Upstream library may omit a lockfile; missing resolved versions remain explicit.' };
    await save('github-scan.json', repository);
  } catch (error) { incomplete.push(`GitHub ingestion: ${error instanceof Error ? error.message : String(error)}`); }

  console.log('Uploading controlled npm project with npm-generated lockfile…');
  const archive = await publishedArchive(); await writeFile(join(directory, 'project.zip'), archive);
  evidence.zipSha256 = createHash('sha256').update(archive).digest('hex');
  const form = new FormData(); form.append('archive', new Blob([new Uint8Array(archive)]), 'traceguard-published-vulnerabilities.zip');
  const scan: ScanResult = await api('/api/scans', { method: 'POST', body: form }, 201);
  const graph = scan.graph!; const libraries = graph.nodes.filter(n => !n.isProject);
  assert.equal(libraries.length, 8); assert.equal(libraries.filter(n => n.direct).length, 4); assert.equal(libraries.filter(n => n.transitive).length, 4);
  assert.equal(graph.unresolved.length, 0); assert.deepEqual(graph.warnings, []);
  evidence.scanId = scan.id; evidence.dashboard = `${base}/#/scans/${scan.id}/overview`;
  evidence.findings = `${base}/#/scans/${scan.id}/findings`;
  evidence.inventory = { packages: libraries.length, direct: libraries.filter(n => n.direct).length, transitive: libraries.filter(n => n.transitive).length, relationships: graph.edges.length };
  await save('scan.json', scan);
  const sbom = await api(`/api/scans/${scan.id}/sbom`); validateSbom(sbom); await save('sbom.cdx.json', sbom);

  console.log('Checking live OSV matches, CVE aliases and source severity…');
  const advisory: VulnerabilityReport = await api(`/api/scans/${scan.id}/vulnerabilities`, post());
  assert.equal(advisory.status, 'complete', JSON.stringify(advisory.warnings));
  const lodash = libraries.find(n => n.name === 'lodash')!;
  const minimist = libraries.find(n => n.name === 'minimist')!;
  for (const node of [lodash, minimist]) assert.equal(advisory.checks.find(c => c.nodeId === node.id)?.status, 'matched');
  const details = Object.values(advisory.advisories ?? {});
  const cves = [...new Set(details.filter(d => d.verification === 'verified').flatMap(d => d.aliases.filter(a => a.startsWith('CVE-'))))];
  assert.ok(cves.length, 'Live CVE aliases should be available for this fixture');
  assert.ok(details.some(d => d.verification === 'verified' && (d.severityLabel || d.severity.length)), 'Live severity evidence should be available');
  evidence.advisories = { matchedInstances: advisory.checks.filter(c => c.status === 'matched').length, noKnownMatch: advisory.checks.filter(c => c.status === 'no-known').length, unknownLibraries: advisory.checks.filter(c => libraries.some(n => n.id === c.nodeId) && c.status === 'unknown').length, ids: [...new Set(advisory.checks.flatMap(c => c.advisoryIds))], cves, warnings: advisory.warnings };
  await save('vulnerabilities.json', advisory);

  console.log('Checking UNKNOWN, scoped NOT REACHABLE and REACHABLE static results…');
  const lodashAdvisoryId = advisory.checks.find(check => check.nodeId === lodash.id)?.advisoryIds[0];
  const analyze = (symbol: string, exportName: string) => api(`/api/scans/${scan.id}/reachability`, post({ entrypoints: [{ file: 'src/entry.js', symbol }], target: { packageNodeId: lodash.id, exportName, ...(lodashAdvisoryId ? { advisoryId: lodashAdvisoryId } : {}) } })) as Promise<ReachabilityReport>;
  const unknown = await analyze('handler', ''); assert.equal(unknown.status, 'UNKNOWN');
  const unused = await analyze('<module>', 'template'); assert.equal(unused.status, 'NOT REACHABLE');
  const reachable = await analyze('handler', 'template'); assert.equal(reachable.status, 'REACHABLE');
  await save('reachability.json', { unknown, unused, reachable });
  evidence.reachability = { noMapping: unknown.status, moduleOnly: unused.status, declaredHandler: reachable.status, boundary: 'User-declared lodash.template export; potential static path, not runtime exploitability.' };

  console.log('Generating real security reports and verifying all four downloads…');
  const bundle: ReportBundle = await api(`/api/scans/${scan.id}/reports`, post(), 201);
  assert.ok(bundle.securityFindings.findings.length >= 2);
  assert.equal(bundle.securityFindings.findings.find(f => f.package.id === lodash.id)?.reachability.status, 'REACHABLE');
  assert.deepEqual(await api(`/api/scans/${scan.id}/reports`), bundle);
  for (const type of ['security-findings', 'remediation-plan']) for (const format of ['json', 'pdf']) {
    const response = await fetch(`${base}/api/scans/${scan.id}/reports/${type}/${format}`);
    assert.equal(response.status, 200); assert.match(response.headers.get('content-disposition')!, /attachment/);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (format === 'pdf') assert.ok((await PDFDocument.load(bytes)).getPageCount() > 0);
    else assert.equal(JSON.parse(bytes.toString()).scan.id, scan.id);
    await writeFile(join(directory, `${type}.${format}`), bytes);
  }
  evidence.reports = { status: 'passed', coverage: bundle.securityFindings.coverage, actions: bundle.remediationPlan.actions.map(a => ({ package: a.packageName, status: a.status, suggestedVersion: a.suggestedVersion, compatibility: a.verification.compatibility })) };

  console.log('Verifying missing-lockfile coverage and invalid ZIP rejection…');
  const noLock = new FormData(); noLock.append('archive', new Blob([new Uint8Array(await publishedArchive(false))]), 'missing-lock.zip');
  const missing: ScanResult = await api('/api/scans', { method: 'POST', body: noLock }, 201);
  assert.equal(missing.graph!.nodes.filter(n => !n.isProject).length, 0); assert.equal(missing.graph!.unresolved.length, 4);
  const missingReport: VulnerabilityReport = await api(`/api/scans/${missing.id}/vulnerabilities`, post()); assert.equal(missingReport.status, 'unavailable');
  const invalid = new FormData(); invalid.append('archive', new Blob(['not a zip']), 'invalid.zip');
  await api('/api/scans', { method: 'POST', body: invalid }, 400);
  evidence.invalidInputs = { missingLock: 'accepted as incomplete with 4 unresolved dependencies; advisory coverage unavailable', invalidZip: 'rejected with HTTP 400' };
} catch (error) { incomplete.push(error instanceof Error ? error.message : String(error)); }

await save('summary.json', evidence);
console.log(JSON.stringify(evidence, null, 2));
if (incomplete.length) process.exitCode = 1;

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import { ZipFile } from 'yazl';
import { PDFDocument } from 'pdf-lib';
import { validateSbom } from '../backend/src/sbom.js';
import type { ScanResult, ReportBundle, VulnerabilityReport } from '@traceguard/shared';

const base = process.env.TRACEGUARD_URL ?? 'http://127.0.0.1:5173';
const directory = resolve('artifacts/python-demo'); await mkdir(directory, { recursive: true });
const save = (name: string, value: unknown) => writeFile(join(directory, name), JSON.stringify(value, null, 2));
const post = (body?: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
async function api(path: string, init: RequestInit = {}, status = 200) { const response = await fetch(`${base}${path}`, { ...init, signal: AbortSignal.timeout(120_000) }); const data = await response.json(); assert.equal(response.status, status, JSON.stringify(data)); return data; }
const summary: Record<string, unknown> = { mode: 'CONTROLLED PYTHON METADATA + LIVE OSV/PyPI; no uploaded code installed or executed', verifiedAt: new Date().toISOString(), incomplete: [] };
try {
  await api('/api/health');
  const zip = new ZipFile(); const chunks: Buffer[] = []; zip.outputStream.on('data', chunk => chunks.push(chunk)); const end = once(zip.outputStream, 'end');
  for (const name of ['pyproject.toml', 'poetry.lock', 'app.py']) zip.addBuffer(await readFile(`tests/fixtures/python/poetry/${name}`), name, { mtime: new Date('2020-01-01T00:00:00Z') });
  zip.end(); await end; const buffer = Buffer.concat(chunks); await writeFile(join(directory, 'python-project.zip'), buffer);
  const form = new FormData(); form.append('archive', new Blob([new Uint8Array(buffer)]), 'python-project.zip');
  console.log('Uploading controlled Python Poetry snapshot…');
  const scan: ScanResult = await api('/api/scans', { method: 'POST', body: form }, 201); await save('scan.json', scan);
  assert.deepEqual(scan.ecosystems, ['PyPI']); const nodes = scan.graph!.nodes.filter(n => !n.isProject); assert.equal(nodes.length, 6);
  summary.scanId = scan.id; summary.dashboard = `${base}/#/scans/${scan.id}/overview`; summary.findings = `${base}/#/scans/${scan.id}/findings`;
  summary.inventory = { packages: nodes.length, direct: nodes.filter(n => n.direct).length, transitive: nodes.filter(n => n.transitive).length, relationships: scan.graph!.edges.length, warnings: scan.graph!.warnings };
  const sbom = await api(`/api/scans/${scan.id}/sbom`); validateSbom(sbom); await save('sbom.cdx.json', sbom);
  console.log('Checking real OSV PyPI matches and advisory details…');
  const checked: VulnerabilityReport = await api(`/api/scans/${scan.id}/vulnerabilities`, post()); await save('vulnerabilities.json', checked);
  const pyyaml = nodes.find(n => n.name === 'pyyaml')!; assert.equal(checked.checks.find(c => c.nodeId === pyyaml.id)?.status, 'matched');
  const details = Object.values(checked.advisories ?? {}); assert.ok(details.some(d => d.verification === 'verified' && d.aliases.includes('CVE-2020-14343')));
  const unknown = await api(`/api/scans/${scan.id}/reachability`, post({ entrypoints: [{ file: 'app.py', symbol: '<module>' }], target: { packageNodeId: pyyaml.id, exportName: 'load' } })); assert.equal(unknown.status, 'UNKNOWN'); assert.equal(unknown.coverage.functionsVisited, 0); await save('reachability.json', unknown);
  console.log('Verifying PyPI fix candidates and downloading both report types…');
  const bundle: ReportBundle = await api(`/api/scans/${scan.id}/reports`, post(), 201);
  assert.ok(bundle.securityFindings.findings.length > 0); assert.ok(bundle.securityFindings.findings.every(f => f.reachability.status === 'UNKNOWN'));
  for (const type of ['security-findings', 'remediation-plan']) for (const format of ['json', 'pdf']) {
    const response = await fetch(`${base}/api/scans/${scan.id}/reports/${type}/${format}`); assert.equal(response.status, 200); const bytes = Buffer.from(await response.arrayBuffer());
    if (format === 'pdf') assert.ok((await PDFDocument.load(bytes)).getPageCount() > 0); else assert.equal(JSON.parse(bytes.toString()).scan.id, scan.id);
    await writeFile(join(directory, `${type}.${format}`), bytes);
  }
  summary.advisories = { matchedInstances: checked.checks.filter(c => c.status === 'matched').length, ids: [...new Set(checked.checks.flatMap(c => c.advisoryIds))], cves: [...new Set(details.flatMap(d => d.aliases.filter(a => a.startsWith('CVE-'))))], coverage: checked.status };
  summary.actions = bundle.remediationPlan.actions.map(a => ({ package: a.packageName, status: a.status, candidate: a.suggestedVersion, compatibility: a.verification.compatibility }));
  summary.reachability = 'UNKNOWN: Python analysis is not implemented';
} catch (error) { (summary.incomplete as string[]).push(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
await save('summary.json', summary); console.log(JSON.stringify(summary, null, 2));

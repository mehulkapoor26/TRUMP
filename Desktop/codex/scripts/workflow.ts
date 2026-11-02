import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PDFDocument } from 'pdf-lib';
import type { ScanResult, ReportBundle } from '@traceguard/shared';
import { demoArchive, demoAdvisory } from './demo-fixture.js';

export async function verifyWorkflow(base: string, directory: string, live = false) {
  await mkdir(directory, { recursive: true });
  async function json(path: string, init?: RequestInit, status = 200) {
    const response = await fetch(`${base}/api/scans${path}`, init);
    const value = await response.json(); assert.equal(response.status, status, JSON.stringify(value)); return value;
  }
  const post = (value?: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
  const repository = live ? 'https://github.com/expressjs/serve-static' : 'https://github.com/traceguard-demo/fixture';
  let repositoryScan: ScanResult | undefined;
  const incomplete: string[] = [];
  try {
    const scanned: ScanResult = await json('', post({ url: repository }), 201);
    repositoryScan = scanned;
    const repositoryBundle = await json(`/${scanned.id}/reports`, post(), 201);
    await writeFile(join(directory, 'repository-report.json'), JSON.stringify(repositoryBundle, null, 2));
  } catch (error) {
    if (!live) throw error;
    incomplete.push(`Live repository-to-report check failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const zip = await demoArchive(); await writeFile(join(directory, 'before.zip'), zip);
  const form = new FormData(); form.append('archive', new Blob([new Uint8Array(zip)]), 'before.zip');
  const before: ScanResult = await json('', { method: 'POST', body: form }, 201);
  const target = before.graph!.nodes.find(n => !n.isProject && n.name === 'lodash')!; assert.ok(target);
  const advisory = await json(`/${before.id}/vulnerabilities`, post());
  assert.equal(advisory.checks.find((c: { nodeId: string }) => c.nodeId === target.id).status, 'matched');
  if (!live) assert.ok(advisory.checks.some((c: { advisoryIds: string[] }) => c.advisoryIds.includes(demoAdvisory)));
  const reachability = await json(`/${before.id}/reachability`, post({ entrypoints: [{ file: 'src/entry.js', symbol: 'handler' }], target: { packageNodeId: target.id, exportName: 'default' } }));
  assert.equal(reachability.status, 'REACHABLE');
  const bundle: ReportBundle = await json(`/${before.id}/reports`, post(), 201);
  assert.ok(bundle.securityFindings.findings.length > 0);
  assert.equal(bundle.securityFindings.findings[0].reachability.status, 'REACHABLE');
  if (!live) assert.equal(bundle.remediationPlan.actions[0].status, 'VERIFIED CANDIDATE');
  assert.deepEqual(await json(`/${before.id}/reports`), bundle);
  for (const type of ['security-findings', 'remediation-plan']) for (const format of ['json', 'pdf']) {
    const response = await fetch(`${base}/api/scans/${before.id}/reports/${type}/${format}`);
    assert.equal(response.status, 200); assert.match(response.headers.get('content-disposition')!, /attachment/);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (format === 'pdf') assert.ok((await PDFDocument.load(bytes)).getPageCount() > 0);
    else assert.equal(JSON.parse(bytes.toString()).scan.id, before.id);
    await writeFile(join(directory, `${type}.${format}`), bytes);
  }
  const sbomResponse = await fetch(`${base}/api/scans/${before.id}/sbom`); assert.equal(sbomResponse.status, 200);
  const sbom = await sbomResponse.json(); assert.equal(sbom.specVersion, '1.6');
  await writeFile(join(directory, 'sbom.cdx.json'), JSON.stringify(sbom, null, 2));
  let afterId: string | undefined;
  if (!live) {
    const afterArchive = await demoArchive('4.17.21'); await writeFile(join(directory, 'after.zip'), afterArchive);
    const updated = new FormData(); updated.append('archive', new Blob([new Uint8Array(afterArchive)]), 'after.zip');
    const after = await json('', { method: 'POST', body: updated }, 201); afterId = after.id;
    const comparison = await json(`/${after.id}/comparison`, post({ beforeScanId: before.id, sameProject: true }), 201);
    assert.equal(comparison.counts.resolved, 1);
    assert.equal(comparison.counts.unverifiable, 0);
    await writeFile(join(directory, 'comparison.json'), JSON.stringify(comparison, null, 2));
    assert.deepEqual(await json(`/${after.id}/comparison`), comparison);
  }
  const summary = { mode: live ? 'LIVE GitHub/OSV/npm; results change over time' : 'OFFLINE DEMO: synthetic GitHub/OSV/npm responses; not live security evidence', verifiedAt: new Date().toISOString(), repository, repositoryScanId: repositoryScan?.id, beforeScanId: before.id, afterScanId: afterId, advisoryMatches: bundle.securityFindings.coverage.matched, coverage: bundle.securityFindings.coverage.status, incomplete, checks: [...(repositoryScan ? ['repository ingestion to saved report'] : []), 'ZIP ingestion', 'OSV matches', 'isolated scoped reachability', 'persisted reports', 'two JSON and two parseable PDF downloads', 'CycloneDX SBOM', ...(!live ? ['before/after comparison'] : [])] };
  await writeFile(join(directory, 'summary.json'), JSON.stringify(summary, null, 2));
  return summary;
}

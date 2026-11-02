import test from 'node:test';
import assert from 'node:assert/strict';
import { enrichVulnerabilityReport } from '../backend/src/reports.js';
import type { DependencyGraph, VulnerabilityReport } from '@traceguard/shared';

const graph: DependencyGraph = { nodes: [{ id: 'pkg', name: 'lodash', version: '4.17.20', project: 'package-lock.json', installPath: 'node_modules/lodash', direct: true, transitive: false, isProject: false }], edges: [], roots: [], unresolved: [], warnings: [] };
const report: VulnerabilityReport = { source: 'OSV', checkedAt: new Date().toISOString(), status: 'complete', warnings: [], checks: [{ nodeId: 'pkg', status: 'matched', complete: true, advisoryIds: ['GHSA-fixture'] }] };

test('advisory enrichment retains CVEs and source severity and verifies npm package identity', async () => {
  const enriched = await enrichVulnerabilityReport(graph, report, async (url, options) => {
    assert.equal(url, 'https://api.osv.dev/v1/vulns/GHSA-fixture'); assert.equal(options?.redirect, 'error');
    return Response.json({ id: 'GHSA-fixture', aliases: ['CVE-2021-23337'], summary: '<script>untrusted summary</script>', database_specific: { severity: 'HIGH' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], affected: [{ package: { name: 'lodash', ecosystem: 'npm' } }] });
  });
  const detail = enriched.advisories![JSON.stringify(['GHSA-fixture', 'lodash'])];
  assert.deepEqual(detail.aliases, ['CVE-2021-23337']); assert.equal(detail.severityLabel, 'HIGH'); assert.equal(detail.verification, 'verified');
  assert.equal(enriched.checks[0].status, 'matched');
  assert.ok(detail.severity[0].score.startsWith('CVSS:'));
});

test('detail outages and withdrawn/mismatched advisories never invent severity or erase version evidence', async () => {
  for (const fetcher of [async () => { throw new Error('offline'); }, async () => Response.json({ id: 'GHSA-fixture', affected: [{ package: { name: 'other', ecosystem: 'npm' } }] }), async () => Response.json({ id: 'GHSA-fixture', withdrawn: new Date().toISOString(), affected: [{ package: { name: 'lodash', ecosystem: 'npm' } }] })]) {
    const enriched = await enrichVulnerabilityReport(graph, report, fetcher);
    assert.equal(enriched.checks[0].status, 'matched');
    assert.notEqual(enriched.advisories![JSON.stringify(['GHSA-fixture', 'lodash'])].verification, 'verified');
    assert.ok(enriched.warnings.length);
  }
});

test('detail lookups are bounded and deduplicate repeated instances', async () => {
  const ids = Array.from({ length: 42 }, (_, i) => `GHSA-fixture-${i}`); let calls = 0;
  const enriched = await enrichVulnerabilityReport(graph, { ...report, checks: [{ ...report.checks[0], advisoryIds: ids }, { ...report.checks[0], advisoryIds: ids }] }, async input => {
    calls++; return Response.json({ id: String(input).split('/').at(-1), affected: [{ package: { name: 'lodash', ecosystem: 'npm' } }] });
  });
  assert.equal(calls, 40); assert.equal(Object.keys(enriched.advisories!).length, 40);
  assert.ok(enriched.warnings.some(w => w.includes('limited to 40')));
});

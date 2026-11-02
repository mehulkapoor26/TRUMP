import assert from 'node:assert/strict';
import test from 'node:test';
import { generateReportBundle } from '../backend/src/reports.js';
import type { ScanResult } from '@traceguard/shared';

const scan: ScanResult = { id: 'test', source: 'ZIP upload', createdAt: '2026-11-01T00:00:00Z', status: 'completed', files: [], graph: {
  nodes: [{ id: 'pkg', name: 'example', version: '1.0.0', installPath: 'node_modules/example', project: '.', isProject: false, direct: true, transitive: false }], edges: [], roots: [], unresolved: [], warnings: [],
} };
function sources(failCandidate = false): typeof fetch {
  return async (url, options) => {
    const address = String(url);
    if (address.includes('/vulns/')) return Response.json({ id: 'GHSA-example', summary: 'Example vulnerability', affected: [{ package: { name: 'example', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }] });
    if (address.includes('registry.npmjs.org')) return Response.json({ name: 'example', version: '1.0.1' });
    const query = JSON.parse(String(options?.body)).queries[0];
    if (query.version === '1.0.1') return failCandidate ? new Response(null, { status: 503 }) : Response.json({ results: [{}] });
    return Response.json({ results: [{ vulns: [{ id: 'GHSA-example' }] }] });
  };
}
test('recommendations require advisory fixes, published releases, and a clean candidate lookup', async () => {
  const bundle = await generateReportBundle(scan, [], sources());
  assert.equal(bundle.securityFindings.findings[0].package.version, '1.0.0');
  assert.equal(bundle.securityFindings.findings[0].exploitability, 'NOT ASSESSED');
  const action = bundle.remediationPlan.actions[0];
  assert.equal(action.suggestedVersion, '1.0.1');
  assert.equal(action.status, 'VERIFIED CANDIDATE');
  assert.equal(action.verification.compatibility, 'NOT TESTED');
  assert.equal(bundle.securityFindings.bundleId, bundle.remediationPlan.bundleId);
  const failed = await generateReportBundle(scan, [], sources(true));
  assert.equal(failed.remediationPlan.actions[0].status, 'MANUAL REVIEW');
  assert.equal(failed.remediationPlan.actions[0].suggestedVersion, undefined);
});
test('source outages stay unknown and cannot produce clean findings or upgrade advice', async () => {
  const bundle = await generateReportBundle(scan, [], async () => { throw new Error('offline'); });
  assert.equal(bundle.securityFindings.coverage.status, 'unavailable');
  assert.equal(bundle.securityFindings.coverage.unknown, 1);
  assert.equal(bundle.securityFindings.findings.length, 0);
  assert.ok(bundle.remediationPlan.coverageActions.some(action => action.includes('unknown')));
});

test('truncated advisory evidence makes report coverage partial and prevents verified upgrades', async () => {
  const ids = Array.from({ length: 21 }, (_, i) => `GHSA-example-${i}`);
  const bundle = await generateReportBundle(scan, [], async (input) => {
    const address = String(input);
    if (address.includes('/vulns/')) return Response.json({ id: address.split('/').at(-1), affected: [{ package: { name: 'example', ecosystem: 'npm' } }] });
    if (address.includes('registry.npmjs.org')) return Response.json({ name: 'example', version: '1.0.0' });
    return Response.json({ results: [{ vulns: ids.map(id => ({ id })) }] });
  });
  assert.equal(bundle.securityFindings.coverage.status, 'partial');
  assert.equal(bundle.securityFindings.findings[0].advisories.length, 20);
  assert.equal(bundle.remediationPlan.actions[0].status, 'MANUAL REVIEW');
});

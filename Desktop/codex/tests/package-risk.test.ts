import assert from 'node:assert/strict';
import test from 'node:test';
import type { DependencyGraph, SecurityFinding } from '@traceguard/shared';
import { checkPackageRisks, similarName } from '../backend/src/package-risk.js';
import { parseDependencies } from '../backend/src/dependencies.js';
const graph = (name = 'expres', extras = {}): DependencyGraph => ({ nodes: [{ id: 'pkg', name, version: '1.0.0', installPath: `node_modules/${name}`, project: '.', direct: true, transitive: false, isProject: false, ...extras }], edges: [], roots: [], unresolved: [], warnings: [] });
const registry: typeof fetch = async () => Response.json({ name: 'expres', version: '1.0.0', description: 'Example', maintainers: [{ name: 'publisher' }], repository: { url: 'javascript:alert(1)' }, scripts: { postinstall: 'node setup.js' }, dist: { integrity: 'sha512-YQ==', attestations: { url: 'https://registry.npmjs.org/-/npm/v1/attestations/expres@1.0.0' }, signatures: [{ keyid: 'key', sig: 'signature' }] } });
test('name signals explain single edits and transposition without labeling intended or scoped names', () => {
  assert.equal(similarName('expres'), 'express');
  assert.equal(similarName('axois'), 'axios');
  assert.equal(similarName('express'), undefined);
  assert.equal(similarName('@company/express'), undefined);
  assert.equal(similarName('unrelated'), undefined);
});
test('metadata, integrity mismatch and advertised provenance remain unverified evidence', async () => {
  const report = await checkPackageRisks(graph('expres', { integrity: 'sha512-Yg==' }), [], registry);
  const result = report.results[0];
  assert.equal(result.classification, 'SUSPICIOUS');
  assert.deepEqual(result.signals.map(s => s.code), ['NAME_SIMILARITY', 'INSTALL_SCRIPT', 'INTEGRITY_MISMATCH']);
  assert.equal(result.integrity.comparison, 'MISMATCH');
  assert.equal(result.provenance.status, 'ADVERTISED');
  assert.equal(result.provenance.verification, 'NOT PERFORMED');
  assert.equal(result.metadata?.repository, undefined);
  assert.deepEqual(result.metadata?.maintainers, ['publisher']);
});
test('missing data, private sources, limits and network failures never become clean metadata', async () => {
  const failed = await checkPackageRisks(graph('example'), [], async () => { throw new Error('offline'); });
  assert.equal(failed.results[0].classification, 'UNKNOWN');
  assert.equal(failed.coverage.unavailable, 1);
  const custom = await checkPackageRisks(graph('example', { resolved: 'https://private.example/pkg.tgz' }), [], async () => { assert.fail('Custom registry identity must not be sent to npm'); });
  assert.equal(custom.coverage.skipped, 1);
  const wrong = await checkPackageRisks(graph('other'), [], registry);
  assert.equal(wrong.results[0].metadataStatus, 'unavailable');
});
test('only a verified matched MAL advisory can confirm malware, not a GHSA or withdrawn advisory', async () => {
  const finding = { package: { id: 'pkg' }, advisories: [{ id: 'GHSA-example', verification: 'verified', source: 'https://api.osv.dev/v1/vulns/GHSA-example' }] } as SecurityFinding;
  assert.equal((await checkPackageRisks(graph(), [finding], registry)).results[0].classification, 'SUSPICIOUS');
  finding.advisories[0].id = 'MAL-2026-1';
  finding.advisories[0].source = 'https://api.osv.dev/v1/vulns/MAL-2026-1';
  const result = (await checkPackageRisks(graph(), [finding], registry)).results[0];
  assert.equal(result.classification, 'CONFIRMED MALICIOUS');
  assert.equal(result.maliciousSources.length, 1);
  finding.advisories[0].verification = 'withdrawn';
  assert.equal((await checkPackageRisks(graph(), [finding], registry)).results[0].classification, 'SUSPICIOUS');
});
test('lock parsing preserves recorded integrity and safe resolved locations', () => {
  const parsed = parseDependencies([{ path: 'package-lock.json', data: { lockfileVersion: 3, packages: { '': { name: 'app' }, 'node_modules/example': { version: '1.0.0', integrity: 'sha512-YQ==', resolved: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz' } } } }]);
  const node = parsed.nodes.find(n => n.name === 'example')!;
  assert.equal(node.integrity, 'sha512-YQ==');
  assert.match(node.resolved!, /^https:\/\/registry.npmjs.org\//);
});
test('metadata lookups deduplicate instances and stop at 100 pairs with explicit coverage', async () => {
  const inventory = graph('example');
  inventory.nodes = Array.from({ length: 102 }, (_, i) => ({ ...inventory.nodes[0], id: String(i), version: i === 101 ? '1.0.0' : `1.0.${i}` }));
  let calls = 0;
  const report = await checkPackageRisks(inventory, [], async input => {
    calls++;
    const version = decodeURIComponent(String(input).split('/').at(-1)!);
    return Response.json({ name: 'example', version });
  });
  assert.equal(calls, 100);
  assert.equal(report.coverage.skipped, 1);
  assert.equal(report.coverage.metadataChecked, 101);
  assert.equal(report.results[100].classification, 'UNKNOWN');
  assert.equal(report.results[101].classification, 'NO SIGNALS');
});

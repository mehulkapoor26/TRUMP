import assert from 'node:assert/strict';
import test from 'node:test';
import { dependencyImpact, graphLayout } from '../frontend/src/graph-model.js';
import type { DependencyGraph, DependencyNode } from '@traceguard/shared';
import { checkVulnerabilities } from '../backend/src/vulnerabilities.js';

const node = (id: string, name = id, version = '1.0.0'): DependencyNode => ({ id, name, version, isProject: id === 'root', direct: id === 'a', transitive: id !== 'a' && id !== 'root', installPath: id, project: 'package-lock.json' });
const graph: DependencyGraph = {
  nodes: [node('root'), node('a'), node('b'), node('duplicate', 'b', '2.0.0'), node('same', 'b'), node('orphan')],
  roots: ['root'], edges: [
    { from: 'root', to: 'a', kind: 'runtime', name: 'a', requested: '1' },
    { from: 'a', to: 'b', kind: 'runtime', name: 'b', requested: '1' },
    { from: 'b', to: 'a', kind: 'peer', name: 'a', requested: '1' },
    { from: 'a', to: 'duplicate', kind: 'optional', name: 'b', requested: '2' },
  ], unresolved: [], warnings: [],
};

test('impact follows reverse real edges, handles cycles and preserves distinct instances', () => {
  const impact = dependencyImpact(graph, 'b');
  assert.deepEqual([...impact.ancestors].sort(), ['a', 'root']);
  assert.deepEqual(impact.paths, [{ ids: ['root', 'a', 'b'], truncated: false }]);
  assert.equal(impact.ancestors.has('duplicate'), false);
  assert.deepEqual(dependencyImpact(graph, 'orphan').paths, []);
  const layout = graphLayout(graph);
  assert.equal(new Set(layout.nodes.map(n => n.node.id)).size, graph.nodes.length);
  assert.deepEqual(layout.edges, graph.edges);
  assert.equal(layout.nodes.find(n => n.node.id === 'root')?.position.x, 0);
  const limited = graphLayout(graph, 'duplicate', 3);
  assert.equal(limited.nodes.length, 3);
  assert.ok(limited.nodes.some(n => n.node.id === 'duplicate'));
  assert.ok(limited.edges.every(e => limited.nodes.some(n => n.node.id === e.from) && limited.nodes.some(n => n.node.id === e.to)));
});

test('OSV checks exact versions, deduplicates identical instances, and distinguishes unknown from no match', async () => {
  let calls = 0;
  const report = await checkVulnerabilities(graph, async (url, options) => {
    calls++; assert.equal(url, 'https://api.osv.dev/v1/querybatch'); assert.equal(options?.redirect, 'error');
    const queries = JSON.parse(options?.body as string).queries;
    assert.equal(queries.filter((q: { package: { name: string }; version: string }) => q.package.name === 'b' && q.version === '1.0.0').length, 1);
    return Response.json({ results: queries.map((q: { package: { name: string }; version: string }) => q.package.name === 'b' && q.version === '1.0.0' ? { vulns: [{ id: 'GHSA-test-fixture' }] } : {}) });
  });
  assert.equal(calls, 1);
  assert.equal(report.status, 'complete');
  assert.equal(report.checks.find(c => c.nodeId === 'b')?.status, 'matched');
  assert.equal(report.checks.find(c => c.nodeId === 'same')?.status, 'matched');
  assert.equal(report.checks.find(c => c.nodeId === 'duplicate')?.status, 'no-known');
  assert.equal(report.checks.find(c => c.nodeId === 'root')?.status, 'unknown');
});

test('OSV failures, malformed entries and pagination never become clean results', async () => {
  const failure = await checkVulnerabilities(graph, async () => { throw new Error('offline'); });
  assert.equal(failure.status, 'unavailable'); assert.ok(failure.checks.every(c => c.status === 'unknown'));
  const malformed = await checkVulnerabilities(graph, async () => Response.json({ results: [] }));
  assert.ok(malformed.checks.every(c => c.status === 'unknown'));
  const paginated = await checkVulnerabilities({ ...graph, nodes: [node('b')] }, async () => Response.json({ results: [{ vulns: [{ id: 'GHSA-test-fixture' }], next_page_token: 'more' }] }));
  assert.equal(paginated.status, 'partial'); assert.equal(paginated.checks[0].status, 'matched'); assert.equal(paginated.checks[0].complete, false);
  const invalid = await checkVulnerabilities({ ...graph, nodes: [node('b')] }, async () => Response.json({ results: [{ vulns: [{ id: '<script>' }] }] }));
  assert.equal(invalid.checks[0].status, 'unknown');
  const error = await checkVulnerabilities({ ...graph, nodes: [node('b')] }, async () => Response.json({ results: [{ error: 'unavailable' }] }));
  assert.equal(error.checks[0].status, 'unknown');
});

test('incomplete inventories cannot claim complete advisory coverage', async () => {
  const report = await checkVulnerabilities({ ...graph, warnings: ['Missing sibling manifest'], unresolved: [{ from: 'root', name: 'missing', requested: '^1', kind: 'runtime' }] }, async (_url, options) => Response.json({ results: JSON.parse(String(options?.body)).queries.map(() => ({})) }));
  assert.equal(report.status, 'partial');
  assert.ok(report.warnings.some(w => w.includes('inventory')));
  const empty = await checkVulnerabilities({ nodes: [], roots: [], edges: [], warnings: [], unresolved: [] }, async () => { assert.fail('no network lookup without inventory'); });
  assert.equal(empty.status, 'unavailable'); assert.ok(empty.warnings.length);
});

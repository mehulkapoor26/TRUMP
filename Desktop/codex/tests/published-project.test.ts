import test from 'node:test';
import assert from 'node:assert/strict';
import { publishedArchive } from '../scripts/published-fixture.js';
import { inspectArchive } from '../backend/src/scanner.js';
import { parseDependencies, type NpmDocument } from '../backend/src/dependencies.js';
import { generateSbom, validateSbom } from '../backend/src/sbom.js';
import { checkVulnerabilities } from '../backend/src/vulnerabilities.js';

test('published vulnerable project ZIP has exact direct/transitive inventory and schema-valid SBOM without executing source', async () => {
  const documents: NpmDocument[] = [];
  const files = await inspectArchive(await publishedArchive(), documents);
  assert.equal(files.filter(f => f.kind === 'manifest').length, 1); assert.equal(files.filter(f => f.kind === 'lockfile').length, 1);
  const graph = parseDependencies(documents); const libraries = graph.nodes.filter(n => !n.isProject);
  assert.equal(libraries.length, 8); assert.equal(libraries.filter(n => n.direct).length, 4); assert.equal(libraries.filter(n => n.transitive).length, 4);
  assert.equal(graph.edges.length, 8); assert.deepEqual(graph.warnings, []);
  validateSbom(generateSbom(graph, '00000000-0000-4000-8000-000000000000', new Date().toISOString()));
  assert.equal(libraries.find(n => n.name === 'lodash')?.version, '4.17.20');
  assert.equal(libraries.find(n => n.name === 'minimist')?.version, '0.0.8');
});

test('same real manifest without a lockfile remains unresolved and cannot produce a clean scan', async () => {
  const documents: NpmDocument[] = []; await inspectArchive(await publishedArchive(false), documents);
  const graph = parseDependencies(documents); assert.equal(graph.unresolved.length, 4);
  assert.equal(graph.nodes.filter(n => !n.isProject).length, 0);
  const report = await checkVulnerabilities(graph, async () => { assert.fail('No guessed version queries are allowed'); });
  assert.equal(report.status, 'unavailable'); assert.ok(report.warnings.length);
});

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parseDependencies } from '../backend/src/dependencies.js';
import { generateSbom, validateSbom } from '../backend/src/sbom.js';
import { attachInventory } from '../backend/src/inventory.js';
import { checkVulnerabilities } from '../backend/src/vulnerabilities.js';
import type { DependencyGraph } from '@traceguard/shared';

const id = '11111111-1111-4111-8111-111111111111';
const timestamp = '2026-01-01T00:00:00.000Z';
const json = async (path: string) => JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
const node = (graph: DependencyGraph, path: string) => {
  const found = graph.nodes.find(node => node.installPath === path);
  assert.ok(found, `missing node: ${path}`); return found;
};
const children = (graph: DependencyGraph, path: string) => graph.edges.filter(edge => edge.from === node(graph, path).id).map(edge => graph.nodes.find(node => node.id === edge.to)!);

for (const version of [1, 2, 3]) {
  test(`real npm v${version} lockfile preserves resolved versions, hoisting and nested duplicates`, async () => {
    const manifest = await json('./fixtures/npm-project/package.json');
    const lock = await json(version === 3 ? './fixtures/npm-project/package-lock.json' : `./fixtures/package-lock-v${version}.json`);
    const graph = parseDependencies([{ path: 'project/package.json', data: manifest }, { path: 'project/package-lock.json', data: lock }]);
    assert.equal(graph.nodes.filter(n => !n.isProject).length, 8);
    assert.deepEqual(graph.nodes.filter(n => n.name === 'is-number').map(n => n.version).sort(), ['3.0.0', '6.0.0', '7.0.0']);
    assert.equal(node(graph, 'node_modules/is-number').direct, true);
    assert.equal(node(graph, 'node_modules/is-odd/node_modules/is-number').direct, false);
    assert.equal(node(graph, 'node_modules/is-odd/node_modules/is-number').transitive, true);
    assert.equal(children(graph, 'node_modules/is-odd')[0].version, '6.0.0');
    assert.equal(children(graph, 'node_modules/is-even/node_modules/is-odd')[0].version, '3.0.0');
    assert.equal(children(graph, 'node_modules/is-even/node_modules/is-number')[0].installPath, 'node_modules/kind-of');
    assert.equal(graph.unresolved.length, 0);
    assert.deepEqual(graph.warnings, []);
    const bom = generateSbom(graph, id, timestamp);
    validateSbom(bom);
    assert.equal(bom.compositions[0].aggregate, 'complete');
    assert.equal(bom.components.filter(c => c.name === 'is-number').length, 3);
    assert.equal(bom.dependencies.find(d => d.ref === node(graph, 'node_modules/is-odd').id)?.dependsOn[0], node(graph, 'node_modules/is-odd/node_modules/is-number').id);
  });
}

test('same-version instances, scoped packages, aliases, peer resolution and dependency kinds', () => {
  const manifest = { name: 'app', version: '1.0.0', dependencies: { a: '^1', b: '1', shared: '1', alias: 'npm:real@4', '@scope/pkg': '3' }, devDependencies: { dev: '1' }, optionalDependencies: { absent: '^1' } };
  const graph = parseDependencies([
    { path: 'package.json', data: manifest },
    { path: 'package-lock.json', data: { lockfileVersion: 3, packages: {
      '': manifest,
      'node_modules/a': { version: '1.0.0', dependencies: { shared: '^2' }, peerDependencies: { shared: '^1' } },
      'node_modules/b': { version: '1.0.0', dependencies: { shared: '^2' } },
      'node_modules/shared': { version: '1.0.0' },
      'node_modules/a/node_modules/shared': { version: '2.0.0' },
      'node_modules/b/node_modules/shared': { version: '2.0.0' },
      'node_modules/alias': { name: 'real', version: '4.0.0' },
      'node_modules/@scope/pkg': { version: '3.0.0' },
      'node_modules/dev': { version: '1.0.0', dev: true },
    } } },
  ]);
  const aEdges = graph.edges.filter(edge => edge.from === node(graph, 'node_modules/a').id);
  assert.equal(aEdges.find(edge => edge.kind === 'runtime')?.to, node(graph, 'node_modules/a/node_modules/shared').id);
  assert.equal(aEdges.find(edge => edge.kind === 'peer')?.to, node(graph, 'node_modules/shared').id);
  assert.equal(node(graph, 'node_modules/shared').direct, true);
  assert.equal(node(graph, 'node_modules/shared').transitive, true);
  assert.equal(node(graph, 'node_modules/alias').name, 'real');
  assert.ok(graph.edges.some(edge => edge.kind === 'dev' && edge.name === 'dev'));
  assert.equal(graph.unresolved[0].kind, 'optional');
  const bom = generateSbom(graph, id, timestamp);
  const duplicates = bom.components.filter(c => c.name === 'shared' && c.version === '2.0.0');
  assert.equal(duplicates.length, 2);
  assert.notEqual(duplicates[0]['bom-ref'], duplicates[1]['bom-ref']);
  assert.equal(duplicates[0].purl, duplicates[1].purl);
  assert.ok(bom.components.some(c => c.purl === 'pkg:npm/%40scope/pkg@3.0.0'));
  assert.ok(bom.components.some(c => c.purl === 'pkg:npm/real@4.0.0'));
  assert.equal(bom.compositions[0].aggregate, 'incomplete');
});

test('optional peer absences are classified separately and do not make mandatory inventory coverage incomplete', async () => {
  const optionalManifest = { name: 'app', version: '1.0.0', dependencies: { present: '1.0.0' }, peerDependencies: { optionalPlugin: '^2' }, peerDependenciesMeta: { optionalPlugin: { optional: true } } };
  const lock = { lockfileVersion: 3, packages: { '': optionalManifest, 'node_modules/present': { version: '1.0.0' } } };
  const optional = parseDependencies([{ path: 'package.json', data: optionalManifest }, { path: 'package-lock.json', data: lock }]);
  assert.equal(optional.unresolved.length, 1); assert.equal(optional.unresolved[0].name, 'optionalPlugin'); assert.equal(optional.unresolved[0].optionalPeer, true);
  assert.ok(optional.warnings.some(warning => warning.startsWith('Optional peer dependency')));
  const optionalScan = { id, createdAt: timestamp, source: 'ZIP upload', status: 'completed' as const, files: [{ path: 'package.json', kind: 'manifest' as const, bytes: 1 }, { path: 'package-lock.json', kind: 'lockfile' as const, bytes: 1 }], graph: optional };
  attachInventory(optionalScan, Buffer.from('same-repository-revision'), []);
  assert.equal(optionalScan.analysisStatus, 'analyzed'); assert.equal(optionalScan.counts?.unresolvedDeclarations, 1);
  const optionalReport = await checkVulnerabilities(optional, async (_url, options) => Response.json({ results: JSON.parse(String(options?.body)).queries.map(() => ({})) }));
  assert.equal(optionalReport.status, 'complete');

  const requiredManifest = { ...optionalManifest, dependencies: { present: '1.0.0', requiredPackage: '^3' }, peerDependencies: undefined, peerDependenciesMeta: undefined };
  const required = parseDependencies([{ path: 'package.json', data: requiredManifest }, { path: 'package-lock.json', data: { lockfileVersion: 3, packages: { '': requiredManifest, 'node_modules/present': { version: '1.0.0' } } } }]);
  assert.equal(required.unresolved.length, 1); assert.equal(required.unresolved[0].name, 'requiredPackage'); assert.equal(required.unresolved[0].optionalPeer, undefined);
  const requiredReport = await checkVulnerabilities(required, async (_url, options) => Response.json({ results: JSON.parse(String(options?.body)).queries.map(() => ({})) }));
  assert.equal(requiredReport.status, 'partial'); assert.ok(requiredReport.warnings.some(warning => warning.includes('inventory is incomplete')));
});

test('workspace links resolve to canonical packages and their own dependency context', () => {
  const manifest = { name: 'app', version: '1.0.0', dependencies: { '@scope/workspace': 'file:packages/one' } };
  const workspace = { name: '@scope/workspace', version: '2.0.0', dependencies: { shared: '^2' } };
  const graph = parseDependencies([
    { path: 'repo/package.json', data: manifest },
    { path: 'repo/packages/one/package.json', data: workspace },
    { path: 'repo/package-lock.json', data: { lockfileVersion: 3, packages: {
      '': manifest,
      'packages/one': workspace,
      'node_modules/@scope/workspace': { resolved: 'packages/one', link: true },
      'node_modules/shared': { version: '1.0.0' },
      'packages/one/node_modules/shared': { version: '2.0.0' },
    } } },
  ]);
  assert.equal(graph.nodes.length, 4);
  assert.equal(graph.roots.length, 2);
  assert.equal(children(graph, '')[0].id, node(graph, 'packages/one').id);
  assert.equal(children(graph, 'packages/one')[0].version, '2.0.0');
  assert.deepEqual(graph.warnings, []);
  validateSbom(generateSbom(graph, id, timestamp));
});

test('missing locks and stale ranges remain explicit, never treated as resolved versions', () => {
  const graph = parseDependencies([{ path: 'package.json', data: { dependencies: { missing: '^2.0.0' } } }]);
  assert.equal(graph.nodes.length, 1);
  assert.equal(graph.unresolved[0].requested, '^2.0.0');
  assert.equal(generateSbom(graph, id, timestamp).components.some(c => c.version === '^2.0.0'), false);
  const stale = parseDependencies([
    { path: 'package.json', data: { dependencies: { dep: '^2' } } },
    { path: 'package-lock.json', data: { lockfileVersion: 2, packages: { '': {}, 'node_modules/dep': { version: '1.0.0' } } } },
  ]);
  assert.match(stale.warnings.join(' '), /does not satisfy/);
  assert.equal(node(stale, 'node_modules/dep').version, '1.0.0');
  const invalidVersion = parseDependencies([
    { path: 'package.json', data: { dependencies: { dep: '^2' } } },
    { path: 'package-lock.json', data: { lockfileVersion: 3, packages: { '': {}, 'node_modules/dep': { version: '^2.0.0' } } } },
  ]);
  assert.equal(node(invalidVersion, 'node_modules/dep').version, undefined);
  assert.match(invalidVersion.warnings.join(' '), /No exact semantic version/);

});

test('malformed lockfiles and maps are rejected without trusting install paths', () => {
  for (const lock of [
    { lockfileVersion: 3 },
    { lockfileVersion: 99 },
    { lockfileVersion: 3, packages: { '../evil': {} } },
    { lockfileVersion: 3, packages: { 'node_modules/a': { version: 123 } } },
    { lockfileVersion: 3, packages: { '': { dependencies: { foo: {} } } } },
  ]) assert.throws(() => parseDependencies([{ path: 'package-lock.json', data: lock }]));
});

test('shrinkwrap takes precedence and cycles terminate', () => {
  const manifest = { dependencies: { a: '1' } };
  const lock = { lockfileVersion: 3, packages: { '': manifest, 'node_modules/a': { version: '1.0.0', dependencies: { b: '1' } }, 'node_modules/b': { version: '1.0.0', dependencies: { a: '1' } } } };
  const graph = parseDependencies([{ path: 'package.json', data: manifest }, { path: 'package-lock.json', data: { lockfileVersion: 99 } }, { path: 'npm-shrinkwrap.json', data: lock }]);
  assert.equal(graph.nodes.length, 3); assert.equal(graph.edges.length, 3);
  assert.match(graph.warnings[0], /takes precedence/);
  validateSbom(generateSbom(graph, id, timestamp));
});

test('official schema and reference checks reject invalid SBOMs', async () => {
  const graph = parseDependencies([{ path: 'package.json', data: await json('./fixtures/npm-project/package.json') }, { path: 'package-lock.json', data: await json('./fixtures/npm-project/package-lock.json') }]);
  const bom = generateSbom(graph, id, timestamp);
  assert.throws(() => validateSbom({ ...bom, bomFormat: 'invalid' }), /Invalid CycloneDX/);
  assert.throws(() => validateSbom({ ...bom, components: [{ ...bom.components[0], type: 'invalid' }] }), /Invalid CycloneDX/);
  const duplicate = structuredClone(bom); duplicate.components[1]['bom-ref'] = duplicate.components[0]['bom-ref'];
  assert.throws(() => validateSbom(duplicate), /Duplicate/);
  const dangling = structuredClone(bom); dangling.dependencies[0].dependsOn.push('unknown-component');
  assert.throws(() => validateSbom(dangling), /Dangling/);
});


test('independent lock contexts and legacy aliases retain distinct identities', () => {
  const graph = parseDependencies(['one', 'two'].flatMap(project => [
    { path: `${project}/package.json`, data: { name: project, dependencies: { alias: 'npm:real@1.0.0' } } },
    { path: `${project}/package-lock.json`, data: { lockfileVersion: 1, dependencies: { alias: { version: 'npm:real@1.0.0' } } } },
  ]));
  const instances = graph.nodes.filter(node => node.name === 'real');
  assert.equal(instances.length, 2);
  assert.notEqual(instances[0].id, instances[1].id);
  assert.ok(instances.every(node => node.version === '1.0.0' && node.direct));
  validateSbom(generateSbom(graph, id, timestamp));
});


test('v1 locks without sibling manifests retain installed packages without guessing direct roots', () => {
  const graph = parseDependencies([
    { path: 'package-lock.json', data: { name: 'orphan', version: '1.0.0', lockfileVersion: 1, dependencies: { a: { version: '1.0.0', requires: { b: '^2' } }, b: { version: '2.0.0' } } } },
  ]);
  assert.equal(graph.nodes.length, 3);
  assert.equal(graph.edges.length, 1);
  assert.ok(graph.nodes.every(node => !node.direct));
  assert.match(graph.warnings.join(' '), /No sibling package.json/);
  validateSbom(generateSbom(graph, id, timestamp));
});

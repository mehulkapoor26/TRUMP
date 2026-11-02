import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeReachability, validateReachabilityRequest } from '../backend/src/reachability.js';
import { runReachability } from '../backend/src/reachability-runner.js';
import { parseDependencies } from '../backend/src/dependencies.js';
import type { ReachabilityRequest, SourceSnapshot } from '@traceguard/shared';

const graph = parseDependencies([
  { path: 'repo/package.json', data: { name: 'app', dependencies: { risky: '1.0.0', other: '1.0.0' } } },
  { path: 'repo/package-lock.json', data: { lockfileVersion: 3, packages: { '': {}, 'node_modules/risky': { version: '1.0.0' }, 'node_modules/other': { version: '1.0.0', dependencies: { risky: '2.0.0' } }, 'node_modules/other/node_modules/risky': { version: '2.0.0' } } } },
]);
const targetId = graph.nodes.find(n => n.name === 'risky' && n.version === '1.0.0')!.id;
const request: ReachabilityRequest = { entrypoints: [{ file: 'repo/main.js', symbol: '<module>' }], target: { packageNodeId: targetId, exportName: 'danger' } };
const snapshot = (files: Record<string, string>): SourceSnapshot => ({ files: Object.entries(files).map(([path, content]) => ({ path, content })), skipped: [] });
const analyze = (content: string, req = request) => analyzeReachability(snapshot({ 'repo/main.js': content }), graph, req);

test('scoped call traversal follows real imports and local calls with file and line evidence', () => {
  const result = analyzeReachability(snapshot({
    'repo/main.js': "import { run } from './helper.js';\nrun();",
    'repo/helper.js': "import { danger as affected } from 'risky';\nexport function run() {\n  affected();\n}",
  }), graph, request);
  assert.equal(result.status, 'REACHABLE', JSON.stringify(result.gaps));
  assert.equal(result.coverage.completeForDeclaredEntrypoints, true);
  assert.ok(result.evidence.some(e => e.file === 'repo/main.js' && e.line === 2 && e.kind === 'call'));
  assert.ok(result.evidence.some(e => e.file === 'repo/helper.js' && e.line === 3 && e.kind === 'target' && e.snippet === 'affected();'));
  assert.equal(result.mapping, 'user-declared export; not independently verified');
});

test('unused functions are not reachable within module scope, but declared exported entrypoints are', () => {
  const content = "import { danger } from 'risky';\nexport function handler() { danger(); }";
  const moduleOnly = analyze(content);
  assert.equal(moduleOnly.status, 'NOT REACHABLE');
  assert.equal(moduleOnly.coverage.completeForDeclaredEntrypoints, true);
  assert.equal(analyze(content, { ...request, entrypoints: [{ file: 'repo/main.js', symbol: 'handler' }] }).status, 'REACHABLE');
  assert.equal(analyze("import { danger } from 'risky'; export const handler = () => danger();", { ...request, entrypoints: [{ file: 'repo/main.js', symbol: 'handler' }] }).status, 'REACHABLE');
});

test('default and namespace ESM calls are supported, cycles terminate, and shadowing does not match imports', () => {
  assert.equal(analyze("import * as api from 'risky'; api.danger();").status, 'REACHABLE');
  assert.equal(analyze("import danger from 'risky'; danger();", { ...request, target: { ...request.target, exportName: 'default' } }).status, 'REACHABLE');
  assert.equal(analyze("import { danger } from 'risky'; function f(danger) { danger(); } f(() => {});").status, 'UNKNOWN');
  assert.equal(analyze("function a() { b(); } function b() { a(); } a();").status, 'NOT REACHABLE');
});

test('dynamic calls, callbacks, aliases, mutations, methods, async, syntax errors and CommonJS are UNKNOWN', () => {
  for (const content of [
    "import { danger } from 'risky'; const alias = danger; alias();",
    "import { danger } from 'risky'; something(danger);",
    "import * as api from 'risky'; api['danger']();",
    "import { danger } from 'risky'; danger?.();",
    "import { danger } from 'risky'; let f = () => danger(); f = () => {}; f();",
    "import { danger } from 'risky'; const obj = { get value() { return danger(); } }; obj.value;",
    "async function run() {} run();",
    "const p = require('risky'); p.danger();",
    "import('risky');",
    "import { danger } from 'risky'; eval('danger()');",
    "const = broken;",
    "import { other } from 'other'; other();",
    "class Foo {}",
    "import { danger } from 'risky'; function f() { danger(); } function f() {} f();",
  ]) { const result = analyze(content); assert.equal(result.status, 'UNKNOWN', content); assert.ok(result.gaps.length); }
});

test('missing function mappings, source, modules, and entries cannot produce a negative', () => {
  assert.equal(analyze('', { ...request, target: { ...request.target, exportName: '' } }).status, 'UNKNOWN');
  assert.equal(analyzeReachability(null, graph, request).status, 'UNKNOWN');
  assert.equal(analyze("import { helper } from './missing.js';").status, 'UNKNOWN');
  assert.equal(analyze('export const value = 1;', { ...request, entrypoints: [{ file: 'repo/main.js', symbol: 'missing' }] }).status, 'UNKNOWN');
  assert.equal(analyze('export const value = 1;', { ...request, entrypoints: [{ file: 'repo/missing.js', symbol: '<module>' }] }).status, 'UNKNOWN');
});

test('matching function names do not collapse duplicate package instances or subpaths', () => {
  const wrongVersion = graph.nodes.find(n => n.name === 'risky' && n.version === '2.0.0')!;
  assert.equal(analyze("import { danger } from 'risky'; danger();", { ...request, target: { ...request.target, packageNodeId: wrongVersion.id } }).status, 'UNKNOWN');
  assert.equal(analyze("import { danger } from 'risky/tools'; danger();", { ...request, target: { ...request.target, subpath: 'tools' } }).status, 'REACHABLE');
  assert.equal(analyze("import { danger } from 'risky/tools'; danger();").status, 'UNKNOWN');
});

test('request validation rejects traversal paths and malformed targets', () => {
  validateReachabilityRequest(request);
  for (const value of [null, {}, { ...request, entrypoints: [{ file: '../secret.js', symbol: '<module>' }] }, { ...request, target: { ...request.target, subpath: '../internal' } }]) assert.throws(() => validateReachabilityRequest(value));
});

test('bounded analysis worker parses source without running it', async () => {
  const result = await runReachability(snapshot({ 'repo/main.js': "import { danger } from 'risky';\ndanger();" }), graph, request);
  assert.equal(result.status, 'REACHABLE', JSON.stringify(result));
});

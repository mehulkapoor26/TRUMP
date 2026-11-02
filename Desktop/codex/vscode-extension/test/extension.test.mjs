import { test } from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
async function load(entry, mocks = {}) {
  const result = await build({ entryPoints: [new URL(`../src/${entry}.ts`, import.meta.url).pathname], bundle: true, platform: 'node', format: 'cjs', target: 'node20', external: ['vscode'], write: false });
  const module = { exports: {} };
  new Function('require', 'module', 'exports', result.outputFiles[0].text)(name => mocks[name] ?? require(name), module, module.exports);
  return module.exports;
}
const manifest = JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: { lodash: '4.17.20' } });
const lock = version => JSON.stringify({ name: 'demo', version: '1.0.0', lockfileVersion: 3, packages: { '': { name: 'demo', version: '1.0.0', dependencies: { lodash: version } }, 'node_modules/lodash': { version } } });
const files = version => [{ path: 'package.json', content: manifest.replace('4.17.20', version) }, { path: 'package-lock.json', content: lock(version) }];
const { checkFiles } = await load('checker');
const reply = results => new Response(JSON.stringify({ results }));

test('checks exact locked versions with OSV and locates advisory diagnostics', async () => {
  const result = await checkFiles(files('4.17.20'), async (url, options) => {
    assert.equal(url, 'https://api.osv.dev/v1/querybatch');
    assert.deepEqual(JSON.parse(options.body).queries, [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }]);
    return reply([{ vulns: [{ id: 'GHSA-test' }] }]);
  });
  assert.equal(result.matched, 1);
  const finding = result.findings.find(f => f.advisoryId);
  assert.equal(finding.path, 'package-lock.json');
  assert.equal(lock('4.17.20').slice(finding.offset, finding.offset + finding.length), '"node_modules/lodash"');
});
test('complete empty advisory response clears findings', async () => {
  const result = await checkFiles(files('4.17.21'), async () => reply([{}]));
  assert.equal(result.matched, 0);
  assert.equal(result.unknown, 0);
  assert.equal(result.findings.length, 0);
});
test('outages and malformed responses remain unknown', async () => {
  for (const fetcher of [async () => { throw new Error('offline'); }, async () => reply([]), async () => reply([{ vulns: 'invalid' }])]) {
    const result = await checkFiles(files('4.17.20'), fetcher);
    assert.equal(result.unknown, 1);
    assert.ok(result.findings.some(f => f.kind === 'coverage'));
  }
});
test('paginated advisory results retain matches and incomplete coverage', async () => {
  const result = await checkFiles(files('4.17.20'), async () => reply([{ vulns: [{ id: 'GHSA-test' }], next_page_token: 'more' }]));
  assert.equal(result.matched, 1);
  assert.equal(result.unknown, 1);
});
test('manifest alone never invents resolved versions', async () => {
  const result = await checkFiles(files('4.17.20').slice(0, 1), async () => { assert.fail('no exact versions to query'); });
  assert.equal(result.matched, 0);
  assert.ok(result.warnings.length);
  assert.ok(result.findings.some(f => f.kind === 'coverage'));
});
test('invalid metadata rejects rather than reporting a clean scan', async () => {
  await assert.rejects(checkFiles([{ path: 'package.json', content: '{' }]));
});

function harness() {
  const callbacks = {}, commands = new Map(), diagnostics = new Map(), notices = [], logs = [];
  const disposable = { dispose() {} };
  const event = name => callback => { callbacks[name] = callback; return disposable; };
  const uri = path => ({ path, scheme: 'file', toString: () => `file://${path}` });
  const folder = { name: 'demo', uri: uri('/demo') };
  const documents = new Map(files('4.17.20').map(f => [`/demo/${f.path}`, { uri: uri(`/demo/${f.path}`), isDirty: false, getText: () => f.content, positionAt: offset => ({ offset }) }]));
  const config = { enabled: true, notifications: true, debounceMs: 250 };
  const vscode = {
    Uri: { joinPath: (base, path) => uri(`${base.path}/${path}`), parse: value => value },
    Range: class { constructor(...args) { this.args = args; } },
    Diagnostic: class { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } },
    DiagnosticSeverity: { Warning: 1, Information: 2 }, StatusBarAlignment: { Left: 1 }, RelativePattern: class {},
    languages: { createDiagnosticCollection: () => ({ ...disposable, clear: () => diagnostics.clear(), set: (uri, values) => diagnostics.set(uri.path, values) }) },
    window: { createOutputChannel: () => ({ ...disposable, show() {}, appendLine: line => logs.push(line) }), createStatusBarItem: () => ({ ...disposable, show() {} }), showWarningMessage: async message => { notices.push(message); } },
    commands: { registerCommand: (name, handler) => { commands.set(name, handler); return disposable; }, executeCommand: async () => {} },
    workspace: {
      isTrusted: true, workspaceFolders: [folder], getConfiguration: () => ({ get: (key, fallback) => config[key] ?? fallback }),
      findFiles: async () => [...documents.values()].map(d => d.uri), fs: { stat: async () => ({ size: 100 }) }, openTextDocument: async uri => documents.get(uri.path), asRelativePath: uri => uri.path.slice(6),
      createFileSystemWatcher: () => ({ ...disposable, onDidChange: event('change'), onDidCreate: event('create'), onDidDelete: event('delete') }),
      onDidSaveTextDocument: event('save'), onDidChangeTextDocument: event('edit'), onDidChangeWorkspaceFolders: event('folders'), onDidChangeConfiguration: event('config'), onDidGrantWorkspaceTrust: event('trust'),
    },
  };
  return { vscode, callbacks, commands, diagnostics, notices, documents, config };
}
test('activation publishes diagnostics and deduplicates notifications; changes clear stale results', async () => {
  const h = harness();
  const { activate } = await load('extension', { vscode: h.vscode });
  const original = globalThis.fetch;
  globalThis.fetch = async () => reply([{ vulns: [{ id: 'GHSA-test' }] }]);
  const context = { subscriptions: [] };
  const api = activate(context);
  try {
    await api.scanNow();
    assert.ok(h.diagnostics.get('/demo/package-lock.json').some(d => d.code.value === 'GHSA-test' && d.severity === 1));
    assert.equal(h.notices.length, 1);
    await api.scanNow();
    assert.equal(h.notices.length, 1);
    h.callbacks.change(h.documents.get('/demo/package-lock.json').uri);
    assert.equal(h.diagnostics.size, 0);
    globalThis.fetch = async () => reply([{}]);
    await api.scanNow();
    assert.equal(h.diagnostics.size, 0);
    h.config.enabled = false;
    await api.scanNow();
    assert.equal(h.diagnostics.size, 0);
  } finally { context.subscriptions.forEach(s => s.dispose()); globalThis.fetch = original; }
});
test('unsaved metadata reports incomplete coverage without querying OSV', async () => {
  const h = harness();
  h.documents.get('/demo/package.json').isDirty = true;
  const { activate } = await load('extension', { vscode: h.vscode });
  const context = { subscriptions: [] };
  const api = activate(context);
  try {
    await api.scanNow();
    assert.ok([...h.diagnostics.values()].flat().some(d => d.code === 'check-failed' && /Save pending/.test(d.message)));
    assert.equal(h.notices.length, 1);
  } finally { context.subscriptions.forEach(s => s.dispose()); }
});
test('filesystem changes trigger a debounced scan and discard in-flight stale findings', async () => {
  const h = harness();
  const { activate } = await load('extension', { vscode: h.vscode });
  const context = { subscriptions: [] };
  const original = globalThis.fetch;
  let release, calls = 0;
  globalThis.fetch = async () => {
    calls++;
    if (calls === 1) return await new Promise(resolve => { release = () => resolve(reply([{ vulns: [{ id: 'GHSA-stale' }] }])); });
    return reply([{}]);
  };
  const api = activate(context);
  try {
    const first = api.scanNow();
    while (!release) await new Promise(resolve => setTimeout(resolve, 1));
    h.callbacks.change(h.documents.get('/demo/package-lock.json').uri);
    release();
    await first;
    assert.equal(calls, 2);
    assert.equal(h.diagnostics.size, 0);
    assert.equal(h.notices.length, 0);
    await new Promise(resolve => setTimeout(resolve, 350));
    assert.equal(calls, 3);
    assert.equal(h.diagnostics.size, 0);
  } finally { context.subscriptions.forEach(s => s.dispose()); globalThis.fetch = original; }
});

test('untrusted workspaces make no network requests', async () => {
  const h = harness(); h.vscode.workspace.isTrusted = false;
  const { activate } = await load('extension', { vscode: h.vscode });
  const context = { subscriptions: [] }, original = globalThis.fetch;
  globalThis.fetch = async () => { assert.fail('untrusted network request'); };
  const api = activate(context);
  try { await api.scanNow(); assert.equal(h.diagnostics.size, 0); }
  finally { context.subscriptions.forEach(s => s.dispose()); globalThis.fetch = original; }
});

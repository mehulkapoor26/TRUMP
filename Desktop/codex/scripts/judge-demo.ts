import express from 'express';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { demoFetcher } from './demo-fixture.js';
import { verifyWorkflow } from './workflow.js';

const live = process.argv.includes('--live');
const check = process.argv.includes('--check') || live;
const compiled = process.argv.includes('--compiled');
const backendDirectory = compiled ? 'dist' : 'src';
const { createApp } = await import(new URL(`../backend/${backendDirectory}/app.${compiled ? 'js' : 'ts'}`, import.meta.url).href) as typeof import('../backend/src/app.js');
const { scanStore } = await import(new URL(`../backend/${backendDirectory}/scanner.${compiled ? 'js' : 'ts'}`, import.meta.url).href) as typeof import('../backend/src/scanner.js');
const directory = await mkdtemp(join(tmpdir(), 'traceguard-demo-'));
const application = express();
let ready: Awaited<ReturnType<typeof verifyWorkflow>> | undefined;
application.get('/api/demo', (_req, res) => res.status(ready ? 200 : 503).json(ready ?? { status: 'preparing' }));
if (!check) application.get('/', async (_req, res, next) => {
  try {
    const html = await readFile(resolve('frontend/dist/index.html'), 'utf8');
    res.type('html').send(html.replace('<body>', '<body><div role="status" style="padding:12px;background:#713f12;color:white;text-align:center">OFFLINE JUDGE DEMO — GitHub, OSV and npm evidence is simulated. No live security assessment.</div>'));
  } catch (error) { next(error); }
});
const store = scanStore(directory);
if (!live) {
  const create = store.create.bind(store);
  store.create = (archive, source) => create(archive, `OFFLINE DEMO — simulated external evidence — ${source}`);
}
application.use(createApp({ store, fetcher: live ? fetch : demoFetcher }));
const port = check ? 0 : Number(process.env.DEMO_PORT ?? 4173);
const server = application.listen(port, '127.0.0.1');
async function close() { await new Promise<void>(resolve => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
try {
  await once(server, 'listening'); const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Demo server did not start.');
  const base = `http://127.0.0.1:${address.port}`;
  const summary = await verifyWorkflow(base, resolve(live ? 'artifacts/live-workflow' : compiled ? 'artifacts/production-check' : 'artifacts/judge-demo'), live);
  ready = summary;
  console.log(JSON.stringify(summary, null, 2));
  if (summary.incomplete.length) process.exitCode = 1;
  if (check) await close();
  else {
    console.log(`\nOFFLINE DEMO READY: ${base}/#/scans/${summary.beforeScanId}/overview\nArtifacts: artifacts/judge-demo\nCtrl+C removes temporary scan storage. Exported artifacts remain.`);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void close().then(() => process.exit(0)); });
  }
} catch (error) { await close(); console.error(error); process.exitCode = 1; }

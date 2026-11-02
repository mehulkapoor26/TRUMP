import express from 'express';
import multer from 'multer';
import { scanRouter } from './scans.js';
import { ScanError } from './scanner.js';
import type { HealthResponse } from '@traceguard/shared';
import { fileURLToPath } from 'node:url';
import { scanStore } from './scanner.js';

export function createApp(options: { store?: ReturnType<typeof scanStore>; fetcher?: typeof fetch; frontendDirectory?: string | false } = {}) {
const app = express();
app.disable('x-powered-by');
app.use((request, response, next) => {
  response.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' });
  if (request.method === 'POST' && request.get('Sec-Fetch-Site') === 'cross-site') {
    response.status(403).json({ error: 'Cross-site submissions are not allowed.' }); return;
  }
  next();
});
app.use(express.json({ limit: '100kb' }));

app.get('/api/health', (_request, response) => {
  const health: HealthResponse = {
    status: 'ok', service: 'traceguard-api',
    timestamp: new Date().toISOString(), uptime: process.uptime(),
  };
  response.set('Cache-Control', 'no-store').json(health);
});

app.use('/api/scans', scanRouter(options.store, options.fetcher));

// Hash routing needs only the static index; unknown API routes still return JSON 404.
const frontendDirectory = options.frontendDirectory === undefined ? fileURLToPath(new URL('../../frontend/dist/', import.meta.url)) : options.frontendDirectory;
if (frontendDirectory) app.use(express.static(frontendDirectory, { index: 'index.html', dotfiles: 'deny' }));

app.use((_request, response) => {
  response.status(404).json({ error: 'Not found' });
});

app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  if (error instanceof ScanError) { if (error.retryAfter) response.set('Retry-After', String(error.retryAfter)); response.status(error.status).json({ error: error.message }); return; }
  if (error instanceof multer.MulterError) { response.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: 'Invalid upload or upload limit exceeded (one ZIP, 10 MiB maximum).' }); return; }
  const status = (error as { status?: number })?.status;
  if (status === 400 || status === 413) { response.status(status).json({ error: status === 413 ? 'Request too large.' : 'Invalid JSON request.' }); return; }
  console.error('Scan request failed:', error);
  response.status(500).json({ error: 'Unable to complete scan.' });
});
return app;
}

export const app = createApp();

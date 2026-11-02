import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { app } from '../backend/src/app.js';
import { healthyResponse } from './fixtures/health.js';

test('health API returns the shared contract and unknown routes return 404', async () => {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const base = `http://127.0.0.1:${address.port}`;
    const response = await fetch(`${base}/api/health`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const health = await response.json();
    assert.equal(health.status, healthyResponse.status);
    assert.equal(health.service, healthyResponse.service);
    assert.ok(Number.isFinite(Date.parse(health.timestamp)));
    assert.equal(typeof health.uptime, 'number');
    assert.ok(health.uptime >= 0);
    assert.equal((await fetch(`${base}/api/missing`)).status, 404);
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});

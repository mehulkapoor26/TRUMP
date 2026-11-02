import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import { RescanPanel } from '../frontend/src/RescanPanel.js';
import { compareScans } from '../backend/src/comparison.js';
import type { ScanResult } from '@traceguard/shared';

test('rescan interface requires an after scan and declared project identity, then shows comparison outcomes', async () => {
  const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost', pretendToBeVisual: true });
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, HTMLElement: dom.window.HTMLElement, IS_REACT_ACT_ENVIRONMENT: true })) {
    previous.set(key, Object.getOwnPropertyDescriptor(globalThis, key)); Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  const originalFetch = globalThis.fetch;
  const { render, fireEvent, cleanup } = await import('@testing-library/react');
  const before: ScanResult = { id: 'before', createdAt: '2026-01-01T00:00:00Z', source: 'Controlled baseline', status: 'completed', files: [], graph: { nodes: [{ id: 'root', name: 'app', version: '1.0.0', isProject: true, project: '.', installPath: '', direct: false, transitive: false }], roots: ['root'], edges: [], unresolved: [], warnings: [] } };
  const after = { ...before, id: 'after', createdAt: '2026-01-02T00:00:00Z' };
  const comparison = await compareScans(before, after, async () => Response.json({ results: [] }));
  let posted: unknown;
  globalThis.fetch = async (input, options) => {
    if (options?.method === 'POST') { posted = JSON.parse(String(options.body)); assert.equal(input, '/api/scans/after/comparison'); return Response.json(comparison, { status: 201 }); }
    if (input === '/api/scans') return Response.json({ scans: [before, after].map(scan => ({ ...scan, packages: 0, relationships: 0, warnings: 0, sourceFiles: 0 })) });
    return Response.json({ error: 'Not found' }, { status: 404 });
  };
  try {
    let view!: ReturnType<typeof render>;
    await act(async () => { view = render(React.createElement(RescanPanel, { scan: before })); });
    const button = view.getByRole('button', { name: 'Compare vulnerabilities' }) as HTMLButtonElement;
    assert.equal(button.disabled, true);
    fireEvent.change(view.getByLabelText('After scan'), { target: { value: 'after' } });
    assert.equal(button.disabled, true);
    fireEvent.click(view.getByRole('checkbox'));
    assert.equal(button.disabled, false);
    await act(async () => { fireEvent.click(button); });
    assert.deepEqual(posted, { beforeScanId: 'before', sameProject: true });
    assert.ok(view.getByText(/Resolved: 0/));
    assert.equal(view.getByRole('link', { name: 'Download comparison JSON' }).getAttribute('href'), '/api/scans/after/comparison');
    assert.ok(view.getByText(/No advisory differences/));
  } finally {
    cleanup(); globalThis.fetch = originalFetch;
    for (const [key, descriptor] of previous) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key); }
    dom.window.close();
  }
});

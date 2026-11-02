import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import React, { act } from 'react';
import { ScanForm } from '../frontend/src/ScanForm.js';
import { parseDependencies } from '../backend/src/dependencies.js';
import { generateSbom } from '../backend/src/sbom.js';

test('beginner scan form submits GitHub and ZIP sources and explains failures', async () => {
  const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost', pretendToBeVisual: true });
  const originalFetch = globalThis.fetch;
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, HTMLElement: dom.window.HTMLElement, File: dom.window.File, FormData: dom.window.FormData, IS_REACT_ACT_ENVIRONMENT: true, ResizeObserver: class { observe() {} unobserve() {} disconnect() {} }, requestAnimationFrame: dom.window.requestAnimationFrame.bind(dom.window), cancelAnimationFrame: dom.window.cancelAnimationFrame.bind(dom.window) })) {
    previous.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
  const { render, fireEvent, cleanup } = await import('@testing-library/react');
  const graph = parseDependencies([
    { path: 'package.json', data: { name: 'fixture', version: '1.0.0', dependencies: { dependency: '^2' } } },
    { path: 'package-lock.json', data: { lockfileVersion: 3, packages: { '': {}, 'node_modules/dependency': { version: '2.1.0' } } } },
  ]);
  const sbom = generateSbom(graph, '11111111-1111-4111-8111-111111111111', '2026-01-01T00:00:00.000Z');
  const result = { graph, sbom, id: '11111111-1111-4111-8111-111111111111', files: [{ path: 'package.json', kind: 'manifest', bytes: 2 }] };
  const calls: RequestInit[] = [];
  globalThis.fetch = async (input, options) => { if (input === '/api/scans/limits') return Response.json({ compressedBytes: 10 * 1024 * 1024 }); assert.equal(input, '/api/scans'); calls.push(options!); return Response.json(result, { status: 201 }); };
  try {
    const view = render(React.createElement(ScanForm));
    fireEvent.change(view.getByLabelText('Public GitHub link'), { target: { value: 'https://github.com/example/project' } });
    await act(async () => { fireEvent.submit(view.getByRole('button', { name: 'Scan My Project' }).closest('form')!); });
    assert.equal(JSON.parse(calls[0].body as string).url, 'https://github.com/example/project');
    assert.ok(view.getByText('Dependency inventory ready. Opening project results…'));
    fireEvent.change(view.getByLabelText('Project source'), { target: { value: 'zip' } });
    const file = new dom.window.File(['zip fixture'], 'project.zip', { type: 'application/zip' });
    fireEvent.change(view.getByLabelText('ZIP file (up to 10 MiB)'), { target: { files: [file] } });
    await act(async () => { fireEvent.submit(view.getByRole('button', { name: 'Scan My Project' }).closest('form')!); });
    assert.equal((calls[1].body as FormData).get('archive'), file);
    assert.ok(view.getByText('Dependency inventory ready. Opening project results…'));
    globalThis.fetch = async (input) => input === '/api/scans/limits' ? Response.json({ compressedBytes: 10 * 1024 * 1024 }) : Response.json({ error: 'archive exceeds compressed-size limit' }, { status: 400 });
    await act(async () => { fireEvent.submit(view.getByRole('button', { name: 'Scan My Project' }).closest('form')!); });
    assert.ok(view.getByRole('alert').textContent?.includes('Remove large generated folders'));
  } finally {
    cleanup(); dom.window.close(); globalThis.fetch = originalFetch;
    for (const [key, descriptor] of previous) { if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key); }
  }
});

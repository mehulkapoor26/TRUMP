import assert from 'node:assert/strict';
import test from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { PackageRiskPanel } from '../frontend/src/PackageRiskPanel.js';
import { checkPackageRisks } from '../backend/src/package-risk.js';

test('package signal interface shows uncertainty, metadata, hashes and provenance without interpreting publisher HTML', async () => {
  const report = await checkPackageRisks({ nodes: [{ id: 'instance', name: 'expres', version: '1.0.0', project: '.', installPath: 'node_modules/expres', direct: true, transitive: false, isProject: false, integrity: 'sha512-YQ==' }], edges: [], roots: [], unresolved: [], warnings: [] }, [], async () => Response.json({ name: 'expres', version: '1.0.0', description: '<script>bad()</script>', dist: { integrity: 'sha512-YQ==', attestations: { url: 'https://registry.npmjs.org/attestation' } } }));
  const html = renderToStaticMarkup(React.createElement(PackageRiskPanel, { report }));
  assert.match(html, /SUSPICIOUS/);
  assert.match(html, /NAME_SIMILARITY/);
  assert.match(html, /sha512-YQ==/);
  assert.match(html, /ADVERTISED/);
  assert.match(html, /NOT PERFORMED/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

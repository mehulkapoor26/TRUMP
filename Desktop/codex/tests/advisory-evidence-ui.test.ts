import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AdvisoryEvidence } from '../frontend/src/AdvisoryEvidence.js';
import type { VulnerabilityReport } from '@traceguard/shared';
import { AdvisoryMarkdown, advisoryImpact, advisorySentences } from '../frontend/src/advisory-content.js';

test('findings show CVE links and source severity while escaping advisory HTML', () => {
  const report: VulnerabilityReport = { source: 'OSV', checkedAt: '', status: 'complete', checks: [], warnings: [], advisories: { '["GHSA-fixture","lodash"]': { id: 'GHSA-fixture', source: 'https://api.osv.dev/v1/vulns/GHSA-fixture', verification: 'verified', summary: '<script>alert(1)</script>', description: '', aliases: ['CVE-2021-23337'], severityLabel: 'HIGH', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }], fixedVersions: [], references: [] } } };
  const html = renderToStaticMarkup(createElement(AdvisoryEvidence, { ids: ['GHSA-fixture'], name: 'lodash', report }));
  assert.match(html, /CVE-2021-23337/); assert.match(html, /Severity: HIGH/); assert.match(html, /CVSS:3.1/);
  assert.doesNotMatch(html, /<script>/); assert.match(html, /&lt;script&gt;/);
  const unknown = renderToStaticMarkup(createElement(AdvisoryEvidence, { ids: ['GHSA-fixture'], name: 'lodash' }));
  assert.match(unknown, /Unknown — details not verified/);
});

test('advisory Markdown renders safe formatting without interpreting raw HTML or unsafe links', () => {
  const html = renderToStaticMarkup(createElement(AdvisoryMarkdown, { source: '## Impact\n\n**High risk** in `parse()`; see [details](https://example.com/advisory).\n\n<script>alert(1)</script>\n\n[xss](javascript:alert(1))' }));
  assert.match(html, /<h4>Impact<\/h4>/); assert.match(html, /<strong>High risk<\/strong>/); assert.match(html, /<code>parse\(\)<\/code>/);
  assert.match(html, /href="https:\/\/example.com\/advisory"/); assert.doesNotMatch(html, /href="javascript:/); assert.doesNotMatch(html, /<script>/); assert.match(html, /&lt;script&gt;/);
});

test('advisory summary helper keeps only a concise source-derived sentence count', () => {
  assert.equal(advisorySentences('First sentence. Second sentence. Third sentence.', 2), 'First sentence. Second sentence.');
  assert.equal(advisorySentences('First sentence. Second sentence. Third sentence.', 2, 420, 1), 'Second sentence. Third sentence.');
  assert.equal(advisorySentences('Versions 17.21 and 0.2.4 are affected. An attacker may cause denial of service.', 2), 'Versions 17.21 and 0.2.4 are affected. An attacker may cause denial of service.');
  assert.equal(advisoryImpact('A crafted input may cause denial of service. Steps to reproduce: js, function setKey().', 'Example issue'), 'A crafted input may cause denial of service.');
  assert.match(advisoryImpact('Steps to reproduce: js, function setKey().', 'Prototype Pollution in minimist'), /Prototype Pollution in minimist/);
});

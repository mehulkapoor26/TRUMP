import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { ZipFile } from 'yazl';
import { once } from 'node:events';
import type { ScanResult, VulnerabilityReport } from '../../shared/src/index.js';

test('Python upload reuses graph and findings UI and explicitly disables JavaScript reachability', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  const zip = new ZipFile(); const chunks: Buffer[] = []; zip.outputStream.on('data', chunk => chunks.push(chunk)); const end = once(zip.outputStream, 'end');
  for (const name of ['pyproject.toml', 'poetry.lock', 'app.py']) zip.addBuffer(await readFile(`tests/fixtures/python/poetry/${name}`), name); zip.end(); await end;
  await page.goto('/#/scanner'); let graph: ScanResult['graph'];
  await page.route('**/api/scans/*/vulnerabilities', async route => {
    while (!graph) await new Promise(resolve => setTimeout(resolve, 10));
    const report: VulnerabilityReport = { source: 'OSV', checkedAt: new Date().toISOString(), status: 'partial', warnings: ['Controlled browser-test advisory data'], checks: graph.nodes.map(n => ({ nodeId: n.id, status: n.name === 'pyyaml' ? 'matched' : n.isProject ? 'unknown' : 'no-known', complete: !n.isProject, advisoryIds: n.name === 'pyyaml' ? ['GHSA-python-browser-fixture'] : [] })), advisories: { '["GHSA-python-browser-fixture","pyyaml","PyPI"]': { id: 'GHSA-python-browser-fixture', source: 'https://api.osv.dev/v1/vulns/GHSA-python-browser-fixture', verification: 'verified', summary: 'Simulated browser fixture', description: '', aliases: ['CVE-2020-14343'], severityLabel: 'CRITICAL', severity: [], affectedVersions: ['ECOSYSTEM: introduced 0; fixed 5.4'], fixedVersions: ['5.4'], references: [] } } };
    return route.fulfill({ json: report });
  });
  await page.getByRole('combobox', { name: 'Project source', exact: true }).selectOption('zip');
  await page.getByLabel(/ZIP file \(up to .* MiB\)/).setInputFiles({ name: 'controlled-python.zip', mimeType: 'application/zip', buffer: Buffer.concat(chunks) });
  const created = page.waitForResponse(r => r.url().endsWith('/api/scans') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Scan My Project', exact: true }).click(); const scan = await (await created).json() as ScanResult; graph = scan.graph!;
  expect(scan.ecosystems).toEqual(['PyPI']); await expect(page.getByRole('heading', { name: 'Project scan results', exact: true })).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Workspace navigation' }); await nav.getByRole('link', { name: 'Dependency map' }).click();
  await expect(page.locator('.react-flow__node')).toHaveCount(7); await expect(page.locator('.react-flow__edge')).toHaveCount(6);
  await page.getByLabel('Find a package instance').fill('pyyaml'); await page.getByRole('button', { name: /pyyaml@5.3.1/ }).click();
  const region = page.getByRole('region', { name: 'Scoped function reachability' }); await expect(region.getByRole('status')).toContainText('UNKNOWN');
  await expect(region).toContainText('JavaScript AST analyzer does not analyze Python'); await expect(region.getByRole('button', { name: 'Analyze scoped reachability' })).toHaveCount(0);
  // This route controls only the advisory service response; scans and reports use the app API.
  await nav.getByRole('link', { name: /Security findings/ }).click(); await page.getByRole('button', { name: 'Check security findings' }).click();
  const finding = page.locator('.finding-card').filter({ hasText: 'pyyaml' });
  await expect(finding).toContainText('CRITICAL'); await expect(finding).toContainText('UNKNOWN');
  const technical = finding.getByText('View full technical details'); await expect(technical).toBeVisible();
  await technical.click(); await expect(finding).toContainText('CVE-2020-14343');
  expect(errors).toEqual([]);
});

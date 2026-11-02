import { chromium, expect } from '@playwright/test';
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

const summary = JSON.parse(await readFile('artifacts/published-demo/summary.json', 'utf8'));
if (summary.incomplete.length || !summary.scanId) throw new Error('Run npm run demo:live successfully before the browser verification.');
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_EXECUTABLE ?? (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) });
const errors = []; const checks = [];
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(`${summary.base}/#/scanner`);
  await expect(page.getByRole('heading', { level: 1, name: 'Scan your project', exact: true })).toBeVisible(); checks.push('scanner accessible');
  await page.goto(summary.findings);
  const responsePromise = page.waitForResponse(r => r.url().endsWith('/vulnerabilities') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Check security findings' }).click();
  const response = await responsePromise; expect(response.status()).toBe(200);
  await page.getByLabel('Filter findings by status').selectOption('matched');
  await expect(page.locator('.finding-card')).toHaveCount(2);
  const lodashFinding = page.locator('.finding-card').filter({ hasText: 'lodash' }).first();
  await expect(lodashFinding).toContainText('HIGH');
  await expect(lodashFinding.locator('.finding-advisory').filter({ hasText: 'GHSA-29mw-wpgm-hmr9' }).locator('.reachability-badge')).toHaveText('REACHABLE');
  await lodashFinding.getByText('View full technical details').first().click();
  await expect(lodashFinding).toContainText('CVE-2021-23337');
  await expect(lodashFinding).toContainText('GHSA-35jh-r3h4-6jhm');
  await expect(page.getByText('Unique advisory IDs')).toBeVisible();
  await page.getByLabel('Search findings').fill('CVE-2021-23337'); await expect(page.locator('.finding-card')).toHaveCount(1);
  await page.getByLabel('Search findings').fill(''); await page.getByLabel('Filter findings by status').selectOption('no-known');
  await expect(page.locator('.finding-card')).toHaveCount(6);
  await page.getByLabel('Filter findings by status').selectOption('all');
  await page.screenshot({ path: 'artifacts/published-demo/findings.png', fullPage: true });
  checks.push('live OSV/CVE links and severity rendered', 'CVE search and matched/no-known filters');

  const nav = page.getByRole('navigation', { name: 'Workspace navigation' });
  await nav.getByRole('link', { name: 'Dependency map' }).click();
  await expect(page.locator('.react-flow__node')).toHaveCount(9); await expect(page.locator('.react-flow__edge')).toHaveCount(8);
  await page.getByLabel('Find a package instance').fill('lodash');
  await page.getByRole('button', { name: /lodash@4.17.20/ }).click();
  await expect(page.getByRole('complementary', { name: 'Selected package details' })).toContainText('lodash@4.17.20');
  await page.screenshot({ path: 'artifacts/published-demo/graph.png', fullPage: true }); checks.push('interactive 9-node/8-edge graph and package selection');

  await nav.getByRole('link', { name: 'Project results', exact: true }).click();
  const download = page.waitForEvent('download'); await page.getByRole('link', { name: 'Download Security Findings (PDF)', exact: true }).click();
  await (await download).saveAs('artifacts/published-demo/security-findings-ui.pdf');
  await page.screenshot({ path: 'artifacts/published-demo/dashboard.png', fullPage: true }); checks.push('saved report status and PDF download through UI');
  expect(errors).toEqual([]);
} finally { await browser.close(); }
await writeFile('artifacts/published-demo/browser.json', JSON.stringify({ verifiedAt: new Date().toISOString(), mode: 'Real running website, no network interception or mocked responses', checks, errors }, null, 2));
console.log(JSON.stringify({ checks, errors, dashboard: summary.dashboard }, null, 2));
if (process.argv.includes('--open')) execFileSync('open', [summary.dashboard]);

import { chromium, expect } from '@playwright/test';
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

const summary = JSON.parse(await readFile('artifacts/python-demo/summary.json', 'utf8'));
if (summary.incomplete.length || !summary.dashboard) throw new Error('Run npm run demo:python successfully first.');
const scan = JSON.parse(await readFile('artifacts/python-demo/scan.json', 'utf8'));
const base = new URL(summary.dashboard).origin;
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_EXECUTABLE ?? (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) });
const errors = []; const checks = [];
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } }); page.on('pageerror', error => errors.push(error.message));
  await page.goto(summary.findings);
  const checked = page.waitForResponse(r => r.url().endsWith('/vulnerabilities') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Check vulnerability advisories' }).click(); expect((await checked).status()).toBe(200);
  await expect(page.getByRole('link', { name: 'CVE-2020-14343', exact: true }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'GHSA-8q59-q68h-6hv4', exact: true }).first()).toBeVisible();
  await page.screenshot({ path: 'artifacts/python-demo/findings.png', fullPage: true }); checks.push('real live PyPI OSV/CVE findings');
  const nav = page.getByRole('navigation', { name: 'Workspace navigation' }); await nav.getByRole('link', { name: 'Dependency graph' }).click();
  await expect(page.locator('.react-flow__node')).toHaveCount(scan.graph.nodes.length); await expect(page.locator('.react-flow__edge')).toHaveCount(6);
  await page.getByLabel('Find a package instance').fill('pyyaml'); await page.getByRole('button', { name: /pyyaml@5.3.1/ }).click();
  const reachability = page.getByRole('region', { name: 'Scoped function reachability' }); await expect(reachability.getByRole('status')).toContainText('UNKNOWN'); await expect(reachability).toContainText('JavaScript AST analyzer does not analyze Python');
  await expect(reachability.getByRole('button')).toHaveCount(0); checks.push('interactive Python graph and explicit unsupported reachability');
  await page.goto(summary.dashboard); await expect(page.getByRole('status').filter({ hasText: 'Generated' })).toBeVisible();
  const fixes = page.getByLabel('Verified fixes and manual review'); await expect(fixes).toContainText('pyyaml@5.3.1'); await expect(fixes).toContainText('VERIFIED CANDIDATE: 5.4');
  const download = page.waitForEvent('download'); await page.getByRole('link', { name: 'Download PDF', exact: true }).first().click(); await (await download).saveAs('artifacts/python-demo/security-findings-ui.pdf');
  await page.screenshot({ path: 'artifacts/python-demo/dashboard.png', fullPage: true }); checks.push('verified PyPI candidate displayed and report downloaded');
  expect(errors).toEqual([]);
} finally { await browser.close(); }
await writeFile('artifacts/python-demo/browser.json', JSON.stringify({ verifiedAt: new Date().toISOString(), base, checks, errors, network: 'live; no mocked responses' }, null, 2));
console.log(JSON.stringify({ checks, errors, dashboard: summary.dashboard }, null, 2));
if (process.argv.includes('--open')) execFileSync('open', [summary.dashboard]);

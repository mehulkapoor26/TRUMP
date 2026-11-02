import { test, expect } from '@playwright/test';

test('judge demo shows its simulation label, saved evidence and downloadable reports in the built UI', async ({ page, request }) => {
  const response = await request.get('/api/demo'); const demo = await response.json();
  expect(demo.incomplete).toEqual([]);
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(`/#/scans/${demo.beforeScanId}/overview`);
  await expect(page.getByText('OFFLINE JUDGE DEMO —', { exact: false })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: 'Generated' })).toContainText('1 matched');
  const pdf = page.getByRole('link', { name: 'Download PDF', exact: true }).first();
  const download = page.waitForEvent('download'); await pdf.click();
  expect((await download).suggestedFilename()).toBe(`traceguard-${demo.beforeScanId}-security-findings.pdf`);
  const nav = page.getByRole('navigation', { name: 'Workspace navigation' });
  await nav.getByRole('link', { name: 'Dependency graph' }).click();
  await page.getByRole('button', { name: 'Check vulnerability advisories' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'OSV lookup:' })).toContainText('1 package instances with advisory matches');
  expect(errors).toEqual([]);
});

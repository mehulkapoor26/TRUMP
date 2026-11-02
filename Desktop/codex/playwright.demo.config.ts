import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/demo',
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:4173', headless: true, launchOptions: { executablePath: process.env.CHROME_EXECUTABLE ?? (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined) } },
  webServer: { command: 'npm run demo', url: 'http://127.0.0.1:4173/api/demo', reuseExistingServer: false, timeout: 60_000 },
});

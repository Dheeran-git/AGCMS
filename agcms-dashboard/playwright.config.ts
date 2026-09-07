import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,         // run sequentially — single stack
  retries: 1,
  timeout: 30_000,
  reporter: 'list',
  use: {
    baseURL: process.env.AGCMS_DASHBOARD_URL || 'http://localhost:4173',
    headless: true,
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

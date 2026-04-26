/**
 * EP Playwright E2E Configuration
 * @license Apache-2.0
 *
 * Smoke tests for critical user-facing pages.
 * Runs against the local Next.js dev server.
 */

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 30_000,

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // In CI, run against the production server (`npm run build` happens in the
  // workflow step ahead of `playwright test`, so this just boots the built
  // bundle). Locally, run against `npm run dev` for fast iteration. The dev
  // server's startup cost + hot-reload noise was the root cause of flaky CI
  // boots; the production server boots in ~3s and behaves exactly like prod.
  webServer: {
    command: process.env.CI ? 'npm run start' : 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});

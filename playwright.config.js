/**
 * EP Playwright E2E Configuration
 * @license Apache-2.0
 *
 * Smoke tests for critical user-facing pages.
 * Runs against the local Next.js dev server.
 */

import { defineConfig, devices } from '@playwright/test';

const agentRecordE2eEnvironment = {
  NEXT_PUBLIC_SUPABASE_URL: 'http://127.0.0.1:54321',
  NEXT_PUBLIC_SUPABASE_ANON_KEY: 'e2e-anon-key',
  SUPABASE_SERVICE_ROLE_KEY: 'e2e-service-role-key',
  EP_COMMIT_SIGNING_KEY: Buffer.alloc(32, 1).toString('base64'),
  EP_AGENT_RECORD_SIGNING_KEY_ID: 'e2e-agent-record-signing-key',
  EP_AGENT_RECORD_CREATION_CAPABILITY: `earc1_${'0'.repeat(64)}`,
  UPSTASH_REDIS_REST_URL: 'http://127.0.0.1:54321/upstash',
  UPSTASH_REDIS_REST_TOKEN: 'e2e-upstash-token',
};

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
  webServer: process.env.CI
    ? [
        {
          command: 'node e2e/agent-record-readiness-stub.mjs',
          url: 'http://127.0.0.1:54321/health',
          reuseExistingServer: false,
          timeout: 30_000,
        },
        {
          command: 'npm run start',
          url: 'http://localhost:3000',
          reuseExistingServer: false,
          timeout: 120_000,
          env: agentRecordE2eEnvironment,
        },
      ]
    : {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: true,
        timeout: 120_000,
      },
});

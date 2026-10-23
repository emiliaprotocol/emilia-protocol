// SPDX-License-Identifier: Apache-2.0
//
// Evidence run for the OrcaRouter Cyber Inference provider surface. This is a
// dedicated config so the regular e2e suite is untouched, and it targets the
// provider settings page against a real Next.js dev server whose catalog comes
// from the authoritative OrcaRouter endpoint.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// The settings surface requires a signed internal administrator session. These
// are throw-away automation identities, not deployment secrets; a real
// verification environment may override them.
process.env.TRUST_DESK_SESSION_SECRET ||= 'orca-evidence-session-secret-0123456789abcdef';
process.env.TRUST_DESK_REVIEWER_ID ||= 'orca-evidence-admin';

const PORT = Number(process.env.ORCA_EVIDENCE_PORT || 3107);
const chromium = ['/usr/bin/chromium', '/usr/bin/chromium-browser'].find((candidate) => fs.existsSync(candidate));

export default defineConfig({
  testDir: './e2e',
  testMatch: 'orca-evidence.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 30_000 },
  reporter: [['list']],
  outputDir: path.join(os.tmpdir(), 'orca-evidence-results'),
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1280, height: 900 },
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    launchOptions: {
      ...(chromium ? { executablePath: chromium } : {}),
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npx next dev --webpack --port ${PORT} --hostname 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}/internal/trust-desk/providers`,
    reuseExistingServer: false,
    timeout: 240_000,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      ORCAROUTER_PROVIDER_ADMIN: '1',
      ORCAROUTER_STATE_DIR: path.join(os.tmpdir(), `orca-evidence-state-${process.pid}`),
    },
  },
});

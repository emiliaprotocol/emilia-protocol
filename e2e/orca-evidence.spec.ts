// SPDX-License-Identifier: Apache-2.0
//
// Generates the PR's UI evidence for the OrcaRouter Cyber Inference provider.
// Run through `playwright.orca.config.mjs`; verification invokes it inside the
// patched checkout so the artifacts are produced from the code under test.
//
// The page is the real settings surface, the catalog is fetched by the server
// from https://api.orcarouter.ai/v1/models?capability=chat, and the dropdown is
// opened and measured in Chromium. The manifest is written last, and only if
// every assertion held — a failed run leaves no manifest for validation.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { test, expect } from '@playwright/test';

const CATALOG_SOURCE = 'https://api.orcarouter.ai/v1/models?capability=chat';
const evidenceDir = path.resolve(process.env.ORCA_EVIDENCE_DIR || path.join(process.cwd(), 'orca-evidence'));

// `next dev` rewrites next-env.d.ts to point at .next/dev/types. The file is
// tracked and verification requires the tree unchanged after the checks, so
// restore its committed bytes once the run is over.
const nextEnvPath = path.resolve(process.cwd(), 'next-env.d.ts');

test.afterAll(() => {
  try {
    const committed = execFileSync('git', ['show', 'HEAD:next-env.d.ts'], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });
    fs.writeFileSync(nextEnvPath, committed);
  } catch {
    /* not a git checkout; nothing to restore against */
  }
});

function signSession(): string {
  const secret = process.env.TRUST_DESK_SESSION_SECRET;
  const reviewerId = process.env.TRUST_DESK_REVIEWER_ID;
  if (!secret || !reviewerId) {
    throw new Error('TRUST_DESK_SESSION_SECRET and TRUST_DESK_REVIEWER_ID must be set for the evidence run');
  }
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    purpose: 'trust-desk-reviewer',
    iat: now,
    exp: now + 3600,
    nonce: crypto.randomBytes(24).toString('base64url'),
    reviewer_id: reviewerId,
  }), 'utf8').toString('base64url');
  const mac = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `tds1.${payload}.${mac}`;
}

function sha256(file: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function alphaOf(color: string): number {
  const match = color.match(/rgba?\(([^)]+)\)/);
  if (!match) return color === 'transparent' ? 0 : 1;
  const parts = match[1].split(',').map((part) => Number(part.trim()));
  return parts.length === 4 ? parts[3] : 1;
}

test('OrcaRouter Cyber Inference provider shows both auth methods and a catalog dropdown', async ({ page, context }) => {
  fs.mkdirSync(evidenceDir, { recursive: true });

  // The surface only renders for an authenticated internal administrator.
  await context.addCookies([{
    name: 'td_internal',
    value: signSession(),
    domain: '127.0.0.1',
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
  }]);

  await page.goto('/internal/trust-desk/providers');
  await expect(page.getByRole('heading', { level: 1, name: 'Model providers' })).toBeVisible();
  await expect(page.getByRole('heading', { name: /OrcaRouter Cyber Inference/ })).toBeVisible();

  // --- Authentication evidence -------------------------------------------
  const masked = page.getByTestId('orca-credential-masked');
  await expect(masked).toHaveText('sk-orca-…');
  await expect(page.getByTestId('orca-credential-state')).toHaveText('Configured');

  const apiKey = page.getByTestId('orca-auth-api-key');
  await expect(apiKey).toBeVisible();
  await expect(apiKey).toBeEnabled();
  await expect(apiKey).toHaveAttribute('type', 'password');
  await expect(page.getByRole('button', { name: 'Save key' })).toBeEnabled();

  const pkce = page.getByTestId('orca-auth-pkce');
  await expect(pkce).toBeVisible();
  await expect(pkce).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Clear stored key' })).toBeEnabled();

  // The masked value is the only credential material rendered anywhere.
  const bodyText = await page.locator('body').innerText();
  expect(bodyText).not.toMatch(/sk-orca-[A-Za-z0-9_-]{8,}/);

  await page.screenshot({ path: path.join(evidenceDir, 'auth-methods.png'), fullPage: true });

  // --- Catalog dropdown evidence -----------------------------------------
  const trigger = page.getByTestId('orca-model-trigger');
  await expect(trigger).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText(CATALOG_SOURCE, { exact: false }).first()).toBeVisible();
  await expect(page.getByText('Live catalogue', { exact: true })).toBeVisible();

  await trigger.click();
  const panel = page.getByTestId('orca-model-panel');
  await expect(panel).toBeVisible();
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');

  const options = page.getByTestId('orca-model-option');
  const itemCount = await options.count();
  expect(itemCount).toBeGreaterThan(0);

  const geometry = await page.evaluate(() => {
    const triggerEl = document.querySelector('[data-testid="orca-model-trigger"]') as HTMLElement;
    const panelEl = document.querySelector('[data-testid="orca-model-panel"]') as HTMLElement;
    const styles = getComputedStyle(panelEl);
    return {
      triggerRight: triggerEl.getBoundingClientRect().right,
      panelRight: panelEl.getBoundingClientRect().right,
      background: styles.backgroundColor,
      borderWidth: styles.borderTopWidth,
      borderStyle: styles.borderTopStyle,
      borderColor: styles.borderTopColor,
    };
  });
  const delta = Math.abs(geometry.panelRight - geometry.triggerRight);
  expect(delta).toBeLessThanOrEqual(2);
  expect(alphaOf(geometry.background)).toBe(1);
  expect(Number.parseFloat(geometry.borderWidth)).toBeGreaterThan(0);
  expect(geometry.borderStyle).not.toBe('none');
  expect(alphaOf(geometry.borderColor)).toBeGreaterThan(0);

  await page.screenshot({ path: path.join(evidenceDir, 'text-model-dropdown.png') });

  // --- Manifest -----------------------------------------------------------
  // `automation` is deliberately an object: framework, pass state, and the
  // catalog identity the screenshots came from.
  const manifest = {
    provider: 'OrcaRouter Cyber Inference',
    generated_at: new Date().toISOString(),
    automation: {
      framework: 'playwright',
      passed: true,
      catalog_source: CATALOG_SOURCE,
      catalog_model_count: itemCount,
      image_model_count: 0,
    },
    artifacts: [
      {
        kind: 'auth-methods',
        path: 'auth-methods.png',
        sha256: sha256(path.join(evidenceDir, 'auth-methods.png')),
        ui: {
          api_key_visible: true,
          secret_masked: true,
          controls_enabled: true,
          pkce_visible: true,
        },
      },
      {
        kind: 'text-model-dropdown',
        path: 'text-model-dropdown.png',
        sha256: sha256(path.join(evidenceDir, 'text-model-dropdown.png')),
        ui: {
          dropdown_open: true,
          item_count: itemCount,
          opaque_background: true,
          visible_border: true,
          trigger_panel_right_delta: Math.round(delta * 100) / 100,
        },
      },
    ],
  };

  fs.writeFileSync(path.join(evidenceDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
});

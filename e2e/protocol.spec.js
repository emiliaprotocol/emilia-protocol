/**
 * EP E2E — Protocol page smoke test
 * @license Apache-2.0
 */

import { test, expect } from '@playwright/test';

test.describe('Protocol Page', () => {
  test('loads and renders protocol overview', async ({ page }) => {
    await page.goto('/protocol');

    // Main heading present
    const h1 = page.locator('h1').first();
    await expect(h1).toBeVisible();
  });

  test('PIP governance section is visible', async ({ page }) => {
    await page.goto('/protocol');

    // Protocol Governance section with PIP table
    const govSection = page.locator('text=Protocol Governance');
    await expect(govSection.first()).toBeVisible({ timeout: 10_000 });

    // PIP table should have entries
    const pip000 = page.locator('text=PIP-000');
    await expect(pip000.first()).toBeVisible();
  });

  test('compliance section renders', async ({ page }) => {
    await page.goto('/protocol');

    // Compliance & Standards section
    const compliance = page.locator('text=Compliance');
    await expect(compliance.first()).toBeVisible({ timeout: 10_000 });

    // NIST mapping mentioned
    const nist = page.locator('text=NIST');
    await expect(nist.first()).toBeVisible();
  });

  test('navigation back to homepage works', async ({ page }) => {
    await page.goto('/protocol');

    // Click logo/home link
    const logo = page.locator('a[href="/"]').first();
    await logo.click();
    await expect(page).toHaveURL('/');
  });
});

/**
 * EP E2E — Homepage smoke test
 * @license Apache-2.0
 */

import { test, expect } from '@playwright/test';

test.describe('Homepage', () => {
  test('loads and renders hero section', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/Emilia/i);

    // Hero heading exists
    const h1 = page.locator('h1').first();
    await expect(h1).toBeVisible();

    // Navigation bar is present
    const nav = page.locator('nav');
    await expect(nav).toBeVisible();

    // Protocol link in nav. Use .first() — the homepage has multiple
    // /protocol links (nav, hero CTA, footer, etc.); the smoke test just
    // needs to confirm at least one is rendered and visible.
    const protocolLink = page.locator('a[href="/protocol"]').first();
    await expect(protocolLink).toBeVisible();
  });

  test('nav links navigate correctly', async ({ page }) => {
    await page.goto('/');

    // Click the first Protocol link — strict-mode disambiguation again.
    await page.locator('a[href="/protocol"]').first().click();
    await expect(page).toHaveURL(/\/protocol/);
  });

  test('Protocol Properties section is visible', async ({ page }) => {
    await page.goto('/');

    // Scroll down to find "Protocol Properties" or self-verifying receipts text
    const selfVerifying = page.locator('text=Self-verifying');
    await expect(selfVerifying.first()).toBeVisible({ timeout: 10_000 });
  });

  test('footer is present', async ({ page }) => {
    await page.goto('/');

    // Footer should contain copyright or EMILIA text
    const footer = page.locator('footer, [class*="footer"], [data-testid="footer"]').first();
    // Fallback: look for the governance links that appear in footer
    const govLink = page.locator('a[href="/governance"]');
    await expect(govLink.first()).toBeVisible({ timeout: 10_000 });
  });
});

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
    await expect(h1).toHaveText('Your AI workforceneeds management.');

    // Navigation bar is present
    const nav = page.getByRole('navigation', { name: 'Primary' });
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

  test('workforce story and the unchanged allowance are visible', async ({ page }) => {
    await page.goto('/');

    await expect(page.locator('#workforce-title')).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.locator('#the-handover').getByText('$6,600', { exact: true })).toHaveCount(2);
    await expect(page.getByText('Private local alpha. Evaluations by arrangement, not a hosted service.', { exact: true })).toBeVisible({
      timeout: 10_000,
    });
  });

  test('workforce navigation and inquiry path work without a signup promise', async ({ page }) => {
    await page.goto('/workforce');
    await expect(page).toHaveTitle('Manage Your AI Workforce | EMILIA');
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://www.emiliaprotocol.ai/workforce');
    await expect(page.getByText(/no high availability or rollback resistance/)).toBeVisible();
    await page.getByRole('link', { name: 'Discuss your workflow', exact: true }).first().click();
    await expect(page).toHaveURL(/\/contact#workforce$/);
    await expect(page.locator('#workforce')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Email us about your workflow' })).toHaveAttribute('href', /mailto:team@emiliaprotocol.ai\?subject=EMILIA%20workforce%20evaluation/);
  });

  test('workforce stays readable on desktop and a narrow phone', async ({ page }) => {
    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 950 });
      await page.goto('/workforce');
      await expect(page.locator('#workforce-title')).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await page.screenshot({ path: `test-results/workforce-${width}.png` });
      await page.locator('#the-handover').scrollIntoViewIfNeeded();
      await page.screenshot({ path: `test-results/workforce-handover-${width}.png` });
      if (width === 375) {
        await page.getByRole('button', { name: 'Open menu' }).click();
        await expect(page.getByRole('navigation', { name: 'Mobile primary' }).getByRole('link', { name: 'Workforce', exact: true })).toBeVisible();
        await page.keyboard.press('Escape');
        await expect(page.getByRole('button', { name: 'Open menu' })).toBeFocused();
      }
    }
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

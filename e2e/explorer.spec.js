/**
 * EP E2E — Trust Explorer smoke test
 * @license Apache-2.0
 */

import { test, expect } from '@playwright/test';

test.describe('Trust Explorer', () => {
  test('loads and renders search interface', async ({ page }) => {
    await page.goto('/explorer');

    // Hero text
    const heading = page.locator('h1');
    await expect(heading).toContainText('Verify anything');

    // Tab bar is present with three tabs
    const receiptTab = page.locator('button', { hasText: 'Verify Receipt' });
    const proofTab = page.locator('button', { hasText: 'Verify Proof' });
    const entityTab = page.locator('button', { hasText: 'Trust Profile' });

    await expect(receiptTab).toBeVisible();
    await expect(proofTab).toBeVisible();
    await expect(entityTab).toBeVisible();
  });

  test('tab switching updates placeholder', async ({ page }) => {
    await page.goto('/explorer');

    // Default tab: receipt
    const input = page.locator('input[type="text"]');
    await expect(input).toHaveAttribute('placeholder', /ep_r_/);

    // Switch to proof tab
    await page.click('button:has-text("Verify Proof")');
    await expect(input).toHaveAttribute('placeholder', /ep_zkp_/);

    // Switch to entity tab
    await page.click('button:has-text("Trust Profile")');
    await expect(input).toHaveAttribute('placeholder', /ep_entity_/);
  });

  test('search form submits and handles not-found', async ({ page }) => {
    await page.goto('/explorer');

    const input = page.locator('input[type="text"]');
    await input.fill('ep_r_nonexistent_test_id_12345');

    const button = page.locator('button[type="submit"]');
    await button.click();

    // Should show error state (not found or network error)
    const errorOrResult = page.locator('text=/Not found|Network error|error/i');
    await expect(errorOrResult.first()).toBeVisible({ timeout: 10_000 });
  });

  test('How verification works section is visible', async ({ page }) => {
    await page.goto('/explorer');

    const howSection = page.locator('text=How verification works');
    await expect(howSection).toBeVisible();

    // Three steps: Signature check, Merkle proof, On-chain anchor
    const sigCheck = page.locator('text=Signature check');
    await expect(sigCheck).toBeVisible();
  });
});

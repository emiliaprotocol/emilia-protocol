/**
 * EP E2E — Gate-first protocol hub
 * @license Apache-2.0
 */

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const standardsStatus = JSON.parse(readFileSync(resolve(process.cwd(), 'standards/STATUS.json'), 'utf8'));

test.describe('Protocol Page', () => {
  test('leads with Gate and renders the canonical four-document path', async ({ page }) => {
    await page.goto('/protocol');

    await expect(page.getByRole('heading', { level: 1, name: 'Gate exact actions before consequences.' })).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Four documents. One evidence path.' })).toBeVisible();

    const expectedDocuments = standardsStatus.canonical_four_document_surface.documents.map((document) => [
      `canonical-document-${document.order}`,
      document.label,
      `${document.draft}-${document.revision}`,
    ] as const);

    for (const [testId, label, revision] of expectedDocuments) {
      const document = page.getByTestId(testId);
      await expect(document).toContainText(label);
      await expect(document).toContainText(revision);
    }
  });

  test('links the canonical path to the two local explainers', async ({ page }) => {
    await page.goto('/protocol');

    await expect(page.getByTestId('canonical-document-1').getByRole('link')).toHaveAttribute('href', '/spec');
    await expect(page.getByTestId('canonical-document-4').getByRole('link')).toHaveAttribute('href', '/evidence-chain');
  });

  test('keeps complete-mediation and evidence-decision boundaries visible', async ({ page }) => {
    await page.goto('/protocol');

    await expect(page.getByRole('heading', { name: 'Evidence is an input to authorization, not a synonym for it.' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'A protected path is not proof of complete mediation.' })).toBeVisible();
    await expect(page.getByText(/verified bypass overrides a successful blocked-path demonstration/i)).toBeVisible();
  });

  test('does not add the canonical document set to the top navigation', async ({ page }) => {
    await page.goto('/protocol');

    const topNav = page.locator('header nav');
    await expect(topNav.getByText('Human Authorization Binding')).toHaveCount(0);
    await expect(topNav.getByText('Authority Introduction')).toHaveCount(0);
    await expect(topNav.getByText('Authorization Evidence Chain')).toHaveCount(0);
  });

  test('navigation back to homepage works', async ({ page }) => {
    await page.goto('/protocol');

    const logo = page.locator('a[href="/"]').first();
    await logo.click();
    await expect(page).toHaveURL('/');
  });
});

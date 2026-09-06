// SPDX-License-Identifier: Apache-2.0
import { test, expect } from '@playwright/test';

test.describe('marketplace entry', () => {
  test.skip(process.env.WORKS_V0 !== '1', 'Run this feature-gated suite with WORKS_V0=1.');

  test('scan sample, local download, edit invalidation and clear', async ({ page }) => {
    await page.goto('/works/scan');
    await page.getByRole('button', { name: 'Try a synthetic example' }).click();
    await page.getByRole('button', { name: 'Scan declarations, free' }).click();
    await expect(page.getByRole('heading', { name: '3 declared actions. Actual behavior unknown.' })).toBeVisible();
    await expect(page.getByText('Potential consequential action', { exact: true })).toBeVisible();
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download JSON report' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('emilia-declared-action-scan.json');
    const stream = await download.createReadStream();
    expect(stream).not.toBeNull();
    const chunks: Buffer[] = [];
    for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
    const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    expect(report.example).toBe('SYNTHETIC_EXAMPLE');
    expect(report.source.input_sha256).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(report.scope.enforcement).toBe('UNKNOWN');
    expect(report.scope.certification).toBe('NONE');
    await page.getByLabel('Or paste JSON').fill('{broken');
    await expect(page.getByRole('button', { name: 'Download JSON report' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Scan declarations, free' }).click();
    await expect(page.locator('main').getByRole('alert')).toContainText('Invalid JSON');
    await page.getByRole('button', { name: 'Clear', exact: true }).click();
    await expect(page.getByLabel('Or paste JSON')).toHaveValue('');
    await expect(page.locator('main').getByRole('alert')).toHaveCount(0);
  });

  test('does not transmit declaration text and renders hostile text literally', async ({ page }) => {
    await page.goto('/works/scan');
    const marker = 'PRIVATE_SCAN_SENTINEL_b814a';
    const transmitted: string[] = [];
    page.on('request', request => transmitted.push(request.url() + (request.postData() || '')));
    const description = `${marker} <img src=x onerror="window.scanInjected=true">`;
    await page.getByLabel('Or paste JSON').fill(JSON.stringify({ actions: [{ name: 'unknown_action', description }] }));
    await page.getByRole('button', { name: 'Scan declarations, free' }).click();
    await expect(page.getByRole('heading', { name: '1 declared actions. Actual behavior unknown.' })).toBeVisible();
    await expect(page.getByText(description, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => Object.hasOwn(window, 'scanInjected'))).toBe(false);
    expect(transmitted.some(text => text.includes(marker))).toBe(false);
    expect(await page.evaluate(() => Object.keys(localStorage).some(key => localStorage.getItem(key)?.includes('PRIVATE_SCAN_SENTINEL')))).toBe(false);
    expect(await page.evaluate(() => Object.keys(sessionStorage).some(key => sessionStorage.getItem(key)?.includes('PRIVATE_SCAN_SENTINEL')))).toBe(false);
  });

  test('JSON file selection is local and oversized files are refused', async ({ page }) => {
    await page.goto('/works/scan');
    await page.getByLabel('Choose JSON file').setInputFiles({ name: 'agent.json', mimeType: 'application/json', buffer: Buffer.from('["delete_customer"]') });
    await expect(page.getByLabel('Or paste JSON')).toHaveValue('["delete_customer"]');
    await page.getByRole('button', { name: 'Scan declarations, free' }).click();
    await expect(page.getByRole('button', { name: 'Download JSON report' })).toBeVisible();
    await page.getByLabel('Choose JSON file').setInputFiles({ name: 'large.json', mimeType: 'application/json', buffer: Buffer.alloc(1_048_577, 32) });
    await expect(page.locator('main').getByRole('alert')).toContainText('too large');
    await expect(page.getByRole('button', { name: 'Download JSON report' })).toHaveCount(0);
  });

  test('paid setup is quote-first and never implies a charge or qualification', async ({ page }) => {
    await page.goto('/works/gate');
    await expect(page.getByRole('heading', { name: 'No charge until you agree.' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Ask for a Gate setup quote' })).toHaveAttribute('href', /^mailto:team@emiliaprotocol.ai\?subject=/);
    await expect(page.getByText(/Self-service checkout is not open/)).toBeVisible();
    await expect(page.getByRole('heading', { name: 'The test result is not for sale.' })).toBeVisible();
    await expect(page.locator('a[href*="checkout.stripe"],a[href*="buy.stripe"]')).toHaveCount(0);
    await page.getByRole('link', { name: 'Run a free browser scan' }).click();
    await expect(page).toHaveURL(/\/works\/scan$/);
  });

  test('qualification requires explicit upload consent and clears old results', async ({ page }) => {
    await page.goto('/works/qualification');
    await page.getByLabel('Registered scope ID').fill('unregistered-test-scope');
    await page.getByLabel('Evidence bundle JSON').fill('{}');
    await expect(page.getByRole('button', { name: 'Verify evidence', exact: true })).toBeDisabled();
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Verify evidence', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'No qualification result available' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Qualified for this test scope', exact: true })).toHaveCount(0);
    await page.getByLabel('Evidence bundle JSON').fill('{"changed":true}');
    await expect(page.locator('#qualification-result-title')).toHaveCount(0);
    await expect(page.getByRole('checkbox')).not.toBeChecked();
    await expect(page.getByRole('button', { name: 'Verify evidence', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Clear evidence' }).click();
    await expect(page.getByLabel('Registered scope ID')).toHaveValue('');
    await expect(page.getByLabel('Evidence bundle JSON')).toHaveValue('');
  });

  test('marketplace, scanner, offer and qualification fit desktop and a narrow phone', async ({ page }) => {
    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 950 });
      for (const path of ['/works', '/works/scan', '/works/gate', '/works/qualification']) {
        await page.goto(path);
        await expect(page.locator('main h1')).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await page.screenshot({ path: `test-results/marketplace-${path.replaceAll('/', '-')}-${width}.png` });
      }
    }
  });
});

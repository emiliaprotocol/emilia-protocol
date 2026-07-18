// SPDX-License-Identifier: Apache-2.0

import { expect, test } from '@playwright/test';

const LOCK_ID = 'rl_demo_kitchen_milestone_01';
const LOCK_PATH = `/release-lock/${LOCK_ID}`;
const DEMO_STATE_KEY = 'emilia_release_lock_demo_v2';

const CORRECT_MIRROR_ANSWERS = {
  co_price: '$12,500.00 USD',
  co_document: 'MSKR-CO-02.pdf · final v1',
  co_scope: 'Approved pantry pull-out change order',
  draw_payees: 'Northline $10,800.00 · Alder Millwork $1,700.00',
  draw_completion: 'MSKR-M4-completion.zip · final',
  draw_waiver: 'MSKR-DRAW-04-waivers.pdf · conditional',
};

async function startFreshCreation(page) {
  await page.context().clearCookies();
  await page.goto('/release-lock/new?pilot=demo-pilot-release-lock');
  await page.evaluate((storageKey) => {
    window.localStorage.removeItem(storageKey);
    window.localStorage.setItem('ep_euaiact_banner_dismissed_v2', '1');
  }, DEMO_STATE_KEY);
  await page.reload();

  await expect(page.getByRole('heading', { name: 'Create a Release Lock' })).toBeVisible();
  await expect(page.getByText('DETERMINISTIC DEMO', { exact: true })).toBeVisible();
  await expect(page.getByText('No real money movement', { exact: true })).toBeVisible();
}

async function selectDemoRole(page, role) {
  const button = page.getByRole('button', { name: role, exact: true });
  await expect(async () => {
    await button.click();
    await expect(button).toHaveAttribute('aria-pressed', 'true', { timeout: 1_000 });
  }).toPass({ timeout: 10_000 });
}

async function createFixtureLock(page) {
  const expectedFields = [
    'Project',
    'Milestone / change-order title',
    'Scope summary',
    'Schedule effect',
    'Change-order price effect',
    'Currency',
    'Draw ID',
    'Exact draw / release amount',
    'Recipient / custodian instruction',
    'Change-order document reference',
    'Change-order acceptance expiration',
    'Change-order document digest',
    'Completion evidence reference',
    'Completion evidence digest',
    'Lien-waiver evidence reference',
    'Lien-waiver evidence digest',
    'Contractor verified contact handle',
    'Customer verified contact handle',
  ];

  for (const label of expectedFields) {
    await expect(page.getByLabel(label, { exact: true })).toBeAttached();
  }

  await expect(page.getByLabel('Project', { exact: true }))
    .toHaveValue('Maple Street Kitchen Renovation');
  await expect(page.getByLabel('Change-order price effect', { exact: true }))
    .toHaveValue('12500.00');
  await expect(page.getByText('CO_ACCEPTED is not payment authority.', { exact: true }).first())
    .toBeVisible();

  await page.getByRole('button', { name: 'Create Release Lock' }).click();
  await expect(page).toHaveURL(new RegExp(`${LOCK_PATH}$`));
  await expect(page.getByRole('heading', {
    name: 'Cabinet installation and change order 02',
  })).toBeVisible();
}

async function completeCustomerMirror(page, ceremony, mobile = false) {
  const code = ceremony === 'co_acceptance' ? 'CO_ACCEPTED' : 'DRAW_RELEASE';
  const passkeyLabel = ceremony === 'co_acceptance'
    ? 'Accept with demo passkey'
    : 'Approve with demo passkey';

  await page.getByRole('button', { name: 'Start Action Mirror' }).click();
  await expect(page.getByText(
    ceremony === 'co_acceptance' ? 'CEDAR 47' : 'MAPLE 82',
    { exact: true },
  )).toBeVisible();

  let mirror = page;
  if (mobile) {
    await page.getByRole('button', { name: 'Open Action Mirror demo' }).click();
    await expect(page).toHaveURL(new RegExp(`/mirror\\?ceremony=${ceremony}$`));
  } else {
    const popupPromise = page.waitForEvent('popup');
    await page.getByRole('button', { name: 'Open Action Mirror demo' }).click();
    mirror = await popupPromise;
    await mirror.waitForLoadState('domcontentloaded');
  }

  await expect(mirror.getByRole('heading', { name: 'Action Mirror' })).toBeVisible();
  await expect(mirror.getByText('Canonical action retrieved', { exact: true })).toBeVisible();
  const questions = mirror.locator('fieldset[data-material-field]');
  await expect(questions).toHaveCount(3);

  const materialFields = [];
  for (let index = 0; index < 3; index += 1) {
    const materialField = await questions.nth(index).getAttribute('data-material-field');
    expect(CORRECT_MIRROR_ANSWERS[materialField]).toBeTruthy();
    materialFields.push(materialField);
  }

  const bindButton = mirror.getByRole('button', { name: `Bind answers to ${code}` });
  await expect(async () => {
    for (let index = 0; index < materialFields.length; index += 1) {
      await questions.nth(index).getByRole('radio', {
        name: CORRECT_MIRROR_ANSWERS[materialFields[index]],
        exact: true,
      }).check();
    }
    await expect(bindButton).toBeEnabled({ timeout: 1_000 });
  }).toPass({ timeout: 10_000 });

  await bindButton.click();
  await expect(mirror.getByRole('heading', {
    name: 'Three digests, one passkey request',
  })).toBeVisible();
  await expect(mirror.getByText('Prompt set', { exact: true })).toBeVisible();
  await expect(mirror.getByText('Answers', { exact: true })).toBeVisible();
  await expect(mirror.getByText(code, { exact: true }).last()).toBeVisible();

  await mirror.getByRole('button', { name: passkeyLabel }).click();
  await expect(mirror.getByRole('heading', {
    name: `${code} approval recorded`,
  })).toBeVisible();

  if (mobile) {
    await expectNoHorizontalOverflow(mirror);
    await mirror.getByRole('link', { name: 'Return to Release Lock' }).click();
    await expect(mirror).toHaveURL(new RegExp(`${LOCK_PATH}$`));
  } else {
    await mirror.close();
    await expect(page.getByText(
      `Customer · ${code} approval recorded`,
      { exact: true },
    )).toBeVisible();
  }
}

async function expectNoHorizontalOverflow(page) {
  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
}

async function completeBothCeremonies(page, mobile = false) {
  await selectDemoRole(page, 'Customer');
  await completeCustomerMirror(page, 'co_acceptance', mobile);

  await page.getByRole('button', { name: 'Continue demo as contractor' }).click();
  await expect(page.getByRole('button', { name: 'Contractor', exact: true }))
    .toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Accept with demo passkey' }).click();
  await expect(page.getByRole('heading', { name: 'CO_ACCEPTED · work may proceed' }))
    .toBeVisible();

  await page.getByRole('button', { name: 'Advance demo to completed milestone' }).click();
  await expect(page.getByRole('heading', { name: 'Milestone evidence available' }))
    .toBeVisible();

  await selectDemoRole(page, 'Customer');
  await completeCustomerMirror(page, 'draw_release', mobile);

  await page.getByRole('button', { name: 'Continue demo as contractor' }).click();
  await expect(page.getByRole('button', { name: 'Contractor', exact: true }))
    .toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Approve with demo passkey' }).click();
  await expect(page.getByRole('heading', {
    name: 'DRAW_RELEASE · instruction eligible',
  })).toBeVisible();
}

test.describe('Release Lock deterministic demo', () => {
  test('desktop completes two separate ceremonies, exports evidence, and invalidates both', async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await startFreshCreation(page);
    await createFixtureLock(page);

    const coDigestBefore = await page.locator(
      '[data-ceremony="co_acceptance"] code[title]',
    ).first().getAttribute('title');
    const drawDigestBefore = await page.locator(
      '[data-ceremony="draw_release"] code[title]',
    ).first().getAttribute('title');
    expect(coDigestBefore).not.toBe(drawDigestBefore);

    await completeBothCeremonies(page);

    await expect(page.getByText('Portable evidence ready', { exact: true })).toBeVisible();
    await expect(page.getByText('4 of 4 refused', { exact: true })).toBeVisible();
    for (const refusal of [
      'Mutation refused',
      'Replay refused',
      'Role substitution refused',
      'Amendment invalidates both',
    ]) {
      await expect(page.getByRole('heading', { name: refusal })).toBeVisible();
    }

    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download portable evidence' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename())
      .toBe(`release-lock-${LOCK_ID}-evidence.json`);

    await page.getByRole('button', { name: 'Simulate amended version' }).click();
    await page.getByRole('button', { name: 'Invalidate both ceremonies' }).click();

    await expect(page.getByText(
      'Both ceremonies invalidated by amendment.',
      { exact: true },
    )).toBeVisible();
    await expect(page.getByText('Immutable version 2', { exact: true }).first()).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Milestone stage locked' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Draw release blocked' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download portable evidence' }))
      .toBeDisabled();

    const coDigestAfter = await page.locator(
      '[data-ceremony="co_acceptance"] code[title]',
    ).first().getAttribute('title');
    const drawDigestAfter = await page.locator(
      '[data-ceremony="draw_release"] code[title]',
    ).first().getAttribute('title');
    expect(coDigestAfter).not.toBe(coDigestBefore);
    expect(drawDigestAfter).not.toBe(drawDigestBefore);
    expect(coDigestAfter).not.toBe(drawDigestAfter);
  });

  test('mobile completes the two-round Action Mirror path without horizontal overflow', async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 390, height: 844 });
    await startFreshCreation(page);
    await expectNoHorizontalOverflow(page);
    await createFixtureLock(page);
    await expectNoHorizontalOverflow(page);

    await completeBothCeremonies(page, true);

    await expect(page.getByText('Portable evidence ready', { exact: true })).toBeVisible();
    await expect(page.getByText('Eligible · not executed', { exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  });

  test('capability exchange returns a 303 and removes the token before rendering', async ({
    page,
    request,
  }) => {
    const token = 'demo-secret-capability-never-render-abc123';
    const response = await request.get(`/release-lock/c/${token}`, {
      maxRedirects: 0,
    });

    expect(response.status()).toBe(303);
    const location = response.headers().location;
    expect(new URL(location).pathname).toBe(LOCK_PATH);
    expect(location).not.toContain(token);
    expect(response.headers()['cache-control']).toContain('no-store');

    await page.goto(`/release-lock/c/${token}`);
    await expect(page).toHaveURL(new RegExp(`${LOCK_PATH}$`));
    await expect(page.getByText('Customer view', { exact: true })).toBeVisible();
    expect(await page.content()).not.toContain(token);
    expect(page.url()).not.toContain(token);
  });
});

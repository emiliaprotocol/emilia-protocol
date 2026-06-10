// SPDX-License-Identifier: Apache-2.0
// Class A signoff — full-journey acceptance with a CDP virtual authenticator.
//
// This exercises the REAL WebAuthn stack end to end: the browser creates a
// real CTAP2 credential, sets the UV flag, and produces a real ES256
// assertion — everything a Touch ID run does except the finger. The flow:
//
//   register entities → enroll passkey (/approvers/enroll)
//   → mint $82k receipt (signoff required) → request signoff
//   → approve on /signoff/[id] with the device key
//   → receipt reports approved_pending_consume + signoff_key_class 'A'
//
// The SAME virtual authenticator must serve both ceremonies (the private
// key lives in it), so enrollment and signing share one page/CDP session.

import { test, expect } from '@playwright/test';

// Opt-in: this journey registers entities and writes receipts/credentials
// through the dev server's configured Supabase. Run it deliberately —
//   E2E_WEBAUTHN=1 npx playwright test e2e/webauthn-signoff.spec.js
// — never implicitly in CI.
test.skip(process.env.E2E_WEBAUTHN !== '1', 'set E2E_WEBAUTHN=1 to run the WebAuthn journey (writes test data)');

const RUN = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
const INITIATOR_ID = `e2e-webauthn-initiator-${RUN}`;
const ADMIN_ID = `e2e-webauthn-admin-${RUN}`;
const APPROVER_ID = `ep:approver:e2e-${RUN}`;

async function registerEntity(request, entityId, description) {
  const res = await request.post('/api/entities/register', {
    data: {
      entity_id: entityId,
      display_name: entityId,
      entity_type: 'agent',
      description,
    },
  });
  expect(res.ok(), `register ${entityId}: ${res.status()}`).toBeTruthy();
  const data = await res.json();
  expect(data.api_key, 'registration returns api_key once').toBeTruthy();
  return data.api_key;
}

test('Class A signoff: enroll passkey, gate $82k, sign on device, receipt reports key class A', async ({ page, request, baseURL }) => {
  test.setTimeout(120_000);

  // Surface browser-side failures in the test output — a dead button or a
  // hydration error is invisible otherwise.
  page.on('console', (msg) => {
    if (msg.type() === 'error' || msg.type() === 'warning') {
      console.log(`[browser ${msg.type()}] ${msg.text()}`);
    }
  });
  page.on('pageerror', (err) => console.log(`[pageerror] ${err.message}`));

  // ── Actors: an initiating agent and a distinct org admin (SoD demands the
  // approver differ from the initiator; the admin attests the enrollment).
  const initiatorKey = await registerEntity(request, INITIATOR_ID, 'E2E initiator agent for Class A signoff acceptance');
  const adminKey = await registerEntity(request, ADMIN_ID, 'E2E org admin attesting approver enrollment');

  // ── One virtual authenticator for the whole journey.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,            // the "biometric" succeeds
      automaticPresenceSimulation: true,
    },
  });

  // ── Enroll the approver's passkey.
  await page.goto('/approvers/enroll');
  await page.fill('#ep-key', adminKey);
  await page.fill('#ep-appr', APPROVER_ID);
  await page.fill('#ep-name', 'E2E Treasury Controller');
  await page.getByRole('button', { name: /Create passkey/ }).click();
  await expect(page.getByText(/Enrolled/)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/key class A/)).toBeVisible();

  // ── Agent proposes the wire: $82k + payee bank change → signoff required.
  const mintRes = await request.post('/api/v1/trust-receipts', {
    headers: { Authorization: `Bearer ${initiatorKey}` },
    data: {
      organization_id: `org-e2e-${RUN}`,
      action_type: 'large_payment_release',
      target_resource_id: `wire/e2e-${RUN}`,
      amount: 82000,
      currency: 'USD',
      target_changed_fields: ['bank_account'],
      risk_flags: ['new_destination', 'after_hours'],
    },
  });
  expect(mintRes.status(), await mintRes.text()).toBe(201);
  const receipt = await mintRes.json();
  expect(receipt.signoff_required, 'an $82k release must require signoff').toBe(true);

  const signoffRes = await request.post('/api/v1/signoffs/request', {
    headers: { Authorization: `Bearer ${initiatorKey}` },
    data: { receipt_id: receipt.receipt_id },
  });
  expect(signoffRes.status(), await signoffRes.text()).toBe(201);
  const { signoff_id } = await signoffRes.json();

  // ── The named human reviews the exact action and signs on their device.
  await page.goto(`/signoff/${signoff_id}?approver=${encodeURIComponent(APPROVER_ID)}`);
  await expect(page.getByText('$82,000')).toBeVisible();
  await expect(page.getByText(`wire/e2e-${RUN}`).first()).toBeVisible(); // WYSIWYS: canonical bytes render
  await page.getByRole('button', { name: /Approve & sign/ }).click();
  await expect(page.getByText(/Signed and approved/)).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText(/key class A/)).toBeVisible();

  // ── The receipt now carries the Class A decision.
  const getRes = await request.get(`/api/v1/trust-receipts/${receipt.receipt_id}`, {
    headers: { Authorization: `Bearer ${initiatorKey}` },
  });
  expect(getRes.ok()).toBeTruthy();
  const finalReceipt = await getRes.json();
  expect(finalReceipt.receipt_status).toBe('approved_pending_consume');
  expect(finalReceipt.signoff_key_class).toBe('A');

  // ── Replay resistance at the HTTP layer: a second approval attempt with a
  // fresh challenge against the SAME signoff must be refused (already decided).
  const replayOpts = await request.post(`/api/v1/signoffs/${signoff_id}/webauthn-options`, {
    data: { approver_id: APPROVER_ID },
  });
  expect(replayOpts.status()).toBe(409);

  console.log(`[e2e] signoff_id=${signoff_id} receipt_id=${receipt.receipt_id} approver=${APPROVER_ID}`);
});

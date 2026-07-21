// SPDX-License-Identifier: Apache-2.0
// EP-QUORUM-v1 — multi-party signoff full-journey acceptance.
//
// Exercises the REAL multi-party stack end to end with THREE CDP virtual
// authenticators — one per approver, i.e. genuine multi-device. Each creates a
// real CTAP2 credential, sets UV, and produces a real ES256 assertion (a Touch
// ID run without the finger). The flow proves the security boundary:
//
//   register initiator + admin → enroll PO, AO, IG passkeys (3 devices)
//   → mint an $82k receipt WITH an ordered quorum_policy (PO→AO→IG)
//   → request signoff (quorum fan-out: one signoff_id per approver)
//   → PO signs   → consume is 403 quorum_not_satisfied
//   → AO signs   → consume is 403 quorum_not_satisfied
//   → IG signs   → consume is 200 (quorum satisfied)
//   → negative: an out-of-order signer is refused before any approval lands
//
// Each approver gets its OWN browser context (its key lives in its own
// authenticator), mirroring three real people on three real devices.

import { test, expect } from '@playwright/test';

// Opt-in: writes receipts / credentials / decisions through the dev server's
// configured Supabase. Run it deliberately —
//   E2E_WEBAUTHN=1 npx playwright test e2e/multi-party-quorum.spec.js
// — never implicitly in CI.
test.skip(process.env.E2E_WEBAUTHN !== '1', 'set E2E_WEBAUTHN=1 to run the multi-party quorum journey (writes test data)');

const RUN = `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
const INITIATOR_ID = `e2e-quorum-initiator-${RUN}`;
const ADMIN_ID = `e2e-quorum-admin-${RUN}`;

const SEATS = [
  { role: 'program_officer',      approver: `ep:approver:e2e-po-${RUN}`, name: 'E2E Program Officer' },
  { role: 'authorizing_official', approver: `ep:approver:e2e-ao-${RUN}`, name: 'E2E Authorizing Official' },
  { role: 'inspector_general',    approver: `ep:approver:e2e-ig-${RUN}`, name: 'E2E Inspector General' },
];

async function registerEntity(request, entityId, description) {
  const res = await request.post('/api/entities/register', {
    data: { entity_id: entityId, display_name: entityId, entity_type: 'agent', description },
  });
  expect(res.ok(), `register ${entityId}: ${res.status()}`).toBeTruthy();
  const data = await res.json();
  expect(data.api_key, 'registration returns api_key once').toBeTruthy();
  return data.api_key;
}

// One isolated device (own context + own virtual authenticator) per approver.
async function newDevice(browser, baseURL) {
  const context = await browser.newContext({ baseURL });
  const page = await context.newPage();
  page.on('pageerror', (err) => console.log(`[pageerror] ${err.message}`));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,           // the "biometric" succeeds
      automaticPresenceSimulation: true,
    },
  });
  return { context, page };
}

async function enrollPasskey(page, adminKey, seat) {
  await page.goto('/approvers/enroll');
  await page.fill('#ep-key', adminKey);
  await page.fill('#ep-appr', seat.approver);
  await page.fill('#ep-name', seat.name);
  await page.getByRole('button', { name: /Create passkey/ }).click();
  await expect(page.getByText(/Enrolled/)).toBeVisible({ timeout: 15_000 });
}

async function signOn(page, signoffId, approver) {
  await page.goto(`/signoff/${signoffId}?approver=${encodeURIComponent(approver)}`);
  await page.getByRole('button', { name: /Approve & sign/ }).click();
  await expect(page.getByText(/Signed and approved/)).toBeVisible({ timeout: 20_000 });
}

async function tryConsume(request, key, receiptId, actionHash) {
  return request.post(`/api/v1/trust-receipts/${receiptId}/consume`, {
    headers: { Authorization: `Bearer ${key}` },
    data: { action_hash: actionHash, executing_system: `e2e-quorum-${RUN}` },
  });
}

test('EP-QUORUM-v1: ordered 3-party signoff — consume blocked until quorum satisfied', async ({ browser, request, baseURL }) => {
  test.setTimeout(180_000);

  // ── Actors: an initiating agent + an org admin attesting enrollments. The
  // initiator is distinct from every approver (separation of duties).
  const initiatorKey = await registerEntity(request, INITIATOR_ID, 'E2E initiator for multi-party quorum');
  const adminKey = await registerEntity(request, ADMIN_ID, 'E2E org admin attesting approver enrollment');

  // ── Three devices, three passkeys.
  const devices: any[] = [];
  for (const seat of SEATS) {
    const dev = await newDevice(browser, baseURL);
    await enrollPasskey(dev.page, adminKey, seat);
    devices.push({ ...dev, seat });
  }

  // ── Agent proposes the wire with an ordered quorum requirement (PO→AO→IG).
  const quorumPolicy = {
    mode: 'ordered',
    required: 3,
    approvers: SEATS.map((s) => ({ role: s.role, approver: s.approver })),
    distinct_humans: true,
    window_sec: 3600,
  };
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
      quorum_policy: quorumPolicy,
    },
  });
  expect(mintRes.status(), await mintRes.text()).toBe(201);
  const receipt = await mintRes.json();
  const receiptId = receipt.receipt_id;

  const getRes = await request.get(`/api/v1/trust-receipts/${receiptId}`, { headers: { Authorization: `Bearer ${initiatorKey}` } });
  const actionHash = (await getRes.json()).action_hash || receipt.action_hash;
  expect(actionHash, 'receipt exposes an action_hash to consume against').toBeTruthy();

  // ── Quorum fan-out: one signoff per roster seat.
  const reqRes = await request.post('/api/v1/signoffs/request', {
    headers: { Authorization: `Bearer ${initiatorKey}` },
    data: { receipt_id: receiptId },
  });
  expect(reqRes.status(), await reqRes.text()).toBe(201);
  const { signoffs } = await reqRes.json();
  expect(signoffs, 'fan-out returns one signoff per approver').toHaveLength(3);
  const sigByApprover = Object.fromEntries(signoffs.map((s) => [s.approver_id, s.signoff_id]));

  // ── Negative: an out-of-order signer (AO before PO) is refused at signoff.
  // The early gate (canAccept) rejects with quorum_signer_rejected; the UI
  // surfaces the failure rather than a success.
  const ao = devices.find((d) => d.seat.role === 'authorizing_official');
  await ao.page.goto(`/signoff/${sigByApprover[ao.seat.approver]}?approver=${encodeURIComponent(ao.seat.approver)}`);
  await ao.page.getByRole('button', { name: /Approve & sign/ }).click();
  await expect(ao.page.getByText(/Signed and approved/)).toHaveCount(0, { timeout: 8_000 });

  // ── Sign in order, asserting consume is blocked until the quorum holds.
  const ordered = SEATS.map((s) => devices.find((d) => d.seat.approver === s.approver));

  await signOn(ordered[0].page, sigByApprover[ordered[0].seat.approver], ordered[0].seat.approver); // PO
  let c = await tryConsume(request, initiatorKey, receiptId, actionHash);
  expect(c.status(), 'after PO only — quorum not satisfied').toBe(403);
  expect((await c.json()).type || await c.text()).toMatch(/quorum_not_satisfied|signoff/i);

  await signOn(ordered[1].page, sigByApprover[ordered[1].seat.approver], ordered[1].seat.approver); // AO
  c = await tryConsume(request, initiatorKey, receiptId, actionHash);
  expect(c.status(), 'after PO+AO — still not satisfied (needs 3)').toBe(403);

  await signOn(ordered[2].page, sigByApprover[ordered[2].seat.approver], ordered[2].seat.approver); // IG
  c = await tryConsume(request, initiatorKey, receiptId, actionHash);
  expect(c.status(), 'full ordered quorum — consume allowed').toBe(200);
  const consumed = await c.json();
  expect(consumed.status).toBe('consumed');

  console.log(`[e2e] quorum receipt=${receiptId} signoffs=${signoffs.map((s) => s.signoff_id).join(',')}`);

  for (const d of devices) await d.context.close();
});

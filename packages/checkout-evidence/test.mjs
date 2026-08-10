// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildDisputeDossier,
  buildPurchaseAction,
  buildStructuredPresentation,
  createCheckoutEvidencePacket,
  verifyCheckoutEvidencePacket,
  _internals,
} from './index.mjs';
import { captureAp2V02Evidence } from './ap2.mjs';

const D = (char) => `sha256:${char.repeat(64)}`;
const AT = '2026-08-08T19:00:00Z';

function terms() {
  return {
    merchant: { account_digest: D('a'), display_name: 'Example Merchant' },
    items: [
      { item_ref: 'sku:shoe-8', description: 'Running shoe, size 8', quantity: 1, unit_amount: '79.00', line_total: '79.00' },
      { item_ref: 'sku:sock-blue', description: 'Blue socks', quantity: 2, unit_amount: '5.00', line_total: '10.00' },
    ],
    totals: { currency: 'USD', subtotal: '89.00', tax: '7.12', shipping: '0', discount: '0', total: '96.12' },
    fulfillment: { type: 'ship', destination_digest: D('b') },
    recurrence: { recurring: false },
  };
}

function artifact(label) {
  return { media_type: 'application/json', content: { type: label, signature: D('c') } };
}

function ap2() {
  return captureAp2V02Evidence({
    checkout_mandate: 'eyJhbGciOiJFUzI1NiJ9.checkout.signature',
    checkout_receipt: 'eyJhbGciOiJFUzI1NiJ9.checkout-receipt.signature',
    payment_mandate: 'eyJhbGciOiJFUzI1NiJ9.payment.signature',
    payment_receipt: 'eyJhbGciOiJFUzI1NiJ9.payment-receipt.signature',
  });
}

function packet(overrides = {}) {
  const checkoutTerms = overrides.checkoutTerms ?? terms();
  const built = buildPurchaseAction({ checkoutTerms, paymentInstructionId: 'pi_checkout_001' });
  const presentation = buildStructuredPresentation({
    checkoutTerms,
    action: built.action,
    actionCaid: built.action_caid,
  });
  return createCheckoutEvidencePacket({
    createdAt: AT,
    checkoutTerms,
    paymentInstructionId: 'pi_checkout_001',
    presentation,
    authorization: {
      profile: 'ep-receipt-v1',
      action_caid: built.action_caid,
      presentation_digest: presentation.display_digest,
      authorized_at: AT,
      artifact: artifact('authorization'),
    },
    execution: {
      provider: 'example-processor',
      operation_id: 'op_checkout_001',
      payment_instruction_id: 'pi_checkout_001',
      status: overrides.effectStatus ?? 'confirmed',
      observed_action: overrides.observedAction ?? built.action,
      observed_at: '2026-08-08T19:00:02Z',
      evidence: overrides.noExecutionEvidence ? undefined : artifact('execution'),
    },
    consumption: {
      status: overrides.consumptionStatus ?? 'consumed',
      action_caid: built.action_caid,
      operation_id: 'op_checkout_001',
      recorded_at: '2026-08-08T19:00:01Z',
      evidence: overrides.noConsumptionEvidence ? undefined : artifact('consumption'),
    },
    nativeEvidence: overrides.nativeEvidence ?? [ap2()],
  });
}

const validVerifiers = {
  verifyAuthorization: () => true,
  verifyExecution: () => ({ status: 'valid' }),
  verifyConsumption: () => 'valid',
  nativeVerifiers: { 'ap2-v0.2': () => true },
};

test('builds a local exact-purchase CAID without misusing payment.release.1', () => {
  const built = buildPurchaseAction({ checkoutTerms: terms(), paymentInstructionId: 'pi_checkout_001' });
  assert.match(built.action_caid, /^caid:1:commerce\.purchase\.submit\.1:/);
  assert.equal(built.action.checkout_digest, _internals.digest(terms()));
  assert.equal(built.action.amount, '96.12');
});

test('the approval presentation carries every checkout term, including extensions', () => {
  const checkoutTerms = terms();
  checkoutTerms.return_policy = { window_days: 30, restocking_fee: '0' };
  const built = buildPurchaseAction({ checkoutTerms, paymentInstructionId: 'pi_checkout_001' });
  const presentation = buildStructuredPresentation({
    checkoutTerms,
    action: built.action,
    actionCaid: built.action_caid,
  });
  assert.deepEqual(presentation.display.checkout_terms, checkoutTerms);
});

test('verifies an exact packet with AP2 native verification', async () => {
  const result = await verifyCheckoutEvidencePacket(packet(), validVerifiers);
  assert.equal(result.verdict, 'VERIFIED', JSON.stringify(result));
  assert.equal(result.effect_status, 'confirmed');
  assert.equal(result.reasons.length, 0);
});

test('produces an honest neutral dispute dossier, not a network eligibility claim', async () => {
  const source = packet();
  const verification = await verifyCheckoutEvidencePacket(source, validVerifiers);
  const dossier = buildDisputeDossier(source, verification, { generatedAt: '2026-08-08T20:00:00Z' });
  assert.equal(dossier.verification.verdict, 'VERIFIED');
  assert.equal(dossier.scheme_mapping.status, 'not_supplied');
  assert.match(dossier.scheme_mapping.note, /processor- and reason-code-specific/);
  assert.match(dossier.dossier_digest, /^sha256:[0-9a-f]{64}$/);
});

for (const [label, mutate] of [
  ['item substitution', (p) => { p.checkout_terms.items[0].item_ref = 'sku:attacker'; }],
  ['quantity substitution', (p) => { p.checkout_terms.items[1].quantity = 200; }],
  ['merchant substitution', (p) => { p.checkout_terms.merchant.account_digest = D('d'); }],
  ['total substitution', (p) => { p.checkout_terms.totals.total = '996.12'; }],
  ['currency substitution', (p) => { p.checkout_terms.totals.currency = 'EUR'; }],
  ['fulfillment substitution', (p) => { p.checkout_terms.fulfillment.destination_digest = D('e'); }],
]) {
  test(`refuses ${label} even when the packet digest is recomputed`, async () => {
    const tampered = structuredClone(packet());
    mutate(tampered);
    const { packet_digest: ignored, ...core } = tampered;
    void ignored;
    tampered.packet_digest = _internals.digest(core);
    const result = await verifyCheckoutEvidencePacket(tampered, validVerifiers);
    assert.equal(result.verdict, 'INVALID');
    assert.ok(result.reasons.some((reason) => /checkout|action|presentation/.test(reason)), JSON.stringify(result));
  });
}

test('refuses approve-A/execute-B even when both actions have valid CAIDs', async () => {
  const approved = buildPurchaseAction({ checkoutTerms: terms(), paymentInstructionId: 'pi_checkout_001' });
  const changed = terms();
  changed.totals.total = '196.12';
  const executed = buildPurchaseAction({ checkoutTerms: changed, paymentInstructionId: 'pi_checkout_001' });
  const source = packet({ observedAction: executed.action });
  const result = await verifyCheckoutEvidencePacket(source, validVerifiers);
  assert.equal(result.verdict, 'INVALID');
  assert.ok(result.reasons.includes('executed_action_mismatch'));
  assert.notEqual(approved.action_caid, executed.action_caid);
});

test('refuses forged presentation binding', async () => {
  const tampered = structuredClone(packet());
  tampered.authorization.presentation_digest = D('f');
  const { packet_digest: ignored, ...core } = tampered;
  void ignored;
  tampered.packet_digest = _internals.digest(core);
  const result = await verifyCheckoutEvidencePacket(tampered, validVerifiers);
  assert.equal(result.verdict, 'INVALID');
  assert.ok(result.reasons.includes('authorization_binding_mismatch'));
});

test('refuses unregistered packet and evidence fields even when re-digested', async () => {
  const tampered = structuredClone(packet());
  tampered.authorization.legal_conclusion = 'authorized';
  tampered.network_eligible = true;
  const { packet_digest: ignored, ...core } = tampered;
  void ignored;
  tampered.packet_digest = _internals.digest(core);
  const result = await verifyCheckoutEvidencePacket(tampered, validVerifiers);
  assert.equal(result.verdict, 'INVALID');
  assert.ok(result.reasons.includes('packet_fields_invalid'));
  assert.ok(result.reasons.includes('authorization_fields_invalid'));
});

test('returns INDETERMINATE when native trust verification is unavailable', async () => {
  const result = await verifyCheckoutEvidencePacket(packet(), {
    verifyAuthorization: () => true,
    verifyExecution: () => true,
    verifyConsumption: () => true,
  });
  assert.equal(result.verdict, 'INDETERMINATE');
  assert.ok(result.reasons.includes('native_ap2-v0.2_verifier_missing'));
});

test('returns INVALID when the AP2 verifier rejects the native chain', async () => {
  const result = await verifyCheckoutEvidencePacket(packet(), {
    ...validVerifiers,
    nativeVerifiers: { 'ap2-v0.2': () => false },
  });
  assert.equal(result.verdict, 'INVALID');
  assert.ok(result.reasons.includes('native_ap2-v0.2_verification_failed'));
});

test('returns INDETERMINATE instead of guessing after an unknown provider effect', async () => {
  const result = await verifyCheckoutEvidencePacket(packet({ effectStatus: 'unknown', noExecutionEvidence: true }), validVerifiers);
  assert.equal(result.verdict, 'INDETERMINATE');
  assert.ok(result.reasons.includes('execution_effect_unknown'));
});

test('refuses a confirmed effect whose one-use authority was not consumed', async () => {
  const result = await verifyCheckoutEvidencePacket(packet({ consumptionStatus: 'not_consumed', noConsumptionEvidence: true }), validVerifiers);
  assert.equal(result.verdict, 'INVALID');
  assert.ok(result.reasons.includes('confirmed_effect_without_consumption'));
});

test('missing authorization verification is INDETERMINATE, never assumed valid', async () => {
  const result = await verifyCheckoutEvidencePacket(packet(), {
    verifyExecution: () => true,
    verifyConsumption: () => true,
    nativeVerifiers: { 'ap2-v0.2': () => true },
  });
  assert.equal(result.verdict, 'INDETERMINATE');
  assert.ok(result.reasons.includes('authorization_verifier_missing'));
});

test('refuses raw PAN and CVV fields instead of putting them in an evidence packet', () => {
  const panTerms = terms();
  panTerms.card_number = '4242424242424242';
  assert.throws(
    () => buildPurchaseAction({ checkoutTerms: panTerms, paymentInstructionId: 'pi_checkout_001' }),
    /raw payment credential field is prohibited/,
  );
  const cvvArtifact = { media_type: 'application/json', content: { cvv: '123' } };
  assert.throws(() => _internals.artifactEnvelope(cvvArtifact, 'test'), /raw payment credential/);
});

test('AP2 capture requires the complete four-artifact dispute chain', () => {
  assert.throws(() => captureAp2V02Evidence({
    checkout_mandate: 'eyJhbGciOiJFUzI1NiJ9.checkout.signature',
    checkout_receipt: 'eyJhbGciOiJFUzI1NiJ9.checkout-receipt.signature',
    payment_mandate: 'eyJhbGciOiJFUzI1NiJ9.payment.signature',
  }), /payment_receipt/);
});

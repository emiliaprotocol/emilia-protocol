// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { loadDefaultAgilityMldsaBackend } from '@emilia-protocol/verify/pq-signature-agility';

import {
  FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
  GRACE_CURTAILMENT_IMPACT_PROFILE,
  GRID_ACTIVE_POWER_PROFILE,
  allocateConsequenceEnvelopeSlice,
  createConsequenceEnvelopeBoundary,
  createMemoryConsequenceEnvelopeStore,
  issueConsequenceEnvelope,
  verifyConsequenceEnvelope,
} from './dist/consequence-envelope.js';

const NOW = '2027-01-15T08:00:30.000Z';
const ED_PRIVATE_JWK = {
  crv: 'Ed25519',
  d: 'EBsZ3aVNd8cSzmZECgG0MMAPTreFIhgDFtTY9UTkQ_Y',
  x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
  kty: 'OKP',
} as const;
const ED_PUBLIC_JWK = {
  crv: 'Ed25519',
  x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
  kty: 'OKP',
} as const;

async function cryptoFixture() {
  const edPrivate = crypto.createPrivateKey({ key: ED_PRIVATE_JWK, format: 'jwk' });
  const edPublic = crypto.createPublicKey({ key: ED_PUBLIC_JWK, format: 'jwk' });
  const pqPair = ml_dsa65.keygen(new Uint8Array(32).fill(0x51));
  const mldsaBackend = await loadDefaultAgilityMldsaBackend();
  assert.ok(mldsaBackend);
  return {
    mldsaBackend,
    signing_keys: [
      { alg: 'Ed25519' as const, key_id: 'envelope-ed', private_key: edPrivate },
      { alg: 'ML-DSA-65' as const, key_id: 'envelope-pq', private_key: pqPair.secretKey },
    ],
    verification_keys: [
      {
        alg: 'Ed25519' as const,
        key_id: 'envelope-ed',
        public_key: edPublic.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
      {
        alg: 'ML-DSA-65' as const,
        key_id: 'envelope-pq',
        public_key: Buffer.from(pqPair.publicKey).toString('base64url'),
      },
    ],
  };
}

async function financeBoundary(capacityUnits = '1000', epoch = 7) {
  const keys = await cryptoFixture();
  let currentTime = NOW;
  const envelope = await issueConsequenceEnvelope({
    envelope_id: `envelope:finance:${epoch}`,
    state_domain_id: 'state-domain:finance-primary',
    epoch,
    capacity_units: capacityUnits,
    impact_profile_id: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.id,
    impact_profile_digest: FINANCE_CUMULATIVE_EXPOSURE_PROFILE.digest,
    validity: {
      not_before: '2027-01-15T08:00:00.000Z',
      not_after: '2027-01-15T09:00:00.000Z',
    },
    issuer: { id: 'authority:finance-risk', key_id: 'envelope-ed' },
    parent_allocation: null,
    renewable: false,
  }, keys);
  const store = createMemoryConsequenceEnvelopeStore();
  const boundary = await createConsequenceEnvelopeBoundary({
    envelope,
    verification_keys: keys.verification_keys,
    mldsaBackend: keys.mldsaBackend,
    profile: FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
    store,
    allow_test_store: true,
    now: () => currentTime,
  });
  return { keys, envelope, store, boundary, setNow: (value: string) => { currentTime = value; } };
}

test('hybrid-signed finance envelope reserves conservatively and refuses oversubscription', async () => {
  const h = await financeBoundary();
  const verified = await verifyConsequenceEnvelope(h.envelope, {
    verification_keys: h.keys.verification_keys,
    mldsaBackend: h.keys.mldsaBackend,
    now: NOW,
  });
  assert.equal(verified.verified, true, JSON.stringify(verified));

  const first = await h.boundary.reserve({
    operation_id: 'operation:finance:one',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 600, currency: 'USD' },
  });
  assert.equal(first.status, 'RESERVED');
  const second = await h.boundary.reserve({
    operation_id: 'operation:finance:two',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 500, currency: 'USD' },
  });
  assert.deepEqual(second, { status: 'REFUSED', reason: 'consequence_envelope_capacity_exceeded' });
  assert.deepEqual(h.boundary.snapshot(), {
    capacity_units: '1000',
    available_units: '400',
    held_units: '600',
    committed_units: '0',
  });
});

test('concurrent reservations cannot oversubscribe one owning state domain', async () => {
  const h = await financeBoundary();
  const [a, b] = await Promise.all([
    h.boundary.reserve({
      operation_id: 'operation:concurrent:a',
      state_domain_id: 'state-domain:finance-primary',
      expected_epoch: 7,
      action: { action_type: 'finance.vendor-payment.1', amount_minor: 600, currency: 'USD' },
    }),
    h.boundary.reserve({
      operation_id: 'operation:concurrent:b',
      state_domain_id: 'state-domain:finance-primary',
      expected_epoch: 7,
      action: { action_type: 'finance.vendor-payment.1', amount_minor: 600, currency: 'USD' },
    }),
  ]);
  assert.deepEqual([a.status, b.status].sort(), ['REFUSED', 'RESERVED']);
  assert.equal(h.boundary.snapshot().held_units, '600');
});

test('domain, epoch, duplicate operation, and material-action changes fail closed', async () => {
  const h = await financeBoundary();
  assert.deepEqual(await h.boundary.reserve({
    operation_id: 'operation:wrong-domain',
    state_domain_id: 'state-domain:other',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 100, currency: 'USD' },
  }), { status: 'REFUSED', reason: 'consequence_envelope_state_domain_mismatch' });
  assert.deepEqual(await h.boundary.reserve({
    operation_id: 'operation:stale-epoch',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 6,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 100, currency: 'USD' },
  }), { status: 'REFUSED', reason: 'consequence_envelope_epoch_mismatch' });

  const first = await h.boundary.reserve({
    operation_id: 'operation:stable-binding',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 100, currency: 'USD' },
  });
  assert.equal(first.status, 'RESERVED');
  assert.deepEqual(await h.boundary.reserve({
    operation_id: 'operation:stable-binding',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 101, currency: 'USD' },
  }), { status: 'REFUSED', reason: 'consequence_envelope_operation_conflict' });
});

test('entry consumes capacity, proven non-entry releases it, and uncertainty keeps it unavailable', async () => {
  const h = await financeBoundary();
  const entered = await h.boundary.reserve({
    operation_id: 'operation:entered',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 300, currency: 'USD' },
  });
  assert.equal(entered.status, 'RESERVED');
  if (entered.status !== 'RESERVED') return;
  assert.equal((await h.boundary.beginProviderEntry(entered.reservation)).status, 'ENTERED');
  assert.equal((await h.boundary.settle(entered.reservation, 'INDETERMINATE')).status, 'INDETERMINATE');
  assert.equal(h.boundary.snapshot().committed_units, '300');

  const notEntered = await h.boundary.reserve({
    operation_id: 'operation:not-entered',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 200, currency: 'USD' },
  });
  assert.equal(notEntered.status, 'RESERVED');
  if (notEntered.status !== 'RESERVED') return;
  assert.equal((await h.boundary.releaseNotEntered(notEntered.reservation)).status, 'RELEASED');
  assert.deepEqual(h.boundary.snapshot(), {
    capacity_units: '1000',
    available_units: '700',
    held_units: '0',
    committed_units: '300',
  });

  assert.equal((await h.boundary.settle(entered.reservation, 'PROVEN_NOT_COMMITTED')).status, 'RELEASED');
  assert.equal(h.boundary.snapshot().available_units, '1000');
});

test('expiration never refills an envelope and a new signed epoch is required', async () => {
  const h = await financeBoundary();
  h.setNow('2027-01-15T09:00:00.000Z');
  assert.deepEqual(await h.boundary.reserve({
    operation_id: 'operation:after-expiry',
    state_domain_id: 'state-domain:finance-primary',
    expected_epoch: 7,
    action: { action_type: 'finance.vendor-payment.1', amount_minor: 1, currency: 'USD' },
  }), { status: 'REFUSED', reason: 'consequence_envelope_expired' });
  assert.equal(h.boundary.snapshot().available_units, '1000');
});

test('a preissued local slice is globally deducted, epoch-bound, and nonrenewable offline', async () => {
  const parent = await financeBoundary();
  const allocation = await allocateConsequenceEnvelopeSlice({
    parent: parent.boundary,
    operation_id: 'operation:slice:edge-one',
    child: {
      envelope_id: 'envelope:finance-edge:1',
      state_domain_id: 'state-domain:finance-edge-one',
      epoch: 1,
      capacity_units: '300',
      validity: {
        not_before: '2027-01-15T08:00:00.000Z',
        not_after: '2027-01-15T08:30:00.000Z',
      },
      issuer: { id: 'authority:finance-risk', key_id: 'envelope-ed' },
    },
    signing_keys: parent.keys.signing_keys,
    mldsaBackend: parent.keys.mldsaBackend,
  });
  assert.equal(allocation.status, 'ALLOCATED');
  if (allocation.status !== 'ALLOCATED') return;
  assert.equal(parent.boundary.snapshot().available_units, '700');
  assert.equal(parent.boundary.snapshot().committed_units, '300');
  assert.equal(allocation.envelope.body.renewable, false);
  assert.equal(allocation.envelope.body.parent_allocation?.parent_epoch, 7);

  const child = await createConsequenceEnvelopeBoundary({
    envelope: allocation.envelope,
    verification_keys: parent.keys.verification_keys,
    mldsaBackend: parent.keys.mldsaBackend,
    profile: FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
    store: createMemoryConsequenceEnvelopeStore(),
    allow_test_store: true,
    now: () => NOW,
  });
  assert.equal(child.snapshot().capacity_units, '300');
  assert.deepEqual(await child.renew(), { status: 'REFUSED', reason: 'consequence_envelope_new_signed_epoch_required' });
});

test('grid hard safety derives conservative impact; telemetry cannot increase capacity', async () => {
  const keys = await cryptoFixture();
  const envelope = await issueConsequenceEnvelope({
    envelope_id: 'envelope:grid:1',
    state_domain_id: 'state-domain:grid-feeder-7',
    epoch: 4,
    capacity_units: '1000000',
    impact_profile_id: GRID_ACTIVE_POWER_PROFILE.id,
    impact_profile_digest: GRID_ACTIVE_POWER_PROFILE.digest,
    validity: {
      not_before: '2027-01-15T08:00:00.000Z',
      not_after: '2027-01-15T08:05:00.000Z',
    },
    issuer: { id: 'authority:grid-operator', key_id: 'envelope-ed' },
    parent_allocation: null,
    renewable: false,
  }, keys);
  const boundary = await createConsequenceEnvelopeBoundary({
    envelope,
    verification_keys: keys.verification_keys,
    mldsaBackend: keys.mldsaBackend,
    profile: GRID_ACTIVE_POWER_PROFILE,
    store: createMemoryConsequenceEnvelopeStore(),
    allow_test_store: true,
    now: () => NOW,
  });
  const reserved = await boundary.reserve({
    operation_id: 'operation:grid:curtailment-one',
    state_domain_id: 'state-domain:grid-feeder-7',
    expected_epoch: 4,
    action: {
      action_type: 'grid.active-power-change.1',
      target_id: 'der-fleet:west',
      active_power_delta_watts: -750000,
      telemetry: { intent_velocity: 99, entropy_basis_points: 1, anomaly_score: 1 },
    },
  });
  assert.equal(reserved.status, 'RESERVED', JSON.stringify(reserved));
  if (reserved.status !== 'RESERVED') return;
  assert.equal(reserved.reservation.impact_units, '750000');
  assert.equal(boundary.snapshot().available_units, '250000');
});

test('GRACE curtailment reserves requested watts and ignores claimed telemetry benefit', async () => {
  assert.deepEqual(GRACE_CURTAILMENT_IMPACT_PROFILE.derive({
    action_type: 'grid.curtailment.1',
    facility: 'facility:us-west-dc-17',
    target_delta_kw: '18000.125',
    telemetry: { delivered_kw: '999999', confidence: 1 },
  }), { ok: true, impact_units: 18000125n });
  assert.deepEqual(GRACE_CURTAILMENT_IMPACT_PROFILE.derive({
    action_type: 'grid.curtailment.1',
    facility: 'facility:us-west-dc-17',
    target_delta_kw: '-1',
  }), { ok: false, reason: 'consequence_impact_amount_invalid' });
});

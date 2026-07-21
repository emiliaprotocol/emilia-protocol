// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { hashCanonical } from './execution-binding.js';
import {
  createActionEscrowCustodianBridge,
  createActionEscrowCustodianStatementVerifier,
} from './action-escrow-custodian.js';

const digest = (character) => `sha256:${character.repeat(64)}`;
const transaction = {
  transaction_id: 'transaction-001',
  currency: 'USD',
  milestones: [{
    provider_item_id: 'milestone-provider-001',
    schedules: [{
      amount: '18400.00',
      beneficiary_customer: 'contractor@example.test',
    }],
  }],
};

function adapter(overrides = {}) {
  return {
    kind: 'external_custodian',
    provider: 'escrow.com',
    environment: 'sandbox',
    async reconcileTransaction() {
      return {
        kind: 'reconciled',
        provider: 'escrow.com',
        environment: 'sandbox',
        operation: 'reconcile_transaction',
        transaction_id: 'transaction-001',
        transaction,
      };
    },
    async releaseMilestone() {
      return {
        kind: 'release_submitted',
        provider: 'escrow.com',
        environment: 'sandbox',
        operation: 'release_milestone',
        effect_reference: 'ep-ae-release:test',
        transaction_id: 'transaction-001',
        milestone_id: 'milestone-provider-001',
        transaction,
      };
    },
    async requestMilestoneDisbursement() {
      return {
        kind: 'released',
        provider: 'escrow.com',
        environment: 'sandbox',
        operation: 'request_milestone_disbursement',
        effect_reference: 'ep-ae-release:test',
        transaction_id: 'transaction-001',
        milestone_id: 'milestone-provider-001',
        provider_phase: 'disbursed',
        transaction,
      };
    },
    ...overrides,
  };
}

const profile = {
  provider_id: 'escrow.com',
};
const profileDigest = digest('6');
const requestWithoutDigest = {
  method: 'POST',
  provider_id: 'escrow.com',
  agreement_digest: digest('1'),
  document_action_binding_digest: digest('2'),
  milestone_id: 'milestone-01',
  release_action_digest: digest('3'),
  parties: [
    { party_id: 'client', role: 'client' },
    { party_id: 'contractor', role: 'contractor' },
  ],
  parties_digest: digest('4'),
  profile,
  profile_digest: profileDigest,
  agreement_id: 'agreement-01',
  binding_id: 'binding-01',
  document_digest: digest('5'),
  release_action_template: {
    action_type: 'escrow.milestone.release',
    action_escrow_profile_digest: profileDigest,
    agreement_id: 'agreement-01',
    agreement_digest: digest('1'),
    milestone_id: 'milestone-01',
    amount: '18400.00',
    currency: 'USD',
    destination_id: 'contractor@example.test',
    payee_id: 'contractor',
    custodian_provider: 'escrow.com',
    custodian_environment: 'sandbox',
    custodian_transaction_id: 'transaction-001',
    custodian_milestone_id: 'milestone-provider-001',
    document_sha256: digest('5'),
    material_terms_sha256: digest('7'),
    completion_evidence_sha256: digest('8'),
    amendment_version: 1,
  },
  release_key: 'ep-ae-reservation:test',
  idempotency_key: 'ep-ae-release:test',
};
const request = {
  ...requestWithoutDigest,
  request_digest: `sha256:${hashCanonical({
    '@version': 'EP-ACTION-ESCROW-PROVIDER-REQUEST-v1',
    ...requestWithoutDigest,
  })}`,
};

function expectedObservation() {
  return {
    statement_type: 'release',
    provider_id: 'escrow.com',
    agreement_digest: request.agreement_digest,
    document_action_binding_digest: request.document_action_binding_digest,
    milestone_id: request.milestone_id,
    release_action_digest: request.release_action_digest,
    parties_digest: request.parties_digest,
    profile_digest: request.profile_digest,
    provider_idempotency_key: request.idempotency_key,
    provider_request_digest: request.request_digest,
    provider_transaction_id:
      request.release_action_template.custodian_transaction_id,
    provider_milestone_id:
      request.release_action_template.custodian_milestone_id,
    amount: request.release_action_template.amount,
    currency: request.release_action_template.currency,
    destination_id: request.release_action_template.destination_id,
  };
}

function setup(adapterOverride = adapter()) {
  const keys = crypto.generateKeyPairSync('ed25519');
  const keyId = 'operator-key-01';
  const bridge = createActionEscrowCustodianBridge({
    adapter: adapterOverride,
    observationSigner: { key_id: keyId, privateKey: keys.privateKey },
    now: () => '2026-07-17T12:00:00.000Z',
  });
  const verify = createActionEscrowCustodianStatementVerifier({
    operatorKeys: {
      [keyId]: {
        public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
    },
    providerId: 'escrow.com',
    environment: 'sandbox',
  });
  return { bridge, verify };
}

test('bridges the exact signed action to provider release and a portable observation', async () => {
  const { bridge, verify } = setup();
  await assert.doesNotReject(bridge.release(request));
  const response = await bridge.getRelease({ ...request, method: 'GET' });
  assert.equal(response.authenticated, true);
  const result = await verify(response.statement, expectedObservation());
  assert.equal(result.valid, true);
  assert.equal(result.status, 'released');
});

test('wrong amount or beneficiary refuses before the provider mutation', async () => {
  let releaseCalls = 0;
  const bad = adapter({
    async releaseMilestone() {
      releaseCalls++;
      return {
        kind: 'released',
        provider: 'escrow.com',
        environment: 'sandbox',
        operation: 'release_milestone',
        effect_reference: 'ep-ae-release:test',
        transaction_id: 'transaction-001',
        milestone_id: 'milestone-provider-001',
        transaction,
      };
    },
  });
  const { bridge } = setup(bad);
  await assert.rejects(
    bridge.release({
      ...request,
      release_action_template: {
        ...request.release_action_template,
        amount: '184000.00',
      },
    }),
    /invalid kernel release request|does not match/,
  );
  assert.equal(releaseCalls, 0);
});

test('sandbox and production cannot be crossed', () => {
  const keys = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => createActionEscrowCustodianBridge({
    adapter: { ...adapter(), environment: 'preview' },
    observationSigner: { key_id: 'operator', privateKey: keys.privateKey },
  }), /external custodian adapter/);
});

test('tampered observations and request substitutions are refused', async () => {
  const { bridge, verify } = setup();
  const response = await bridge.getRelease({ ...request, method: 'GET' });
  const tampered = structuredClone(response.statement);
  tampered.payload.status = 'not_released';
  assert.equal((await verify(tampered, expectedObservation())).valid, false);
  await assert.rejects(
    bridge.release({ ...request, document_action_binding_digest: digest('9') }),
    /invalid kernel release request/,
  );
});

test('unknown or unavailable provider state remains indeterminate', async () => {
  const { bridge } = setup(adapter({
    async requestMilestoneDisbursement() {
      return {
        kind: 'provider_error',
        provider: 'escrow.com',
        environment: 'sandbox',
        operation: 'request_milestone_disbursement',
        effect_reference: 'ep-ae-release:test',
        transaction_id: 'transaction-001',
        milestone_id: 'milestone-provider-001',
        reason_code: 'PROVIDER_UNAVAILABLE',
      };
    },
  }));
  await assert.rejects(
    bridge.getRelease({ ...request, method: 'GET' }),
    /indeterminate/,
  );
});

test('provider identity and transaction substitutions are never re-signed', async () => {
  for (const substituted of [
    { provider: 'other-provider' },
    { environment: 'production' },
    { operation: 'release_milestone' },
    { transaction_id: 'transaction-attacker' },
    { milestone_id: 'milestone-attacker' },
    { effect_reference: 'effect-attacker' },
    {
      transaction: {
        ...transaction,
        transaction_id: 'transaction-attacker',
      },
    },
  ]) {
    const { bridge } = setup(adapter({
      async requestMilestoneDisbursement() {
        return {
          kind: 'released',
          provider: 'escrow.com',
          environment: 'sandbox',
          operation: 'request_milestone_disbursement',
          effect_reference: 'ep-ae-release:test',
          transaction_id: 'transaction-001',
          milestone_id: 'milestone-provider-001',
          provider_phase: 'disbursed',
          transaction,
          ...substituted,
        };
      },
    }));
    await assert.rejects(
      bridge.getRelease({ ...request, method: 'GET' }),
      /indeterminate/,
    );
  }
});

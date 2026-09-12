// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { buildOutcomeObservationV2 } from '@emilia-protocol/verify/outcome-binding';
import {
  PROVIDER_OUTCOME_CONTEXT_VERSION,
  buildProviderOutcomeBinding,
  providerOutcomeContextDigest,
  providerOutcomeObservationEffects,
  verifyProviderOutcomeBinding,
  type ProviderOutcomeContext,
} from './provider-outcome-binding.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const NOW = '2026-09-04T12:03:00.000Z';
const SOURCE = {
  role: 'system_of_record' as const,
  source_id: 'source:stripe-ledger',
  source_class: 'provider.system-of-record',
};

const context: ProviderOutcomeContext = {
  '@version': PROVIDER_OUTCOME_CONTEXT_VERSION,
  tenant_id: 'tenant:alpha',
  admission_id: 'admission:001',
  operation_id: 'operation:001',
  snapshot_digest: D('1'),
  caid: CAID,
  action_digest: D('2'),
  effect_request_digest: D('3'),
  provider: 'provider:stripe',
  account: 'account:merchant',
  environment: 'production',
  adapter_id: 'adapter:stripe:v1',
  idempotency_key: 'idempotency:operation:001',
  outcome: 'COMMITTED',
  observed_at: '2026-09-04T12:01:00.000Z',
};

const ed = crypto.generateKeyPairSync('ed25519');
const edPublic = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPublic = Buffer.from(pq.publicKey).toString('base64url');
const pqSecret = Buffer.from(pq.secretKey).toString('base64url');

const activeSourceKeys = {
  [SOURCE.source_id]: {
    public_key: edPublic,
    pq_public_key: pqPublic,
    role: SOURCE.role,
    source_class: SOURCE.source_class,
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
    status: 'active',
  },
};

async function fixture(overrides: Partial<ProviderOutcomeContext> = {}) {
  const providerContext = { ...context, ...overrides } as ProviderOutcomeContext;
  const observation = await buildOutcomeObservationV2({
    receipt_id: 'receipt:001',
    receipt_digest: D('4'),
    action_hash: providerContext.action_digest,
    action_caid: providerContext.caid,
    consumption_nonce: 'consumption:001',
    operation_id: providerContext.operation_id,
    source: SOURCE,
    observed_from: '2026-09-04T12:00:00.000Z',
    observed_until: providerContext.observed_at,
    attested_at: '2026-09-04T12:02:00.000Z',
    observed_effects: providerOutcomeObservationEffects(providerContext),
    signer: {
      privateKey: ed.privateKey,
      pqPrivateKey: pqSecret,
      pqPublicKey: pqPublic,
    },
  });
  const binding = buildProviderOutcomeBinding({
    provider_context: providerContext,
    outcome_observation: observation,
  });
  return { providerContext, observation, binding };
}

function options(expectedContext: ProviderOutcomeContext = context) {
  return {
    source_keys: activeSourceKeys,
    expected_source: SOURCE,
    expected_context: expectedContext,
    now: NOW,
    maximum_observation_age_ms: 120_000,
  };
}

test('provider context digest is deterministic and changes with exact action context', () => {
  assert.equal(providerOutcomeContextDigest(context), providerOutcomeContextDigest(structuredClone(context)));
  assert.notEqual(
    providerOutcomeContextDigest(context),
    providerOutcomeContextDigest({ ...context, account: 'account:other' }),
  );
});

test('verifies a complete hybrid-signed provider outcome under external pins', async () => {
  const { providerContext, observation, binding } = await fixture();
  const verified = await verifyProviderOutcomeBinding(
    binding,
    observation,
    options(providerContext),
  );
  assert.equal(verified.valid, true, verified.reason ?? verified.source_errors.join(' | '));
  assert.equal(verified.status, 'VERIFIED');
  assert.ok(Object.values(verified.checks).every(Boolean));
  assert.equal(verified.context?.outcome, 'COMMITTED');
});

test('refuses digest-only evidence and missing external context', async () => {
  const { observation, binding } = await fixture();
  const digestOnly = {
    '@version': 'EP-OUTCOME-OBSERVATION-v2',
    observed_effects_digest: observation.observed_effects_digest,
  };
  const missingObservation = await verifyProviderOutcomeBinding(
    binding,
    digestOnly,
    options(),
  );
  assert.equal(missingObservation.valid, false);
  assert.equal(missingObservation.status, 'INCOMPLETE');
  assert.equal(missingObservation.reason, 'complete_signed_observation_required');

  const missingContext = await verifyProviderOutcomeBinding(
    binding,
    observation,
    { ...options(), expected_context: undefined as unknown as ProviderOutcomeContext },
  );
  assert.equal(missingContext.status, 'INCOMPLETE');
  assert.equal(missingContext.reason, 'expected_context_missing_or_invalid');
});

test('refuses presenter-supplied trust keys in the closed bridge', async () => {
  const { observation, binding } = await fixture();
  const injected = {
    ...structuredClone(binding),
    source_keys: activeSourceKeys,
  };
  const verified = await verifyProviderOutcomeBinding(injected, observation, options());
  assert.equal(verified.status, 'CONFLICTED');
  assert.equal(verified.reason, 'binding_structure_invalid');
});

test('every exact provider-context substitution is refused', async (t) => {
  const { observation, binding } = await fixture();
  const substitutions: Array<[keyof ProviderOutcomeContext, string]> = [
    ['tenant_id', 'tenant:other'],
    ['admission_id', 'admission:other'],
    ['operation_id', 'operation:other'],
    ['snapshot_digest', D('5')],
    ['caid', `caid:1:payment.release.1:jcs-sha256:${'B'.repeat(43)}`],
    ['action_digest', D('6')],
    ['effect_request_digest', D('7')],
    ['provider', 'provider:other'],
    ['account', 'account:other'],
    ['environment', 'sandbox'],
    ['adapter_id', 'adapter:other:v1'],
    ['idempotency_key', 'idempotency:other'],
    ['outcome', 'PROVEN_NOT_COMMITTED'],
    ['observed_at', '2026-09-04T12:01:30.000Z'],
  ];
  for (const [field, replacement] of substitutions) {
    await t.test(String(field), async () => {
      const changed = {
        ...context,
        [field]: replacement,
      } as ProviderOutcomeContext;
      const verified = await verifyProviderOutcomeBinding(
        binding,
        observation,
        options(changed),
      );
      assert.equal(verified.status, 'CONFLICTED');
      assert.equal(verified.reason, 'expected_context_mismatch');
    });
  }
});

test('refuses source substitution, missing pins, stale pins, and compromised pins', async (t) => {
  const { observation, binding } = await fixture();
  await t.test('source substitution', async () => {
    const verified = await verifyProviderOutcomeBinding(binding, observation, {
      ...options(),
      expected_source: { ...SOURCE, source_id: 'source:other-ledger' },
    });
    assert.equal(verified.status, 'CONFLICTED');
    assert.equal(verified.reason, 'outcome_source_substitution');
  });
  await t.test('missing pin', async () => {
    const verified = await verifyProviderOutcomeBinding(binding, observation, {
      ...options(),
      source_keys: {},
    });
    assert.equal(verified.status, 'INCOMPLETE');
    assert.equal(verified.reason, 'pinned_outcome_source_key_required');
  });
  await t.test('stale pin', async () => {
    const verified = await verifyProviderOutcomeBinding(binding, observation, {
      ...options(),
      source_keys: {
        [SOURCE.source_id]: {
          ...activeSourceKeys[SOURCE.source_id],
          valid_to: '2026-09-04T11:59:00.000Z',
        },
      },
    });
    assert.equal(verified.status, 'INCOMPLETE');
    assert.equal(verified.reason, 'outcome_source_not_current');
  });
  await t.test('compromised pin', async () => {
    const verified = await verifyProviderOutcomeBinding(binding, observation, {
      ...options(),
      source_keys: {
        [SOURCE.source_id]: {
          ...activeSourceKeys[SOURCE.source_id],
          status: 'compromised',
          compromised_at: '2026-09-04T12:01:30.000Z',
        },
      },
    });
    assert.equal(verified.status, 'INCOMPLETE');
    assert.equal(verified.reason, 'outcome_source_not_current');
  });
});

test('refuses signature tampering, signed-field substitution, and stale observation', async (t) => {
  const { observation, binding } = await fixture();
  await t.test('signature tampering', async () => {
    const tampered = structuredClone(observation);
    const original = tampered.proof.signatures[0].sig;
    tampered.proof.signatures[0].sig = `${original.slice(0, -1)}${original.endsWith('A') ? 'B' : 'A'}`;
    const changedBinding = buildProviderOutcomeBinding({
      provider_context: context,
      outcome_observation: tampered,
    });
    const verified = await verifyProviderOutcomeBinding(changedBinding, tampered, options());
    assert.equal(verified.status, 'CONFLICTED');
    assert.equal(verified.reason, 'outcome_observation_not_verified');
  });
  await t.test('signed action substitution', async () => {
    const tampered = structuredClone(observation);
    tampered.action_hash = D('8');
    const changedBinding = buildProviderOutcomeBinding({
      provider_context: context,
      outcome_observation: tampered,
    });
    const verified = await verifyProviderOutcomeBinding(changedBinding, tampered, options());
    assert.equal(verified.status, 'CONFLICTED');
    assert.equal(verified.reason, 'outcome_observation_not_verified');
  });
  await t.test('stale observation', async () => {
    const verified = await verifyProviderOutcomeBinding(binding, observation, {
      ...options(),
      now: '2026-09-04T13:00:00.000Z',
    });
    assert.equal(verified.status, 'INCOMPLETE');
    assert.equal(verified.reason, 'outcome_observation_stale');
  });
});

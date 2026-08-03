// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  createExecutionValueProviderEntryGuard,
  signExecutionValueAttestation,
  verifyExecutionValueAttestation,
  hashCanonical,
  providerEntryContext,
} from './index.js';

const NOW = Date.parse('2026-08-03T12:00:00.000Z');
const ACTION = {
  action_type: 'trade.execute',
  instrument: 'EURUSD',
  amount: 10_000,
  currency: 'EUR',
  order_id: 'order-1',
};

function fixture(overrides: Record<string, any> = {}) {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const attestation = signExecutionValueAttestation({
    action_digest: `sha256:${hashCanonical(ACTION)}`,
    asset_currency: 'EUR',
    quote_currency: 'USD',
    value_minor: 1_080_000,
    source: 'oracle.example/v1',
    key_id: 'oracle-key-1',
    observed_at: new Date(NOW - 1_000).toISOString(),
    expires_at: new Date(NOW + 5_000).toISOString(),
    ...overrides,
  }, pair.privateKey);
  return { pair, publicKey, attestation };
}

test('execution value attestation is signature-, action-, source-, time-, and cap-bound', () => {
  const f = fixture();
  const options = {
    action: ACTION,
    trustedKeys: { 'oracle-key-1': f.publicKey },
    allowedSources: ['oracle.example/v1'],
    maxValueMinor: 1_100_000,
    now: NOW,
  };
  assert.equal(verifyExecutionValueAttestation(f.attestation, options).ok, true);
  assert.equal(verifyExecutionValueAttestation(f.attestation, { ...options, action: { ...ACTION, order_id: 'other' } }).reason, 'execution_value_action_mismatch');
  assert.equal(verifyExecutionValueAttestation(f.attestation, { ...options, allowedSources: ['other'] }).reason, 'execution_value_source_untrusted');
  assert.equal(verifyExecutionValueAttestation(f.attestation, { ...options, maxValueMinor: 1_000_000 }).reason, 'execution_value_limit_exceeded');
  assert.equal(verifyExecutionValueAttestation(f.attestation, { ...options, now: NOW + 20_000 }).reason, 'execution_value_stale');
  const tampered = structuredClone(f.attestation) as any;
  tampered.payload.value_minor = 1;
  assert.equal(verifyExecutionValueAttestation(tampered, options).reason, 'execution_value_signature_invalid');
});

test('non-USD provider entry requires the fresh signed value while USD is checked directly', async () => {
  const f = fixture();
  let resolverCalls = 0;
  const guard = createExecutionValueProviderEntryGuard({
    maxValueMinor: 1_100_000,
    trustedKeys: { 'oracle-key-1': f.publicKey },
    allowedSources: ['oracle.example/v1'],
    resolveAttestation: async () => { resolverCalls += 1; return f.attestation; },
    now: NOW,
  });
  const result = await guard(providerEntryContext({ observedAction: ACTION, now: NOW }));
  assert.equal(result.ok, true);
  assert.equal(resolverCalls, 1);

  const usd = await guard(providerEntryContext({
    observedAction: { action_type: 'payment.release', amount_minor: 500_000, currency: 'USD' },
    now: NOW,
  }));
  assert.equal(usd.ok, true);
  assert.equal(resolverCalls, 1);

  const tooLarge = await guard(providerEntryContext({
    observedAction: { action_type: 'payment.release', amount_minor: 2_000_000, currency: 'USD' },
    now: NOW,
  }));
  assert.equal(tooLarge.reason, 'execution_value_limit_exceeded');
});

test('oracle outage and malformed evidence fail closed', async () => {
  const f = fixture();
  const unavailable = createExecutionValueProviderEntryGuard({
    maxValueMinor: 2_000_000,
    trustedKeys: { 'oracle-key-1': f.publicKey },
    allowedSources: ['oracle.example/v1'],
    resolveAttestation: async () => { throw new Error('down'); },
    now: NOW,
  });
  assert.equal((await unavailable(providerEntryContext({ observedAction: ACTION, now: NOW }))).reason, 'execution_value_oracle_unavailable');

  const malformed = createExecutionValueProviderEntryGuard({
    maxValueMinor: 2_000_000,
    trustedKeys: { 'oracle-key-1': f.publicKey },
    allowedSources: ['oracle.example/v1'],
    resolveAttestation: async () => ({}),
    now: NOW,
  });
  assert.equal((await malformed(providerEntryContext({ observedAction: ACTION, now: NOW }))).reason, 'execution_value_attestation_malformed');
});

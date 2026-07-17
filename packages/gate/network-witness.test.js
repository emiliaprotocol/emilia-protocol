// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  NETWORK_WITNESS_ACCEPTANCE_VERSION,
  acceptNetworkWitnessStatement,
  createMemoryWitnessSequenceStore,
  parseNetworkWitnessStatement,
  signNetworkWitnessStatement,
  validateTrustedNetworkWitnessAcceptance,
  verifyNetworkWitnessStatement,
} from './network-witness.js';

const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const ACTION = `sha256:${'11'.repeat(32)}`;
const CONFIG = `sha256:${'22'.repeat(32)}`;
const FLOW = `sha256:${'33'.repeat(32)}`;

function fixture(sequence = 7) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const statement = signNetworkWitnessStatement({
    witness_id: 'witness:edge-1',
    capture_point_id: 'capture:grid-ingress-a',
    sequence,
    observed_at: '2026-07-16T19:59:30.000Z',
    event: 'request_observed',
    direction: 'ingress',
    action_digest: ACTION,
    flow_digest: FLOW,
    byte_count: 487,
    config_digest: CONFIG,
  }, privateKey);
  const pin = {
    witness_id: 'witness:edge-1',
    key_id: statement.witness.key_id,
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    capture_point_ids: ['capture:grid-ingress-a'],
    config_digests: [CONFIG],
  };
  return { statement, pin, privateKey, publicKey };
}

test('accepts a fresh, exact-action observation from a pinned capture point', () => {
  const { statement, pin } = fixture();
  const result = verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [pin], expectedActionDigest: ACTION, expectedEvent: 'request_observed', now: NOW,
  });
  assert.equal(result.accepted, true);
  assert.equal(result.action_digest, ACTION);
  assert.equal(result.sequence, 7);
  assert.equal(result.checks.signature, true);
});

test('refuses unpinned, cross-capture, wrong-config, and wrong-action statements', () => {
  const { statement, pin } = fixture();
  assert.equal(verifyNetworkWitnessStatement(statement, { pinnedWitnesses: [], now: NOW }).reason, 'witness_key_unpinned');
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [{ ...pin, capture_point_ids: ['capture:other'] }], now: NOW,
  }).reason, 'witness_key_unpinned');
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [{ ...pin, config_digests: [`sha256:${'99'.repeat(32)}`] }], now: NOW,
  }).reason, 'witness_config_unpinned');
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [{ ...pin, config_digests: undefined }], now: NOW,
  }).reason, 'witness_config_unpinned');
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [pin], expectedActionDigest: `sha256:${'44'.repeat(32)}`, now: NOW,
  }).reason, 'action_digest_mismatch');
});

test('tampering signed fields fails even when visible digest fields look valid', () => {
  const { statement, pin } = fixture();
  const tampered = structuredClone(statement);
  tampered.observation.byte_count = 488;
  assert.equal(verifyNetworkWitnessStatement(tampered, { pinnedWitnesses: [pin], now: NOW }).reason, 'statement_digest_mismatch');
  const relabeled = structuredClone(statement);
  relabeled.witness.id = 'witness:attacker';
  assert.equal(verifyNetworkWitnessStatement(relabeled, { pinnedWitnesses: [pin], now: NOW }).reason, 'witness_key_unpinned');
});

test('stale, future, invalid calendar, payload-capture, and unknown-field artifacts refuse', () => {
  const { statement, pin, privateKey } = fixture();
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [pin], maxAgeSec: 10, now: NOW,
  }).reason, 'observation_stale');
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [pin], now: Date.parse('2026-07-16T19:58:00.000Z'), maxFutureSkewSec: 5,
  }).reason, 'observation_from_future');
  assert.throws(() => signNetworkWitnessStatement({
    witness_id: 'w', capture_point_id: 'c', sequence: 1, observed_at: '2026-02-30T00:00:00.000Z',
    event: 'request_observed', direction: 'ingress', action_digest: ACTION, config_digest: CONFIG,
  }, privateKey), /observed_at_invalid/);
  const capture = structuredClone(statement);
  capture.privacy.payload_captured = true;
  assert.equal(verifyNetworkWitnessStatement(capture, { pinnedWitnesses: [pin], now: NOW }).reason, 'payload_capture_forbidden');
  const extended = structuredClone(statement);
  extended.observation.source_ip = '203.0.113.1';
  assert.equal(verifyNetworkWitnessStatement(extended, { pinnedWitnesses: [pin], now: NOW }).reason, 'observation_shape_invalid');
});

test('online ingestion refuses replay, rollback, equivocation, ephemeral production stores, and outages', async () => {
  const first = fixture(7);
  const store = createMemoryWitnessSequenceStore();
  const options = { pinnedWitnesses: [first.pin], now: NOW, sequenceStore: store, allowEphemeralStore: true };
  assert.equal((await acceptNetworkWitnessStatement(first.statement, options)).accepted, true);
  assert.equal((await acceptNetworkWitnessStatement(first.statement, options)).reason, 'statement_replay');

  const rollback = signNetworkWitnessStatement({
    witness_id: 'witness:edge-1', capture_point_id: 'capture:grid-ingress-a', sequence: 6,
    observed_at: '2026-07-16T19:59:40.000Z', event: 'request_observed', direction: 'ingress',
    action_digest: ACTION, flow_digest: FLOW, config_digest: CONFIG,
  }, first.privateKey);
  assert.equal((await acceptNetworkWitnessStatement(rollback, options)).reason, 'sequence_rollback');

  const equivocation = signNetworkWitnessStatement({
    witness_id: 'witness:edge-1', capture_point_id: 'capture:grid-ingress-a', sequence: 7,
    observed_at: '2026-07-16T19:59:45.000Z', event: 'response_observed', direction: 'egress',
    action_digest: ACTION, config_digest: CONFIG,
  }, first.privateKey);
  assert.equal((await acceptNetworkWitnessStatement(equivocation, options)).reason, 'sequence_equivocation');

  assert.equal((await acceptNetworkWitnessStatement(first.statement, {
    pinnedWitnesses: [first.pin], now: NOW, sequenceStore: createMemoryWitnessSequenceStore(),
  })).reason, 'durable_sequence_store_required');
  assert.equal((await acceptNetworkWitnessStatement(first.statement, {
    pinnedWitnesses: [first.pin], now: NOW,
    sequenceStore: { durable: true, advance: async () => { throw new Error('down'); } },
  })).reason, 'sequence_store_unavailable');
  const contradictory = await acceptNetworkWitnessStatement(first.statement, {
    pinnedWitnesses: [first.pin], now: NOW,
    sequenceStore: {
      durable: true,
      advance: async () => ({ accepted: true, reason: 'sequence_equivocation' }),
    },
  });
  assert.equal(contradictory.accepted, false);
  assert.equal(contradictory.reason, 'sequence_equivocation');
});

test('a durable acceptance result can be reused only through the explicit trusted channel', async () => {
  const { statement, pin } = fixture();
  const memory = createMemoryWitnessSequenceStore();
  const acceptance = await acceptNetworkWitnessStatement(statement, {
    pinnedWitnesses: [pin],
    now: NOW,
    sequenceStore: { durable: true, advance: (...args) => memory.advance(...args) },
  });
  assert.equal(acceptance.acceptance_version, NETWORK_WITNESS_ACCEPTANCE_VERSION);
  assert.equal(acceptance.sequence_store_durable, true);
  assert.equal(validateTrustedNetworkWitnessAcceptance(acceptance, {
    expectedStatementDigest: acceptance.statement_digest,
    expectedActionDigest: ACTION,
    expectedEvent: 'request_observed',
    now: NOW,
  }).accepted, true);

  const ephemeralFixture = fixture();
  const ephemeral = await acceptNetworkWitnessStatement(ephemeralFixture.statement, {
    pinnedWitnesses: [ephemeralFixture.pin],
    now: NOW,
    sequenceStore: createMemoryWitnessSequenceStore(),
    allowEphemeralStore: true,
  });
  assert.equal(validateTrustedNetworkWitnessAcceptance(ephemeral, { now: NOW }).reason, 'durable_sequence_store_required');
});

test('hostile values never escape the verifier', () => {
  for (const value of [null, [], 'x', 1, { '@version': 'x' }]) {
    assert.doesNotThrow(() => verifyNetworkWitnessStatement(value));
    assert.equal(verifyNetworkWitnessStatement(value).accepted, false);
  }
  const hostile = {};
  Object.defineProperty(hostile, 'witness', { enumerable: true, get() { throw new Error('boom'); } });
  assert.doesNotThrow(() => verifyNetworkWitnessStatement(hostile));
  assert.equal(verifyNetworkWitnessStatement(hostile).reason, 'hostile_input_refused');
});

test('serialized ingress refuses duplicate keys, invalid Unicode, and oversized artifacts', () => {
  const { statement } = fixture();
  assert.deepEqual(parseNetworkWitnessStatement(JSON.stringify(statement)), statement);
  assert.equal(parseNetworkWitnessStatement('{"witness":{},"witness":{}}'), null);
  assert.equal(parseNetworkWitnessStatement('{"x":"\\ud800"}'), null);
  assert.equal(parseNetworkWitnessStatement(JSON.stringify(statement), { maxBytes: 10 }), null);
});

test('non-canonical encodings and non-Ed25519 pinned keys refuse', () => {
  const { statement, pin } = fixture();
  const badSignature = structuredClone(statement);
  badSignature.signature.signature_b64u += '=';
  assert.equal(verifyNetworkWitnessStatement(badSignature, { pinnedWitnesses: [pin], now: NOW }).reason, 'signature_invalid');
  const badKey = { ...pin, public_key: `${pin.public_key}=` };
  assert.equal(verifyNetworkWitnessStatement(statement, { pinnedWitnesses: [badKey], now: NOW }).reason, 'pinned_key_invalid');
  const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const wrongAlgorithm = {
    ...pin,
    public_key: p256.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  assert.equal(verifyNetworkWitnessStatement(statement, {
    pinnedWitnesses: [wrongAlgorithm], now: NOW,
  }).reason, 'pinned_key_invalid');
});

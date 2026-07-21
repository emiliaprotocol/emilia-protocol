// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEPLOYMENT_PROFILE_VERSION,
  deploymentProfileDigest,
  verifyDeploymentAttestation,
} from './deployment-attestation.js';

const NOW = Date.parse('2026-07-16T20:00:00.000Z');
const profile = {
  '@version': DEPLOYMENT_PROFILE_VERSION,
  profile_id: 'profile:grid-gate-prod',
  verifier_id: 'verifier:rat-eat-prod',
  evidence_type: 'application/eat+cwt',
  gate_id: 'gate:grid-west',
  environment_id: 'env:prod-west',
  audience: 'rp:grid-settlement',
  nonce: 'challenge:2026-07-16T20:00Z',
  max_age_sec: 300,
  max_future_skew_sec: 30,
  required_measurements: {
    config: `sha256:${'11'.repeat(32)}`,
    image: `sha256:${'22'.repeat(32)}`,
    policy: `sha256:${'33'.repeat(32)}`,
    workload: `sha256:${'44'.repeat(32)}`,
  },
};

function claims(over = {}) {
  return {
    verified: true,
    verifier_id: profile.verifier_id,
    evidence_type: profile.evidence_type,
    gate_id: profile.gate_id,
    environment_id: profile.environment_id,
    audience: profile.audience,
    nonce: profile.nonce,
    issued_at: '2026-07-16T19:59:30.000Z',
    expires_at: '2026-07-16T20:04:30.000Z',
    measurements: { ...profile.required_measurements },
    ...over,
  };
}

test('accepts normalized claims only from the profile-pinned verifier', async () => {
  const result = await verifyDeploymentAttestation({ token: 'opaque' }, {
    profile, now: NOW, verifiers: { [profile.verifier_id]: async () => claims() },
  });
  assert.equal(result.accepted, true);
  assert.equal(result.verdict, 'attested');
  assert.equal(result.profile_hash, deploymentProfileDigest(profile));
  assert.equal(result.checks.measurements, true);
});

test('empty object verifier registry cannot inherit constructor and accept supplied claims', async () => {
  const constructorProfile = { ...profile, verifier_id: 'constructor' };
  const result = await verifyDeploymentAttestation(claims({ verifier_id: 'constructor' }), {
    profile: constructorProfile,
    now: NOW,
    verifiers: {},
  });
  assert.equal(result.accepted, false);
  assert.equal(result.verdict, 'refuse_verifier_unpinned');
  assert.equal(result.reason, 'pinned_verifier_missing');
  assert.equal(result.checks.verifier, false);
});

test('object verifier registries ignore inherited names, accessors, and non-callable own entries', async () => {
  for (const verifierId of Object.getOwnPropertyNames(Object.prototype)) {
    if (verifierId === 'constructor') continue;
    const result = await verifyDeploymentAttestation({}, {
      profile: { ...profile, verifier_id: verifierId },
      now: NOW,
      verifiers: {},
    });
    assert.equal(result.verdict, 'refuse_verifier_unpinned', verifierId);
  }

  const nonCallable = await verifyDeploymentAttestation({}, {
    profile,
    now: NOW,
    verifiers: { [profile.verifier_id]: {} },
  });
  assert.equal(nonCallable.verdict, 'refuse_verifier_unpinned');

  let accessorCalled = false;
  const accessorBacked = {};
  Object.defineProperty(accessorBacked, profile.verifier_id, {
    enumerable: true,
    get() {
      accessorCalled = true;
      return async () => claims();
    },
  });
  const accessorResult = await verifyDeploymentAttestation({}, {
    profile,
    now: NOW,
    verifiers: accessorBacked,
  });
  assert.equal(accessorResult.verdict, 'refuse_verifier_unpinned');
  assert.equal(accessorCalled, false);
});

test('accepts an own callable verifier whose id matches a prototype name', async () => {
  const constructorProfile = { ...profile, verifier_id: 'constructor' };
  let verifierCalls = 0;
  const result = await verifyDeploymentAttestation({ token: 'opaque' }, {
    profile: constructorProfile,
    now: NOW,
    verifiers: {
      constructor: async () => {
        verifierCalls += 1;
        return claims({ verifier_id: 'constructor' });
      },
    },
  });
  assert.equal(result.accepted, true);
  assert.equal(result.verdict, 'attested');
  assert.equal(result.checks.verifier, true);
  assert.equal(verifierCalls, 1);
});

test('artifact labels cannot select an unpinned verifier', async () => {
  const result = await verifyDeploymentAttestation({ verifier_id: 'attacker', verified: true }, {
    profile, now: NOW, verifiers: { attacker: async () => claims() },
  });
  assert.equal(result.verdict, 'refuse_verifier_unpinned');
});

test('context, nonce, measurement, freshness, and calendar mismatches refuse', async () => {
  const run = (over) => verifyDeploymentAttestation({}, {
    profile, now: NOW, verifiers: { [profile.verifier_id]: async () => claims(over) },
  });
  assert.equal((await run({ gate_id: 'gate:attacker' })).verdict, 'refuse_context_mismatch');
  assert.equal((await run({ nonce: 'wrong' })).verdict, 'refuse_context_mismatch');
  assert.equal((await run({ measurements: { ...profile.required_measurements, policy: `sha256:${'99'.repeat(32)}` } })).verdict, 'refuse_measurement_mismatch');
  assert.equal((await run({ issued_at: '2026-07-16T19:00:00.000Z' })).verdict, 'refuse_stale');
  assert.equal((await run({ expires_at: '2026-07-16T19:59:59.999Z' })).verdict, 'refuse_stale');
  assert.equal((await run({ issued_at: '2026-02-30T00:00:00.000Z' })).verdict, 'refuse_stale');
});

test('invalid profile, invalid result, callback errors, hostile claims, and partial measurements refuse', async () => {
  assert.equal((await verifyDeploymentAttestation({}, { profile: { ...profile, max_age_sec: '300' } })).verdict, 'refuse_profile_invalid');
  assert.equal((await verifyDeploymentAttestation({}, { profile: { ...profile, nonce: undefined } })).reason, 'profile_nonce_invalid');
  assert.equal((await verifyDeploymentAttestation({}, {
    profile, verifiers: { [profile.verifier_id]: async () => null }, now: NOW,
  })).verdict, 'refuse_evidence_invalid');
  assert.equal((await verifyDeploymentAttestation({}, {
    profile, verifiers: { [profile.verifier_id]: async () => { throw new Error('down'); } }, now: NOW,
  })).verdict, 'refuse_verifier_error');
  assert.equal((await verifyDeploymentAttestation({}, {
    profile, verifiers: { [profile.verifier_id]: async () => claims({ measurements: { image: profile.required_measurements.image } }) }, now: NOW,
  })).verdict, 'refuse_measurement_mismatch');
  const cyclic = claims();
  cyclic.self = cyclic;
  assert.equal((await verifyDeploymentAttestation({}, {
    profile, verifiers: { [profile.verifier_id]: async () => cyclic }, now: NOW,
  })).verdict, 'refuse_evidence_invalid');
});

test('profile mutation during verifier execution cannot weaken the pinned context', async () => {
  const mutable = structuredClone(profile);
  const result = await verifyDeploymentAttestation({}, {
    profile: mutable,
    now: NOW,
    verifiers: {
      [profile.verifier_id]: async () => {
        mutable.gate_id = 'gate:attacker';
        mutable.required_measurements = { image: profile.required_measurements.image };
        return claims();
      },
    },
  });
  assert.equal(result.accepted, true);
  assert.equal(result.gate_id, profile.gate_id);
  assert.deepEqual(result.measurements, profile.required_measurements);
});

test('accessor-backed profiles refuse without throwing', async () => {
  const hostile = { '@version': DEPLOYMENT_PROFILE_VERSION };
  Object.defineProperty(hostile, 'profile_id', {
    enumerable: true,
    get() { throw new Error('boom'); },
  });
  await assert.doesNotReject(() => verifyDeploymentAttestation({}, { profile: hostile }));
  const result = await verifyDeploymentAttestation({}, { profile: hostile });
  assert.equal(result.verdict, 'refuse_profile_invalid');
  assert.equal(result.reason, 'profile_hostile_input');
});

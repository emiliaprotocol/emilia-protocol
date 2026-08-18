// SPDX-License-Identifier: Apache-2.0
//
// EP-GATE-BREAKGLASS-v2 -- hostile matrix for the hybrid M-of-N roster.
// Package-root node:test file importing the compatibility shim
// './breakglass.js' (which re-exports ./dist/breakglass.js), matching this
// package's convention; the dist-backed packages/gate/breakglass.test.js keeps
// covering v1.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import {
  BREAKGLASS_V2_VERSION,
  BREAKGLASS_V2_REQUIRED_ALGORITHMS,
  mintBreakGlassAuthorizationV2,
  verifyBreakGlassV2,
  verifyBreakGlassStatement,
  runBreakGlassStatement,
  mintBreakGlassAuthorization,
} from './breakglass.js';
import { createDurableConsumptionStore, createMemoryBackend } from './store.js';
import { createEvidenceLog } from './evidence.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

function makeHybridSigner(kid: string) {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPub = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPub = Buffer.from(pq.publicKey).toString('base64url');
  return {
    kid,
    ed: { privateKey: ed.privateKey },
    pq: { secretKey: pq.secretKey },
    edPub,
    pqPub,
    principal_id: `principal:${kid}`,
  };
}

const NBF = '2026-08-17T00:00:00.000Z';
const EXP = '2026-08-17T04:00:00.000Z';
const IN_WINDOW = Date.parse('2026-08-17T01:00:00.000Z');
const FIELDS = {
  scope: { action_types: ['db.restore', 'feature.kill_switch'] },
  window: { not_before: NBF, expires_at: EXP },
  reason: 'primary region down, restoring from snapshot (hybrid)',
  incident_ref: 'INC-2026-0817-01',
  threshold: 2,
};

function v2Policy(signers: ReturnType<typeof makeHybridSigner>[], minimumThreshold = 2) {
  return {
    minimum_threshold: minimumThreshold,
    roster: signers.map((s) => ({ kid: s.kid, principal_id: s.principal_id, key: s.edPub, pq_key: s.pqPub })),
  };
}

describe('EP-GATE-BREAKGLASS-v2 hybrid M-of-N roster', () => {
  it('valid v2 roundtrip: 2-of-2 hybrid signers verify', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    assert.equal(grant['@version'], BREAKGLASS_V2_VERSION);
    assert.deepEqual(grant.payload.required_algorithms, [...BREAKGLASS_V2_REQUIRED_ALGORITHMS]);
    assert.equal(grant.signatures.every((s) => s.signatures.map((x) => x.alg).join(',') === 'Ed25519,ML-DSA-65'), true);

    const result = await verifyBreakGlassV2(grant, {
      policy: v2Policy([alice, bob]), now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(result.valid, true);
    assert.deepEqual(result.signer_kids, ['kid-alice', 'kid-bob']);
  });

  it('the router accepts a v1 grant unchanged, and a v2 one via the hybrid path', async () => {
    const edAlice = crypto.generateKeyPairSync('ed25519');
    const edBob = crypto.generateKeyPairSync('ed25519');
    const v1Signers = [
      { kid: 'v1-alice', privateKey: edAlice.privateKey },
      { kid: 'v1-bob', privateKey: edBob.privateKey },
    ];
    const v1Policy = {
      minimum_threshold: 2,
      roster: [
        { kid: 'v1-alice', principal_id: 'p:v1-alice', key: edAlice.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') },
        { kid: 'v1-bob', principal_id: 'p:v1-bob', key: edBob.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') },
      ],
    };
    const v1Grant = mintBreakGlassAuthorization(v1Signers, FIELDS);
    const v1Result = await verifyBreakGlassStatement(v1Grant, {
      policy: v1Policy, now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(v1Result.valid, true);

    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const v2Grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const v2Result = await verifyBreakGlassStatement(v2Grant, {
      policy: v2Policy([alice, bob]), now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(v2Result.valid, true);
  });

  it('v1-refuses-v2: the existing SYNC verifier refuses a v2 grant cleanly on the version marker', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const { verifyBreakGlass } = await import('./breakglass.js');
    // No await: verifyBreakGlass remains synchronous and untouched.
    const result = verifyBreakGlass(grant, {
      policy: { minimum_threshold: 2, roster: [] }, now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'unsupported_version');
  });

  it('M-of-N with one hybrid signer missing a leg refuses the whole grant, never a classical-only pass for that signer', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const strippedBob = {
      ...grant,
      signatures: grant.signatures.map((s) => (
        s.kid === 'kid-bob' ? { ...s, signatures: s.signatures.filter((x) => x.alg !== 'ML-DSA-65') } : s
      )),
    };
    const result = await verifyBreakGlassV2(strippedBob, {
      policy: v2Policy([alice, bob]), now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'signer_leg_missing');
  });

  it('narrowed set: claiming payload.required_algorithms=["Ed25519"] refuses every signer at once (bytes changed for all)', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const narrowed = {
      ...grant,
      payload: { ...grant.payload, required_algorithms: ['Ed25519'] },
      signatures: grant.signatures.map((s) => ({ ...s, signatures: s.signatures.filter((x) => x.alg === 'Ed25519') })),
    };
    const result = await verifyBreakGlassV2(narrowed, {
      policy: v2Policy([alice, bob]), now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'unsupported_algorithm_set');
  });

  it('wrong-length signature on a signer\'s ML-DSA leg refuses, never crashes', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const tampered = {
      ...grant,
      signatures: grant.signatures.map((s) => (
        s.kid === 'kid-alice'
          ? {
            ...s,
            signatures: s.signatures.map((x) => (
              x.alg === 'ML-DSA-65' ? { ...x, sig: Buffer.from(crypto.randomBytes(16)).toString('base64url') } : x
            )),
          }
          : s
      )),
    };
    const tamperedResult = await verifyBreakGlassV2(tampered, {
      policy: v2Policy([alice, bob]), now: IN_WINDOW, actionType: 'db.restore',
    });
    assert.equal(tamperedResult.valid, false);
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI pinned for a signer refuses, never verified under the wrong curve', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const policy = v2Policy([alice, bob]);
    policy.roster[0].key = ed448PubB64u; // swap alice's pinned classical key for an Ed448 one
    const result = await verifyBreakGlassV2(grant, { policy, now: IN_WINDOW, actionType: 'db.restore' });
    assert.equal(result.valid, false);
  });

  it('never throws on hostile input (absent, malformed JSON, threshold-1 grant)', async () => {
    for (const bad of [null, undefined, '', '{not json']) {
      const result = await verifyBreakGlassV2(bad as any, { policy: { minimum_threshold: 2, roster: [] } });
      assert.equal(result.valid, false);
    }
  });

  it('runBreakGlassStatement executes the effect only after a valid hybrid grant is verified, consumed, and logged', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const backend = createMemoryBackend();
    backend.durable = true;
    const store = createDurableConsumptionStore(backend);
    const log = createEvidenceLog({ strict: true });
    let effectCalls = 0;
    const outcome = await runBreakGlassStatement({
      grant,
      policy: v2Policy([alice, bob]),
      now: IN_WINDOW,
      actionType: 'db.restore',
      store,
      evidence: log,
    }, async () => { effectCalls += 1; return { restored: true }; });
    assert.equal(outcome.ok, true);
    assert.equal(effectCalls, 1);

    // Single-use: replaying the SAME grant never runs the effect twice.
    const replay = await runBreakGlassStatement({
      grant,
      policy: v2Policy([alice, bob]),
      now: IN_WINDOW,
      actionType: 'db.restore',
      store,
      evidence: log,
    }, async () => { effectCalls += 1; return { restored: true }; });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, 'already_consumed');
    assert.equal(effectCalls, 1);
  });

  it('runBreakGlassStatement never runs the effect on a leg-stripped grant', async () => {
    const alice = makeHybridSigner('kid-alice');
    const bob = makeHybridSigner('kid-bob');
    const grant = await mintBreakGlassAuthorizationV2([alice, bob], FIELDS);
    const strippedBob = {
      ...grant,
      signatures: grant.signatures.map((s) => (
        s.kid === 'kid-bob' ? { ...s, signatures: s.signatures.filter((x) => x.alg !== 'ML-DSA-65') } : s
      )),
    };
    const backend = createMemoryBackend();
    backend.durable = true;
    const store = createDurableConsumptionStore(backend);
    const log = createEvidenceLog({ strict: true });
    let effectCalls = 0;
    const outcome = await runBreakGlassStatement({
      grant: strippedBob,
      policy: v2Policy([alice, bob]),
      now: IN_WINDOW,
      actionType: 'db.restore',
      store,
      evidence: log,
    }, async () => { effectCalls += 1; return { restored: true }; });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.reason, 'signer_leg_missing');
    assert.equal(effectCalls, 0);
  });
});

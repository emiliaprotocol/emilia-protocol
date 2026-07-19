// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  createRegisteredEvidenceChallenge,
  evaluateRegisteredPresentation,
} from '../lib/negotiate/evidence-challenge.js';
import { artifactDigest, EVIDENCE_GRAPH_VERSION } from '../lib/evidence/evidence-graph.js';
import { getPolicyPack } from '../lib/evidence/policy-packs.js';
import { createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createMemoryBackend } from '../packages/gate/store.js';

const policy = getPolicyPack('ep:pack:wire-transfer:v1');
const action = { type: 'urn:ep:action:payments.wire_transfer', amount: '250000.00', currency: 'USD' };
const asOf = '2026-07-03T12:01:00Z';
const expiresAt = '2026-07-03T12:10:00Z';
const verifiers = {
  authorization_receipt: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at, revoked: false }),
  policy_permit: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at }),
  workload_identity: (artifact) => ({ valid: true, action_digest: artifact.action, issued_at: artifact.issued_at }),
};

function completeGraph() {
  const actionDigest = artifactDigest(action);
  const artifacts = ['authorization_receipt', 'policy_permit', 'workload_identity'].map((typ) => ({
    typ, action: actionDigest, issued_at: '2026-07-03T12:00:00Z',
  }));
  const authorization = artifacts[0];
  artifacts[1].permits_receipt = artifactDigest(authorization);
  const nodes = artifacts.map((artifact) => ({ id: artifactDigest(artifact), type: artifact.typ, artifact }));
  return {
    '@version': EVIDENCE_GRAPH_VERSION,
    action_digest: actionDigest,
    nodes,
    edges: [{ from: nodes[1].id, rel: 'permits', to: nodes[0].id }],
  };
}

describe('durable AE-CHALLENGE lifecycle', () => {
  it('atomically registers one exact challenge across 100 concurrent workers', async () => {
    const backend = createMemoryBackend();
    const stores = Array.from({ length: 100 }, () => createDurableChallengeStore(backend));
    const challenge = {
      '@version': 'AE-CHALLENGE-v1', challenge_id: 'challenge-atomic', nonce: 'nonce-atomic',
      action_digest: artifactDigest(action), expires_at: expiresAt,
    };
    const results = await Promise.all(stores.map((store) => store.register(challenge)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('survives restart and admits exactly one concurrent presentation', async () => {
    const backend = createMemoryBackend();
    const issuerStore = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: issuerStore, challenge_id: 'challenge-restart', nonce: 'nonce-restart', expires_at: expiresAt,
    });

    const restartedA = createDurableChallengeStore(backend);
    const restartedB = createDurableChallengeStore(backend);
    const results = await Promise.all([
      evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: restartedA, verifiers, as_of: asOf }),
      evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: restartedB, verifiers, as_of: asOf }),
    ]);
    expect(results.filter((result) => result.verdict === 'admissible')).toHaveLength(1);
    expect(results.filter((result) => result.verdict === 'refused')).toHaveLength(1);
    expect(results.find((result) => result.verdict === 'refused').reasons.join(' ')).toContain('replay');
  });

  it('binds registration to the entire challenge body, not only id and nonce', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-body', nonce: 'nonce-body', expires_at: expiresAt,
    });
    const tampered = { ...challenge, action_digest: `sha256:${'ef'.repeat(32)}` };
    const refused = await evaluateRegisteredPresentation(tampered, completeGraph(), policy, { challengeStore: store, verifiers, as_of: asOf });
    expect(refused.verdict).toBe('refused');
    expect(refused.reasons.join(' ')).toContain('tampered');

    const original = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, { challengeStore: store, verifiers, as_of: asOf });
    expect(original.verdict).toBe('admissible');
  });

  it('refuses policy drift without consuming the registered challenge', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-policy', nonce: 'nonce-policy', expires_at: expiresAt,
    });
    const weakened = { ...policy, requirement: 'authorization_receipt' };
    const refused = await evaluateRegisteredPresentation(challenge, completeGraph(), weakened, {
      challengeStore: store, verifiers, as_of: asOf,
    });
    expect(refused.verdict).toBe('refused');
    expect(refused.reasons.join(' ')).toContain('policy');

    const original = await evaluateRegisteredPresentation(challenge, completeGraph(), policy, {
      challengeStore: store, verifiers, as_of: asOf,
    });
    expect(original.verdict).toBe('admissible');
  });

  it('registers a missing-evidence follow-up before returning it', async () => {
    const backend = createMemoryBackend();
    const store = createDurableChallengeStore(backend);
    const challenge = await createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-followup', nonce: 'nonce-first', expires_at: expiresAt,
    });
    const partial = { ...completeGraph(), nodes: completeGraph().nodes.slice(0, 1), edges: [] };
    const first = await evaluateRegisteredPresentation(challenge, partial, policy, {
      challengeStore: store, verifiers, as_of: asOf, nonce: 'nonce-second',
    });
    expect(first.verdict).toBe('missing_evidence');
    expect(await createDurableChallengeStore(backend).has(first.next_challenge)).toBe(true);
  });

  it('propagates backend outage without an in-memory fallback', async () => {
    const outage = new Error('durable_challenge_backend_unavailable');
    const backend = {
      async addIfAbsent() { throw outage; },
      async compareAndSet() { throw outage; },
      async has() { throw outage; },
    };
    const store = createDurableChallengeStore(backend);
    await expect(createRegisteredEvidenceChallenge(action, policy, {
      challengeStore: store, challenge_id: 'challenge-outage', nonce: 'nonce-outage', expires_at: expiresAt,
    })).rejects.toThrow(/backend_unavailable/);
  });
});

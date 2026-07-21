// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';

import {
  buildModelToMatterGraph,
  createRegisteredModelToMatterChallenge,
  evaluateRegisteredModelToMatterPresentation,
  verifyModelToMatterCaid,
  verifyModelToMatterEffect,
} from '../lib/frontier/model-to-matter.js';
import { createDurableChallengeStore } from '../packages/gate/challenge-store.js';
import { createDurableConsumptionStore, createMemoryBackend } from '../packages/gate/store.js';

const suite = JSON.parse(readFileSync(new URL('./vectors/model-to-matter.v1.json', import.meta.url), 'utf8'));
const failures: string[] = [];

function assertEqual(id, field, actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    failures.push(`${id}: ${field} expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function stores() {
  return {
    challengeStore: createDurableChallengeStore(createMemoryBackend()),
    clearanceStore: createDurableConsumptionStore(createMemoryBackend()),
  };
}

async function challenge(challengeStore, nonce) {
  return createRegisteredModelToMatterChallenge(suite.action, suite.profile, {
    challengeStore,
    expires_at: suite.challenge_expires_at,
    nonce,
  });
}

function graphFor(vector) {
  return buildModelToMatterGraph(suite.action, suite.evidence_sets[vector.evidence_set]);
}

function inputFor(vector, registeredChallenge, challengeStore, clearanceStore) {
  return {
    action: { ...structuredClone(suite.action), ...(vector.action_overrides || {}) },
    profile: suite.profile,
    challenge: registeredChallenge,
    graph: graphFor(vector),
    as_of: suite.as_of,
    challengeStore,
    clearanceStore,
    revokedEvidenceDigests: new Set(vector.revoked_evidence_digests || []),
  };
}

for (const vector of suite.vectors) {
  try {
    if (vector.kind === 'caid') {
      const action = { ...structuredClone(suite.action), ...(vector.action_overrides || {}) };
      const result = verifyModelToMatterCaid(action, suite.caid.caid);
      assertEqual(vector.id, 'valid', result.valid, vector.expect.valid);
      continue;
    }

    if (vector.kind === 'effect') {
      const effect = { ...structuredClone(suite.effect_fixture.effect), ...(vector.tamper || {}) };
      const result = verifyModelToMatterEffect(effect, {
        expectedAction: suite.action,
        expectedClearanceReplayDigest: suite.effect_fixture.expected_clearance_replay_digest,
        pinnedExecutorKeys: [suite.effect_fixture.executor_pin],
      });
      assertEqual(vector.id, 'accepted', result.accepted, vector.expect.accepted);
      continue;
    }

    const state = stores();
    if (vector.kind === 'presentation') {
      const registered = await challenge(state.challengeStore, `m2m-vector-${vector.id}`);
      const clearanceStore = vector.clearance_store === 'throw'
        ? { consume: async () => { throw new Error('simulated storage failure'); } }
        : state.clearanceStore;
      const result = await evaluateRegisteredModelToMatterPresentation(
        inputFor(vector, registered, state.challengeStore, clearanceStore),
      );
      assertEqual(vector.id, 'verdict', result.verdict, vector.expect.verdict);
      if (Object.hasOwn(vector.expect, 'reconciliation_required')) {
        assertEqual(vector.id, 'reconciliation_required', result.reconciliation_required, vector.expect.reconciliation_required);
      }
      continue;
    }

    if (vector.kind === 'same_challenge_replay') {
      const registered = await challenge(state.challengeStore, `m2m-vector-${vector.id}`);
      const input = inputFor(vector, registered, state.challengeStore, state.clearanceStore);
      const first = await evaluateRegisteredModelToMatterPresentation(input);
      const second = await evaluateRegisteredModelToMatterPresentation(input);
      assertEqual(vector.id, 'verdicts', [first.verdict, second.verdict], vector.expect.verdicts);
      continue;
    }

    if (vector.kind === 'two_challenge_race') {
      const firstChallenge = await challenge(state.challengeStore, `m2m-vector-${vector.id}-a`);
      const secondChallenge = await challenge(state.challengeStore, `m2m-vector-${vector.id}-b`);
      const results = await Promise.all([
        evaluateRegisteredModelToMatterPresentation(inputFor(vector, firstChallenge, state.challengeStore, state.clearanceStore)),
        evaluateRegisteredModelToMatterPresentation(inputFor(vector, secondChallenge, state.challengeStore, state.clearanceStore)),
      ]);
      assertEqual(vector.id, 'verdicts', results.map((result) => result.verdict).sort(), [...vector.expect.verdicts].sort());
      continue;
    }

    failures.push(`${vector.id}: unsupported vector kind ${vector.kind}`);
  } catch (error) {
    failures.push(`${vector.id}: runner threw ${error.message}`);
  }
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`EP-MODEL-TO-MATTER-v1: ${suite.vectors.length}/${suite.vectors.length} vectors passed`);
}

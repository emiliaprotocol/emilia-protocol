// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createAECExecutionGate } from './aec-execution.js';
import { createEvidenceLog } from './evidence.js';
import { MemoryConsumptionStore } from './store.js';

const suite = JSON.parse(readFileSync(
  new URL('../../conformance/vectors/aec-role.v1.json', import.meta.url), 'utf8',
));
const vector = () => structuredClone(suite.vectors.find(
  (entry) => entry.id === 'accept_pinned_human_receipt',
));

function gateFor(v, requirement) {
  return createAECExecutionGate({
    requirement,
    policiesByType: v.policies_by_type,
    humanFloor: 'class_a',
    store: new MemoryConsumptionStore(),
    log: createEvidenceLog({ strict: true }),
    allowEphemeralState: true,
    now: () => Date.parse(v.verification_time),
  });
}

test('Verify 7 migration preserves legacy Gate admission and one-time consumption', async () => {
  const v = vector();
  const gate = gateFor(v, ` \t${v.requirement}\r\n`);
  const request = { chain: v.aec_chain, expectedAction: v.aec_chain.action };
  let providerEntries = 0;
  const first = await gate.run(request, async () => ++providerEntries);
  const replay = await gate.run(request, async () => ++providerEntries);
  assert.equal(first.ok, true);
  assert.equal(first.result.satisfied, true);
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'replay_refused');
  assert.equal(providerEntries, 1);
});

test('Verify 7 migration refuses non-ASCII requirement whitespace before provider entry', async () => {
  const v = vector();
  for (const requirement of [
    `\u00a0${v.requirement}`, `${v.requirement}\u00a0`,
    `\u2028${v.requirement}`, `\ufeff${v.requirement}`,
    `${v.requirement}\u000b`, `\u000c${v.requirement}`,
  ]) {
    const gate = gateFor(v, requirement);
    let providerEntries = 0;
    const result = await gate.run(
      { chain: v.aec_chain, expectedAction: v.aec_chain.action },
      async () => ++providerEntries,
    );
    assert.equal(result.ok, false, JSON.stringify(requirement));
    assert.equal(result.reason, 'aec_refused', JSON.stringify(requirement));
    assert.equal(result.result.satisfied, false);
    assert.equal(result.result.requirement_source, 'relying_party');
    assert.equal(providerEntries, 0);
  }
});

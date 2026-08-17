#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// ApertoID + EMILIA Gate + OAuth DAI: three independent legs, one exact
// action, joined by digests. Run: node examples/apertoid-gate-dai/demo.mjs

import {
  ACTION,
  ACTION_OTHER_CONTEXT,
  ADAPTER_KEYS,
  ADAPTER_STATUS_CHECKED_AT,
  ASSERTION,
  ASSERTION_FOR_OTHER_RESOURCE,
  ISSUER_KEYS,
  LOOKUP_AFFIRMATIVE,
  LOOKUP_AFFIRMATIVE_MONITOR,
  LOOKUP_SERVFAIL,
  MEMORY_PROJECTION_RECORD,
  MEMORY_VERIFICATION_LIMITS,
  VERIFICATION_TIME,
} from './fixtures.mjs';
import { createApertoIdGateDaiAdmission } from './gate.mjs';

function gateWith(overrides = {}) {
  return createApertoIdGateDaiAdmission({
    adapterKeys: ADAPTER_KEYS,
    adapterStatusCheckedAt: ADAPTER_STATUS_CHECKED_AT,
    memoryLimits: MEMORY_VERIFICATION_LIMITS,
    issuerKeys: ISSUER_KEYS,
    verificationTime: VERIFICATION_TIME,
    ...overrides,
  });
}

export async function runDemo() {
  const request = {
    action: ACTION,
    memoryRecord: MEMORY_PROJECTION_RECORD,
    assertion: ASSERTION,
    lookup: LOOKUP_AFFIRMATIVE,
  };
  let executions = 0;
  const effect = async () => { executions += 1; };
  const mustNotExecute = async () => {
    throw new Error('effect ran on a non-admitted decision');
  };

  // 1 + 2. Happy path admits and executes exactly once; the identical exact
  // action through the same gate is refused as replay.
  const liveGate = gateWith();
  const happy = await liveGate.admit(request, effect);
  const replay = await liveGate.admit(request, mustNotExecute);

  // 3. Leg unavailable: the adapter status source cannot be evaluated, so
  // the memory leg is INDETERMINATE. INDETERMINATE never authorizes.
  const memoryIndeterminate = await gateWith({
    adapterStatusCheckedAt: null,
  }).admit(request, mustNotExecute);

  // 4. DAI lookup Indeterminate (DNS SERVFAIL): fail closed per Section 5.1
  // of the pinned draft; no fallback channel is consulted.
  const daiIndeterminate = await gateWith().admit(
    { ...request, lookup: LOOKUP_SERVFAIL },
    mustNotExecute,
  );

  // 5. Cross-leg substitution, memory side: the presented projection record
  // is validly signed and VERIFIES, but the action was prepared under a
  // different context digest. The digest join refuses.
  const memorySubstitution = await gateWith().admit(
    { ...request, action: ACTION_OTHER_CONTEXT },
    mustNotExecute,
  );

  // 6. Cross-leg substitution, DAI side: an assertion from the same issuer,
  // individually valid, but minted for a different resource. Refused before
  // the Trust Method even runs.
  const daiSubstitution = await gateWith().admit(
    { ...request, assertion: ASSERTION_FOR_OTHER_RESOURCE },
    mustNotExecute,
  );

  // 7. Monitor-mode floor: the domain's policy is in monitor mode and does
  // not list the issuer. Per Section 6.1 the Trust Method is satisfied and
  // the mismatch is logged; the Gate still refuses admission because its
  // local floor requires an enforce-mode policy for consequential actions.
  const monitorFloor = await gateWith().admit(
    { ...request, lookup: LOOKUP_AFFIRMATIVE_MONITOR },
    mustNotExecute,
  );

  const observed = {
    happy_path: happy.admitted && executions === 1 ? 'admitted_executed_once' : 'UNEXPECTED',
    replay: replay.reason,
    memory_leg_unavailable: `${memoryIndeterminate.state}:${memoryIndeterminate.reason}`,
    dai_lookup_servfail: daiIndeterminate.reason,
    memory_context_substitution: memorySubstitution.reason,
    dai_assertion_substitution: daiSubstitution.reason,
    monitor_mode_floor: monitorFloor.reason,
  };
  const expected = {
    happy_path: 'admitted_executed_once',
    replay: 'replay_refused',
    memory_leg_unavailable: 'INDETERMINATE:memory_leg_indeterminate:adapter_status_unavailable',
    dai_lookup_servfail: 'dai_lookup_indeterminate:dns_servfail',
    memory_context_substitution: 'memory_context_join_mismatch',
    dai_assertion_substitution: 'dai_assertion_audience_mismatch',
    monitor_mode_floor: 'dai_monitor_mode_below_admission_floor',
  };
  if (JSON.stringify(observed) !== JSON.stringify(expected)) {
    throw new Error(`unexpected composition result: ${JSON.stringify({ observed, expected })}`);
  }

  return {
    cases: observed,
    executions,
    admitted_decision: happy,
    monitor_mode_leg: monitorFloor.legs.dai ?? null,
  };
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const result = await runDemo();
  console.log('ApertoID-rooted context AND domain-authorized delegated authorization,');
  console.log('joined by digests on the exact action; the Gate admitted it once.');
  console.log(JSON.stringify(result, null, 2));
}

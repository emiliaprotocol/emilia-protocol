// SPDX-License-Identifier: Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createRuntimeMonitor,
  RUNTIME_INVARIANTS,
  RUNTIME_MONITOR_MODES,
} from './runtime-monitor.js';
import { createTrustedActionFirewall } from './index.js';
import { createEg1Harness, EG1_DEFAULT_SELECTOR } from './eg1-conformance.js';

test('runtime monitor enforces the authorization → effect → consume order', () => {
  const divergences = [];
  const monitor = createRuntimeMonitor({ onDivergence: (event) => divergences.push(event) });
  const cycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rcpt_1' });

  assert.equal(monitor.recordDecision(cycle, {
    allow: true, status: 200, reason: 'allow', guarded: true, receipt_id: 'rcpt_1',
  }).ok, true);
  assert.equal(monitor.beginExecution(cycle, { allow: true, status: 200 }).ok, true);
  assert.equal(monitor.effectReturned(cycle).ok, true);
  assert.equal(monitor.consumptionCommitted(cycle).ok, true);
  assert.equal(monitor.executionRecorded(cycle).ok, true);
  assert.equal(monitor.getState(cycle).phase, 'execution_recorded');
  assert.equal(divergences.length, 0);
});

test('an effect before authorization enters lockdown and emits a theorem violation', () => {
  const divergences = [];
  const monitor = createRuntimeMonitor({ onDivergence: (event) => divergences.push(event) });
  const cycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rcpt_2' });

  const result = monitor.effectReturned(cycle);
  assert.equal(result.ok, false);
  assert.equal(result.reason, `runtime_divergence:${RUNTIME_INVARIANTS.WRITE_BYPASS}`);
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.LOCKDOWN);
  assert.equal(divergences[0].type, 'SPEC_DIVERGENCE');
  assert.equal(divergences[0].theorem, RUNTIME_INVARIANTS.WRITE_BYPASS);
  assert.equal(divergences[0].context.receipt_id, 'rcpt_2');
});

test('a second consumption transition is refused and cannot self-recover', () => {
  const monitor = createRuntimeMonitor();
  const cycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rcpt_3' });
  monitor.recordDecision(cycle, { allow: true, status: 200, guarded: true, receipt_id: 'rcpt_3' });
  monitor.beginExecution(cycle, { allow: true, status: 200 });
  monitor.effectReturned(cycle);
  assert.equal(monitor.consumptionCommitted(cycle).ok, true);
  assert.equal(monitor.consumptionCommitted(cycle).ok, false);
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.LOCKDOWN);
  assert.equal(monitor.recover().ok, false);
});

test('recovery requires an explicit operator authorizer and resets only the monitor mode', () => {
  let authorized = false;
  const monitor = createRuntimeMonitor({ authorizeRecovery: () => authorized });
  const cycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rcpt_4' });
  monitor.effectReturned(cycle);
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.LOCKDOWN);
  assert.equal(monitor.recover().ok, false);
  authorized = true;
  assert.equal(monitor.recover({ reason: 'operator-reviewed' }).ok, true);
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.NORMAL);
  // The old cycle remains unusable; recovery never re-authorizes a receipt.
  assert.equal(monitor.beginExecution(cycle, { allow: true }).ok, false);
});

test('monitor bounds process-local cycle state', () => {
  const monitor = createRuntimeMonitor({ now: 1 });
  const first = monitor.beginCheck({ action: 'payment.release' });
  for (let i = 0; i < 1024; i += 1) monitor.beginCheck({ action: 'payment.release' });
  assert.equal(monitor.getState(first), null);
});

test('Gate safe mode refuses pass-through and still permits only verified Class-A signoff', async () => {
  const monitor = createRuntimeMonitor();
  const brokenCycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rt_bad' });
  monitor.effectReturned(brokenCycle);
  const harness = createEg1Harness();
  const gate = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
    rpId: harness.rpId,
    allowedOrigins: harness.allowedOrigins,
    allowEphemeralStore: true,
    runtimeMonitor: monitor,
  });
  let effects = 0;

  const refused = await gate.run({ selector: EG1_DEFAULT_SELECTOR, receipt: null }, async () => { effects++; });
  assert.equal(refused.ok, false);
  assert.equal(refused.authorization.reason, 'runtime_safe_mode_signoff_required');
  assert.equal(effects, 0);

  const allowed = await gate.run({
    selector: EG1_DEFAULT_SELECTOR,
    receipt: harness.mint({ outcome: 'allow_with_signoff' }),
    observedAction: harness.action,
  }, async () => { effects++; return 'ran'; });
  assert.equal(allowed.ok, true);
  assert.equal(effects, 1);
});

test('Gate-proven non-entry closes a prepared execution without claiming consumption', () => {
  const monitor = createRuntimeMonitor();
  const cycle = monitor.beginCheck({ action: 'payment.release', receipt_id: 'rcpt_pre_entry' });
  monitor.recordDecision(cycle, { allow: true, status: 200 });
  monitor.beginExecution(cycle, { allow: true });
  const result = monitor.providerEntryRefused(cycle, { providerNotInvoked: true });
  assert.equal(result.ok, true);
  assert.equal(monitor.getState(cycle).phase, 'provider_entry_refused');
  assert.equal(monitor.getState(cycle).complete, true);
  assert.equal(monitor.getState(cycle).consumed, false);
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.NORMAL);
});

test('prepared execution cannot claim non-entry without an explicit Gate assertion', () => {
  const monitor = createRuntimeMonitor();
  const cycle = monitor.beginCheck({ action: 'payment.release' });
  monitor.recordDecision(cycle, { allow: true, status: 200 });
  monitor.beginExecution(cycle, { allow: true });
  assert.equal(monitor.providerEntryRefused(cycle).ok, false);
  assert.equal(monitor.getState(cycle).phase, 'effect_attempted');
  assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.LOCKDOWN);
});

for (const phase of ['effect_returned', 'effect_failed', 'consumed', 'execution_recorded', 'complete']) {
  test(`pre-provider refusal cannot erase ${phase}`, () => {
    const monitor = createRuntimeMonitor();
    const cycle = monitor.beginCheck({ action: 'payment.release' });
    monitor.recordDecision(cycle, { allow: true, status: 200 });
    monitor.beginExecution(cycle, { allow: true });
    if (phase === 'effect_failed') monitor.effectFailed(cycle);
    else monitor.effectReturned(cycle);
    if (['consumed', 'execution_recorded', 'complete'].includes(phase)) monitor.consumptionCommitted(cycle);
    if (phase === 'execution_recorded') monitor.executionRecorded(cycle);
    if (phase === 'complete') monitor.executionSkipped(cycle);
    const before = monitor.getState(cycle);
    const result = monitor.providerEntryRefused(cycle, { providerNotInvoked: true });
    assert.equal(result.ok, false);
    assert.deepEqual(monitor.getState(cycle), before);
    assert.equal(monitor.getMode(), RUNTIME_MONITOR_MODES.LOCKDOWN);
  });
}

test('capability refusal still cannot reset a started execution', () => {
  const monitor = createRuntimeMonitor();
  const cycle = monitor.beginCheck({ action: 'payment.release' });
  monitor.recordDecision(cycle, { allow: true, status: 200 });
  monitor.beginExecution(cycle, { allow: true });
  assert.equal(monitor.capabilityRefused(cycle).ok, false);
  assert.equal(monitor.getState(cycle).phase, 'effect_attempted');
});

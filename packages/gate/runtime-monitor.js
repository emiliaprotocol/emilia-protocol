// SPDX-License-Identifier: Apache-2.0

/**
 * Runtime bridge for the Gate lifecycle.
 *
 * This is deliberately an explicit, reviewable monitor rather than a claim
 * that TLA+ can be mechanically compiled into JavaScript. Its transition
 * table mirrors the load-bearing lifecycle invariants in
 * formal/ep_handshake.tla: an effect follows authorization, consumption is
 * one-way, and execution evidence follows the effect attempt. A divergence
 * enters fail-closed safe mode; recovery requires an operator-supplied
 * authorizer and never re-authorizes an old receipt.
 */

export const RUNTIME_MONITOR_VERSION = 'EP-GATE-RUNTIME-MONITOR-v1';
export const RUNTIME_MONITOR_MODES = Object.freeze({
  NORMAL: 'normal',
  DEGRADED: 'degraded',
  LOCKDOWN: 'lockdown',
});

export const RUNTIME_INVARIANTS = Object.freeze({
  CONSUME_ONCE: 'ConsumeOnceSafety',
  WRITE_BYPASS: 'WriteBypassSafety',
  SIGNOFF_BINDING: 'SignoffBindingMatch',
});

const TIER_RANK = Object.freeze({ software: 0, class_a: 1, quorum: 2 });
const SAFE_MODE_TIER = 'class_a';
const MAX_EVENTS = 256;
const MAX_CYCLES = 1024;

function isPromiseLike(value) {
  return value !== null
    && (typeof value === 'object' || typeof value === 'function')
    && typeof value.then === 'function';
}

function publicContext(context = {}) {
  return {
    cycle_id: context.cycle_id ?? null,
    action: typeof context.action === 'string' ? context.action : null,
    receipt_id: typeof context.receipt_id === 'string' ? context.receipt_id : null,
    phase: context.phase ?? null,
  };
}

function copyEvent(event) {
  return Object.freeze({ ...event, context: Object.freeze({ ...event.context }) });
}

/**
 * Create a process-local monitor. Operators should export divergence events to
 * durable SIEM/evidence storage through onDivergence; the monitor itself keeps
 * only a bounded diagnostic buffer.
 *
 * @param {{ now?: (() => number) | number, onDivergence?: ((event: object) => any) | null, authorizeRecovery?: ((input: object) => boolean) | null }} [options]
 */
export function createRuntimeMonitor({ now = Date.now, onDivergence = null, authorizeRecovery = null } = {}) {
  /** @type {string} */
  let mode = RUNTIME_MONITOR_MODES.NORMAL;
  let sequence = 0;
  const cycles = new Map();
  const events = [];

  function timestamp() {
    const value = typeof now === 'function' ? now() : now;
    return new Date(Number(value)).toISOString();
  }

  function clockValue() {
    return typeof now === 'function' ? now() : now;
  }

  function emitDivergence(cycle, theorem, expected, actual, severity = 'critical') {
    const event = copyEvent({
      version: RUNTIME_MONITOR_VERSION,
      type: 'SPEC_DIVERGENCE',
      at: timestamp(),
      theorem,
      expected,
      actual,
      severity,
      context: publicContext({ ...cycle, phase: cycle?.phase }),
    });
    events.push(event);
    if (events.length > MAX_EVENTS) events.shift();
    mode = severity === 'critical' ? RUNTIME_MONITOR_MODES.LOCKDOWN : RUNTIME_MONITOR_MODES.DEGRADED;
    if (typeof onDivergence === 'function') {
      try {
        const result = onDivergence(event);
        if (isPromiseLike(result)) result.catch(() => {});
      } catch { /* monitoring must not weaken the fail-closed transition */ }
    }
    return { ok: false, reason: `runtime_divergence:${theorem}`, event };
  }

  function fail(cycle, theorem, expected, actual, severity = 'critical') {
    return emitDivergence(cycle, theorem, expected, actual, severity);
  }

  function transition(cycleId, event, details = {}) {
    const cycle = cycles.get(cycleId);
    if (!cycle) {
      return fail({ cycle_id: cycleId, ...details }, RUNTIME_INVARIANTS.WRITE_BYPASS,
        'known runtime cycle', 'unknown runtime cycle');
    }
    if (event === 'decision') {
      if (cycle.phase !== 'checking') {
        return fail(cycle, RUNTIME_INVARIANTS.WRITE_BYPASS, 'checking → decision', `${cycle.phase} → decision`);
      }
      if (details.allow === true && details.status !== 200) {
        return fail(cycle, RUNTIME_INVARIANTS.WRITE_BYPASS, 'allow requires HTTP 200', `allow with ${details.status}`);
      }
      if (details.allow === true && details.guarded === true && !details.receipt_id) {
        return fail(cycle, RUNTIME_INVARIANTS.SIGNOFF_BINDING, 'guarded allow has receipt_id', 'guarded allow without receipt_id');
      }
      cycle.phase = details.allow === true ? 'authorized' : 'refused';
      cycle.allow = details.allow === true;
      cycle.reason = details.reason ?? null;
      return { ok: true };
    }
    const expected = {
      effect_attempted: ['authorized'],
      effect_returned: ['effect_attempted'],
      effect_failed: ['effect_attempted', 'effect_returned'],
      capability_refused: ['authorized'],
      consumed: ['effect_returned', 'effect_failed'],
      execution_recorded: ['consumed'],
    }[event];
    if (!expected || !expected.includes(cycle.phase)) {
      const theorem = event === 'consumed'
        ? RUNTIME_INVARIANTS.CONSUME_ONCE
        : RUNTIME_INVARIANTS.WRITE_BYPASS;
      return fail(cycle, theorem, `${expected?.join(' or ') || 'known event'} → ${event}`, `${cycle.phase} → ${event}`);
    }
    if (event === 'consumed' && cycle.consumed === true) {
      return fail(cycle, RUNTIME_INVARIANTS.CONSUME_ONCE, 'consumed at most once', 'second consumption transition');
    }
    cycle.phase = event;
    if (event === 'consumed') cycle.consumed = true;
    if (event === 'execution_recorded') cycle.complete = true;
    return { ok: true };
  }

  return {
    version: RUNTIME_MONITOR_VERSION,
    beginCheck({ action = null, receipt_id = null } = {}) {
      const cycle_id = `rt_${Number(clockValue()).toString(36)}_${(++sequence).toString(36)}`;
      cycles.set(cycle_id, { cycle_id, action, receipt_id, phase: 'checking', consumed: false });
      while (cycles.size > MAX_CYCLES) cycles.delete(cycles.keys().next().value);
      return cycle_id;
    },
    preflight(/** @type {{ hasReceipt?: boolean }} */ { hasReceipt } = {}) {
      if (mode === RUNTIME_MONITOR_MODES.NORMAL || hasReceipt === true) return { ok: true };
      return { ok: false, reason: 'runtime_safe_mode_signoff_required', mode };
    },
    minimumAssuranceTier(declaredTier) {
      if (mode === RUNTIME_MONITOR_MODES.NORMAL || declaredTier === undefined || declaredTier === null) return declaredTier;
      return (TIER_RANK[declaredTier] ?? 0) < TIER_RANK[SAFE_MODE_TIER] ? SAFE_MODE_TIER : declaredTier;
    },
    recordDecision(cycleId, details) {
      return transition(cycleId, 'decision', details);
    },
    beginExecution(cycleId, authorization) {
      if (!authorization || authorization.allow !== true || isPromiseLike(authorization)) {
        const cycle = cycles.get(cycleId) || { cycle_id: cycleId };
        return fail(cycle, RUNTIME_INVARIANTS.WRITE_BYPASS, 'resolved allow authorization', 'missing or promise authorization');
      }
      return transition(cycleId, 'effect_attempted');
    },
    effectReturned(cycleId) { return transition(cycleId, 'effect_returned'); },
    effectFailed(cycleId) { return transition(cycleId, 'effect_failed'); },
    capabilityRefused(cycleId) { return transition(cycleId, 'capability_refused'); },
    consumptionCommitted(cycleId) { return transition(cycleId, 'consumed'); },
    executionRecorded(cycleId) { return transition(cycleId, 'execution_recorded'); },
    executionSkipped(cycleId) {
      const cycle = cycles.get(cycleId);
      if (!cycle || cycle.phase !== 'consumed') {
        return fail(cycle || { cycle_id: cycleId }, RUNTIME_INVARIANTS.WRITE_BYPASS,
          'consumed → execution skipped', `${cycle?.phase || 'unknown'} → execution skipped`);
      }
      cycle.phase = 'complete';
      cycle.complete = true;
      return { ok: true };
    },
    getMode() { return mode; },
    getEvents() { return events.map(copyEvent); },
    getState(cycleId) {
      const cycle = cycles.get(cycleId);
      return cycle ? Object.freeze({ ...cycle }) : null;
    },
    recover(input = {}) {
      if (mode === RUNTIME_MONITOR_MODES.NORMAL) return { ok: true, mode };
      if (typeof authorizeRecovery !== 'function' || authorizeRecovery(input) !== true) {
        return { ok: false, reason: 'runtime_recovery_authorization_required', mode };
      }
      mode = RUNTIME_MONITOR_MODES.NORMAL;
      return { ok: true, mode };
    },
  };
}

export default { createRuntimeMonitor, RUNTIME_MONITOR_VERSION, RUNTIME_MONITOR_MODES, RUNTIME_INVARIANTS };

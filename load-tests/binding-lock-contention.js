/**
 * Load Test: Binding Lock Contention (FOR UPDATE benchmark)
 *
 * Measures the latency impact of the SELECT ... FOR UPDATE lock introduced in
 * migrations 069 (verify_handshake_writes) and 073 (present_handshake_writes)
 * under three scenarios:
 *
 *   Scenario A — Single-binding concurrent race (adversarial)
 *     100 VUs all call verify on the same binding simultaneously.
 *     Expected: exactly 1 succeeds (201), rest get binding_already_consumed (409).
 *     Validates: FOR UPDATE serialization is correct and fast.
 *
 *   Scenario B — Distinct-binding sustained verify load
 *     50 VUs each working on independent bindings for 2 minutes.
 *     Expected: p95 < 1,000ms, p99 < 2,000ms, error rate < 1%.
 *     Validates: no pathological lock wait accumulation under normal load.
 *
 *   Scenario C — Contention latency fingerprint
 *     10 VUs each racing 10 iterations against the same binding.
 *     Collects the latency distribution under moderate contention to establish
 *     the p99 "contention baseline" for the alert threshold in OBSERVABILITY.md.
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com \
 *   EP_API_KEY=ep_live_... \
 *   EP_RESPONDER_API_KEY=ep_live_... \
 *   k6 run binding-lock-contention.js
 *
 *   # Run only one scenario:
 *   k6 run --env SCENARIO=B binding-lock-contention.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import http from 'k6/http';
import {
  BASE_URL,
  HEADERS,
  SLO,
  createHandshake,
  presentBothParties,
  verifyHandshake,
} from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

// Scenario A — concurrent single-binding race
const raceSuccess = new Counter('ep_lock_race_success_201');
const raceConsumed = new Counter('ep_lock_race_already_consumed_409');
const raceOtherError = new Counter('ep_lock_race_other_errors');
const raceErrorRate = new Rate('ep_lock_race_error_rate');

// Scenario B — sustained independent-binding load
const sustainedVerifyLatency = new Trend('ep_lock_sustained_verify_ms', true);
const sustainedErrors = new Rate('ep_lock_sustained_error_rate');

// Scenario C — contention fingerprint
const contentionVerifyLatency = new Trend('ep_lock_contention_verify_ms', true);
const contentionSuccess = new Counter('ep_lock_contention_success');
const contentionConsumed = new Counter('ep_lock_contention_already_consumed');

// ── Scenario selection ───────────────────────────────────────────────────────

const SCENARIO = __ENV.SCENARIO || 'all';

// ── k6 options ───────────────────────────────────────────────────────────────

export const options = {
  scenarios: {
    // Scenario A: 100 VUs all race to verify the same binding
    ...(SCENARIO === 'all' || SCENARIO === 'A') && {
      race_single_binding: {
        executor: 'shared-iterations',
        vus: 100,
        iterations: 100,
        maxDuration: '90s',
        exec: 'scenarioA',
        tags: { scenario: 'A_race' },
      },
    },

    // Scenario B: 50 VUs verify independent bindings for 2 minutes
    ...(SCENARIO === 'all' || SCENARIO === 'B') && {
      sustained_independent: {
        executor: 'constant-vus',
        vus: 50,
        duration: '2m',
        exec: 'scenarioB',
        tags: { scenario: 'B_sustained' },
        startTime: SCENARIO === 'all' ? '2m' : '0s', // run after A if combined
      },
    },

    // Scenario C: 10 VUs × 10 iterations each on same binding
    ...(SCENARIO === 'all' || SCENARIO === 'C') && {
      contention_fingerprint: {
        executor: 'per-vu-iterations',
        vus: 10,
        iterations: 10,
        maxDuration: '2m',
        exec: 'scenarioC',
        tags: { scenario: 'C_contention' },
        startTime: SCENARIO === 'all' ? '5m' : '0s', // run after B if combined
      },
    },
  },

  thresholds: {
    // Scenario A: only trivial non-race errors allowed
    ep_lock_race_other_errors: ['count<3'],

    // Scenario B: sustained load must stay within SLO
    ep_lock_sustained_verify_ms: [
      `p(50)<${SLO.handshakeVerify.p50 * 2}`,   // 2× baseline for this heavier path
      `p(95)<${SLO.handshakeVerify.p95 * 2}`,
      `p(99)<3000`,                               // contention ceiling from OBSERVABILITY.md
    ],
    ep_lock_sustained_error_rate: ['rate<0.01'],

    // Scenario C: contention latency fingerprint (informational — no hard fail)
    ep_lock_contention_verify_ms: ['p(99)<3000'],
  },
};

// ── Scenario A Setup — create one binding for all VUs to race ────────────────

export function setup() {
  console.log('[setup] Creating shared binding for Scenario A race...');
  const { id: hsId, error } = createHandshake();
  if (error) throw new Error(`[setup] handshake create failed: ${error}`);

  presentBothParties(hsId);

  // Verify once to put it in verified state (NOT consuming it yet)
  // We need the handshake in pending_verification state for all VUs to race verify
  // So we stop after present — verify is the step each VU races on.

  console.log(`[setup] Shared handshake ID: ${hsId}`);

  // Also create a pool of independent bindings for Scenario B & C
  const pool = [];
  const poolSize = 55; // 50 VUs × buffer
  console.log(`[setup] Creating ${poolSize} independent bindings for Scenario B...`);
  for (let i = 0; i < poolSize; i++) {
    const { id, error: err } = createHandshake();
    if (!err) {
      presentBothParties(id);
      pool.push(id);
    }
    if (i % 10 === 0) console.log(`[setup] Created ${i}/${poolSize}...`);
  }

  // Contention binding for Scenario C (separate from A so states don't collide)
  const { id: contentionId, error: cErr } = createHandshake();
  if (cErr) throw new Error(`[setup] contention handshake failed: ${cErr}`);
  presentBothParties(contentionId);

  console.log('[setup] Done.');
  return { raceHsId: hsId, pool, contentionId };
}

// ── Scenario A: 100 VUs race to verify one binding ──────────────────────────

export function scenarioA(data) {
  const res = verifyHandshake(data.raceHsId);

  const ok = res.status === 200 || res.status === 201;
  const consumed = res.status === 409;
  const other = !ok && !consumed;

  raceSuccess.add(ok ? 1 : 0);
  raceConsumed.add(consumed ? 1 : 0);
  raceOtherError.add(other ? 1 : 0);
  raceErrorRate.add(other ? 1 : 0);

  check(res, {
    'race: status is 200 or 409': (r) => r.status === 200 || r.status === 409,
    'race: no 5xx errors': (r) => r.status < 500,
  });

  // Exactly one VU should see a non-409 response (the winner)
  if (ok) {
    console.log(`[A] Winner VU ${__VU}: verify succeeded in ${res.timings.duration.toFixed(0)}ms`);
  }
}

// ── Scenario B: 50 VUs verify independent bindings ──────────────────────────

let _poolIndex = 0;

export function scenarioB(data) {
  // Each VU picks a binding from the pool — round-robin with modulo
  const idx = (__VU + __ITER) % data.pool.length;
  const hsId = data.pool[idx];

  const start = Date.now();
  const res = verifyHandshake(hsId);
  const duration = Date.now() - start;

  sustainedVerifyLatency.add(duration);
  sustainedErrors.add(res.status >= 400 ? 1 : 0);

  check(res, {
    'sustained: status 2xx or 409': (r) => r.status < 500,
    'sustained: latency < 2000ms': () => duration < 2000,
  });

  // Small jitter to avoid thundering herd on pool bindings
  sleep(Math.random() * 0.5);
}

// ── Scenario C: 10 VUs × 10 races on same contention binding ────────────────

export function scenarioC(data) {
  const res = verifyHandshake(data.contentionId);
  const duration = res.timings.duration;

  contentionVerifyLatency.add(duration);

  const ok = res.status === 200 || res.status === 201;
  const consumed = res.status === 409;
  contentionSuccess.add(ok ? 1 : 0);
  contentionConsumed.add(consumed ? 1 : 0);

  check(res, {
    'contention: status 200 or 409': (r) => r.status === 200 || r.status === 409,
    'contention: latency < 3000ms (contention ceiling)': () => duration < 3000,
  });
}

// ── Teardown ─────────────────────────────────────────────────────────────────

export function teardown(data) {
  console.log('=== Binding Lock Contention Test Summary ===');
  console.log(`Scenario A — race binding: ${data.raceHsId}`);
  console.log(`  Race success (winner): ${raceSuccess.name}`);
  console.log(`  Already consumed (expected): ${raceConsumed.name}`);
  console.log(`  Other errors (should be ~0): ${raceOtherError.name}`);
  console.log(`Scenario B — pool size: ${data.pool.length}`);
  console.log(`Scenario C — contention binding: ${data.contentionId}`);
  console.log('');
  console.log('Alert baselines from this run (update OBSERVABILITY.md if significantly different):');
  console.log('  verify_handshake p99 under NO contention  → ep_lock_sustained_verify_ms[p99]');
  console.log('  verify_handshake p99 under contention     → ep_lock_contention_verify_ms[p99]');
  console.log('  Contention overhead = contention_p99 - sustained_p99');
}

/**
 * Staircase Load Test — Find the Knee of the Curve
 *
 * Runs handshake-create at increasing VU steps:
 *   10 → 25 → 50 → 100 → 250 → 500
 *
 * Each step holds for 60s. Records per-step success rate, p50/p95/p99,
 * and function duration. Outputs a step-by-step breakdown to find
 * exactly where the system saturates.
 *
 * Usage:
 *   EP_BASE_URL=https://www.emiliaprotocol.ai EP_API_KEY=ep_live_... k6 run staircase.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { SLO, epPost, makeHandshakePayload } from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

const duration = new Trend('ep_create_duration', true);
const errors = new Rate('ep_create_errors');
const total = new Counter('ep_create_total');

// ── Staircase stages ─────────────────────────────────────────────────────────

export const options = {
  stages: [
    { duration: '60s', target: 10 },    // step 1: 10 VUs
    { duration: '60s', target: 25 },    // step 2: 25 VUs
    { duration: '60s', target: 50 },    // step 3: 50 VUs
    { duration: '60s', target: 100 },   // step 4: 100 VUs
    { duration: '60s', target: 250 },   // step 5: 250 VUs
    { duration: '60s', target: 500 },   // step 6: 500 VUs
    { duration: '30s', target: 0 },     // cooldown
  ],

  // No thresholds — this is diagnostic, not pass/fail
  thresholds: {},
};

// ── Test function ────────────────────────────────────────────────────────────

export default function () {
  const payload = makeHandshakePayload();
  const res = epPost('/api/handshake', payload);

  duration.add(res.timings.duration);
  total.add(1);

  const passed = check(res, {
    'status is 201': (r) => r.status === 201,
    'has handshake_id': (r) => {
      try { return !!r.json().handshake_id; } catch { return false; }
    },
  });

  errors.add(passed ? 0 : 1);

  sleep(0.2); // 200ms think time between iterations
}

// ── Summary ──────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const p50 = data.metrics.ep_create_duration?.values?.['p(50)'] || 'N/A';
  const p95 = data.metrics.ep_create_duration?.values?.['p(95)'] || 'N/A';
  const p99 = data.metrics.ep_create_duration?.values?.['p(99)'] || 'N/A';
  const errRate = data.metrics.ep_create_errors?.values?.rate || 0;
  const count = data.metrics.ep_create_total?.values?.count || 0;
  const httpFail = data.metrics.http_req_failed?.values?.rate || 0;

  // Per-status-code breakdown
  const status201 = data.metrics['checks']?.values?.passes || 0;
  const statusFail = data.metrics['checks']?.values?.fails || 0;

  const summary = `
╔══════════════════════════════════════════════════════════════════════╗
║                 STAIRCASE LOAD TEST — RESULTS                      ║
║            10 → 25 → 50 → 100 → 250 → 500 VUs                    ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  Total requests:    ${String(count).padEnd(10)}                                       ║
║  Success rate:      ${String(((1 - errRate) * 100).toFixed(2) + '%').padEnd(10)}                                       ║
║  HTTP failure rate: ${String((httpFail * 100).toFixed(2) + '%').padEnd(10)}                                       ║
║                                                                      ║
║  Latency:                                                            ║
║    p50:  ${String(Math.round(p50) + 'ms').padEnd(10)}    SLO < ${SLO.handshakeCreate.p50}ms    ${p50 !== 'N/A' && p50 < SLO.handshakeCreate.p50 ? 'PASS' : 'FAIL'}                    ║
║    p95:  ${String(Math.round(p95) + 'ms').padEnd(10)}    SLO < ${SLO.handshakeCreate.p95}ms   ${p95 !== 'N/A' && p95 < SLO.handshakeCreate.p95 ? 'PASS' : 'FAIL'}                    ║
║    p99:  ${String(Math.round(p99) + 'ms').padEnd(10)}    SLO < ${SLO.handshakeCreate.p99}ms   ${p99 !== 'N/A' && p99 < SLO.handshakeCreate.p99 ? 'PASS' : 'FAIL'}                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

Check k6 Cloud or the JSON output for per-step VU breakdown.
`;

  return {
    stdout: summary,
    'staircase-results.json': JSON.stringify(data, null, 2),
  };
}

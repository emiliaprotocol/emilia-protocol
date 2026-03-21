/**
 * Load Test: Handshake Verification
 *
 * Pre-creates handshakes with presentations in setup(), then verifies at scale.
 * Tests POST /api/handshake/{id}/verify.
 * SLO targets: p50 < 80ms, p95 < 200ms, p99 < 400ms, error rate < 1%
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com EP_API_KEY=sk-... k6 run handshake-verify.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import {
  standardStages,
  SLO,
  epPost,
  createHandshake,
  presentBothParties,
} from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

const verifyDuration = new Trend('ep_handshake_verify_duration', true);
const verifyErrors = new Rate('ep_handshake_verify_errors');
const verifyCount = new Counter('ep_handshake_verify_total');

// ── k6 options ───────────────────────────────────────────────────────────────

const PEAK_VUS = 100;

export const options = {
  stages: standardStages(PEAK_VUS),

  thresholds: {
    ep_handshake_verify_duration: [
      `p(50)<${SLO.handshakeVerify.p50}`,
      `p(95)<${SLO.handshakeVerify.p95}`,
      `p(99)<${SLO.handshakeVerify.p99}`,
    ],
    ep_handshake_verify_errors: [`rate<${SLO.errorRate}`],
    http_req_failed: [`rate<${SLO.errorRate}`],
  },
};

// ── Setup: pre-create handshakes with presentations ──────────────────────────

export function setup() {
  const handshakeIds = [];
  const count = PEAK_VUS * 5; // enough for sustained test

  console.log(`Setup: creating ${count} handshakes with presentations...`);

  for (let i = 0; i < count; i++) {
    const { id, error } = createHandshake();
    if (error) {
      console.warn(`Setup: handshake creation failed at index ${i}: ${error}`);
      continue;
    }
    presentBothParties(id);
    handshakeIds.push(id);
  }

  console.log(`Setup complete: ${handshakeIds.length} handshakes ready for verification.`);
  return { handshakeIds };
}

// ── Test function ────────────────────────────────────────────────────────────

export default function (data) {
  const ids = data.handshakeIds;
  if (!ids || ids.length === 0) {
    console.error('No handshake IDs available from setup');
    return;
  }

  // Pick a handshake round-robin by iteration
  const handshakeId = ids[__ITER % ids.length];

  const res = epPost(`/api/handshake/${handshakeId}/verify`, {});

  verifyDuration.add(res.timings.duration);
  verifyCount.add(1);

  const passed = check(res, {
    'status is 200': (r) => r.status === 200,
    'response has result': (r) => {
      try {
        const body = r.json();
        return body.status !== undefined || body.result !== undefined;
      } catch {
        return false;
      }
    },
    'response time < 400ms': (r) => r.timings.duration < SLO.handshakeVerify.p99,
  });

  verifyErrors.add(passed ? 0 : 1);

  sleep(0.1);
}

// ── Summary ──────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const p50 = data.metrics.ep_handshake_verify_duration?.values?.['p(50)'] || 'N/A';
  const p95 = data.metrics.ep_handshake_verify_duration?.values?.['p(95)'] || 'N/A';
  const p99 = data.metrics.ep_handshake_verify_duration?.values?.['p(99)'] || 'N/A';
  const errRate = data.metrics.ep_handshake_verify_errors?.values?.rate || 0;

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║            HANDSHAKE VERIFY — LOAD TEST RESULTS             ║
╠══════════════════════════════════════════════════════════════╣
║  Metric        Actual       SLO Target      Status          ║
║  ─────────     ─────────    ──────────      ──────          ║
║  p50           ${String(Math.round(p50)).padEnd(12)} < ${String(SLO.handshakeVerify.p50 + 'ms').padEnd(13)} ${p50 < SLO.handshakeVerify.p50 ? 'PASS' : 'FAIL'}            ║
║  p95           ${String(Math.round(p95)).padEnd(12)} < ${String(SLO.handshakeVerify.p95 + 'ms').padEnd(13)} ${p95 < SLO.handshakeVerify.p95 ? 'PASS' : 'FAIL'}            ║
║  p99           ${String(Math.round(p99)).padEnd(12)} < ${String(SLO.handshakeVerify.p99 + 'ms').padEnd(13)} ${p99 < SLO.handshakeVerify.p99 ? 'PASS' : 'FAIL'}            ║
║  Error rate    ${String((errRate * 100).toFixed(2) + '%').padEnd(12)} < ${String((SLO.errorRate * 100) + '%').padEnd(14)}${errRate < SLO.errorRate ? 'PASS' : 'FAIL'}            ║
╚══════════════════════════════════════════════════════════════╝
`;

  return {
    stdout: summary,
    'handshake-verify-results.json': JSON.stringify(data, null, 2),
  };
}

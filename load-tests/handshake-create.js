/**
 * Load Test: Handshake Creation
 *
 * Tests POST /api/handshake at escalating concurrency (10 -> 50 -> 100 -> 500 VUs).
 * Validates SLO targets from GOD FILE SS13.1:
 *   p50 < 60ms, p95 < 150ms, p99 < 300ms, error rate < 1%
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com EP_API_KEY=sk-... k6 run handshake-create.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { standardStages, SLO, epPost, makeHandshakePayload } from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

const createDuration = new Trend('ep_handshake_create_duration', true);
const createErrors = new Rate('ep_handshake_create_errors');
const createCount = new Counter('ep_handshake_create_total');

// ── k6 options ───────────────────────────────────────────────────────────────

export const options = {
  stages: standardStages(50),

  thresholds: {
    ep_handshake_create_duration: [
      `p(50)<${SLO.handshakeCreate.p50}`,
      `p(95)<${SLO.handshakeCreate.p95}`,
      `p(99)<${SLO.handshakeCreate.p99}`,
    ],
    ep_handshake_create_errors: [`rate<${SLO.errorRate}`],
    http_req_failed: [`rate<${SLO.errorRate}`],
  },
};

// ── Test function ────────────────────────────────────────────────────────────

export default function handshakeCreate() {
  const payload = makeHandshakePayload();
  const res = epPost('/api/handshake', payload);

  createDuration.add(res.timings.duration);
  createCount.add(1);

  const passed = check(res, {
    'status is 201': (r) => r.status === 201,
    'response has id': (r) => {
      try {
        const body = r.json();
        return !!(body.handshake_id || body.id || body.handshakeId);
      } catch {
        return false;
      }
    },
    'response time < 300ms': (r) => r.timings.duration < SLO.handshakeCreate.p99,
  });

  if (!passed) {
    createErrors.add(1);
  } else {
    createErrors.add(0);
  }

  sleep(0.1); // small pause between iterations
}

// ── Summary ──────────────────────────────────────────────────────────────────

/**
 * @param {{ metrics: Record<string, { values?: Record<string, number> }> }} data
 */
export function handleSummary(data) {
  const p50 = data.metrics.ep_handshake_create_duration?.values?.['p(50)'];
  const p95 = data.metrics.ep_handshake_create_duration?.values?.['p(95)'];
  const p99 = data.metrics.ep_handshake_create_duration?.values?.['p(99)'];
  const errRate = data.metrics.ep_handshake_create_errors?.values?.rate || 0;
  /** @param {number | undefined} v */
  const fmt = (v) => (typeof v === 'number' ? String(Math.round(v)) : 'N/A');
  /** @param {number | undefined} v @param {number} target */
  const slo = (v, target) => (typeof v === 'number' && v < target ? 'PASS' : 'FAIL');

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║              HANDSHAKE CREATE — LOAD TEST RESULTS           ║
╠══════════════════════════════════════════════════════════════╣
║  Metric        Actual       SLO Target      Status          ║
║  ─────────     ─────────    ──────────      ──────          ║
║  p50           ${fmt(p50).padEnd(12)} < ${String(SLO.handshakeCreate.p50 + 'ms').padEnd(13)} ${slo(p50, SLO.handshakeCreate.p50)}            ║
║  p95           ${fmt(p95).padEnd(12)} < ${String(SLO.handshakeCreate.p95 + 'ms').padEnd(13)} ${slo(p95, SLO.handshakeCreate.p95)}            ║
║  p99           ${fmt(p99).padEnd(12)} < ${String(SLO.handshakeCreate.p99 + 'ms').padEnd(13)} ${slo(p99, SLO.handshakeCreate.p99)}            ║
║  Error rate    ${String((errRate * 100).toFixed(2) + '%').padEnd(12)} < ${String((SLO.errorRate * 100) + '%').padEnd(14)}${errRate < SLO.errorRate ? 'PASS' : 'FAIL'}            ║
╚══════════════════════════════════════════════════════════════╝
`;

  return {
    stdout: summary,
    'handshake-create-results.json': JSON.stringify(data, null, 2),
  };
}

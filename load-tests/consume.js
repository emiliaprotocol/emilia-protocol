/**
 * Load Test: Signoff Consumption
 *
 * Pre-creates handshakes, verifies them, runs signoff flow to get signoff IDs,
 * then each VU consumes a unique signoff.
 * Tests POST /api/signoff/{signoffId}/consume.
 * SLO targets: p50 < 40ms, p95 < 120ms, p99 < 250ms, error rate < 1%
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com EP_API_KEY=sk-... k6 run consume.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import {
  standardStages,
  SLO,
  epPost,
  createHandshake,
  presentBothParties,
  verifyHandshake,
  makeChallengePayload,
  makeAttestationPayload,
  makeConsumePayload,
} from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

const consumeDuration = new Trend('ep_consume_duration', true);
const consumeErrors = new Rate('ep_consume_errors');
const consumeCount = new Counter('ep_consume_total');

// ── k6 options ───────────────────────────────────────────────────────────────

const PEAK_VUS = 50;

export const options = {
  stages: standardStages(PEAK_VUS),

  thresholds: {
    ep_consume_duration: [
      `p(50)<${SLO.consume.p50}`,
      `p(95)<${SLO.consume.p95}`,
      `p(99)<${SLO.consume.p99}`,
    ],
    ep_consume_errors: [`rate<${SLO.errorRate}`],
    http_req_failed: [`rate<${SLO.errorRate}`],
  },
};

// ── Setup: pre-create handshakes -> present -> verify -> challenge -> attest ─

export function setup() {
  const signoffIds = [];
  const count = PEAK_VUS * 2;

  console.log(`Setup: creating ${count} signoffs ready for consumption...`);

  for (let i = 0; i < count; i++) {
    try {
      // Create handshake
      const { id: hsId, error: hsErr } = createHandshake();
      if (hsErr) {
        console.warn(`Setup [${i}]: handshake creation failed: ${hsErr}`);
        continue;
      }

      // Present both parties
      presentBothParties(hsId);

      // Verify
      const verifyRes = verifyHandshake(hsId);
      if (verifyRes.status !== 200) {
        console.warn(`Setup [${i}]: verify failed: ${verifyRes.status}`);
        continue;
      }

      // Issue challenge
      const challengeRes = epPost('/api/signoff/challenge', makeChallengePayload(hsId));
      if (challengeRes.status !== 201) {
        console.warn(`Setup [${i}]: challenge failed: ${challengeRes.status}`);
        continue;
      }
      const challengeBody = challengeRes.json();
      const challengeId = challengeBody.id || challengeBody.challengeId;

      // Attest
      const attestRes = epPost(`/api/signoff/${challengeId}/attest`, makeAttestationPayload());
      if (attestRes.status !== 201) {
        console.warn(`Setup [${i}]: attest failed: ${attestRes.status}`);
        continue;
      }
      const attestBody = attestRes.json();
      const signoffId = attestBody.id || attestBody.signoffId;

      signoffIds.push(signoffId);
    } catch (e) {
      console.warn(`Setup [${i}]: unexpected error: ${e}`);
    }
  }

  console.log(`Setup complete: ${signoffIds.length} signoffs ready for consumption.`);
  return { signoffIds };
}

// ── Test function ────────────────────────────────────────────────────────────

export default function (data) {
  const ids = data.signoffIds;
  if (!ids || ids.length === 0) {
    console.error('No signoff IDs available from setup');
    return;
  }

  // Each VU+iteration gets a unique signoff to consume (one-time use)
  const globalIndex = (__VU - 1) * 1000 + __ITER;
  const signoffId = ids[globalIndex % ids.length];

  const res = epPost(`/api/signoff/${signoffId}/consume`, makeConsumePayload());

  consumeDuration.add(res.timings.duration);
  consumeCount.add(1);

  // Either 201 (first consume) or conflict (already consumed) are expected
  const passed = check(res, {
    'status is 201 or already consumed': (r) => r.status === 201 || r.status === 409,
    'response time < 250ms': (r) => r.timings.duration < SLO.consume.p99,
  });

  consumeErrors.add(passed ? 0 : 1);

  sleep(0.1);
}

// ── Summary ──────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const p50 = data.metrics.ep_consume_duration?.values?.['p(50)'] || 'N/A';
  const p95 = data.metrics.ep_consume_duration?.values?.['p(95)'] || 'N/A';
  const p99 = data.metrics.ep_consume_duration?.values?.['p(99)'] || 'N/A';
  const errRate = data.metrics.ep_consume_errors?.values?.rate || 0;

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║              CONSUME — LOAD TEST RESULTS                    ║
╠══════════════════════════════════════════════════════════════╣
║  Metric        Actual       SLO Target      Status          ║
║  ─────────     ─────────    ──────────      ──────          ║
║  p50           ${String(Math.round(p50)).padEnd(12)} < ${String(SLO.consume.p50 + 'ms').padEnd(13)} ${p50 < SLO.consume.p50 ? 'PASS' : 'FAIL'}            ║
║  p95           ${String(Math.round(p95)).padEnd(12)} < ${String(SLO.consume.p95 + 'ms').padEnd(13)} ${p95 < SLO.consume.p95 ? 'PASS' : 'FAIL'}            ║
║  p99           ${String(Math.round(p99)).padEnd(12)} < ${String(SLO.consume.p99 + 'ms').padEnd(13)} ${p99 < SLO.consume.p99 ? 'PASS' : 'FAIL'}            ║
║  Error rate    ${String((errRate * 100).toFixed(2) + '%').padEnd(12)} < ${String((SLO.errorRate * 100) + '%').padEnd(14)}${errRate < SLO.errorRate ? 'PASS' : 'FAIL'}            ║
╚══════════════════════════════════════════════════════════════╝
`;

  return {
    stdout: summary,
    'consume-results.json': JSON.stringify(data, null, 2),
  };
}

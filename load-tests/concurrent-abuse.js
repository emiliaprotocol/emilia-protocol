/**
 * Load Test: Concurrent Abuse (Adversarial)
 *
 * Simulates 100 VUs all attempting to consume the same signoff simultaneously.
 * Validates that exactly 1 succeeds with 201 and the rest get 409 (ALREADY_CONSUMED).
 * Tests idempotency and race-condition safety under real network conditions.
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com EP_API_KEY=sk-... k6 run concurrent-abuse.js
 *
 * @license Apache-2.0
 */

import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import {
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

const successCount = new Counter('ep_abuse_success_201');
const conflictCount = new Counter('ep_abuse_conflict_409');
const otherErrorCount = new Counter('ep_abuse_other_errors');
const abuseErrors = new Rate('ep_abuse_error_rate');

// ── k6 options ───────────────────────────────────────────────────────────────

const CONCURRENT_VUS = 100;

export const options = {
  scenarios: {
    concurrent_consume: {
      executor: 'shared-iterations',
      vus: CONCURRENT_VUS,
      iterations: CONCURRENT_VUS,
      maxDuration: '60s',
    },
  },

  thresholds: {
    ep_abuse_other_errors: ['count<2'],  // expect at most 1 non-201/409 response
  },
};

// ── Setup: create a single signoff for all VUs to race on ────────────────────

export function setup() {
  console.log('Setup: creating a single signoff for concurrent abuse test...');

  // Create handshake
  const { id: hsId, error: hsErr } = createHandshake();
  if (hsErr) {
    throw new Error(`Setup: handshake creation failed: ${hsErr}`);
  }

  // Present
  presentBothParties(hsId);

  // Verify
  const verifyRes = verifyHandshake(hsId);
  if (verifyRes.status !== 200) {
    throw new Error(`Setup: verify failed: ${verifyRes.status}`);
  }

  // Issue challenge
  const challengeRes = epPost('/api/signoff/challenge', makeChallengePayload(hsId));
  if (challengeRes.status !== 201) {
    throw new Error(`Setup: challenge failed: ${challengeRes.status}`);
  }
  const challengeBody = challengeRes.json();
  const challengeId = challengeBody.id || challengeBody.challengeId;

  // Attest
  const attestRes = epPost(`/api/signoff/${challengeId}/attest`, makeAttestationPayload());
  if (attestRes.status !== 201) {
    throw new Error(`Setup: attest failed: ${attestRes.status}`);
  }
  const attestBody = attestRes.json();
  const signoffId = attestBody.id || attestBody.signoffId;

  console.log(`Setup complete: signoff ${signoffId} ready for concurrent abuse.`);
  return { signoffId };
}

// ── Test function: all VUs race to consume the same signoff ──────────────────

export default function (data) {
  const { signoffId } = data;

  const res = epPost(`/api/signoff/${signoffId}/consume`, makeConsumePayload());

  if (res.status === 201) {
    successCount.add(1);
    abuseErrors.add(0);
  } else if (res.status === 409) {
    conflictCount.add(1);
    abuseErrors.add(0);
  } else {
    otherErrorCount.add(1);
    abuseErrors.add(1);
  }

  check(res, {
    'status is 201 or 409': (r) => r.status === 201 || r.status === 409,
  });
}

// ── Summary ──────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const successes = data.metrics.ep_abuse_success_201?.values?.count || 0;
  const conflicts = data.metrics.ep_abuse_conflict_409?.values?.count || 0;
  const others = data.metrics.ep_abuse_other_errors?.values?.count || 0;

  const exactlyOneSuccess = successes === 1;
  const restConflicted = conflicts === CONCURRENT_VUS - 1;
  const noOtherErrors = others === 0;

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║           CONCURRENT ABUSE — LOAD TEST RESULTS              ║
╠══════════════════════════════════════════════════════════════╣
║  ${CONCURRENT_VUS} VUs racing to consume the same signoff             ║
║                                                              ║
║  201 Success:     ${String(successes).padEnd(6)} (expected: 1)       ${exactlyOneSuccess ? 'PASS' : 'FAIL'}     ║
║  409 Conflict:    ${String(conflicts).padEnd(6)} (expected: ${CONCURRENT_VUS - 1})     ${restConflicted ? 'PASS' : 'FAIL'}     ║
║  Other errors:    ${String(others).padEnd(6)} (expected: 0)       ${noOtherErrors ? 'PASS' : 'FAIL'}     ║
║                                                              ║
║  Idempotency:     ${exactlyOneSuccess && noOtherErrors ? 'VERIFIED' : 'FAILED  '}                              ║
║  Race safety:     ${exactlyOneSuccess ? 'VERIFIED' : 'FAILED  '}                              ║
╚══════════════════════════════════════════════════════════════╝
`;

  return {
    stdout: summary,
    'concurrent-abuse-results.json': JSON.stringify(data, null, 2),
  };
}

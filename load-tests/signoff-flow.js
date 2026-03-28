/**
 * Load Test: Full Signoff Flow (End-to-End)
 *
 * Each VU executes the complete signoff lifecycle:
 *   create handshake -> present -> verify -> issue challenge -> attest -> consume
 *
 * Tests the full flow latency as a composite operation.
 * SLO targets: p50 < 500ms, p95 < 1200ms, p99 < 2500ms, error rate < 1%
 *
 * Usage:
 *   EP_BASE_URL=https://your-ep.example.com EP_API_KEY=sk-... k6 run signoff-flow.js
 *
 * @license Apache-2.0
 */

import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import http from 'k6/http';
import {
  standardStages,
  SLO,
  epPost,
  makeHandshakePayload,
  makePresentationPayload,
  makeChallengePayload,
  BASE_URL,
  RESPONDER_HEADERS,
  makeAttestationPayload,
  makeConsumePayload,
} from './config.js';

// ── Custom metrics ───────────────────────────────────────────────────────────

const flowDuration = new Trend('ep_signoff_flow_duration', true);
const flowErrors = new Rate('ep_signoff_flow_errors');
const flowCount = new Counter('ep_signoff_flow_total');

// Per-step durations
const stepCreate = new Trend('ep_step_create_ms', true);
const stepPresent = new Trend('ep_step_present_ms', true);
const stepVerify = new Trend('ep_step_verify_ms', true);
const stepChallenge = new Trend('ep_step_challenge_ms', true);
const stepAttest = new Trend('ep_step_attest_ms', true);
const stepConsume = new Trend('ep_step_consume_ms', true);

// ── k6 options ───────────────────────────────────────────────────────────────

export const options = {
  stages: standardStages(50),

  thresholds: {
    ep_signoff_flow_duration: [
      `p(50)<${SLO.signoffFlow.p50}`,
      `p(95)<${SLO.signoffFlow.p95}`,
      `p(99)<${SLO.signoffFlow.p99}`,
    ],
    ep_signoff_flow_errors: [`rate<${SLO.errorRate}`],
    http_req_failed: [`rate<${SLO.errorRate}`],
  },
};

// ── Test function ────────────────────────────────────────────────────────────

export default function () {
  const flowStart = Date.now();
  let failed = false;

  group('signoff-flow', function () {
    // Step 1: Create handshake
    const createRes = epPost('/api/handshake', makeHandshakePayload());
    stepCreate.add(createRes.timings.duration);

    if (!check(createRes, { 'create: 201': (r) => r.status === 201 })) {
      failed = true;
      return;
    }
    const hsBody = createRes.json();
    const handshakeId = hsBody.handshake_id || hsBody.id || hsBody.handshakeId;

    // Step 2: Present both parties (mutual mode — dual-key auth)
    const presInit = epPost(
      `/api/handshake/${handshakeId}/present`,
      makePresentationPayload('initiator'),
    );
    const presResp = http.post(
      `${BASE_URL}/api/handshake/${handshakeId}/present`,
      JSON.stringify(makePresentationPayload('responder')),
      { headers: RESPONDER_HEADERS },
    );
    stepPresent.add(presInit.timings.duration + presResp.timings.duration);

    if (!check(presInit, { 'present initiator: 201': (r) => r.status === 201 })) {
      failed = true;
      return;
    }
    if (!check(presResp, { 'present responder: 201': (r) => r.status === 201 })) {
      failed = true;
      return;
    }

    // Step 3: Verify handshake
    // Pass all hashes from the create response so verify can match them
    const bindingData = hsBody.binding || {};
    const verifyRes = epPost(`/api/handshake/${handshakeId}/verify`, {
      payload_hash: bindingData.payload_hash || null,
      nonce: bindingData.nonce || null,
      action_hash: hsBody.action_hash || null,
      policy_hash: hsBody.policy_hash || null,
    });
    stepVerify.add(verifyRes.timings.duration);

    if (!check(verifyRes, { 'verify: 200': (r) => r.status === 200 })) {
      failed = true;
      return;
    }

    // Step 4: Issue challenge (pass binding_hash from create response)
    const bindingHash = bindingData.binding_hash || '';
    const challengeRes = epPost('/api/signoff/challenge', makeChallengePayload(handshakeId, bindingHash));
    stepChallenge.add(challengeRes.timings.duration);

    if (!check(challengeRes, { 'challenge: 201': (r) => r.status === 201 })) {
      failed = true;
      return;
    }
    const challengeBody = challengeRes.json();
    const challengeId = challengeBody.id || challengeBody.challengeId;

    // Step 5: Attest
    const attestRes = epPost(`/api/signoff/${challengeId}/attest`, makeAttestationPayload());
    stepAttest.add(attestRes.timings.duration);

    if (!check(attestRes, { 'attest: 201': (r) => r.status === 201 })) {
      failed = true;
      return;
    }
    const attestBody = attestRes.json();
    const signoffId = attestBody.id || attestBody.signoffId;

    // Step 6: Consume signoff
    const consumeRes = epPost(`/api/signoff/${signoffId}/consume`, makeConsumePayload());
    stepConsume.add(consumeRes.timings.duration);

    if (!check(consumeRes, { 'consume: 201': (r) => r.status === 201 })) {
      failed = true;
    }
  });

  const elapsed = Date.now() - flowStart;
  flowDuration.add(elapsed);
  flowCount.add(1);
  flowErrors.add(failed ? 1 : 0);

  sleep(0.5);
}

// ── Summary ──────────────────────────────────────────────────────────────────

export function handleSummary(data) {
  const p50 = data.metrics.ep_signoff_flow_duration?.values?.['p(50)'] || 'N/A';
  const p95 = data.metrics.ep_signoff_flow_duration?.values?.['p(95)'] || 'N/A';
  const p99 = data.metrics.ep_signoff_flow_duration?.values?.['p(99)'] || 'N/A';
  const errRate = data.metrics.ep_signoff_flow_errors?.values?.rate || 0;

  const summary = `
╔══════════════════════════════════════════════════════════════╗
║           SIGNOFF FLOW (E2E) — LOAD TEST RESULTS            ║
╠══════════════════════════════════════════════════════════════╣
║  Metric        Actual       SLO Target      Status          ║
║  ─────────     ─────────    ──────────      ──────          ║
║  p50           ${String(Math.round(p50)).padEnd(12)} < ${String(SLO.signoffFlow.p50 + 'ms').padEnd(13)} ${p50 < SLO.signoffFlow.p50 ? 'PASS' : 'FAIL'}            ║
║  p95           ${String(Math.round(p95)).padEnd(12)} < ${String(SLO.signoffFlow.p95 + 'ms').padEnd(13)} ${p95 < SLO.signoffFlow.p95 ? 'PASS' : 'FAIL'}            ║
║  p99           ${String(Math.round(p99)).padEnd(12)} < ${String(SLO.signoffFlow.p99 + 'ms').padEnd(13)} ${p99 < SLO.signoffFlow.p99 ? 'PASS' : 'FAIL'}            ║
║  Error rate    ${String((errRate * 100).toFixed(2) + '%').padEnd(12)} < ${String((SLO.errorRate * 100) + '%').padEnd(14)}${errRate < SLO.errorRate ? 'PASS' : 'FAIL'}            ║
╠══════════════════════════════════════════════════════════════╣
║  Per-step breakdown (p50):                                  ║
║    Create:     ${String(Math.round(data.metrics.ep_step_create_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
║    Present:    ${String(Math.round(data.metrics.ep_step_present_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
║    Verify:     ${String(Math.round(data.metrics.ep_step_verify_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
║    Challenge:  ${String(Math.round(data.metrics.ep_step_challenge_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
║    Attest:     ${String(Math.round(data.metrics.ep_step_attest_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
║    Consume:    ${String(Math.round(data.metrics.ep_step_consume_ms?.values?.['p(50)'] || 0) + 'ms').padEnd(10)}                                    ║
╚══════════════════════════════════════════════════════════════╝
`;

  return {
    stdout: summary,
    'signoff-flow-results.json': JSON.stringify(data, null, 2),
  };
}

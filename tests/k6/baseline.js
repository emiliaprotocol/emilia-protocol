/**
 * EMILIA Protocol — k6 Baseline Smoke Test
 *
 * Purpose: CI smoke gate — fails if any SLO threshold is violated.
 * This is NOT a full load test. It uses low VU counts to detect regressions
 * against the baselines documented in docs/performance/BENCHMARK_BASELINE.md.
 *
 * For full staircase load tests (10→500 VUs), run manually from the
 * ops runbook or use the k6 Cloud schedule.
 *
 * Usage:
 *   k6 run tests/k6/baseline.js -e BASE_URL=https://staging.example.com -e API_KEY=ep_test_...
 *
 * Required env:
 *   BASE_URL   - Target environment base URL (no trailing slash)
 *   API_KEY    - Valid EP API key for auth (must have test entity pre-registered)
 *   ENTITY_ID  - Entity ID registered in the target environment
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// SLO thresholds (from BENCHMARK_BASELINE.md)
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    smoke: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
    },
  },
  thresholds: {
    // Handshake creation hot path: p95 < 150ms, p99 < 300ms
    'http_req_duration{route:handshake_create}': [
      'p(95)<150',
      'p(99)<300',
    ],
    // Trust evaluation: p95 < 100ms
    'http_req_duration{route:trust_evaluate}': [
      'p(95)<100',
    ],
    // Error rate must be below 1%
    'http_req_failed': ['rate<0.01'],
  },
};

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

const handshakeErrors = new Counter('handshake_errors');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const API_KEY  = __ENV.API_KEY  || 'ep_test_key';
const ENTITY_ID = __ENV.ENTITY_ID || 'test-entity-001';

const HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

function randomNonce() {
  return `k6-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

// ---------------------------------------------------------------------------
// Default scenario
// ---------------------------------------------------------------------------

export default function () {
  // ── 1. Trust evaluation (read — expected to be fast) ─────────────────────
  const trustRes = http.post(
    `${BASE_URL}/api/trust/evaluate`,
    JSON.stringify({ entity_id: ENTITY_ID }),
    { headers: HEADERS, tags: { route: 'trust_evaluate' } },
  );

  check(trustRes, {
    'trust evaluate 200': (r) => r.status === 200,
  });

  sleep(0.1);

  // ── 2. Handshake initiation (protocol write — hot path) ──────────────────
  const initiateRes = http.post(
    `${BASE_URL}/api/handshake`,
    JSON.stringify({
      initiator_id: ENTITY_ID,
      responder_id: 'test-responder-001',
      nonce: randomNonce(),
      policy_id: 'policy-baseline',
    }),
    { headers: HEADERS, tags: { route: 'handshake_create' } },
  );

  const ok = check(initiateRes, {
    'handshake initiate 201 or 200': (r) => r.status === 201 || r.status === 200,
    'handshake response has handshake_id': (r) => {
      try {
        return JSON.parse(r.body).handshake_id !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!ok) {
    handshakeErrors.add(1);
  }

  sleep(0.2);
}

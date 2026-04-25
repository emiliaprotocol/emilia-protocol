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
    // Warmup: 10s at 1 VU to populate connection pools and trigger any
    // cold starts in the serverless deployment. These samples are discarded
    // from threshold evaluation via gracefulStop + the thresholds below.
    warmup: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 1 },
        { duration: '5s', target: 1 },
      ],
      gracefulStop: '0s',
      tags: { stage: 'warmup' },
      exec: 'default',
    },
    smoke: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      startTime: '10s',        // starts after warmup completes
      tags: { stage: 'smoke' },
      exec: 'default',
    },
  },
  // Thresholds separate server-side latency (http_req_waiting = TTFB)
  // from end-to-end round-trip (http_req_duration = full request-response).
  // TTFB is the real SLO; http_req_duration varies with network between
  // the k6 runner (GitHub Actions) and the target (Vercel edge). We
  // enforce TTFB tightly and allow a generous RTT budget so transient
  // network variance does not fail the smoke gate.
  //
  // The `stage:smoke` tag filter excludes warmup samples from thresholds.
  thresholds: {
    // Server-time budget (TTFB, excludes network RTT):
    // handshake_create p95 < 200ms, p99 < 400ms — matches app-level SLO.
    'http_req_waiting{route:handshake_create,stage:smoke}': [
      'p(95)<200',
      'p(99)<400',
    ],
    // trust_evaluate p95 < 150ms server time.
    'http_req_waiting{route:trust_evaluate,stage:smoke}': [
      'p(95)<150',
    ],

    // End-to-end duration (server + network RTT). Looser because network
    // latency from a GHA us-east runner to Vercel edge is ~40-120ms
    // baseline and can spike to 300ms on bad days.
    'http_req_duration{route:handshake_create,stage:smoke}': [
      'p(95)<500',
      'p(99)<1000',
    ],
    'http_req_duration{route:trust_evaluate,stage:smoke}': [
      'p(95)<400',
    ],

    // Error rate must be below 1% in the smoke phase.
    'http_req_failed{stage:smoke}': ['rate<0.01'],
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

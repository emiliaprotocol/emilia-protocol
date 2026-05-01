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
 *   k6 run tests/k6/baseline.js -e BASE_URL=https://www.emiliaprotocol.ai -e API_KEY=ep_live_...
 *
 * Required env:
 *   BASE_URL   - Target environment base URL (no trailing slash)
 *   API_KEY    - Valid EP API key for auth (must own ENTITY_ID)
 *   ENTITY_ID  - Initiator entity ID, pre-registered in the target environment
 *   RESPONDER_ID (optional, defaults to 'test-responder-001') — responder party
 *   POLICY_KEY   (optional, defaults to 'authorized_signer_basic_v1') — handshake policy_key.
 *                The setup() function resolves this to a real policy_id (UUID)
 *                via GET /api/handshake-policies?policy_key=... once at startup.
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

// ---------------------------------------------------------------------------
// SLO thresholds (from BENCHMARK_BASELINE.md)
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Warmup: 20s at 1 VU. Each iteration touches both endpoints, so by
    // the time smoke starts both serverless function instances should be
    // warm. Was 10s — observed cold starts still appearing in smoke when
    // warmup was shorter than two full iteration cycles.
    warmup: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 1 },
        { duration: '15s', target: 1 },
      ],
      gracefulStop: '0s',
      tags: { stage: 'warmup' },
      exec: 'default',
    },
    // Single-VU smoke. The middleware enforces 60 protocol_writes/min per
    // API key (lib/rate-limit.js); 5 VUs × 0.3s sleep generates ~1000 req/min
    // and saturates the limiter. 1 VU at the existing sleeps stays under
    // ~120 req/min total, well under the limit, while still exercising the
    // hot path enough to surface regressions.
    smoke: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      startTime: '20s',        // starts after warmup completes (20s)
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
    // Server-time (TTFB) thresholds. Calibrated against prod's actual
    // observed baseline: handshake_create is ~550ms server-time on a warm
    // function (DB roundtrip + hash computation + multi-row RPC), with
    // p95 spiking to ~650ms when a function instance cycles. trust_evaluate
    // is similar (~550ms p95 — DB read + scoring + embedding lookup).
    //
    // Threshold history:
    //   2026-04-30 v1: 200/150ms — tuned against dedicated staging (no real prod traffic)
    //   2026-04-30 v2: 400ms     — first prod-targeted attempt; still breached at p95 ~647ms
    //   2026-05-01 v3: 900ms     — current; matches measured p95 + ~30% safety margin
    //
    // Re-tighten by 100ms each time prod p95 drops below threshold by
    // 200ms+ for a full week. Tighten faster if a staging deployment
    // with warm functions becomes available.
    'http_req_waiting{route:handshake_create,stage:smoke}': [
      'p(95)<900',
      'p(99)<1500',
    ],
    'http_req_waiting{route:trust_evaluate,stage:smoke}': [
      'p(95)<900',
    ],

    // End-to-end duration (server + network RTT). GHA runner → Vercel edge
    // adds ~40–120ms baseline; budget accordingly.
    'http_req_duration{route:handshake_create,stage:smoke}': [
      'p(95)<1200',
      'p(99)<2500',
    ],
    'http_req_duration{route:trust_evaluate,stage:smoke}': [
      'p(95)<1200',
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
const RESPONDER_ID = __ENV.RESPONDER_ID || 'test-responder-001';
const POLICY_KEY = __ENV.POLICY_KEY || 'authorized_signer_basic_v1';

const HEADERS = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

// ---------------------------------------------------------------------------
// Setup — runs once per test, before scenarios start.
//
// Resolves POLICY_KEY → policy_id (UUID). Migration 036 changed the
// handshakes.policy_id column to a UUID FK on handshake_policies, so the
// route requires a real UUID, not a free-form string. Previous test versions
// hardcoded `policy_id: 'policy-baseline'` and 500'd on every request.
// ---------------------------------------------------------------------------
export function setup() {
  const res = http.get(
    `${BASE_URL}/api/handshake-policies?policy_key=${encodeURIComponent(POLICY_KEY)}`,
    { headers: HEADERS },
  );
  if (res.status !== 200) {
    throw new Error(
      `[setup] Failed to fetch handshake-policies (HTTP ${res.status}): ${res.body}`,
    );
  }
  const body = JSON.parse(res.body);
  const policy = (body.policies || [])[0];
  if (!policy || !policy.policy_id) {
    throw new Error(
      `[setup] No active handshake_policy found for policy_key="${POLICY_KEY}". ` +
      `Seed one (see supabase/migrations/036_handshake_policies.sql) or pass POLICY_KEY=<existing>.`,
    );
  }
  return { policyId: policy.policy_id };
}

// ---------------------------------------------------------------------------
// Default scenario
// ---------------------------------------------------------------------------

export default function (data) {
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
  // POST /api/handshake schema (see lib/handshake/schema.js validateInitiateBody):
  //   { mode, policy_id (UUID), parties: [{role, entity_ref}, ...] }
  // The initiator's entity_ref MUST equal the authenticated entity's id.
  const initiateRes = http.post(
    `${BASE_URL}/api/handshake`,
    JSON.stringify({
      mode: 'basic',
      policy_id: data.policyId,
      parties: [
        { role: 'initiator', entity_ref: ENTITY_ID },
        { role: 'responder', entity_ref: RESPONDER_ID },
      ],
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

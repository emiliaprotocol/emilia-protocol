/**
 * Shared configuration for EP load tests.
 *
 * Environment variables:
 *   EP_BASE_URL  - Base URL of the EP deployment (default: http://localhost:3000)
 *   EP_API_KEY   - API key for authentication
 *   EP_ENTITY_REF - Entity ref for the test actor (default: ep:entity:loadtest-actor)
 *   EP_RESPONDER_REF - Entity ref for the responder (default: ep:entity:loadtest-responder)
 *
 * @license Apache-2.0
 */

// ── Base configuration ──────────────────────────────────────────────────────

export const BASE_URL = __ENV.EP_BASE_URL || 'http://localhost:3000';
export const API_KEY = __ENV.EP_API_KEY || '';
export const ENTITY_REF = __ENV.EP_ENTITY_REF || 'ep:entity:loadtest-actor';
export const RESPONDER_REF = __ENV.EP_RESPONDER_REF || 'ep:entity:loadtest-responder';

export const HEADERS = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${API_KEY}`,
};

// ── SLO thresholds (from GOD FILE SS13.1) ────────────────────────────────────

export const SLO = {
  handshakeCreate: { p50: 60, p95: 150, p99: 300 },
  handshakeVerify: { p50: 80, p95: 200, p99: 400 },
  consume:         { p50: 40, p95: 120, p99: 250 },
  signoffFlow:     { p50: 500, p95: 1200, p99: 2500 },
  errorRate:       0.01, // < 1%
};

// ── Standard ramp profile ────────────────────────────────────────────────────

export function standardStages(peakVUs = 100) {
  return [
    { duration: '30s', target: Math.ceil(peakVUs * 0.1) },   // warmup
    { duration: '2m',  target: peakVUs },                     // sustained peak
    { duration: '30s', target: 0 },                           // cooldown
  ];
}

export function escalatingStages() {
  return [
    { duration: '30s',  target: 10 },
    { duration: '1m',   target: 50 },
    { duration: '1m',   target: 100 },
    { duration: '1m',   target: 500 },
    { duration: '30s',  target: 0 },
  ];
}

// ── Test data generators ─────────────────────────────────────────────────────

let _counter = 0;

/** Generate a unique ID scoped to this VU + iteration. */
export function uniqueId(prefix = 'lt') {
  _counter++;
  const vu = typeof __VU !== 'undefined' ? __VU : 0;
  const iter = typeof __ITER !== 'undefined' ? __ITER : 0;
  return `${prefix}-${vu}-${iter}-${_counter}-${Date.now()}`;
}

/** Generate a pseudo-UUID v4 (k6 has no crypto.randomUUID). */
function uuid4() {
  const hex = '0123456789abcdef';
  let u = '';
  for (let i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) { u += '-'; }
    else if (i === 14) { u += '4'; }
    else if (i === 19) { u += hex[(Math.random() * 4 | 0) + 8]; }
    else { u += hex[Math.random() * 16 | 0]; }
  }
  return u;
}

/** Build a valid handshake creation payload. */
export function makeHandshakePayload(overrides = {}) {
  const id = uniqueId('hs');
  return Object.assign(
    {
      mode: 'mutual',
      policy_id: 'c6466c16-5728-460a-8ab2-731acac0b06f', // authorized_signer_basic_v1
      parties: [
        { role: 'initiator', entity_ref: ENTITY_REF },
        { role: 'responder', entity_ref: RESPONDER_REF },
      ],
      action_type: 'connect',
      resource_ref: uuid4(),
      payload: { test: true, run_id: id },
      idempotency_key: `idem-${id}`,
    },
    overrides,
  );
}

/** Build presentation payload for a handshake. */
export function makePresentationPayload(role = 'initiator') {
  return {
    party_role: role,
    presentation_type: 'self_asserted',
    claims: {
      name: 'Load Test Entity',
      purpose: 'load-testing',
      timestamp: new Date().toISOString(),
    },
    disclosure_mode: 'full',
  };
}

/** Build signoff challenge payload. */
export function makeChallengePayload(handshakeId) {
  return {
    handshakeId,
    accountableActorRef: ENTITY_REF,
    signoffPolicyId: `signoff-policy-${uniqueId('sp')}`,
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  };
}

/** Build attestation payload. */
export function makeAttestationPayload() {
  return {
    humanEntityRef: ENTITY_REF,
    authMethod: 'api_key',
    assuranceLevel: 'high',
    channel: 'load_test',
    attestationHash: `sha256:${uniqueId('hash')}`,
  };
}

/** Build consume payload. */
export function makeConsumePayload() {
  return {
    executionRef: `exec-${uniqueId('ex')}`,
  };
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

import http from 'k6/http';

/** POST JSON to an EP endpoint and return the response. */
export function epPost(path, body) {
  return http.post(`${BASE_URL}${path}`, JSON.stringify(body), {
    headers: HEADERS,
  });
}

/** GET from an EP endpoint. */
export function epGet(path) {
  return http.get(`${BASE_URL}${path}`, { headers: HEADERS });
}

/**
 * Create a handshake via the API and return { id, response }.
 * Throws descriptive error string if creation fails.
 */
export function createHandshake(overrides = {}) {
  const res = epPost('/api/handshake', makeHandshakePayload(overrides));
  if (res.status !== 201) {
    return { id: null, response: res, error: `create failed: ${res.status}` };
  }
  const body = res.json();
  return { id: body.handshake_id || body.id || body.handshakeId, response: res, error: null };
}

/**
 * Present identity proofs for both parties on a handshake.
 */
export function presentBothParties(handshakeId) {
  epPost(`/api/handshake/${handshakeId}/present`, makePresentationPayload('initiator'));
  epPost(`/api/handshake/${handshakeId}/present`, makePresentationPayload('responder'));
}

/**
 * Verify a handshake and return the response.
 */
export function verifyHandshake(handshakeId) {
  return epPost(`/api/handshake/${handshakeId}/verify`, {});
}

/**
 * Run the full signoff flow on a handshake:
 * issue challenge -> attest -> consume signoff.
 * Returns { challengeId, signoffId, consumeRes }.
 */
export function fullSignoffFlow(handshakeId) {
  // Issue challenge
  const challengeRes = epPost('/api/signoff/challenge', makeChallengePayload(handshakeId));
  if (challengeRes.status !== 201) {
    return { error: `challenge failed: ${challengeRes.status}`, challengeRes };
  }
  const challengeBody = challengeRes.json();
  const challengeId = challengeBody.id || challengeBody.challengeId;

  // Attest
  const attestRes = epPost(`/api/signoff/${challengeId}/attest`, makeAttestationPayload());
  if (attestRes.status !== 201) {
    return { error: `attest failed: ${attestRes.status}`, attestRes };
  }
  const attestBody = attestRes.json();
  const signoffId = attestBody.id || attestBody.signoffId;

  // Consume
  const consumeRes = epPost(`/api/signoff/${signoffId}/consume`, makeConsumePayload());

  return { challengeId, signoffId, consumeRes, error: null };
}

/**
 * EP Unified Error Taxonomy
 *
 * Canonical registry of every machine-readable error code in the protocol.
 * Each entry carries the structured code, HTTP status, and default message
 * so that API routes never invent ad-hoc error shapes.
 *
 * Code ranges:
 *   1xxx  Auth & identity
 *   2xxx  Input validation
 *   3xxx  Handshake lifecycle
 *   4xxx  Signoff / attestation
 *   5xxx  Policy & trust evaluation
 *   6xxx  Write discipline & protocol writes
 *   7xxx  Cloud / tenant / rate-limiting
 *   8xxx  Commit & receipt lifecycle
 *   9xxx  System / internal
 *
 * Compatibility: the `code` field uses the `EP-NNNN` prefix so it is
 * unambiguous in logs, client SDKs, and the RFC 7807 `type` URL that
 * epProblem() already emits.
 *
 * @license Apache-2.0
 */

export const EP_ERROR_CODES = Object.freeze({

  // ── Auth & Identity (1xxx) ───────────────────────────────────────────────
  UNAUTHORIZED:           { code: 'EP-1001', status: 401, message: 'Authentication required' },
  FORBIDDEN:              { code: 'EP-1002', status: 403, message: 'Insufficient permissions' },
  NOT_AUTHORIZED:         { code: 'EP-1003', status: 403, message: 'Caller is not authorized for this operation' },
  IDENTITY_NOT_FOUND:     { code: 'EP-1004', status: 404, message: 'Identity not found' },
  PRINCIPAL_NOT_FOUND:    { code: 'EP-1005', status: 404, message: 'Principal not found' },
  DELEGATION_INVALID:     { code: 'EP-1006', status: 403, message: 'Delegation is invalid or out of scope' },
  DELEGATION_NOT_FOUND:   { code: 'EP-1007', status: 404, message: 'Delegation not found' },

  // ── Input Validation (2xxx) ──────────────────────────────────────────────
  INVALID_INPUT:          { code: 'EP-2001', status: 400, message: 'Invalid input' },
  MISSING_REQUIRED:       { code: 'EP-2002', status: 400, message: 'Missing required field' },
  INVALID_ACTION_TYPE:    { code: 'EP-2003', status: 400, message: 'Invalid action type' },
  INVALID_REASON:         { code: 'EP-2004', status: 400, message: 'Invalid reason value' },
  INVALID_FORMAT:         { code: 'EP-2005', status: 400, message: 'Invalid format' },

  // ── Handshake Lifecycle (3xxx) ───────────────────────────────────────────
  HANDSHAKE_NOT_FOUND:    { code: 'EP-3001', status: 404, message: 'Handshake not found' },
  ALREADY_CONSUMED:       { code: 'EP-3002', status: 409, message: 'Handshake binding already consumed' },
  INVALID_STATE:          { code: 'EP-3003', status: 409, message: 'Invalid state transition' },
  BINDING_MISMATCH:       { code: 'EP-3004', status: 409, message: 'Binding hash mismatch' },
  HANDSHAKE_EXPIRED:      { code: 'EP-3005', status: 410, message: 'Handshake binding expired' },
  ACTION_HASH_MISMATCH:   { code: 'EP-3006', status: 409, message: 'Action intent hash mismatch' },
  UNAUTHORIZED_HANDSHAKE: { code: 'EP-3007', status: 403, message: 'Initiator does not own handshake' },
  HANDSHAKE_INITIATION_FAILED: { code: 'EP-3008', status: 500, message: 'Handshake initiation failed' },
  HANDSHAKE_VERIFICATION_FAILED: { code: 'EP-3009', status: 500, message: 'Handshake verification failed' },

  // ── Signoff & Attestation (4xxx) ─────────────────────────────────────────
  CHALLENGE_NOT_FOUND:    { code: 'EP-4001', status: 404, message: 'Challenge not found' },
  CHALLENGE_EXPIRED:      { code: 'EP-4002', status: 410, message: 'Challenge expired' },
  INVALID_AUTH_METHOD:    { code: 'EP-4003', status: 400, message: 'Invalid authentication method' },
  INSUFFICIENT_ASSURANCE: { code: 'EP-4004', status: 403, message: 'Insufficient assurance level' },
  ATTESTATION_FAILED:     { code: 'EP-4005', status: 500, message: 'Signoff attestation failed' },
  CHALLENGE_ISSUANCE_FAILED: { code: 'EP-4006', status: 500, message: 'Challenge issuance failed' },

  // ── Policy & Trust Evaluation (5xxx) ─────────────────────────────────────
  POLICY_NOT_FOUND:       { code: 'EP-5001', status: 404, message: 'Policy not found' },
  POLICY_HASH_MISMATCH:   { code: 'EP-5002', status: 409, message: 'Policy version changed' },
  ENTITY_NOT_FOUND:       { code: 'EP-5003', status: 404, message: 'Entity not found in EP registry' },
  TRUST_EVALUATION_FAILED: { code: 'EP-5004', status: 500, message: 'Trust evaluation failed' },
  GATE_REQUIRED:          { code: 'EP-5005', status: 403, message: 'Action requires trust gate pre-authorization' },
  GATE_DENIED:            { code: 'EP-5006', status: 403, message: 'Trust gate denied the action' },
  GATE_REF_INVALID:       { code: 'EP-5007', status: 403, message: 'Invalid gate reference' },
  GATE_ENTITY_MISMATCH:   { code: 'EP-5008', status: 403, message: 'Gate was issued for a different entity' },
  GATE_ACTION_MISMATCH:   { code: 'EP-5009', status: 403, message: 'Gate was issued for a different action type' },

  // ── Write Discipline (6xxx) ──────────────────────────────────────────────
  WRITE_VIOLATION:        { code: 'EP-6001', status: 500, message: 'Write discipline violation' },
  EVENT_WRITE_FAILED:     { code: 'EP-6002', status: 500, message: 'Event write required but failed' },
  PROTOCOL_WRITE_FAILED:  { code: 'EP-6003', status: 500, message: 'Protocol write failed' },

  // ── Cloud / Tenant (7xxx) ────────────────────────────────────────────────
  TENANT_NOT_FOUND:       { code: 'EP-7001', status: 404, message: 'Tenant not found' },
  API_KEY_INVALID:        { code: 'EP-7002', status: 401, message: 'Invalid API key' },
  RATE_LIMITED:           { code: 'EP-7003', status: 429, message: 'Rate limit exceeded' },

  // ── Commit & Receipt Lifecycle (8xxx) ────────────────────────────────────
  COMMIT_NOT_FOUND:       { code: 'EP-8001', status: 404, message: 'Commit not found' },
  COMMIT_EXPIRED:         { code: 'EP-8002', status: 410, message: 'Commit expired' },
  COMMIT_REVOKED:         { code: 'EP-8003', status: 409, message: 'Commit already revoked' },
  COMMIT_FULFILLED:       { code: 'EP-8004', status: 409, message: 'Commit already fulfilled' },
  COMMIT_ISSUANCE_FAILED: { code: 'EP-8005', status: 500, message: 'Commit issuance failed' },
  RECEIPT_NOT_FOUND:      { code: 'EP-8006', status: 404, message: 'Receipt not found' },
  DUPLICATE_RECEIPT:      { code: 'EP-8007', status: 409, message: 'Duplicate receipt for this commit' },
  DISPUTE_ALREADY_EXISTS: { code: 'EP-8008', status: 409, message: 'Dispute already filed for this receipt' },
  DISPUTE_NOT_FOUND:      { code: 'EP-8009', status: 404, message: 'Dispute not found' },
  DISPUTE_FILING_FAILED:  { code: 'EP-8010', status: 500, message: 'Dispute filing failed' },

  // ── System / Internal (9xxx) ─────────────────────────────────────────────
  INTERNAL:               { code: 'EP-9001', status: 500, message: 'Internal server error' },
  DB_ERROR:               { code: 'EP-9002', status: 503, message: 'Database unavailable' },
  POLICY_LIST_FAILED:     { code: 'EP-9003', status: 500, message: 'Failed to retrieve trust policies' },
});

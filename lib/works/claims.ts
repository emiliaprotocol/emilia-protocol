// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — claim model.
//
// Every material claim on the Works surface (capability cards, opportunity
// funding/authority/eligibility statements) is a Claim: a statement plus
// status, exact scope, source, observed_at, optional expires_at, and
// limitations. The discipline this module enforces:
//
//   * status is exactly VERIFIED | ASSERTED | UNKNOWN — never a score,
//     never a ranking, never an aggregate.
//   * VERIFIED requires a non-claimant source artifact reference: either a
//     content-addressed artifact (with its hash) or an external signer.
//     A claim cannot become VERIFIED on the claimant's own say-so.
//   * Expiry fails closed: past expires_at, the effective status degrades to
//     UNKNOWN regardless of the stored status.
//   * Malformed input never throws — every entry point returns a typed
//     ok/error result.

export const CLAIM_STATUS = Object.freeze({
  VERIFIED: 'VERIFIED',
  ASSERTED: 'ASSERTED',
  UNKNOWN: 'UNKNOWN',
} as const);

export type ClaimStatus = 'VERIFIED' | 'ASSERTED' | 'UNKNOWN';

export const CLAIM_SOURCE_KINDS = Object.freeze([
  'content_addressed_artifact',
  'external_signer',
  'claimant',
] as const);

export type ClaimSourceKind = (typeof CLAIM_SOURCE_KINDS)[number];

export interface ClaimSource {
  /** What kind of evidence backs the claim. */
  kind: ClaimSourceKind;
  /** Where the evidence lives: a repo path, URL, signer id, or claimant id. */
  reference: string;
  /** Content hash for content-addressed artifacts (required for that kind). */
  sha256?: string | null;
}

export interface Claim {
  /** What is being claimed, in plain contextual language. Never "trustworthy",
   *  "safe", "compliant", "best" — a Works claim names an exact observation. */
  statement: string;
  status: ClaimStatus;
  /** Exact scope: repo, release, workflow, environment the claim covers. */
  scope: string;
  /** Evidence reference. Required for VERIFIED and ASSERTED; may be null for UNKNOWN. */
  source: ClaimSource | null;
  /** When the underlying evidence was observed (ISO 8601). */
  observed_at: string;
  /** Optional hard expiry (ISO 8601). Past this, effective status is UNKNOWN. */
  expires_at?: string | null;
  /** Known limits of the claim. A scope limit is substance, not a hedge. */
  limitations?: string | null;
}

export type ClaimError = { ok: false; code: string; detail: string };
export type ClaimOk = { ok: true; claim: Claim };
export type ClaimResult = ClaimOk | ClaimError;

const MAX_STATEMENT_CHARS = 600;
const MAX_SCOPE_CHARS = 600;
const MAX_REFERENCE_CHARS = 600;
const MAX_LIMITATIONS_CHARS = 1000;
const SHA256_HEX = /^[0-9a-f]{64}$/;

function err(code: string, detail: string): ClaimError {
  return { ok: false, code, detail };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) return null;
  return trimmed;
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string'
    && value.length >= 10
    && value.length <= 40
    && Number.isFinite(Date.parse(value));
}

/** Validate a source object. Returns the normalized source or a typed error. */
function validateSource(value: unknown): { ok: true; source: ClaimSource } | ClaimError {
  if (!isPlainObject(value)) return err('invalid_source', 'source must be an object');
  const kind = value.kind;
  if (typeof kind !== 'string' || !(CLAIM_SOURCE_KINDS as readonly string[]).includes(kind)) {
    return err('invalid_source_kind', `source.kind must be one of: ${CLAIM_SOURCE_KINDS.join(', ')}`);
  }
  const reference = boundedString(value.reference, MAX_REFERENCE_CHARS);
  if (!reference) return err('invalid_source_reference', 'source.reference is required (non-empty string)');
  let sha256: string | null = null;
  if (value.sha256 !== undefined && value.sha256 !== null) {
    if (typeof value.sha256 !== 'string' || !SHA256_HEX.test(value.sha256)) {
      return err('invalid_source_hash', 'source.sha256 must be a lowercase hex SHA-256 digest');
    }
    sha256 = value.sha256;
  }
  if (kind === 'content_addressed_artifact' && !sha256) {
    return err('missing_source_hash', 'a content_addressed_artifact source requires source.sha256');
  }
  return { ok: true, source: { kind: kind as ClaimSourceKind, reference, sha256 } };
}

/** True when the source is strong enough to carry VERIFIED status. */
export function sourceSupportsVerified(source: ClaimSource | null | undefined): boolean {
  if (!source) return false;
  return source.kind === 'content_addressed_artifact' || source.kind === 'external_signer';
}

/**
 * Validate untrusted claim input into a normalized Claim. Fail-closed: any
 * malformed field returns a typed error; nothing throws.
 */
export function validateClaim(input: unknown): ClaimResult {
  if (!isPlainObject(input)) return err('invalid_claim', 'claim must be an object');

  const statement = boundedString(input.statement, MAX_STATEMENT_CHARS);
  if (!statement) return err('invalid_claim_statement', 'statement is required (non-empty string)');

  const status = input.status;
  if (status !== 'VERIFIED' && status !== 'ASSERTED' && status !== 'UNKNOWN') {
    return err('invalid_claim_status', 'status must be VERIFIED, ASSERTED, or UNKNOWN');
  }

  const scope = boundedString(input.scope, MAX_SCOPE_CHARS);
  if (!scope) return err('invalid_claim_scope', 'scope is required: name the exact repo/release/workflow/environment');

  let source: ClaimSource | null = null;
  if (input.source !== undefined && input.source !== null) {
    const parsed = validateSource(input.source);
    if (!parsed.ok) return parsed;
    source = parsed.source;
  }

  if (status === 'VERIFIED' && !sourceSupportsVerified(source)) {
    return err(
      'verified_requires_source',
      'a VERIFIED claim requires a content_addressed_artifact or external_signer source; claimant say-so cannot verify',
    );
  }
  if (status === 'ASSERTED' && !source) {
    return err('asserted_requires_source', 'an ASSERTED claim requires a source (claimant is acceptable)');
  }

  if (!isIsoTimestamp(input.observed_at)) {
    return err('invalid_observed_at', 'observed_at must be an ISO 8601 timestamp');
  }

  let expiresAt: string | null = null;
  if (input.expires_at !== undefined && input.expires_at !== null) {
    if (!isIsoTimestamp(input.expires_at)) {
      return err('invalid_expires_at', 'expires_at must be an ISO 8601 timestamp when present');
    }
    expiresAt = input.expires_at;
  }

  let limitations: string | null = null;
  if (input.limitations !== undefined && input.limitations !== null) {
    limitations = boundedString(input.limitations, MAX_LIMITATIONS_CHARS);
    if (!limitations) return err('invalid_limitations', 'limitations must be a non-empty string when present');
  }

  return {
    ok: true,
    claim: {
      statement,
      status,
      scope,
      source,
      observed_at: input.observed_at as string,
      expires_at: expiresAt,
      limitations,
    },
  };
}

export function isClaimExpired(claim: Claim, now: Date | string | number = Date.now()): boolean {
  if (!claim?.expires_at) return false;
  const expiresMs = Date.parse(claim.expires_at);
  const nowMs = typeof now === 'number' ? now : new Date(now).getTime();
  // Unparseable timestamps fail closed: treat as expired.
  if (!Number.isFinite(expiresMs) || !Number.isFinite(nowMs)) return true;
  return expiresMs <= nowMs;
}

/**
 * The status the UI must render. Expired evidence no longer carries its
 * stored status: an expired claim is UNKNOWN until re-observed.
 */
export function effectiveClaimStatus(
  claim: Claim,
  now: Date | string | number = Date.now(),
): ClaimStatus {
  if (isClaimExpired(claim, now)) return 'UNKNOWN';
  return claim.status;
}

/**
 * Transition a claim's status. Rules:
 *   * Downgrades (VERIFIED -> ASSERTED/UNKNOWN, ASSERTED -> UNKNOWN) are
 *     always allowed — losing confidence never needs new evidence.
 *   * Upgrading to ASSERTED requires a source (any kind, claimant included).
 *   * Upgrading to VERIFIED requires a content_addressed_artifact or
 *     external_signer source and stamps a fresh observed_at.
 * Returns a new claim object; never mutates, never throws.
 */
export function transitionClaimStatus(
  claim: Claim,
  nextStatus: ClaimStatus,
  options: { source?: ClaimSource | null; observedAt?: string } = {},
): ClaimResult {
  const validated = validateClaim(claim);
  if (!validated.ok) return validated;
  const current = validated.claim;

  if (nextStatus !== 'VERIFIED' && nextStatus !== 'ASSERTED' && nextStatus !== 'UNKNOWN') {
    return err('invalid_claim_status', 'status must be VERIFIED, ASSERTED, or UNKNOWN');
  }

  const nextSource = options.source !== undefined ? options.source : current.source;
  const observedAt = options.observedAt ?? current.observed_at;

  return validateClaim({
    ...current,
    status: nextStatus,
    source: nextSource,
    observed_at: observedAt,
  });
}

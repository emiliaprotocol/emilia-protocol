// SPDX-License-Identifier: Apache-2.0
/**
 * Exact-action technical refusal evidence. It is not a legal determination,
 * an adverse-benefit denial, an authorization grant, or proof of delivery.
 */
import crypto from 'node:crypto';
import {
  RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier,
  riskInstant, riskRecord, signRiskBody, verifyRiskBody, type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';
import { canonicalize } from './execution-binding.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  type AgilityOptions,
  type AgileSigningKey,
} from '@emilia-protocol/verify/pq-signature-agility';

export const ACTION_REFUSAL_STATEMENT_VERSION = 'EP-ACTION-REFUSAL-STATEMENT-v1';
export const ACTION_REFUSAL_CLAIM_BOUNDARY = 'technical_refusal_not_legal_or_benefit_determination';
export const ACTION_REFUSAL_CLASSES = Object.freeze([
  'verification_failed',
  'action_mismatch',
  'evidence_unsatisfied',
  'authorization_refused',
  'replay_detected',
  'expired',
  'indeterminate',
]);

const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'] as const;
const DELIVERY_KEYS = ['channel', 'recipient_id', 'delivered_at', 'custody_digest'] as const;
const CUSTODY_KEYS = ['custodian_id', 'acknowledged_at', 'evidence_digest'] as const;
const ANCHOR_KEYS = ['method', 'evidence_digest'] as const;
const SEMANTIC_KEYS = ['verification', 'match', 'satisfaction', 'authorization'] as const;
const BODY_KEYS = [
  '@version', 'refusal_id', 'relying_party_id', 'caid', 'action_digest',
  'program', 'failed_requirement_ids', 'evidence_digests',
  'challenge_digests', 'nonce', 'refused_at', 'expires_at', 'refusal_class',
  'semantics', 'delivery', 'custody', 'transparency_anchor', 'claim_boundary',
] as const;
const INPUT_KEYS = new Set([
  ...BODY_KEYS.filter((key) => key !== '@version' && key !== 'semantics'
    && key !== 'delivery' && key !== 'custody' && key !== 'transparency_anchor'
    && key !== 'challenge_digests'),
  'semantics', 'delivery', 'custody', 'transparency_anchor',
  'challenge_digest', 'challenge_digests',
]);
const EXPECTED_KEYS = [
  'caid', 'action_digest', 'relying_party_id', 'program_id', 'program_version',
  'source_digest', 'program_digest', 'nonce',
] as const;

const VERIFICATION = new Set(['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE']);
const MATCH = new Set(['MATCH', 'MISMATCH', 'INDETERMINATE']);
const SATISFACTION = new Set(['SATISFIED', 'NOT_SATISFIED', 'INDETERMINATE']);
const AUTHORIZATION = new Set(['AUTHORIZED', 'NOT_AUTHORIZED', 'NOT_EVALUATED', 'INDETERMINATE']);

export type ActionRefusalExpectedBindings = {
  caid?: string;
  action_digest?: string;
  relying_party_id?: string;
  program_id?: string;
  program_version?: number;
  source_digest?: string;
  program_digest?: string;
  nonce?: string;
};

export type ActionRefusalReplayStore = {
  durable: boolean;
  consume(
    relyingPartyId: string,
    nonce: string,
    refusalDigest: string,
  ): Promise<{ accepted: boolean; reason: string | null }>;
};

export type ActionRefusalExternalEvidenceStatus =
  | 'VERIFIED'
  | 'NOT_VERIFIED'
  | 'INDETERMINATE';

export type ActionRefusalExternalEvidenceVerifier = (input: {
  statement: unknown;
  reference: Readonly<RiskRecord>;
  expected_evidence_digest: string;
}) => Promise<{
  status: ActionRefusalExternalEvidenceStatus;
  evidence_digest: string;
  reason: string | null;
}>;

export type ActionRefusalExternalEvidenceOptions = {
  trusted_keys?: TrustedRiskKeys;
  required?: Array<'delivery' | 'custody' | 'transparency_anchor'>;
  verifiers?: Partial<Record<
    'delivery' | 'custody' | 'transparency_anchor',
    ActionRefusalExternalEvidenceVerifier
  >>;
};

function canonicalSet(
  value: unknown,
  validator: (entry: unknown) => boolean,
  maximum: number,
  requireNonEmpty: boolean,
): value is string[] {
  if (!Array.isArray(value) || value.length > maximum
      || (requireNonEmpty && value.length === 0) || !value.every(validator)
      || new Set(value).size !== value.length) return false;
  return value.every((entry, index) => index === 0
    || Buffer.from(value[index - 1]).compare(Buffer.from(entry)) < 0);
}

function sortedUnique(
  value: unknown,
  validator: (entry: unknown) => boolean,
  maximum: number,
  label: string,
  requireNonEmpty: boolean,
): string[] {
  if (!Array.isArray(value) || value.length > maximum
      || (requireNonEmpty && value.length === 0) || !value.every(validator)) {
    throw new TypeError(`action refusal ${label} are invalid`);
  }
  if (new Set(value).size !== value.length) {
    throw new TypeError(`action refusal ${label} are duplicate`);
  }
  return [...value].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
}

function defaultSemantics(refusalClass: unknown): RiskRecord {
  const base = {
    verification: 'VERIFIED',
    match: 'MATCH',
    satisfaction: 'NOT_SATISFIED',
    authorization: 'NOT_EVALUATED',
  };
  if (refusalClass === 'verification_failed') return { ...base, verification: 'NOT_VERIFIED' };
  if (refusalClass === 'action_mismatch') return { ...base, match: 'MISMATCH' };
  if (refusalClass === 'authorization_refused') return { ...base, authorization: 'NOT_AUTHORIZED' };
  if (refusalClass === 'indeterminate') return { ...base, satisfaction: 'INDETERMINATE' };
  return base;
}

function validSemantics(value: unknown, refusalClass: unknown): value is RiskRecord {
  if (!riskExact(value, SEMANTIC_KEYS)
      || !VERIFICATION.has(value.verification) || !MATCH.has(value.match)
      || !SATISFACTION.has(value.satisfaction) || !AUTHORIZATION.has(value.authorization)
      || value.satisfaction === 'SATISFIED') return false;
  if (refusalClass === 'verification_failed') return value.verification === 'NOT_VERIFIED';
  if (refusalClass === 'action_mismatch') return value.match === 'MISMATCH';
  if (refusalClass === 'evidence_unsatisfied') return value.satisfaction === 'NOT_SATISFIED';
  if (refusalClass === 'authorization_refused') return value.authorization === 'NOT_AUTHORIZED';
  if (refusalClass === 'indeterminate') return Object.values(value).includes('INDETERMINATE');
  return true;
}

function validate(value: unknown): asserts value is RiskRecord {
  if (!riskRecord(value)) throw new TypeError('action refusal statement shape is invalid');
  const { issuer, ...body } = value;
  if (issuer !== undefined && (!riskExact(issuer, ['id', 'key_id'])
      || !riskIdentifier(issuer.id) || !riskIdentifier(issuer.key_id))) {
    throw new TypeError('action refusal issuer is invalid');
  }
  if (!riskExact(body, BODY_KEYS) || body['@version'] !== ACTION_REFUSAL_STATEMENT_VERSION
      || !riskIdentifier(body.refusal_id) || !riskIdentifier(body.relying_party_id)
      || typeof body.caid !== 'string' || !RISK_CAID.test(body.caid)
      || typeof body.action_digest !== 'string' || !RISK_DIGEST.test(body.action_digest)
      || !riskExact(body.program, PROGRAM_KEYS) || !riskIdentifier(body.program.program_id)
      || !Number.isSafeInteger(body.program.version) || body.program.version < 1
      || typeof body.program.source_digest !== 'string' || !RISK_DIGEST.test(body.program.source_digest)
      || typeof body.program.program_digest !== 'string' || !RISK_DIGEST.test(body.program.program_digest)
      || !riskIdentifier(body.nonce) || !ACTION_REFUSAL_CLASSES.includes(body.refusal_class)
      || !validSemantics(body.semantics, body.refusal_class)
      || body.claim_boundary !== ACTION_REFUSAL_CLAIM_BOUNDARY) {
    throw new TypeError('action refusal statement shape is invalid');
  }
  if (!canonicalSet(body.failed_requirement_ids, riskIdentifier, 128, true)) {
    throw new TypeError('action refusal requirements are invalid, duplicate, or unsorted');
  }
  if (!canonicalSet(
    body.evidence_digests,
    (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry),
    256,
    false,
  ) || !canonicalSet(
    body.challenge_digests,
    (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry),
    256,
    true,
  )) throw new TypeError('action refusal evidence or challenge binding is invalid');
  const refused = riskInstant(body.refused_at);
  const expires = riskInstant(body.expires_at);
  if (!Number.isFinite(refused) || !Number.isFinite(expires) || expires <= refused) {
    throw new TypeError('action refusal time window is invalid');
  }
  if (body.delivery !== null && (!riskExact(body.delivery, DELIVERY_KEYS)
      || !riskIdentifier(body.delivery.channel) || !riskIdentifier(body.delivery.recipient_id)
      || !Number.isFinite(riskInstant(body.delivery.delivered_at))
      || riskInstant(body.delivery.delivered_at) < refused
      || riskInstant(body.delivery.delivered_at) > expires
      || typeof body.delivery.custody_digest !== 'string'
      || !RISK_DIGEST.test(body.delivery.custody_digest))) {
    throw new TypeError('action refusal delivery evidence is invalid');
  }
  if (body.custody !== null && (body.delivery === null
      || !riskExact(body.custody, CUSTODY_KEYS)
      || !riskIdentifier(body.custody.custodian_id)
      || !Number.isFinite(riskInstant(body.custody.acknowledged_at))
      || riskInstant(body.custody.acknowledged_at) < riskInstant(body.delivery.delivered_at)
      || riskInstant(body.custody.acknowledged_at) > expires
      || typeof body.custody.evidence_digest !== 'string'
      || !RISK_DIGEST.test(body.custody.evidence_digest))) {
    throw new TypeError('action refusal custody evidence is invalid');
  }
  if (body.transparency_anchor !== null && (!riskExact(body.transparency_anchor, ANCHOR_KEYS)
      || !riskIdentifier(body.transparency_anchor.method)
      || typeof body.transparency_anchor.evidence_digest !== 'string'
      || !RISK_DIGEST.test(body.transparency_anchor.evidence_digest))) {
    throw new TypeError('action refusal transparency anchor is invalid');
  }
}

function normalizedInput(input: RiskRecord): RiskRecord {
  const required = [
    'refusal_id', 'relying_party_id', 'caid', 'action_digest', 'program',
    'failed_requirement_ids', 'evidence_digests', 'nonce', 'refused_at',
    'expires_at', 'refusal_class', 'claim_boundary',
  ];
  if (!riskRecord(input) || !required.every((key) => Object.hasOwn(input, key))
      || !Object.keys(input).every((key) => INPUT_KEYS.has(key))
      || (Object.hasOwn(input, 'challenge_digest') === Object.hasOwn(input, 'challenge_digests'))) {
    throw new TypeError('action refusal input shape is invalid');
  }
  const rawChallenges = input.challenge_digests ?? [input.challenge_digest];
  return {
    '@version': ACTION_REFUSAL_STATEMENT_VERSION,
    refusal_id: input.refusal_id,
    relying_party_id: input.relying_party_id,
    caid: input.caid,
    action_digest: input.action_digest,
    program: input.program,
    failed_requirement_ids: sortedUnique(
      input.failed_requirement_ids, riskIdentifier, 128, 'requirements', true,
    ),
    evidence_digests: sortedUnique(
      input.evidence_digests,
      (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry),
      256,
      'evidence digests',
      false,
    ),
    challenge_digests: sortedUnique(
      rawChallenges,
      (entry) => typeof entry === 'string' && RISK_DIGEST.test(entry),
      256,
      'challenge digests',
      true,
    ),
    nonce: input.nonce,
    refused_at: input.refused_at,
    expires_at: input.expires_at,
    refusal_class: input.refusal_class,
    semantics: input.semantics ?? defaultSemantics(input.refusal_class),
    delivery: input.delivery ?? null,
    custody: input.custody ?? null,
    transparency_anchor: input.transparency_anchor ?? null,
    claim_boundary: input.claim_boundary,
  };
}

export function signActionRefusalStatement(
  input: RiskRecord,
  signer: { issuer_id: string; key_id: string; private_key: any },
) {
  const body = normalizedInput(input);
  validate(body);
  return signRiskBody(ACTION_REFUSAL_STATEMENT_VERSION, body, signer);
}

export function actionRefusalStatementDigest(statement: unknown): string {
  return riskDigest(statement);
}

function expectedMismatch(body: RiskRecord, expected: unknown): string | null {
  if (expected === undefined) return null;
  if (!riskRecord(expected) || !Object.keys(expected).every((key) => EXPECTED_KEYS.includes(key as any))) {
    return 'expected_binding_invalid';
  }
  const bindings: RiskRecord = {
    caid: body.caid,
    action_digest: body.action_digest,
    relying_party_id: body.relying_party_id,
    program_id: body.program.program_id,
    program_version: body.program.version,
    source_digest: body.program.source_digest,
    program_digest: body.program.program_digest,
    nonce: body.nonce,
  };
  for (const key of Object.keys(expected)) {
    if (bindings[key] !== expected[key]) return `${key}_mismatch`;
  }
  return null;
}

export function verifyActionRefusalStatement(statement: unknown, options: {
  trusted_keys?: TrustedRiskKeys;
  now?: string | number;
  max_future_skew_sec?: number;
  expected?: ActionRefusalExpectedBindings;
} = {}) {
  const refuse = (reason: string, refusalDigest: string | null = null) => ({
    accepted: false as const,
    verified: false as const,
    reason,
    refusal_digest: refusalDigest,
    semantics: null,
    delivery_evidence: 'NOT_EVIDENCED' as const,
    custody_evidence: 'NOT_EVIDENCED' as const,
    transparency_anchor: 'NOT_REFERENCED' as const,
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
  });
  const signed = verifyRiskBody(statement, ACTION_REFUSAL_STATEMENT_VERSION, options.trusted_keys);
  if (!signed.valid || !signed.body) return refuse(signed.reason ?? 'refusal_invalid');
  try { validate(signed.body); } catch { return refuse('refusal_schema_invalid', signed.artifact_digest); }
  const now = options.now === undefined
    ? Date.now() : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
  const skew = options.max_future_skew_sec ?? 30;
  if (!Number.isFinite(now) || !Number.isSafeInteger(skew) || skew < 0 || skew > 3600) {
    return refuse('verification_time_invalid', signed.artifact_digest);
  }
  if (riskInstant(signed.body.refused_at) > now + skew * 1000) {
    return refuse('refusal_from_future', signed.artifact_digest);
  }
  if (now >= riskInstant(signed.body.expires_at)) {
    return refuse('refusal_expired', signed.artifact_digest);
  }
  const mismatch = expectedMismatch(signed.body, options.expected);
  if (mismatch) return refuse(mismatch, signed.artifact_digest);
  return {
    accepted: true as const,
    verified: true as const,
    reason: null,
    refusal_digest: signed.artifact_digest,
    relying_party_id: signed.body.relying_party_id,
    nonce: signed.body.nonce,
    semantics: riskClone(signed.body.semantics),
    delivery_evidence: signed.body.delivery === null ? 'NOT_EVIDENCED' : 'REFERENCED',
    custody_evidence: signed.body.custody === null ? 'NOT_EVIDENCED' : 'REFERENCED',
    transparency_anchor: signed.body.transparency_anchor === null
      ? 'NOT_REFERENCED' : 'REFERENCED_NOT_EXTERNALLY_VERIFIED',
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
  };
}

export function createMemoryActionRefusalReplayStore(): ActionRefusalReplayStore {
  const consumed = new Map<string, string>();
  return Object.freeze({
    durable: false,
    async consume(relyingPartyId: string, nonce: string, refusalDigest: string) {
      const key = JSON.stringify([relyingPartyId, nonce]);
      const existing = consumed.get(key);
      if (existing === undefined) {
        consumed.set(key, refusalDigest);
        return { accepted: true, reason: null };
      }
      if (existing === refusalDigest) return { accepted: false, reason: 'statement_replay' };
      return { accepted: false, reason: 'nonce_equivocation' };
    },
  });
}

const EXTERNAL_LEGS = ['delivery', 'custody', 'transparency_anchor'] as const;

/**
 * Verify referenced delivery, custody, and transparency evidence with
 * relying-party-pinned adapters. A digest reference alone remains explicitly
 * unverified. This function never upgrades REFERENCED into VERIFIED by itself.
 */
export async function verifyActionRefusalExternalEvidence(
  statement: unknown,
  options: ActionRefusalExternalEvidenceOptions = {},
) {
  const required = new Set(options.required ?? []);
  if ([...required].some((leg) => !EXTERNAL_LEGS.includes(leg))) {
    return { accepted: false as const, reason: 'external_evidence_requirement_invalid', legs: null };
  }

  const signed = verifyRiskBody(
    statement,
    ACTION_REFUSAL_STATEMENT_VERSION,
    options.trusted_keys,
  );
  if (!signed.valid || !signed.body) {
    return { accepted: false as const, reason: signed.reason ?? 'refusal_invalid', legs: null };
  }
  try { validate(signed.body); } catch {
    return { accepted: false as const, reason: 'refusal_schema_invalid', legs: null };
  }

  const body = signed.body;
  const expectedDigests = {
    delivery: body.delivery?.custody_digest,
    custody: body.custody?.evidence_digest,
    transparency_anchor: body.transparency_anchor?.evidence_digest,
  };
  const legs: RiskRecord = {};

  for (const leg of EXTERNAL_LEGS) {
    const reference = body[leg];
    if (reference === null) {
      legs[leg] = { status: 'ABSENT', evidence_digest: null, reason: null };
      if (required.has(leg)) {
        return { accepted: false as const, reason: `${leg}_reference_required`, legs };
      }
      continue;
    }

    const verifier = options.verifiers?.[leg];
    if (typeof verifier !== 'function') {
      legs[leg] = {
        status: 'REFERENCED_NOT_EXTERNALLY_VERIFIED',
        evidence_digest: expectedDigests[leg],
        reason: 'verifier_not_configured',
      };
      if (required.has(leg)) {
        return { accepted: false as const, reason: `${leg}_verifier_required`, legs };
      }
      continue;
    }

    let result: unknown;
    try {
      result = await verifier({
        statement: riskClone(statement),
        reference: riskClone(reference),
        expected_evidence_digest: expectedDigests[leg],
      });
    } catch {
      legs[leg] = {
        status: 'INDETERMINATE',
        evidence_digest: expectedDigests[leg],
        reason: 'verifier_unavailable',
      };
      return { accepted: false as const, reason: `${leg}_verification_indeterminate`, legs };
    }

    if (!riskExact(result, ['status', 'evidence_digest', 'reason'])
        || !['VERIFIED', 'NOT_VERIFIED', 'INDETERMINATE'].includes(result.status)
        || typeof result.evidence_digest !== 'string' || !RISK_DIGEST.test(result.evidence_digest)
        || (result.reason !== null && typeof result.reason !== 'string')) {
      legs[leg] = {
        status: 'INDETERMINATE',
        evidence_digest: expectedDigests[leg],
        reason: 'verifier_result_invalid',
      };
      return { accepted: false as const, reason: `${leg}_verifier_result_invalid`, legs };
    }
    if (result.evidence_digest !== expectedDigests[leg]) {
      legs[leg] = {
        status: 'NOT_VERIFIED',
        evidence_digest: result.evidence_digest,
        reason: 'evidence_digest_mismatch',
      };
      return { accepted: false as const, reason: `${leg}_evidence_digest_mismatch`, legs };
    }
    legs[leg] = riskClone(result);
    if (result.status !== 'VERIFIED') {
      const suffix = result.status === 'INDETERMINATE' ? 'verification_indeterminate' : 'not_verified';
      return { accepted: false as const, reason: `${leg}_${suffix}`, legs };
    }
  }

  return { accepted: true as const, reason: null, legs };
}

export async function acceptActionRefusalStatement(statement: unknown, options: {
  trusted_keys?: TrustedRiskKeys;
  now?: string | number;
  max_future_skew_sec?: number;
  expected?: ActionRefusalExpectedBindings;
  replayStore?: ActionRefusalReplayStore;
  allowEphemeralReplayStore?: boolean;
  external_evidence?: ActionRefusalExternalEvidenceOptions;
} = {}) {
  const verification = verifyActionRefusalStatement(statement, options);
  const refused = (reason: string, checked = false, durable = false) => ({
    ...verification,
    accepted: false as const,
    reason,
    replay_checked: checked,
    replay_store_durable: durable,
  });
  if (!verification.verified) return refused(verification.reason);
  if (typeof verification.refusal_digest !== 'string') return refused('refusal_digest_missing');
  if (!riskExact(options.expected, EXPECTED_KEYS)) return refused('complete_expected_binding_required');
  let externalEvidence: Awaited<ReturnType<typeof verifyActionRefusalExternalEvidence>> | null = null;
  if (options.external_evidence !== undefined) {
    externalEvidence = await verifyActionRefusalExternalEvidence(statement, {
      ...options.external_evidence,
      trusted_keys: options.external_evidence.trusted_keys ?? options.trusted_keys,
    });
    if (!externalEvidence.accepted) {
      return { ...refused(externalEvidence.reason), external_evidence: externalEvidence };
    }
  }
  const store = options.replayStore;
  if (!store || typeof store.consume !== 'function' || typeof store.durable !== 'boolean') {
    return refused('replay_store_required');
  }
  if (!store.durable && options.allowEphemeralReplayStore !== true) {
    return refused('durable_replay_store_required');
  }
  let result: unknown;
  try {
    result = await store.consume(
      verification.relying_party_id,
      verification.nonce,
      verification.refusal_digest,
    );
  } catch {
    return refused('replay_store_unavailable', false, store.durable);
  }
  if (!riskExact(result, ['accepted', 'reason']) || typeof result.accepted !== 'boolean'
      || (result.reason !== null && typeof result.reason !== 'string')) {
    return refused('replay_store_result_invalid', false, store.durable);
  }
  if (!result.accepted) {
    const reason = result.reason === 'statement_replay' || result.reason === 'nonce_equivocation'
      ? result.reason : 'replay_store_refused';
    return refused(reason, true, store.durable);
  }
  if (result.reason !== null) return refused('replay_store_result_invalid', true, store.durable);
  return {
    ...verification,
    accepted: true as const,
    replay_checked: true,
    replay_store_durable: store.durable,
    external_evidence: externalEvidence,
  };
}

// ===========================================================================
// EP-ACTION-REFUSAL-STATEMENT-v2 -- the hybrid (Ed25519 + ML-DSA-65) refusal
// statement.
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration in docs/protocol/pq-hybrid-program.md, section "PATTERN: the
 * reference hybrid migration" (EP-REVOCATION-v2, packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of the
 *    proof, a wire-format change, so the artifact takes a new @version
 *    (EP-ACTION-REFUSAL-STATEMENT-v2). The v1 verifier is untouched and refuses a
 *    v2 statement on its version marker (verifyRiskBody's @version check) before
 *    inspecting any signature, and never throws.
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures` array
 *    shaped exactly like EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }),
 *    one entry per algorithm in the registered order. Ed25519 keeps its base64url
 *    SPKI DER public key; ML-DSA-65 carries raw base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (actionRefusalV2SignedPayload below), under the same
 *    domain-separated `version\0canonicalize(body)` form the v1 risk-crypto
 *    signer uses. Drop the ML-DSA leg and narrow `required_algorithms` and the
 *    surviving Ed25519 signature no longer verifies. The verifier rebuilds the
 *    bytes from the REGISTERED set; the presented statement never chooses what it
 *    is checked against.
 * 4. V1 COMPATIBILITY. v1 statements keep verifying through the unchanged
 *    synchronous verifyActionRefusalStatement; v2 verification is ASYNC (ML-DSA
 *    verification is async), so it is a SEPARATE entry point, with
 *    verifyActionRefusalStatementAny() routing on @version. The v1 verifier is
 *    never made async.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a readable
 *    reason; nothing throws on caller input. An absent ML-DSA backend is
 *    'pq_backend_unavailable' surfaced through the agility result, never a skipped
 *    check and never a pass on the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: this is exact-action technical refusal
 * evidence, not a legal or benefit determination, not an authorization grant, not
 * proof of delivery. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module. v2
 * does NOT retroactively protect statements already issued under v1.
 */

export const ACTION_REFUSAL_STATEMENT_V2_VERSION = 'EP-ACTION-REFUSAL-STATEMENT-v2';
export const ACTION_REFUSAL_STATEMENT_V2_DOMAIN = `${ACTION_REFUSAL_STATEMENT_V2_VERSION}\0`;

/** The registered required algorithm set, in canonical order. */
export const ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const REFUSAL_PROOF_V2_KEYS = [
  'profile', 'required_algorithms', 'public_key', 'key_id',
  'pq_public_key', 'pq_key_id', 'signatures',
] as const;

export interface ActionRefusalV2TrustedKeys {
  [key_id: string]: { issuer_id: string; public_key: string; pq_public_key: string };
}

function refusalV2AlgorithmSetRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS[i]);
}

/** ML-DSA-65 public-key identifier: SHA-256 of the raw public key bytes. */
function refusalPqKeyId(publicKeyRawB64u: unknown): string {
  try {
    if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0) return '';
    const raw = Buffer.from(publicKeyRawB64u, 'base64url');
    if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u) return '';
    return `ep:refusal-issuer-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
  } catch {
    return '';
  }
}

/** Ed25519 curve-pinned public-key identifier: SHA-256 of the SPKI DER. */
function refusalEdKeyId(publicKeyB64u: unknown): string {
  try {
    if (typeof publicKeyB64u !== 'string' || publicKeyB64u.length === 0) return '';
    const der = Buffer.from(publicKeyB64u, 'base64url');
    if (der.length === 0 || der.toString('base64url') !== publicKeyB64u) return '';
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return '';
    return `ep:refusal-issuer-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
  } catch {
    return '';
  }
}

function refusalAgilityPassthrough(opts: any): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts?.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts?.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

/**
 * The bytes BOTH legs sign: the same domain-separated `version\0canonicalize(body)`
 * form as the v1 risk-crypto signer, plus the committed `required_algorithms` set,
 * under the v2 domain tag. `body` is the full v2 body (with @version and issuer)
 * and WITHOUT the proof. Recomputed independently by the verifier from the
 * PRESENTED body and the REGISTERED set. See PATTERN move 3.
 */
export function actionRefusalV2SignedPayload(
  body: RiskRecord,
  requiredAlgorithms: readonly string[] = ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!refusalV2AlgorithmSetRegistered(requiredAlgorithms)) {
    throw new TypeError('actionRefusalV2SignedPayload: algorithm set is not the registered EP-ACTION-REFUSAL-STATEMENT-v2 set');
  }
  return Buffer.from(
    ACTION_REFUSAL_STATEMENT_V2_DOMAIN + canonicalize({ ...body, required_algorithms: [...requiredAlgorithms] }),
    'utf8',
  );
}

/**
 * Mint a real hybrid v2 refusal statement. Issuance may throw on invalid local
 * input (matching signActionRefusalStatement); verification below never throws.
 * The domain body is validated by the exact same v1 validators, so a v2 statement
 * carries an identical, fully-checked refusal body.
 */
export async function signActionRefusalStatementV2(
  input: RiskRecord,
  signer: {
    issuer_id: string;
    key_id: string;
    private_key: crypto.KeyObject | Parameters<typeof crypto.createPrivateKey>[0];
    pq_public_key: string;
    pq_private_key: string | Uint8Array;
  },
  options: AgilityOptions = {},
): Promise<RiskRecord> {
  const v1Body = normalizedInput(input);
  validate(v1Body); // domain validation under the v1 marker: single source of truth
  if (!riskIdentifier(signer?.issuer_id) || !riskIdentifier(signer?.key_id)) {
    throw new TypeError('action refusal v2 signer is invalid');
  }
  const edKey = signer.private_key instanceof crypto.KeyObject
    ? signer.private_key : crypto.createPrivateKey(signer.private_key);
  if (edKey.asymmetricKeyType !== 'ed25519') throw new TypeError('action refusal v2 Ed25519 key is invalid');
  const edPubB64u = crypto.createPublicKey(edKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  const edId = refusalEdKeyId(edPubB64u);
  const pqId = refusalPqKeyId(signer.pq_public_key);
  if (!edId || !pqId) throw new TypeError('action refusal v2 public key material is invalid');

  const body = riskClone({
    ...v1Body,
    '@version': ACTION_REFUSAL_STATEMENT_V2_VERSION,
    issuer: { id: signer.issuer_id, key_id: signer.key_id },
  });
  const bytes = actionRefusalV2SignedPayload(body, ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS);
  const keys: AgileSigningKey[] = [
    { alg: 'Ed25519', private_key: edKey, key_id: edId },
    { alg: 'ML-DSA-65', private_key: signer.pq_private_key, key_id: pqId },
  ];
  const signatures = await signAgileSet(new Uint8Array(bytes), keys, refusalAgilityPassthrough(options));
  return riskFreeze({
    ...body,
    proof: {
      profile: ACTION_REFUSAL_STATEMENT_V2_VERSION,
      required_algorithms: [...ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS],
      public_key: edPubB64u,
      key_id: edId,
      pq_public_key: signer.pq_public_key,
      pq_key_id: pqId,
      signatures,
    },
  });
}

/**
 * FAIL-CLOSED hybrid verifier for one EP-ACTION-REFUSAL-STATEMENT-v2. Never throws
 * on caller input; a v2 statement NEVER verifies on one leg alone.
 */
export async function verifyActionRefusalStatementV2(statement: unknown, options: {
  trusted_keys?: ActionRefusalV2TrustedKeys;
  now?: string | number;
  max_future_skew_sec?: number;
  expected?: ActionRefusalExpectedBindings;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
} = {}) {
  const checks: Record<string, boolean> = {
    version: false,
    structure: false,
    refusal_schema: false,
    issuer_pin: false,
    issuer_key_bound: false,
    algorithm_set: false,
    legs_present: false,
    signature: false,
    time_window: false,
    expected_bindings: false,
  };
  const refuse = (reason: string, refusalDigest: string | null = null) => riskFreeze({
    accepted: false as const,
    verified: false as const,
    reason,
    refusal_digest: refusalDigest,
    checks,
    semantics: null,
    claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
  });
  try {
    if (!riskRecord(statement) || !riskRecord((statement as RiskRecord).proof)
      || !riskRecord((statement as RiskRecord).issuer)) {
      return refuse('refusal_shape_invalid');
    }
    const { proof, ...bodyNoProof } = statement as RiskRecord;
    checks.version = bodyNoProof['@version'] === ACTION_REFUSAL_STATEMENT_V2_VERSION;
    if (!checks.version) return refuse(`unsupported version: ${String(bodyNoProof['@version'])}`);

    checks.structure = riskExact(proof, REFUSAL_PROOF_V2_KEYS)
      && proof.profile === ACTION_REFUSAL_STATEMENT_V2_VERSION
      && riskExact(bodyNoProof.issuer, ['id', 'key_id'])
      && riskIdentifier(bodyNoProof.issuer.id) && riskIdentifier(bodyNoProof.issuer.key_id);
    if (!checks.structure) return refuse('refusal_proof_envelope_invalid');

    const refusalDigest = riskDigest(statement);

    // Domain validation reuses the exact v1 validators over a v1-marker clone, so
    // every v1 refusal schema refusal is preserved unchanged.
    try {
      const domainClone = riskClone({ ...bodyNoProof, '@version': ACTION_REFUSAL_STATEMENT_VERSION });
      validate(domainClone);
      checks.refusal_schema = true;
    } catch {
      return refuse('refusal_schema_invalid', refusalDigest);
    }

    // Pinning: BOTH halves pinned, presented halves must equal the pinned ones.
    const pin = options.trusted_keys?.[bodyNoProof.issuer.key_id];
    const presentedEdKey = proof.public_key;
    const presentedPqKey = proof.pq_public_key;
    checks.issuer_pin = !!pin
      && pin.issuer_id === bodyNoProof.issuer.id
      && typeof pin.public_key === 'string' && pin.public_key.length > 0
      && typeof pin.pq_public_key === 'string' && pin.pq_public_key.length > 0
      && pin.public_key === presentedEdKey
      && pin.pq_public_key === presentedPqKey;
    if (!checks.issuer_pin) return refuse('refusal_issuer_untrusted', refusalDigest);

    const derivedEdKeyId = refusalEdKeyId(presentedEdKey);
    const derivedPqKeyId = refusalPqKeyId(presentedPqKey);
    checks.issuer_key_bound = !!derivedEdKeyId && proof.key_id === derivedEdKeyId
      && !!derivedPqKeyId && proof.pq_key_id === derivedPqKeyId;
    if (!checks.issuer_key_bound) return refuse('refusal_issuer_key_unbound', refusalDigest);

    checks.algorithm_set = refusalV2AlgorithmSetRegistered(proof.required_algorithms);
    if (!checks.algorithm_set) return refuse('refusal_algorithm_set_invalid', refusalDigest);

    const signatures = Array.isArray(proof.signatures) ? proof.signatures : null;
    if (!signatures || signatures.length === 0) return refuse('refusal_signature_legs_missing', refusalDigest);
    const presented = new Set<string>();
    for (const s of signatures) {
      if (!riskRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        return refuse('refusal_signature_leg_malformed', refusalDigest);
      }
      if (presented.has(s.alg)) return refuse('refusal_signature_leg_duplicate', refusalDigest);
      presented.add(s.alg);
    }
    for (const alg of presented) {
      if (!(ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
        return refuse('refusal_signature_leg_unexpected', refusalDigest);
      }
    }
    for (const alg of ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS) {
      if (!presented.has(alg)) return refuse('refusal_signature_leg_stripped', refusalDigest);
    }
    checks.legs_present = true;

    const bytes = actionRefusalV2SignedPayload(bodyNoProof, ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS);
    const verificationKeys = [
      { alg: 'Ed25519', public_key: pin!.public_key, key_id: derivedEdKeyId },
      { alg: 'ML-DSA-65', public_key: pin!.pq_public_key, key_id: derivedPqKeyId },
    ];
    let setResult: any = null;
    try {
      setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, verificationKeys, {
        ...refusalAgilityPassthrough(options),
        policy: 'hybrid_all',
        requiredAlgorithms: [...ACTION_REFUSAL_V2_REQUIRED_ALGORITHMS],
      });
    } catch {
      setResult = null;
    }
    checks.signature = setResult?.verified === true;
    if (!checks.signature) {
      const reason = String(setResult?.reason ?? 'signature_set_unverified');
      return refuse(`refusal_signature_invalid (${reason})`, refusalDigest);
    }

    const now = options.now === undefined
      ? Date.now() : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
    const skew = options.max_future_skew_sec ?? 30;
    if (!Number.isFinite(now) || !Number.isSafeInteger(skew) || skew < 0 || skew > 3600) {
      return refuse('verification_time_invalid', refusalDigest);
    }
    if (riskInstant(bodyNoProof.refused_at) > now + skew * 1000) return refuse('refusal_from_future', refusalDigest);
    if (now >= riskInstant(bodyNoProof.expires_at)) return refuse('refusal_expired', refusalDigest);
    checks.time_window = true;

    const mismatch = expectedMismatch(bodyNoProof, options.expected);
    if (mismatch) return refuse(mismatch, refusalDigest);
    checks.expected_bindings = true;

    return riskFreeze({
      accepted: true as const,
      verified: true as const,
      reason: null,
      refusal_digest: refusalDigest,
      relying_party_id: bodyNoProof.relying_party_id,
      nonce: bodyNoProof.nonce,
      semantics: riskClone(bodyNoProof.semantics),
      checks,
      claim_boundary: ACTION_REFUSAL_CLAIM_BOUNDARY,
    });
  } catch {
    return refuse('refusal_invalid');
  }
}

/**
 * Route a statement of EITHER version to its verifier. v1 statements keep the
 * exact v1 verdict; v2 statements get the hybrid check. A statement whose
 * @version is neither refuses through the v1 verifier, which is fail-closed.
 */
export async function verifyActionRefusalStatementAny(statement: unknown, options: any = {}) {
  if (riskRecord(statement) && (statement as RiskRecord)['@version'] === ACTION_REFUSAL_STATEMENT_V2_VERSION) {
    return verifyActionRefusalStatementV2(statement, options);
  }
  return verifyActionRefusalStatement(statement, options);
}

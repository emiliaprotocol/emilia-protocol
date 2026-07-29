// SPDX-License-Identifier: Apache-2.0
/**
 * PSEA -02 native verification and optional AEB projection.
 *
 * PSEA is treated as a human-authority evidence provider, never as the final
 * execution authority.  The pure adapter verifies the native JWS/EAT proof and
 * projects its exact action into CAID.  Execution callers MUST additionally use
 * verifyAndCommitPseaProof (or an equivalent durable transaction) so the PSEA
 * counter comparison and jti finalization happen atomically before Gate admits
 * the effect.
 *
 * Source pinned by this implementation:
 * https://www.ietf.org/archive/id/draft-yossif-psea-02.html
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
// The CAID reference implementation is JavaScript and intentionally has no
// TypeScript declaration surface in this repository.
// @ts-expect-error -- checked at runtime and narrowed below.
import { computeCaid } from '../vendor/caid.mjs';
import type {
  Acceptance,
  AebAdapter,
  AebAdapterInput,
  AebDigest,
  AebMappingResult,
  AebNativeResult,
  AebStatusInput,
} from './aeb-adapter-contract.js';

export const PSEA_SOURCE_REVISION = 'draft-yossif-psea-02';
export const PSEA_EAT_PROFILE = 'urn:ietf:params:psea:eat-profile:1';
export const PSEA_PROOF_VERSION = '1';
export const PSEA_AEB_ADAPTER_ID = 'native:psea-eat-jws';
export const PSEA_AEB_ADAPTER_VERSION = '1';
export const PSEA_AEB_CONFIG_VERSION = 'AEB-PSEA-CONFIG-v1';
export const PSEA_AEB_TRUST_ROOT_VERSION = 'AEB-PSEA-ES256-ROOT-v1';
export const PSEA_AEB_CAID_MAPPING_VERSION = 'AEB-PSEA-CAID-MAPPING-v1';
export const PSEA_AEB_CAID_MAPPER_ID = 'mapper:psea-jcs-action-v1';

type Obj = Record<string, unknown>;

export type PseaAttestationStatus =
  | 'verified-hardware-uv'
  | 'verified-key-only'
  | 'not-appraised'
  | 'rejected';

export interface PseaAebConfig {
  '@version': typeof PSEA_AEB_CONFIG_VERSION;
  source_revision: typeof PSEA_SOURCE_REVISION;
  evidence_role: string;
  subject: { id: string; kind: 'human'; native_id: string };
  action_type: string;
  issuer: string;
  audience: string;
  operation: string;
  tier: number;
  expected_nonce: string | null;
  max_token_lifetime_seconds: number;
  max_clock_skew_seconds: number;
  max_status_age_seconds: number;
  required_attestation_statuses: readonly PseaAttestationStatus[];
  replay_mode: 'gate-atomic-consumption-required';
}

export interface PseaTrustRoot {
  '@version': typeof PSEA_AEB_TRUST_ROOT_VERSION;
  source_revision: typeof PSEA_SOURCE_REVISION;
  issuer: string;
  kid: string;
  public_key_spki: string;
  ueid: string;
  subject_native_id: string;
  enrollment_status: 'active' | 'revoked';
  attestation_status: PseaAttestationStatus;
  counter_scope: string;
}

export interface PseaArtifact {
  proof: string;
  actionPayload: unknown;
  integrityEvidence?: unknown;
}

export interface PseaClaims {
  jti: string;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
  ueid: string;
  eat_profile: typeof PSEA_EAT_PROFILE;
  psea_tier: number;
  psea_op: string;
  psea_counter: number;
  psea_payload_hash: string;
  psea_uv: { verified: true; method: string };
  psea_proof_version: typeof PSEA_PROOF_VERSION;
  eat_nonce?: string;
  submods?: { 'psea-device-state': Obj };
  psea_chain_prev?: string;
  psea_caller_package?: string;
  psea_sdk_version?: string;
  psea_user_hash?: string;
  psea_chain_pending?: unknown;
  psea_last_confirmed_head?: unknown;
  psea_rp_context_hash?: unknown;
}

export interface PseaReplayCandidate {
  scope: string;
  counter: number;
  jti: string;
  replay_unit: AebDigest;
}

export interface PseaReplaySnapshot {
  highest_counter: number | null;
  seen_jtis: ReadonlySet<string> | readonly string[];
}

export type PseaReplayCommitResult =
  | { committed: true }
  | { committed: false; reason: 'jti_replay' | 'counter_rollback' };

/** Implement this as one durable compare-and-update transaction in production. */
export interface PseaReplayStore {
  inspect(scope: string): Promise<PseaReplaySnapshot>;
  commit(candidate: PseaReplayCandidate): Promise<PseaReplayCommitResult>;
}

export interface PseaInspectionResult {
  verified: boolean;
  reasons: string[];
  proof_digest: AebDigest;
  action_digest: AebDigest;
  claims: PseaClaims | null;
  root: PseaTrustRoot | null;
  replay_candidate: PseaReplayCandidate | null;
}

export interface PseaCommittedVerification extends PseaInspectionResult {
  replay_committed: boolean;
}

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const IDENT_RE = /^[A-Za-z0-9_.:@/-]{1,256}$/;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const JTI_RE = /^[A-Za-z0-9._-]{1,128}$/;
const KID_RE = /^[A-Za-z0-9._~:/+-]{1,256}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const SHA256_B64_RE = /^[A-Za-z0-9+/]{43}=$/;
const HEADER_KEYS = new Set(['alg', 'kid', 'typ']);
const ARTIFACT_KEYS = new Set(['proof', 'actionPayload', 'integrityEvidence']);
const UV_KEYS = new Set(['verified', 'method']);
const SUBMOD_KEYS = new Set(['psea-device-state']);
const REQUIRED_CLAIMS = new Set([
  'jti', 'aud', 'iss', 'iat', 'exp', 'ueid', 'eat_profile', 'psea_tier',
  'psea_op', 'psea_counter', 'psea_payload_hash', 'psea_uv',
  'psea_proof_version',
]);
const OPTIONAL_CLAIMS = new Set([
  'eat_nonce', 'submods', 'psea_chain_prev', 'psea_caller_package',
  'psea_sdk_version', 'psea_user_hash', 'psea_chain_pending',
  'psea_last_confirmed_head', 'psea_rp_context_hash',
]);
const CLAIM_KEYS = new Set([...REQUIRED_CLAIMS, ...OPTIONAL_CLAIMS]);
const CONFIG_KEYS = new Set([
  '@version', 'source_revision', 'evidence_role', 'subject', 'action_type',
  'issuer', 'audience', 'operation', 'tier', 'expected_nonce',
  'max_token_lifetime_seconds', 'max_clock_skew_seconds',
  'max_status_age_seconds', 'required_attestation_statuses', 'replay_mode',
]);
const SUBJECT_KEYS = new Set(['id', 'kind', 'native_id']);
const ROOT_KEYS = new Set([
  '@version', 'source_revision', 'issuer', 'kid', 'public_key_spki', 'ueid',
  'subject_native_id', 'enrollment_status', 'attestation_status', 'counter_scope',
]);

function isRecord(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Obj, allowed: ReadonlySet<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === allowed.size && keys.every((key) => allowed.has(key));
}

function onlyKnownKeys(value: Obj, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function validUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

/** RFC 8785-compatible JSON canonicalization for I-JSON data. */
export function canonicalizePsea(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    if (!validUnicodeScalarString(value)) throw new Error('invalid_unicode_scalar');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new Error('non_i_json_number');
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value !== 'object' || value === undefined) throw new Error('non_json_value');
  if (seen.has(value)) throw new Error('cyclic_json');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalizePsea(entry, seen)).join(',')}]`;
    }
    const object = value as Obj;
    const keys = Object.keys(object).sort();
    for (const key of keys) {
      if (!validUnicodeScalarString(key) || object[key] === undefined) {
        throw new Error('non_i_json_member');
      }
    }
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizePsea(object[key], seen)}`).join(',')}}`;
  } finally {
    seen.delete(value);
  }
}

function digestBytes(bytes: string | Buffer): AebDigest {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

function safeDigest(value: unknown): AebDigest {
  try { return digestBytes(Buffer.from(canonicalizePsea(value), 'utf8')); }
  catch { return digestBytes(Buffer.from('invalid', 'utf8')); }
}

function decodeB64u(value: unknown): Buffer | null {
  if (!nonEmptyString(value) || !B64U_RE.test(value) || value.length % 4 === 1) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value ? decoded : null;
}

function validUeid(value: unknown): value is string {
  const bytes = decodeB64u(value);
  return Boolean(bytes && bytes.length === 33 && bytes[0] === 0x01);
}

function validP256Spki(value: unknown): value is string {
  const der = decodeB64u(value);
  if (!der) return false;
  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ec'
      && key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
  } catch { return false; }
}

function parseConfig(value: unknown): PseaAebConfig | null {
  if (!isRecord(value) || !exactKeys(value, CONFIG_KEYS)
      || value['@version'] !== PSEA_AEB_CONFIG_VERSION
      || value.source_revision !== PSEA_SOURCE_REVISION
      || !nonEmptyString(value.evidence_role) || !ROLE_RE.test(value.evidence_role)
      || !isRecord(value.subject) || !exactKeys(value.subject, SUBJECT_KEYS)
      || value.subject.kind !== 'human' || !nonEmptyString(value.subject.id)
      || !IDENT_RE.test(value.subject.id) || !nonEmptyString(value.subject.native_id)
      || !ACTION_TYPE_RE.test(String(value.action_type))
      || !nonEmptyString(value.issuer) || !nonEmptyString(value.audience)
      || !nonEmptyString(value.operation) || !safeInteger(value.tier)
      || !(value.expected_nonce === null || nonEmptyString(value.expected_nonce))
      || !safeInteger(value.max_token_lifetime_seconds)
      || !safeInteger(value.max_clock_skew_seconds) || value.max_clock_skew_seconds > 60
      || !safeInteger(value.max_status_age_seconds)
      || !Array.isArray(value.required_attestation_statuses)
      || value.required_attestation_statuses.length === 0
      || !value.required_attestation_statuses.every((item) => [
        'verified-hardware-uv', 'verified-key-only', 'not-appraised', 'rejected',
      ].includes(String(item)))
      || new Set(value.required_attestation_statuses).size !== value.required_attestation_statuses.length
      || value.replay_mode !== 'gate-atomic-consumption-required') return null;
  return value as unknown as PseaAebConfig;
}

function parseRoots(values: readonly unknown[]): Map<string, PseaTrustRoot> | null {
  if (!Array.isArray(values) || values.length === 0) return null;
  const roots = new Map<string, PseaTrustRoot>();
  for (const value of values) {
    if (!isRecord(value) || !exactKeys(value, ROOT_KEYS)
        || value['@version'] !== PSEA_AEB_TRUST_ROOT_VERSION
        || value.source_revision !== PSEA_SOURCE_REVISION
        || !nonEmptyString(value.issuer) || !nonEmptyString(value.kid)
        || !KID_RE.test(value.kid) || !validP256Spki(value.public_key_spki)
        || !validUeid(value.ueid) || !nonEmptyString(value.subject_native_id)
        || !['active', 'revoked'].includes(String(value.enrollment_status))
        || !['verified-hardware-uv', 'verified-key-only', 'not-appraised', 'rejected']
          .includes(String(value.attestation_status))
        || !nonEmptyString(value.counter_scope) || roots.has(value.kid)) return null;
    roots.set(value.kid, value as unknown as PseaTrustRoot);
  }
  return roots;
}

function parseJws(proof: string): {
  header: Obj;
  payload: Obj;
  kid: string;
  signingInput: Buffer;
  signature: Buffer;
} | null {
  const segments = proof.split('.');
  if (segments.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const headerBytes = decodeB64u(encodedHeader);
  const payloadBytes = decodeB64u(encodedPayload);
  const signature = decodeB64u(encodedSignature);
  if (!headerBytes || !payloadBytes || !signature || signature.length !== 64) return null;
  let headerText: string;
  let payloadText: string;
  try {
    headerText = new TextDecoder('utf-8', { fatal: true }).decode(headerBytes);
    payloadText = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
  } catch { return null; }
  if (!strictJsonGate(headerText).ok || !strictJsonGate(payloadText).ok) return null;
  let header: unknown;
  let payload: unknown;
  try { header = JSON.parse(headerText); payload = JSON.parse(payloadText); }
  catch { return null; }
  if (!isRecord(header) || !exactKeys(header, HEADER_KEYS)
      || header.alg !== 'ES256' || header.typ !== 'psea-proof+jwt'
      || !nonEmptyString(header.kid) || !KID_RE.test(header.kid)
      || !isRecord(payload)) return null;
  try {
    if (canonicalizePsea(payload) !== payloadText) return null;
  } catch { return null; }
  return {
    header,
    payload,
    kid: header.kid,
    signingInput: Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
    signature,
  };
}

function parseClaims(value: Obj): PseaClaims | null {
  if (!onlyKnownKeys(value, CLAIM_KEYS)
      || [...REQUIRED_CLAIMS].some((key) => !Object.hasOwn(value, key))
      || !JTI_RE.test(String(value.jti))
      || !nonEmptyString(value.aud) || !nonEmptyString(value.iss)
      || !safeInteger(value.iat) || !safeInteger(value.exp) || value.exp <= value.iat
      || !validUeid(value.ueid) || value.eat_profile !== PSEA_EAT_PROFILE
      || !safeInteger(value.psea_tier) || !nonEmptyString(value.psea_op)
      || !safeInteger(value.psea_counter)
      || typeof value.psea_payload_hash !== 'string'
      || !SHA256_B64_RE.test(value.psea_payload_hash)
      || Buffer.from(value.psea_payload_hash, 'base64').length !== 32
      || !isRecord(value.psea_uv) || !exactKeys(value.psea_uv, UV_KEYS)
      || value.psea_uv.verified !== true || !nonEmptyString(value.psea_uv.method)
      || value.psea_proof_version !== PSEA_PROOF_VERSION
      || (Object.hasOwn(value, 'eat_nonce') && !nonEmptyString(value.eat_nonce))) return null;
  if (Object.hasOwn(value, 'submods')) {
    if (!isRecord(value.submods) || !exactKeys(value.submods, SUBMOD_KEYS)
        || !isRecord(value.submods['psea-device-state'])) return null;
  }
  for (const key of ['psea_chain_prev', 'psea_caller_package', 'psea_sdk_version', 'psea_user_hash']) {
    if (Object.hasOwn(value, key) && !nonEmptyString(value[key])) return null;
  }
  return value as unknown as PseaClaims;
}

function inspectStatus(status: AebStatusInput, now: string, maxAge: number): {
  acceptance: Acceptance; reasons: string[];
} {
  const at = Date.parse(now);
  const checked = Date.parse(status?.checked_at);
  const expires = Date.parse(status?.expires_at);
  if (!Number.isFinite(at) || !Number.isFinite(checked) || !Number.isFinite(expires)) {
    return { acceptance: 'INDETERMINATE', reasons: ['psea:status_time_invalid'] };
  }
  if (status.unavailable || !status.revocation_checked) {
    return { acceptance: 'INDETERMINATE', reasons: ['psea:status_unavailable'] };
  }
  if (checked > at || at - checked > maxAge * 1000 || expires < at) {
    return { acceptance: 'INDETERMINATE', reasons: ['psea:status_stale'] };
  }
  if (status.revoked) return { acceptance: 'REJECTED', reasons: ['psea:enrollment_revoked'] };
  if (status.consumed) return { acceptance: 'REJECTED', reasons: ['psea:evidence_consumed'] };
  return { acceptance: 'ACCEPTED', reasons: [] };
}

function emptyInspection(artifact: unknown, reasons: string[]): PseaInspectionResult {
  return {
    verified: false,
    reasons,
    proof_digest: isRecord(artifact) && typeof artifact.proof === 'string'
      ? digestBytes(Buffer.from(artifact.proof, 'utf8')) : safeDigest(artifact),
    action_digest: isRecord(artifact) && Object.hasOwn(artifact, 'actionPayload')
      ? safeDigest(artifact.actionPayload) : safeDigest(null),
    claims: null,
    root: null,
    replay_candidate: null,
  };
}

/**
 * Pure native inspection.  Optional replaySnapshot permits deterministic
 * historical checks.  It does not mutate replay state.
 */
export function inspectPseaProof(input: {
  artifact: unknown;
  config: unknown;
  trust_roots: readonly unknown[];
  now: string;
  replay_snapshot?: PseaReplaySnapshot;
}): PseaInspectionResult {
  const config = parseConfig(input.config);
  if (!config) return emptyInspection(input.artifact, ['psea:invalid_pinned_config']);
  const roots = parseRoots(input.trust_roots);
  if (!roots) return emptyInspection(input.artifact, ['psea:invalid_pinned_trust_roots']);
  if (!isRecord(input.artifact) || !onlyKnownKeys(input.artifact, ARTIFACT_KEYS)
      || !Object.hasOwn(input.artifact, 'proof')
      || !Object.hasOwn(input.artifact, 'actionPayload')
      || typeof input.artifact.proof !== 'string') {
    return emptyInspection(input.artifact, ['psea:malformed_artifact']);
  }
  let actionCanonical: string;
  try { actionCanonical = canonicalizePsea(input.artifact.actionPayload); }
  catch { return emptyInspection(input.artifact, ['psea:action_not_i_json']); }
  const parsed = parseJws(input.artifact.proof);
  if (!parsed) return emptyInspection(input.artifact, ['psea:malformed_or_noncanonical_jws']);
  const root = roots.get(parsed.kid);
  if (!root) return emptyInspection(input.artifact, ['psea:unknown_enrolled_key']);
  const key = crypto.createPublicKey({
    key: Buffer.from(root.public_key_spki, 'base64url'), format: 'der', type: 'spki',
  });
  const signatureValid = crypto.verify(
    'sha256', parsed.signingInput, { key, dsaEncoding: 'ieee-p1363' }, parsed.signature,
  );
  if (!signatureValid) return emptyInspection(input.artifact, ['psea:signature_invalid']);
  const claims = parseClaims(parsed.payload);
  if (!claims) return emptyInspection(input.artifact, ['psea:claim_set_invalid']);
  const reasons: string[] = [];
  if (claims.iss !== config.issuer || root.issuer !== config.issuer) reasons.push('psea:issuer_mismatch');
  if (claims.aud !== config.audience) reasons.push('psea:audience_mismatch');
  if (claims.psea_op !== config.operation) reasons.push('psea:operation_mismatch');
  if (claims.psea_tier !== config.tier) reasons.push('psea:tier_mismatch');
  if (claims.ueid !== root.ueid) reasons.push('psea:ueid_mismatch');
  if (root.subject_native_id !== config.subject.native_id) reasons.push('psea:subject_enrollment_mismatch');
  if (root.enrollment_status !== 'active') reasons.push('psea:enrollment_revoked');
  if (!config.required_attestation_statuses.includes(root.attestation_status)) {
    reasons.push('psea:inadequate_attestation');
  }
  if (config.expected_nonce !== null && claims.eat_nonce !== config.expected_nonce) {
    reasons.push('psea:nonce_mismatch');
  }
  const nowSeconds = Math.floor(Date.parse(input.now) / 1000);
  if (!Number.isSafeInteger(nowSeconds)) reasons.push('psea:invalid_verification_time');
  else {
    if (claims.iat > nowSeconds + config.max_clock_skew_seconds) reasons.push('psea:issued_in_future');
    if (claims.exp < nowSeconds - config.max_clock_skew_seconds) reasons.push('psea:proof_expired');
    if (claims.exp - claims.iat > config.max_token_lifetime_seconds) reasons.push('psea:lifetime_exceeded');
  }
  const expectedPayloadHash = crypto.createHash('sha256')
    .update(actionCanonical, 'utf8').digest('base64');
  if (claims.psea_payload_hash !== expectedPayloadHash) reasons.push('psea:action_hash_mismatch');
  if (input.replay_snapshot) {
    const seen = input.replay_snapshot.seen_jtis instanceof Set
      ? input.replay_snapshot.seen_jtis
      : new Set(input.replay_snapshot.seen_jtis);
    if (seen.has(claims.jti)) reasons.push('psea:jti_replay');
    if (input.replay_snapshot.highest_counter !== null
        && claims.psea_counter <= input.replay_snapshot.highest_counter) {
      reasons.push('psea:counter_rollback');
    }
  }
  const proofDigest = digestBytes(Buffer.from(input.artifact.proof, 'utf8'));
  const actionDigest = digestBytes(Buffer.from(actionCanonical, 'utf8'));
  const replayUnit = safeDigest({
    source_revision: PSEA_SOURCE_REVISION,
    issuer: claims.iss,
    ueid: claims.ueid,
    counter_scope: root.counter_scope,
    counter: claims.psea_counter,
    jti: claims.jti,
  });
  return {
    verified: reasons.length === 0,
    reasons: [...new Set(reasons)].sort(),
    proof_digest: proofDigest,
    action_digest: actionDigest,
    claims,
    root,
    replay_candidate: {
      scope: root.counter_scope,
      counter: claims.psea_counter,
      jti: claims.jti,
      replay_unit: replayUnit,
    },
  };
}

/** Verify and atomically finalize counter+jti before Gate admission. */
export async function verifyAndCommitPseaProof(input: {
  artifact: unknown;
  config: unknown;
  trust_roots: readonly unknown[];
  now: string;
  replay_store: PseaReplayStore;
}): Promise<PseaCommittedVerification> {
  const config = parseConfig(input.config);
  const roots = parseRoots(input.trust_roots);
  if (!config || !roots || !isRecord(input.artifact) || typeof input.artifact.proof !== 'string') {
    return { ...inspectPseaProof(input), replay_committed: false };
  }
  const preliminary = parseJws(input.artifact.proof);
  const root = preliminary ? roots.get(preliminary.kid) : null;
  if (!root) return { ...inspectPseaProof(input), replay_committed: false };
  const snapshot = await input.replay_store.inspect(root.counter_scope);
  const inspected = inspectPseaProof({ ...input, replay_snapshot: snapshot });
  if (!inspected.verified || !inspected.replay_candidate) {
    return { ...inspected, replay_committed: false };
  }
  const committed = await input.replay_store.commit(inspected.replay_candidate);
  if (!committed.committed) {
    return {
      ...inspected,
      verified: false,
      reasons: [`psea:${committed.reason}`],
      replay_committed: false,
    };
  }
  return { ...inspected, replay_committed: true };
}

/** Reference only. Production must use a durable transaction/fence. */
export class InMemoryPseaReplayStore implements PseaReplayStore {
  private readonly counters = new Map<string, number>();
  private readonly jtis = new Set<string>();

  async inspect(scope: string): Promise<PseaReplaySnapshot> {
    return { highest_counter: this.counters.get(scope) ?? null, seen_jtis: new Set(this.jtis) };
  }

  async commit(candidate: PseaReplayCandidate): Promise<PseaReplayCommitResult> {
    if (this.jtis.has(candidate.jti)) return { committed: false, reason: 'jti_replay' };
    const current = this.counters.get(candidate.scope);
    if (current !== undefined && candidate.counter <= current) {
      return { committed: false, reason: 'counter_rollback' };
    }
    this.jtis.add(candidate.jti);
    this.counters.set(candidate.scope, candidate.counter);
    return { committed: true };
  }
}

function fallbackNative(input: Omit<AebAdapterInput, 'profile'>, reason: string): AebNativeResult {
  const config = parseConfig(input.adapter_config);
  return {
    native_verification: 'FAILED',
    acceptance: 'INDETERMINATE',
    evidence_digest: isRecord(input.artifact) && typeof input.artifact.proof === 'string'
      ? digestBytes(Buffer.from(input.artifact.proof, 'utf8')) : safeDigest(input.artifact),
    status_digest: safeDigest(input.status),
    evidence_role: config?.evidence_role ?? 'human_authorization',
    subject: config ? { id: config.subject.id, kind: 'human' } : { id: 'unknown', kind: 'human' },
    replay_unit: safeDigest({ source_revision: PSEA_SOURCE_REVISION, artifact: input.artifact_ref }),
    reasons: [reason],
  };
}

function validMappingProfile(profile: AebAdapterInput['profile'], actionType: string): Obj | null {
  if (profile.version !== PSEA_AEB_CAID_MAPPING_VERSION
      || profile.mapper_id !== PSEA_AEB_CAID_MAPPER_ID
      || !isRecord(profile.definition)
      || profile.definition['@version'] !== PSEA_AEB_CAID_MAPPING_VERSION
      || profile.definition.native_protocol !== PSEA_SOURCE_REVISION
      || profile.definition.projection !== 'add-action-type-v1'
      || profile.definition.suite !== 'jcs-sha256'
      || profile.definition.action_type !== actionType
      || !Array.isArray(profile.definition.definitions)
      || profile.resolver.id !== PSEA_AEB_CAID_MAPPER_ID
      || profile.resolver.version !== '1'
      || profile.semantic_equivalence.assertion !== 'EQUIVALENT_UNDER_PROFILE'
      || profile.semantic_equivalence.loss_policy !== 'NO_MATERIAL_FIELD_LOSS'
      || profile.semantic_equivalence.omitted_material_fields.length !== 0) return null;
  return profile.definition;
}

/** Pure PSEA-to-AEB adapter. Gate must consume replay_unit atomically. */
export function createPseaAebAdapter(): AebAdapter {
  return Object.freeze({
    id: PSEA_AEB_ADAPTER_ID,
    version: PSEA_AEB_ADAPTER_VERSION,
    verifyNative(input: Omit<AebAdapterInput, 'profile'>): AebNativeResult {
      try {
        const config = parseConfig(input.adapter_config);
        if (!config) return fallbackNative(input, 'psea:invalid_pinned_config');
        const inspected = inspectPseaProof({
          artifact: input.artifact,
          config,
          trust_roots: input.trust_roots,
          now: input.now,
        });
        const base: AebNativeResult = {
          native_verification: inspected.verified ? 'VERIFIED' : 'FAILED',
          acceptance: inspected.verified ? 'ACCEPTED' : 'REJECTED',
          evidence_digest: inspected.proof_digest,
          status_digest: safeDigest(input.status),
          evidence_role: config.evidence_role,
          subject: { id: config.subject.id, kind: 'human' },
          replay_unit: inspected.replay_candidate?.replay_unit
            ?? safeDigest({ source_revision: PSEA_SOURCE_REVISION, artifact: input.artifact_ref }),
          reasons: inspected.reasons,
        };
        if (!inspected.verified) return base;
        const status = inspectStatus(input.status, input.now, config.max_status_age_seconds);
        base.acceptance = status.acceptance;
        base.reasons = status.reasons;
        return base;
      } catch { return fallbackNative(input, 'psea:unexpected_adapter_error'); }
    },
    mapAction(input: AebAdapterInput & { native: AebNativeResult }): AebMappingResult {
      try {
        if (input.native.native_verification !== 'VERIFIED'
            || input.native.acceptance !== 'ACCEPTED') {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_acceptance_required'] };
        }
        const config = parseConfig(input.adapter_config);
        if (!config) return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_pinned_config_invalid'] };
        const definition = validMappingProfile(input.profile, config.action_type);
        if (!definition) return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['mapping_profile_invalid'] };
        if (!isRecord(input.artifact) || !isRecord(input.artifact.actionPayload)
            || Object.hasOwn(input.artifact.actionPayload, 'action_type')) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['native_action_not_exactly_projectable'] };
        }
        const normalized = { action_type: config.action_type, ...input.artifact.actionPayload };
        const actionDigest = safeDigest(normalized);
        if (actionDigest !== safeDigest(input.expected_action)) {
          return { mapping: 'MISMATCH', caid: null, action_digest: actionDigest, reasons: ['normalized_native_action_mismatch'] };
        }
        const computed = computeCaid(normalized, {
          suite: 'jcs-sha256', definitions: definition.definitions,
        });
        if (!isRecord(computed) || typeof computed.caid !== 'string'
            || typeof computed.digest !== 'string' || !DIGEST_RE.test(computed.digest)) {
          const refusals = isRecord(computed) && Array.isArray(computed.refusals)
            ? computed.refusals.map(String) : ['caid_mapping_failed'];
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: refusals.map((item) => `caid:${item}`) };
        }
        if (computed.digest !== actionDigest) {
          return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['caid_digest_disagreement'] };
        }
        return { mapping: 'MATCH', caid: computed.caid, action_digest: actionDigest, reasons: [] };
      } catch {
        return { mapping: 'INDETERMINATE', caid: null, action_digest: null, reasons: ['psea:unexpected_mapping_error'] };
      }
    },
  });
}

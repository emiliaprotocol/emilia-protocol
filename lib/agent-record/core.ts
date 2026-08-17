// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { canonicalize } from '@/lib/canonical-json';
import { getAgentRecordSigningConfig, isAgentRecordSigningKeyId } from '@/lib/env';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
  type AgileSignature,
  type AgileVerificationKey,
} from '../../packages/verify/pq-signature-agility.js';

export const AGENT_RECORD_VERSION = 'EP-AGENT-RECORD-OBSERVATION-v1' as const;
export const AGENT_RECORD_RETENTION_MS = 365 * 24 * 60 * 60 * 1_000;
export const AGENT_RECORD_CLAIM_BOUNDARY =
  'one_operator_observation_of_one_verified_signed_refusal_artifact_only' as const;

const SIGNING_DOMAIN = `${AGENT_RECORD_VERSION}\0`;
const RECORD_ID = /^agent_record_[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function isCanonicalSignature(value: unknown): value is string {
  if (typeof value !== 'string' || !SIGNATURE.test(value)) return false;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === 64 && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

export type AgentRecordObservationInput = Readonly<{
  recordId: string;
  bondId: string;
  bondDigest: string;
  sourceArtifactDigest: string;
  actionDigest: string;
  refusalDigest: string;
  refusedAt: string;
  observedAt: string;
  retentionExpiresAt: string;
}>;

export type AgentRecordObservation = Readonly<{
  '@version': typeof AGENT_RECORD_VERSION;
  record: Readonly<{
    record_id: string;
    bond: Readonly<{ bond_id: string; bond_digest: string }>;
    source: Readonly<{
      profile: 'EP-ACTION-REFUSAL-STATEMENT-v1';
      artifact_digest: string;
    }>;
    action: Readonly<{ action_digest: string }>;
    refusal: Readonly<{ refusal_digest: string; refused_at: string }>;
    observed_at: string;
    retention_expires_at: string;
    claim_boundary: typeof AGENT_RECORD_CLAIM_BOUNDARY;
  }>;
  signature: Readonly<{
    algorithm: 'Ed25519';
    key_id: string;
    key_source: 'operator-commit-signing-key';
    value: string;
  }>;
}>;

export class AgentRecordCoreError extends Error {
  constructor(public code: string, message = code, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AgentRecordCoreError';
  }
}

function fail(code: string, message = code, cause?: unknown): never {
  throw new AgentRecordCoreError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function isRecord(value: unknown): value is Record<string, any> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null)
    && Reflect.ownKeys(value).every((key) => typeof key === 'string');
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, any> {
  return isRecord(value)
    && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function instant(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) return null;
  return parsed;
}

function derivePrivateKey(seedValue: string): crypto.KeyObject {
  const seed = Buffer.from(seedValue, 'base64');
  if (seed.length !== 32) {
    fail(
      'agent_record_operator_key_invalid',
      'EP_COMMIT_SIGNING_KEY must be a base64-encoded 32-byte Ed25519 seed.',
    );
  }
  try {
    return crypto.createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]),
      format: 'der',
      type: 'pkcs8',
    });
  } catch (cause) {
    fail('agent_record_operator_key_invalid', 'The operator signing key is invalid.', cause);
  }
}

function publicKeyFromRaw(value: string): crypto.KeyObject | null {
  try {
    const raw = Buffer.from(value, 'base64');
    if (raw.length !== 32) return null;
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_DER_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}

type AgentRecordKeypair = Readonly<{
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
}>;

let developmentKeypair: AgentRecordKeypair | null = null;

function developmentKeys(): AgentRecordKeypair {
  developmentKeypair ??= crypto.generateKeyPairSync('ed25519');
  return developmentKeypair;
}

function signingConfig(): ReturnType<typeof getAgentRecordSigningConfig> {
  try {
    return getAgentRecordSigningConfig();
  } catch (cause) {
    if ((cause as { code?: unknown })?.code !== 'agent_record_operator_key_id_invalid') {
      throw cause;
    }
    fail(
      'agent_record_operator_key_id_invalid',
      'The current Agent Record signing key id is invalid.',
      cause,
    );
  }
}

function configuredSigner(): Readonly<{ keyId: string; privateKey: crypto.KeyObject }> {
  const config = signingConfig();
  if (config.signingKey) {
    return {
      keyId: config.signingKeyId,
      privateKey: derivePrivateKey(config.signingKey),
    };
  }
  if (config.isProduction) {
    fail(
      'agent_record_operator_key_unavailable',
      'A stable operator commit signing key is required for Agent Record creation.',
    );
  }
  return { keyId: config.signingKeyId, privateKey: developmentKeys().privateKey };
}

function configuredPublicKey(keyId: unknown): crypto.KeyObject | null {
  if (!isAgentRecordSigningKeyId(keyId)) return null;
  const config = signingConfig();
  if (keyId === config.signingKeyId && config.signingKey) {
    return crypto.createPublicKey(
      derivePrivateKey(config.signingKey) as unknown as crypto.PublicKeyInput,
    );
  }
  const trusted = config.trustedKeys?.[keyId];
  if (trusted) return publicKeyFromRaw(trusted);
  if (!config.isProduction && keyId === config.signingKeyId && !config.signingKey) {
    return developmentKeys().publicKey;
  }
  return null;
}

function signingBytes(record: unknown): Buffer {
  return Buffer.from(`${SIGNING_DOMAIN}${canonicalize(record)}`, 'utf8');
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function validInput(value: AgentRecordObservationInput): boolean {
  const refusedAt = instant(value.refusedAt);
  const observedAt = instant(value.observedAt);
  const retentionExpiresAt = instant(value.retentionExpiresAt);
  return RECORD_ID.test(value.recordId)
    && UUID.test(value.bondId)
    && DIGEST.test(value.bondDigest)
    && DIGEST.test(value.sourceArtifactDigest)
    && DIGEST.test(value.actionDigest)
    && DIGEST.test(value.refusalDigest)
    && value.sourceArtifactDigest === value.refusalDigest
    && refusedAt !== null
    && observedAt !== null
    && retentionExpiresAt !== null
    && refusedAt <= observedAt
    && retentionExpiresAt - observedAt === AGENT_RECORD_RETENTION_MS;
}

export function signAgentRecordObservation(
  input: AgentRecordObservationInput,
): AgentRecordObservation {
  if (!validInput(input)) {
    fail('agent_record_observation_input_invalid', 'Agent Record bindings are invalid.');
  }
  const record: AgentRecordObservation['record'] = {
    record_id: input.recordId,
    bond: { bond_id: input.bondId, bond_digest: input.bondDigest },
    source: {
      profile: 'EP-ACTION-REFUSAL-STATEMENT-v1',
      artifact_digest: input.sourceArtifactDigest,
    },
    action: { action_digest: input.actionDigest },
    refusal: { refusal_digest: input.refusalDigest, refused_at: input.refusedAt },
    observed_at: input.observedAt,
    retention_expires_at: input.retentionExpiresAt,
    claim_boundary: AGENT_RECORD_CLAIM_BOUNDARY,
  };
  const signer = configuredSigner();
  const value = crypto.sign(null, signingBytes(record), signer.privateKey).toString('base64url');
  if (!isCanonicalSignature(value)) {
    fail('agent_record_operator_signature_invalid', 'The operator signature is invalid.');
  }
  return deepFreeze({
    '@version': AGENT_RECORD_VERSION,
    record,
    signature: {
      algorithm: 'Ed25519',
      key_id: signer.keyId,
      key_source: 'operator-commit-signing-key',
      value,
    },
  });
}

function structurallyValid(value: unknown): value is AgentRecordObservation {
  if (!exactKeys(value, ['@version', 'record', 'signature'])
      || value['@version'] !== AGENT_RECORD_VERSION
      || !exactKeys(value.record, [
        'record_id',
        'bond',
        'source',
        'action',
        'refusal',
        'observed_at',
        'retention_expires_at',
        'claim_boundary',
      ])
      || !exactKeys(value.record.bond, ['bond_id', 'bond_digest'])
      || !exactKeys(value.record.source, ['profile', 'artifact_digest'])
      || !exactKeys(value.record.action, ['action_digest'])
      || !exactKeys(value.record.refusal, ['refusal_digest', 'refused_at'])
      || !exactKeys(value.signature, ['algorithm', 'key_id', 'key_source', 'value'])) {
    return false;
  }
  const record = value.record;
  return value.signature.algorithm === 'Ed25519'
    && isAgentRecordSigningKeyId(value.signature.key_id)
    && value.signature.key_source === 'operator-commit-signing-key'
    && isCanonicalSignature(value.signature.value)
    && record.source.profile === 'EP-ACTION-REFUSAL-STATEMENT-v1'
    && record.claim_boundary === AGENT_RECORD_CLAIM_BOUNDARY
    && validInput({
      recordId: record.record_id,
      bondId: record.bond.bond_id,
      bondDigest: record.bond.bond_digest,
      sourceArtifactDigest: record.source.artifact_digest,
      actionDigest: record.action.action_digest,
      refusalDigest: record.refusal.refusal_digest,
      refusedAt: record.refusal.refused_at,
      observedAt: record.observed_at,
      retentionExpiresAt: record.retention_expires_at,
    });
}

function refused(reason: string) {
  return Object.freeze({
    verified: false as const,
    within_retention: false,
    status_checked: false as const,
    reason,
    record_id: null,
  });
}

export function verifyAgentRecordObservation(value: unknown, now = Date.now()) {
  try {
    if (!structurallyValid(value)) return refused('agent_record_observation_invalid');
    const publicKey = configuredPublicKey(value.signature.key_id);
    if (!publicKey) return refused('agent_record_operator_key_unavailable');
    const valid = crypto.verify(
      null,
      signingBytes(value.record),
      publicKey,
      Buffer.from(value.signature.value, 'base64url'),
    );
    if (!valid) return refused('agent_record_signature_invalid');
    const observedAt = Date.parse(value.record.observed_at);
    const retentionExpiresAt = Date.parse(value.record.retention_expires_at);
    if (!Number.isFinite(now) || now < observedAt) {
      return Object.freeze({
        verified: true as const,
        within_retention: false,
        status_checked: false as const,
        reason: 'agent_record_not_yet_observed',
        record_id: value.record.record_id,
      });
    }
    if (now >= retentionExpiresAt) {
      return Object.freeze({
        verified: true as const,
        within_retention: false,
        status_checked: false as const,
        reason: 'agent_record_expired',
        record_id: value.record.record_id,
      });
    }
    return Object.freeze({
      verified: true as const,
      within_retention: true,
      status_checked: false as const,
      reason: null,
      record_id: value.record.record_id,
    });
  } catch {
    return refused('agent_record_observation_invalid');
  }
}

// ===========================================================================
// EP-AGENT-RECORD-OBSERVATION-v2 -- the hybrid (Ed25519 + ML-DSA-65) record
// ===========================================================================
/**
 * HYBRID MIGRATION following the reference pattern in
 * docs/protocol/pq-hybrid-program.md ("PATTERN: the reference hybrid
 * migration") and packages/verify/src/revocation.ts's EP-REVOCATION-v2. Five
 * moves, in order: (1) VERSION BUMP, not a field bump — a second signature
 * changes the SHAPE of the proof, so the record takes a new `@version`
 * (EP-AGENT-RECORD-OBSERVATION-v1 -> -v2), the v1 verifier above is untouched
 * and refuses a v2 record on the version marker before inspecting any
 * signature; (2) SET SHAPE — `proof.signatures` is the EP-SIG-AGILITY-v1
 * AgileSignature array ({ alg, sig, key_id? }), one entry per algorithm in the
 * registered order; (3) ANTI-STRIPPING BYTES — the required algorithm set is
 * inside the signed bytes (agentRecordV2SignedPayload), rebuilt by the verifier
 * from the REGISTERED set, so a narrowed set breaks the surviving signature;
 * (4) V1 COMPATIBILITY — the v1 sync verifier is unchanged; v2 verification is
 * ASYNC (ML-DSA is async) and is a SEPARATE entry point; (5) NAMED REFUSALS —
 * every failure names a check and pushes a reason, nothing throws on caller
 * input, and an absent ML-DSA backend is a refusal, never a pass on the
 * classical leg.
 *
 * TRUST MODEL PRESERVED. The Ed25519 operator key is pinned exactly as v1 pins
 * it (resolved from the operator signing config by key_id — identified but not
 * trusted); the ML-DSA-65 half is pinned out of band by the relying party
 * through opts.pqPublicKeys, because the operator config carries no PQ key.
 *
 * HONEST BOUNDARY. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, which is not independently audited and is not a FIPS
 * validated module; v2 does not retroactively protect records signed under v1.
 */

export const AGENT_RECORD_V2_VERSION = 'EP-AGENT-RECORD-OBSERVATION-v2' as const;
export const AGENT_RECORD_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const AGENT_RECORD_PQ_KEY_ID = /^ep:agent-record-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;

export type AgentRecordObservationV2 = Readonly<{
  '@version': typeof AGENT_RECORD_V2_VERSION;
  record: AgentRecordObservation['record'];
  proof: Readonly<{
    profile: typeof AGENT_RECORD_V2_VERSION;
    required_algorithms: string[];
    key_id: string;
    key_source: 'operator-commit-signing-key';
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    pq_key_id: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
    signatures: AgileSignature[];
  }>;
}>;

export interface SignAgentRecordObservationV2PqSigner {
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  secretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  publicKey: Uint8Array | string;
}

export interface VerifyAgentRecordObservationV2Options extends AgilityOptions {
  now?: number;
  /** pq_key_id -> base64url raw ML-DSA-65 public key, pinned out of band. */
  pqPublicKeys?: Record<string, string>;
}

function algorithmSetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === AGENT_RECORD_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === AGENT_RECORD_V2_REQUIRED_ALGORITHMS[i]);
}

function edSpkiB64u(key: crypto.KeyObject): string {
  const pub = key.type === 'public' ? key : crypto.createPublicKey(key as unknown as crypto.PublicKeyInput);
  return pub.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function pqKeyIdOf(rawB64u: string): string {
  return `ep:agent-record-key:ml-dsa-65:sha256:${crypto
    .createHash('sha256').update(Buffer.from(rawB64u, 'base64url')).digest('hex')}`;
}

function pqRawB64u(value: Uint8Array | string, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
  if (bytes.length !== expectedLength) {
    fail('agent_record_pq_key_invalid', `${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

function recordStructurallyValid(record: unknown): record is AgentRecordObservation['record'] {
  if (!exactKeys(record, [
    'record_id', 'bond', 'source', 'action', 'refusal',
    'observed_at', 'retention_expires_at', 'claim_boundary',
  ])
    || !exactKeys(record.bond, ['bond_id', 'bond_digest'])
    || !exactKeys(record.source, ['profile', 'artifact_digest'])
    || !exactKeys(record.action, ['action_digest'])
    || !exactKeys(record.refusal, ['refusal_digest', 'refused_at'])) {
    return false;
  }
  return record.source.profile === 'EP-ACTION-REFUSAL-STATEMENT-v1'
    && record.claim_boundary === AGENT_RECORD_CLAIM_BOUNDARY
    && validInput({
      recordId: record.record_id,
      bondId: record.bond.bond_id,
      bondDigest: record.bond.bond_digest,
      sourceArtifactDigest: record.source.artifact_digest,
      actionDigest: record.action.action_digest,
      refusalDigest: record.refusal.refusal_digest,
      refusedAt: record.refusal.refused_at,
      observedAt: record.observed_at,
      retentionExpiresAt: record.retention_expires_at,
    });
}

/**
 * The bytes BOTH legs sign: the v2 version marker, the record, and the required
 * algorithm set. Recomputed independently by the verifier from the PRESENTED
 * record and the REGISTERED set. canonicalize() sorts keys.
 */
export function agentRecordV2SignedPayload(
  record: unknown,
  requiredAlgorithms: readonly string[] = AGENT_RECORD_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
    fail('agent_record_v2_algorithm_set_invalid', 'algorithm set is not the registered EP-AGENT-RECORD-OBSERVATION-v2 set');
  }
  return Buffer.from(canonicalize({
    '@version': AGENT_RECORD_V2_VERSION,
    record,
    required_algorithms: [...requiredAlgorithms],
  }), 'utf8');
}

/**
 * signAgentRecordObservationV2 — mint a hybrid observation. The Ed25519 leg uses
 * the configured operator signing key (same custody boundary as v1); the ML-DSA
 * leg uses the caller-supplied PQ signer, because the operator config carries no
 * PQ key. THROWS on issuer-side misuse or an unavailable ML-DSA backend, so a
 * half-hybrid record is never produced.
 */
export async function signAgentRecordObservationV2(
  input: AgentRecordObservationInput,
  pqSigner: SignAgentRecordObservationV2PqSigner,
  opts: { deterministic?: boolean } = {},
): Promise<AgentRecordObservationV2> {
  if (!validInput(input)) {
    fail('agent_record_observation_input_invalid', 'Agent Record bindings are invalid.');
  }
  if (!pqSigner || !pqSigner.secretKey || !pqSigner.publicKey) {
    fail('agent_record_pq_key_invalid', 'signAgentRecordObservationV2 requires pqSigner.{secretKey,publicKey}');
  }
  const record: AgentRecordObservation['record'] = {
    record_id: input.recordId,
    bond: { bond_id: input.bondId, bond_digest: input.bondDigest },
    source: {
      profile: 'EP-ACTION-REFUSAL-STATEMENT-v1',
      artifact_digest: input.sourceArtifactDigest,
    },
    action: { action_digest: input.actionDigest },
    refusal: { refusal_digest: input.refusalDigest, refused_at: input.refusedAt },
    observed_at: input.observedAt,
    retention_expires_at: input.retentionExpiresAt,
    claim_boundary: AGENT_RECORD_CLAIM_BOUNDARY,
  };
  const signer = configuredSigner();
  const edPublic = edSpkiB64u(signer.privateKey);
  const pqPublic = pqRawB64u(pqSigner.publicKey, ML_DSA_65_PUBLIC_KEY_BYTES, 'pqSigner.publicKey');
  const pqSecret = pqRawB64u(pqSigner.secretKey, ML_DSA_65_SECRET_KEY_BYTES, 'pqSigner.secretKey');
  const pqKeyId = pqKeyIdOf(pqPublic);

  const messageBytes = agentRecordV2SignedPayload(record, AGENT_RECORD_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(
    new Uint8Array(messageBytes),
    [
      { alg: 'Ed25519', private_key: signer.privateKey, key_id: signer.keyId },
      { alg: 'ML-DSA-65', private_key: pqSecret, key_id: pqKeyId },
    ],
    opts.deterministic === true ? { deterministic: true } : {},
  );
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered = AGENT_RECORD_V2_REQUIRED_ALGORITHMS.map((alg) => {
    const s = byAlg.get(alg);
    if (!s) fail('agent_record_v2_signing_incomplete', `signing produced no ${alg} leg`);
    return s;
  });

  return deepFreeze({
    '@version': AGENT_RECORD_V2_VERSION,
    record,
    proof: {
      profile: AGENT_RECORD_V2_VERSION,
      required_algorithms: [...AGENT_RECORD_V2_REQUIRED_ALGORITHMS],
      key_id: signer.keyId,
      key_source: 'operator-commit-signing-key',
      public_key: edPublic,
      pq_key_id: pqKeyId,
      pq_public_key: pqPublic,
      signatures: ordered,
    },
  });
}

function refusedV2(reason: string, checks: Record<string, boolean>, recordId: string | null = null) {
  return Object.freeze({
    verified: false as const,
    within_retention: false,
    status_checked: false as const,
    reason,
    record_id: recordId,
    checks,
  });
}

/**
 * verifyAgentRecordObservationV2 — FAIL-CLOSED hybrid observation check. Never
 * throws on caller input. A v2 record NEVER verifies on one leg alone.
 */
export async function verifyAgentRecordObservationV2(
  value: unknown,
  opts: VerifyAgentRecordObservationV2Options = {},
) {
  const checks: Record<string, boolean> = {
    version: true,
    structure: true,
    record_valid: true,
    algorithm_set: true,
    legs_present: true,
    operator_key_pinned: true,
    pq_key_pinned: true,
    key_bound: true,
    signature_valid: true,
  };
  const errors: string[] = [];
  const note = (key: string, msg: string) => { checks[key] = false; errors.push(msg); };
  const finish = (recordId: string | null = null) => (
    Object.values(checks).every(Boolean)
      ? null
      : refusedV2(errors[0] ?? 'agent_record_v2_invalid', checks, recordId)
  );

  try {
    opts = opts && typeof opts === 'object' ? opts : {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return refusedV2('agent_record_v2_invalid', { ...checks, structure: false });
    }
    const obs = value as Record<string, any>;

    if (obs['@version'] !== AGENT_RECORD_V2_VERSION) {
      note('version', `unsupported version: ${obs['@version']}`);
    }
    if (!exactKeys(obs, ['@version', 'record', 'proof'])) {
      note('structure', 'agent record must use the exact closed EP-AGENT-RECORD-OBSERVATION-v2 schema');
    }
    const proof = obs.proof;
    if (!exactKeys(proof, [
      'profile', 'required_algorithms', 'key_id', 'key_source',
      'public_key', 'pq_key_id', 'pq_public_key', 'signatures',
    ]) || proof.profile !== AGENT_RECORD_V2_VERSION
      || proof.key_source !== 'operator-commit-signing-key'
      || !isAgentRecordSigningKeyId(proof?.key_id)) {
      note('structure', 'agent record proof must use the exact closed EP-AGENT-RECORD-OBSERVATION-v2 schema');
    }

    if (!recordStructurallyValid(obs.record)) {
      note('record_valid', 'agent record body is structurally invalid');
    }
    const recordId = recordStructurallyValid(obs.record) ? obs.record.record_id : null;

    if (!algorithmSetMatchesRegistered(proof?.required_algorithms)) {
      note('algorithm_set',
        `proof.required_algorithms must be exactly ${JSON.stringify([...AGENT_RECORD_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }

    const signatures = Array.isArray(proof?.signatures) ? proof.signatures as AgileSignature[] : null;
    if (!signatures || signatures.length === 0) {
      note('legs_present', 'proof.signatures must carry one signature per required algorithm');
    } else {
      const presented = new Set<string>();
      let malformed = false;
      for (const s of signatures) {
        if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
          note('legs_present', 'each proof.signatures entry must be { alg, sig, key_id? }');
          malformed = true;
          break;
        }
        if (presented.has(s.alg)) {
          note('legs_present', `duplicate signature for algorithm "${s.alg}"`);
          malformed = true;
          break;
        }
        presented.add(s.alg);
      }
      if (!malformed) {
        for (const alg of AGENT_RECORD_V2_REQUIRED_ALGORITHMS) {
          if (!presented.has(alg)) note('legs_present', `missing required ${alg} signature (leg stripped)`);
        }
        for (const alg of presented) {
          if (!(AGENT_RECORD_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
            note('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
          }
        }
      }
    }

    // Ed25519 operator key: pinned by the operator config (identified but not
    // trusted), and the presented SPKI must equal the configured key's SPKI.
    const configKey = configuredPublicKey(proof?.key_id);
    const presentedEd = typeof proof?.public_key === 'string' ? proof.public_key : '';
    if (!configKey) {
      note('operator_key_pinned', 'agent_record_operator_key_unavailable');
    } else if (!presentedEd || edSpkiB64u(configKey) !== presentedEd) {
      note('operator_key_pinned', 'presented operator key != configured operator key (key substitution)');
    }

    // ML-DSA-65 key: pinned out of band via opts.pqPublicKeys, and the
    // presented raw key must equal the pinned one for its derived id.
    const presentedPq = typeof proof?.pq_public_key === 'string' ? proof.pq_public_key : '';
    const derivedPqKeyId = presentedPq
      && Buffer.from(presentedPq, 'base64url').length === ML_DSA_65_PUBLIC_KEY_BYTES
      && Buffer.from(presentedPq, 'base64url').toString('base64url') === presentedPq
      ? pqKeyIdOf(presentedPq) : '';
    const pinnedPq = derivedPqKeyId ? opts.pqPublicKeys?.[proof.pq_key_id] : undefined;
    if (!derivedPqKeyId || proof?.pq_key_id !== derivedPqKeyId
      || !AGENT_RECORD_PQ_KEY_ID.test(typeof proof?.pq_key_id === 'string' ? proof.pq_key_id : '')) {
      note('key_bound', 'pq_key_id must be the full digest of the presented ML-DSA-65 key');
    }
    if (!pinnedPq) {
      note('pq_key_pinned', `no pinned ML-DSA-65 key for "${proof?.pq_key_id}" (identified but not trusted)`);
    } else if (pinnedPq !== presentedPq) {
      note('pq_key_pinned', 'presented ML-DSA-65 key != pinned key (key substitution)');
    }

    // Signature set: both legs over bytes rebuilt from the PRESENTED record and
    // the REGISTERED set, under the PINNED keys only.
    let recomputedBytes: Buffer | null = null;
    try {
      recomputedBytes = agentRecordV2SignedPayload(obs.record, AGENT_RECORD_V2_REQUIRED_ALGORITHMS);
    } catch {
      recomputedBytes = null;
    }
    if (!recomputedBytes) {
      note('signature_valid', 'agent record body is not canonicalizable');
      return finish(recordId);
    }
    const verificationKeys: AgileVerificationKey[] = [
      { alg: 'Ed25519', public_key: configKey ?? '', key_id: isAgentRecordSigningKeyId(proof?.key_id) ? proof.key_id : undefined },
      { alg: 'ML-DSA-65', public_key: pinnedPq ?? '', key_id: derivedPqKeyId || undefined },
    ];
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(recomputedBytes),
        signatures ?? [],
        verificationKeys,
        {
          ...agilityPassthrough(opts),
          policy: 'hybrid_all',
          requiredAlgorithms: [...AGENT_RECORD_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      setResult = null;
    }
    if (setResult?.verified !== true) {
      const reason = String(setResult?.reason ?? 'signature_set_unverified');
      note('signature_valid',
        `operator signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
    }

    const refusal = finish(recordId);
    if (refusal) return refusal;

    // All gating checks passed: apply the same retention window semantics as v1.
    const now = typeof opts.now === 'number' ? opts.now : Date.now();
    const observedAt = Date.parse(obs.record.observed_at);
    const retentionExpiresAt = Date.parse(obs.record.retention_expires_at);
    if (!Number.isFinite(now) || now < observedAt) {
      return Object.freeze({
        verified: true as const,
        within_retention: false,
        status_checked: false as const,
        reason: 'agent_record_not_yet_observed',
        record_id: recordId,
        checks,
      });
    }
    if (now >= retentionExpiresAt) {
      return Object.freeze({
        verified: true as const,
        within_retention: false,
        status_checked: false as const,
        reason: 'agent_record_expired',
        record_id: recordId,
        checks,
      });
    }
    return Object.freeze({
      verified: true as const,
      within_retention: true,
      status_checked: false as const,
      reason: null,
      record_id: recordId,
      checks,
    });
  } catch {
    return refusedV2('agent_record_v2_invalid', { ...checks, structure: false });
  }
}

function agilityPassthrough(opts: VerifyAgentRecordObservationV2Options): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

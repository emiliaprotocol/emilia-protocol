// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { canonicalize } from '@/lib/canonical-json';
import { getAgentRecordSigningConfig, isAgentRecordSigningKeyId } from '@/lib/env';

export const AGENT_RECORD_VERSION = 'EP-AGENT-RECORD-OBSERVATION-v1' as const;
export const AGENT_RECORD_RETENTION_MS = 365 * 24 * 60 * 60 * 1_000;
export const AGENT_RECORD_CLAIM_BOUNDARY =
  'one_operator_observation_of_one_verified_signed_arena_refusal_only' as const;

const SIGNING_DOMAIN = `${AGENT_RECORD_VERSION}\0`;
const RECORD_ID = /^agent_record_[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ARENA_SHARE_ID = /^arena_share_[0-9a-f]{40}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export type AgentRecordObservationInput = Readonly<{
  recordId: string;
  bondId: string;
  bondDigest: string;
  arenaShareId: string;
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
      arena_share_id: string;
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
    && ARENA_SHARE_ID.test(value.arenaShareId)
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
      arena_share_id: input.arenaShareId,
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
  if (!SIGNATURE.test(value)) {
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
      || !exactKeys(value.record.source, ['profile', 'arena_share_id', 'artifact_digest'])
      || !exactKeys(value.record.action, ['action_digest'])
      || !exactKeys(value.record.refusal, ['refusal_digest', 'refused_at'])
      || !exactKeys(value.signature, ['algorithm', 'key_id', 'key_source', 'value'])) {
    return false;
  }
  const record = value.record;
  return value.signature.algorithm === 'Ed25519'
    && isAgentRecordSigningKeyId(value.signature.key_id)
    && value.signature.key_source === 'operator-commit-signing-key'
    && SIGNATURE.test(value.signature.value)
    && record.source.profile === 'EP-ACTION-REFUSAL-STATEMENT-v1'
    && record.claim_boundary === AGENT_RECORD_CLAIM_BOUNDARY
    && validInput({
      recordId: record.record_id,
      bondId: record.bond.bond_id,
      bondDigest: record.bond.bond_digest,
      arenaShareId: record.source.arena_share_id,
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

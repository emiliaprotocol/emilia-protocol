// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';

export type RiskRecord = Record<string, any>;
export type TrustedRiskKeys = Record<string, { issuer_id: string; public_key: string }>;

export const RISK_DIGEST = /^sha256:[0-9a-f]{64}$/;
export const RISK_CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
export const RISK_ID = /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

export function riskRecord(value: unknown): value is RiskRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

export function riskExact(value: unknown, keys: readonly string[]): value is RiskRecord {
  return riskRecord(value) && Reflect.ownKeys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

export function riskIdentifier(value: unknown): value is string {
  return typeof value === 'string' && RISK_ID.test(value);
}

export function riskInstant(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339);
  if (!match) return NaN;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return NaN;
  return new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19) ? parsed : NaN;
}

export function riskDigest(value: unknown): string {
  return `sha256:${hashCanonical(value)}`;
}

export function riskClone<T>(value: T): T {
  return JSON.parse(canonicalize(value));
}

export function riskFreeze<T>(value: T): T {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as RiskRecord)) riskFreeze(child);
  return value;
}

function signingBytes(version: string, body: RiskRecord): Buffer {
  return Buffer.from(`${version}\0${canonicalize(body)}`, 'utf8');
}

export function signRiskBody(
  version: string,
  bodyInput: RiskRecord,
  signer: { issuer_id: string; key_id: string; private_key: crypto.KeyLike },
): RiskRecord {
  const key = signer.private_key instanceof crypto.KeyObject
    ? signer.private_key : crypto.createPrivateKey(signer.private_key);
  if (key.asymmetricKeyType !== 'ed25519') throw new TypeError('risk artifact signing key must be Ed25519');
  if (!riskIdentifier(signer.issuer_id) || !riskIdentifier(signer.key_id)) throw new TypeError('risk artifact issuer is invalid');
  const body = riskClone({ ...bodyInput, issuer: { id: signer.issuer_id, key_id: signer.key_id } });
  const bodyDigest = riskDigest(body);
  const proof = {
    algorithm: 'Ed25519',
    key_id: signer.key_id,
    body_digest: bodyDigest,
    signature_b64u: crypto.sign(null, signingBytes(version, body), key).toString('base64url'),
  };
  return riskFreeze({ ...body, proof });
}

export function verifyRiskBody(
  artifact: unknown,
  version: string,
  trustedKeys: TrustedRiskKeys | undefined,
): { valid: boolean; reason: string | null; body: RiskRecord | null; artifact_digest: string | null } {
  const refuse = (reason: string) => ({ valid: false, reason, body: null, artifact_digest: null });
  try {
    if (!riskRecord(artifact) || !riskRecord(artifact.proof) || !riskRecord(artifact.issuer)) return refuse('artifact_shape_invalid');
    const proof = artifact.proof;
    const { proof: _proof, ...body } = artifact;
    if (artifact['@version'] !== version || !riskExact(artifact.issuer, ['id', 'key_id'])
        || !riskIdentifier(artifact.issuer.id) || !riskIdentifier(artifact.issuer.key_id)
        || !riskExact(proof, ['algorithm', 'key_id', 'body_digest', 'signature_b64u'])
        || proof.algorithm !== 'Ed25519' || proof.key_id !== artifact.issuer.key_id
        || typeof proof.body_digest !== 'string' || !RISK_DIGEST.test(proof.body_digest)
        || typeof proof.signature_b64u !== 'string' || !/^[A-Za-z0-9_-]+$/.test(proof.signature_b64u)) {
      return refuse('artifact_signature_envelope_invalid');
    }
    if (riskDigest(body) !== proof.body_digest) return refuse('digest_mismatch');
    const pin = trustedKeys?.[artifact.issuer.key_id];
    if (!pin || pin.issuer_id !== artifact.issuer.id) return refuse('issuer_untrusted');
    const keyBytes = Buffer.from(pin.public_key, 'base64url');
    if (keyBytes.toString('base64url') !== pin.public_key) return refuse('pinned_key_invalid');
    const key = crypto.createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
    if (key.asymmetricKeyType !== 'ed25519') return refuse('pinned_key_invalid');
    const signature = Buffer.from(proof.signature_b64u, 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== proof.signature_b64u
        || !crypto.verify(null, signingBytes(version, body), key, signature)) return refuse('signature_invalid');
    return { valid: true, reason: null, body, artifact_digest: riskDigest(artifact) };
  } catch {
    return refuse('artifact_invalid');
  }
}


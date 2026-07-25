// SPDX-License-Identifier: Apache-2.0
import crypto, { type KeyObject } from 'node:crypto';

import { canonicalize } from '@emilia-protocol/gate';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

export const CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION =
  'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
export const CONSEQUENCE_ACTUATOR_OBSERVATION_DOMAIN =
  'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const CAID =
  /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const OBSERVATION_KEYS = Object.freeze([
  '@version',
  'evidence_id',
  'observed_at',
  'outcome',
  'reason',
  'tenant_id',
  'request_digest',
  'provider_id',
  'provider_account_id',
  'environment',
  'attempt_id',
  'operation_id',
  'caid',
  'action_digest',
  'target_digest',
  'operation',
  'provider_observation_digest',
]);

type JsonObject = Record<string, any>;

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, expected: readonly string[]): value is JsonObject {
  if (!plainObject(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && keys.every((key) => typeof key === 'string' && expected.includes(key));
}

function identifier(value: unknown): value is string {
  return typeof value === 'string'
    && IDENTIFIER.test(value)
    && Buffer.byteLength(value, 'utf8') <= 256;
}

function normalizedPrivateKey(value: unknown): KeyObject {
  let key: KeyObject;
  try {
    key = value instanceof crypto.KeyObject
      ? value
      : crypto.createPrivateKey(value as crypto.PrivateKeyInput);
  } catch {
    throw new TypeError('actuator_evidence_private_key_invalid');
  }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('actuator_evidence_private_key_invalid');
  }
  return key;
}

function signatureInput(value: unknown): Buffer {
  return Buffer.concat([
    Buffer.from(CONSEQUENCE_ACTUATOR_OBSERVATION_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalize(value), 'utf8'),
  ]);
}

export function createSignedObservationEvidence({
  observation,
  privateKey,
  keyId,
}: {
  observation: unknown;
  privateKey: unknown;
  keyId: string;
}) {
  if (!exactKeys(observation, OBSERVATION_KEYS)
      || observation['@version'] !== CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION
      || !identifier(observation.evidence_id)
      || typeof observation.observed_at !== 'string'
      || new Date(Date.parse(observation.observed_at)).toISOString() !== observation.observed_at
      || !['COMMITTED', 'NOT_COMMITTED', 'ESCALATED'].includes(observation.outcome)
      || !identifier(observation.reason)
      || !identifier(observation.tenant_id)
      || !DIGEST.test(observation.request_digest)
      || !identifier(observation.provider_id)
      || !identifier(observation.provider_account_id)
      || !identifier(observation.environment)
      || !identifier(observation.attempt_id)
      || !identifier(observation.operation_id)
      || typeof observation.caid !== 'string'
      || !CAID.test(observation.caid)
      || !DIGEST.test(observation.action_digest)
      || !DIGEST.test(observation.target_digest)
      || !identifier(observation.operation)
      || !DIGEST.test(observation.provider_observation_digest)
      || !identifier(keyId)) {
    throw new TypeError('actuator_observation_invalid');
  }
  const key = normalizedPrivateKey(privateKey);
  const evidence = JSON.parse(canonicalize({
    ...observation,
    evidence_digest: digestAeb({
      domain: CONSEQUENCE_ACTUATOR_OBSERVATION_DOMAIN,
      evidence: observation,
    }),
  }));
  return Object.freeze({
    evidence: Object.freeze(evidence),
    signature: Object.freeze({
      algorithm: 'Ed25519',
      key_id: keyId,
      value: crypto.sign(null, signatureInput(evidence), key).toString('base64url'),
    }),
  });
}

export default Object.freeze({
  createSignedObservationEvidence,
});

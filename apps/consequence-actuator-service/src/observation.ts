// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

export const CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION =
  'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1' as const;
export const CONSEQUENCE_ACTUATOR_RESPONSE_VERSION =
  'EP-CONSEQUENCE-ACTUATOR-RESPONSE-v1' as const;

const SIGNATURE_DOMAIN = 'EMILIA-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const CAID =
  /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

type KeyMaterial = crypto.KeyObject | string | Buffer;

export interface ConsequenceActuatorObservationPayload {
  '@version': typeof CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION;
  issuer_id: string;
  tenant_id: string;
  request_digest: string;
  environment: string;
  attempt_id: string;
  action_digest: string;
  caid: string;
  provider_id: string;
  provider_account_id: string;
  target_digest: string;
  operation: string;
  idempotency_key: string;
  nonce: string;
  envelope_digest: string;
  provider_attribution_digest: string;
  outcome: 'COMMITTED' | 'INDETERMINATE';
  observed_at: string;
  reason: string;
  provider_reference: string;
  provider_result_digest: string | null;
}

function validPayload(value: ConsequenceActuatorObservationPayload): boolean {
  const observedAt = Date.parse(value?.observed_at);
  return value?.['@version'] === CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION
    && IDENTIFIER.test(value.issuer_id)
    && IDENTIFIER.test(value.tenant_id)
    && DIGEST.test(value.request_digest)
    && IDENTIFIER.test(value.environment)
    && IDENTIFIER.test(value.attempt_id)
    && DIGEST.test(value.action_digest)
    && CAID.test(value.caid)
    && IDENTIFIER.test(value.provider_id)
    && IDENTIFIER.test(value.provider_account_id)
    && DIGEST.test(value.target_digest)
    && IDENTIFIER.test(value.operation)
    && IDENTIFIER.test(value.idempotency_key)
    && typeof value.nonce === 'string'
    && value.nonce.length >= 22
    && value.nonce.length <= 128
    && BASE64URL.test(value.nonce)
    && DIGEST.test(value.envelope_digest)
    && DIGEST.test(value.provider_attribution_digest)
    && ['COMMITTED', 'INDETERMINATE'].includes(value.outcome)
    && Number.isFinite(observedAt)
    && typeof value.reason === 'string'
    && value.reason.length >= 1
    && value.reason.length <= 256
    && typeof value.provider_reference === 'string'
    && value.provider_reference.length >= 1
    && value.provider_reference.length <= 512
    && (value.provider_result_digest === null
      || DIGEST.test(value.provider_result_digest));
}

function normalizePrivateKey(value: KeyMaterial): crypto.KeyObject {
  let key: crypto.KeyObject;
  try {
    key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value);
  } catch {
    throw new TypeError('actuator_observation_private_key_invalid');
  }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('actuator_observation_private_key_invalid');
  }
  return key;
}

function signatureInput(payload: ConsequenceActuatorObservationPayload): Buffer {
  return Buffer.concat([
    Buffer.from(SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(digestAeb(payload), 'utf8'),
  ]);
}

export function createConsequenceActuatorObservationSigner({
  issuerId,
  keyId,
  privateKey,
}: {
  issuerId: string;
  keyId: string;
  privateKey: KeyMaterial;
}) {
  if (!IDENTIFIER.test(issuerId) || !IDENTIFIER.test(keyId)) {
    throw new TypeError('actuator_observation_signer_invalid');
  }
  const signingKey = normalizePrivateKey(privateKey);
  return Object.freeze({
    issuerId,
    keyId,
    sign(input: Omit<ConsequenceActuatorObservationPayload, '@version' | 'issuer_id'>) {
      const payload: ConsequenceActuatorObservationPayload = {
        '@version': CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION,
        issuer_id: issuerId,
        ...structuredClone(input),
      };
      if (!validPayload(payload)) {
        throw new TypeError('actuator_observation_payload_invalid');
      }
      const signature = crypto.sign(
        null,
        signatureInput(payload),
        signingKey,
      ).toString('base64url');
      return Object.freeze({
        '@version': CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION,
        payload: Object.freeze(payload),
        signature: Object.freeze({
          algorithm: 'Ed25519' as const,
          key_id: keyId,
          value: signature,
        }),
      });
    },
  });
}

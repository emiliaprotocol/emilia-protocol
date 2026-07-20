// SPDX-License-Identifier: Apache-2.0

import {
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

import {
  canonicalize,
  hashCanonical,
} from '../../packages/gate/index.js';

export const PROVIDER_EFFECT_EVIDENCE_VERSION = 'EP-DEMO-PROVIDER-EFFECT-v1';

function clone(value) {
  return structuredClone(value);
}

function publicKeyB64u(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

export function actionDigest(action) {
  return `sha256:${hashCanonical(action)}`;
}

export function evidenceDigest(evidence) {
  return `sha256:${hashCanonical(evidence)}`;
}

function effectProjection(action, effectId) {
  return {
    effect_id: effectId,
    action_type: action.action_type,
    amount: action.amount,
    currency: action.currency,
    destination: action.destination,
    payment_instruction_id: action.payment_instruction_id,
  };
}

export function createSignedMockProvider({
  providerId = 'mock-bank.example',
  now = () => '2026-07-19T04:00:05.000Z',
} = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pinnedPublicKey = publicKeyB64u(publicKey);
  const effects = new Map();
  let executionAttempts = 0;

  /** @param {{ operationId?: string, action?: any }} [o] */
  function signEvidence({ operationId, action } = {}) {
    const committed = effects.get(operationId);
    if (!committed) throw new Error('provider has no committed effect for operation');
    const assertedAction = action ? clone(action) : clone(committed.action);
    const body = {
      '@version': PROVIDER_EFFECT_EVIDENCE_VERSION,
      provider_id: providerId,
      operation_id: operationId,
      status: 'committed',
      action_digest: actionDigest(assertedAction),
      effect: effectProjection(assertedAction, committed.effectId),
      committed_at: committed.committedAt,
    };
    return {
      body,
      signature: {
        algorithm: 'Ed25519',
        public_key: pinnedPublicKey,
        value: sign(
          null,
          Buffer.from(canonicalize(body), 'utf8'),
          privateKey,
        ).toString('base64url'),
      },
    };
  }

  return {
    providerId,
    pinnedPublicKey,

    /**
     * @param {any} action
     * @param {{ operation_id?: string }} [o]
     */
    async execute(action, { operation_id: operationId } = {}) {
      if (!operationId) throw new TypeError('provider operation_id is required');
      executionAttempts += 1;
      if (!effects.has(operationId)) {
        effects.set(operationId, {
          action: clone(action),
          effectId: `provider-effect:${operationId}`,
          committedAt: now(),
        });
      }

      const error = /** @type {Error & { code?: string }} */ (
        new Error('simulated provider response lost after authentic commit')
      );
      error.code = 'PROVIDER_RESPONSE_LOST';
      throw error;
    },

    getSignedEvidence(operationId) {
      return clone(signEvidence({ operationId }));
    },

    signEvidence,

    get executionAttempts() {
      return executionAttempts;
    },

    get committedEffects() {
      return effects.size;
    },

    get actionDigest() {
      const first = effects.values().next().value;
      return first ? actionDigest(first.action) : null;
    },
  };
}

/**
 * @param {any} evidence
 * @param {{ pinnedProviderKey?: string, expectedProviderId?: string, expectedOperationId?: string, expectedAction?: any }} [o]
 */
export function verifySignedProviderEvidence(evidence, {
  pinnedProviderKey,
  expectedProviderId,
  expectedOperationId,
  expectedAction,
} = {}) {
  if (!evidence || typeof evidence !== 'object' || !evidence.body || !evidence.signature) {
    throw new Error('provider evidence malformed');
  }
  if (evidence.body['@version'] !== PROVIDER_EFFECT_EVIDENCE_VERSION
      || evidence.signature.algorithm !== 'Ed25519'
      || evidence.signature.public_key !== pinnedProviderKey) {
    throw new Error('provider evidence trust pin mismatch');
  }

  let authentic = false;
  try {
    authentic = verify(
      null,
      Buffer.from(canonicalize(evidence.body), 'utf8'),
      createPublicKey({
        key: Buffer.from(/** @type {string} */ (pinnedProviderKey), 'base64url'),
        format: 'der',
        type: 'spki',
      }),
      Buffer.from(evidence.signature.value, 'base64url'),
    );
  } catch {
    authentic = false;
  }
  if (!authentic) throw new Error('provider evidence signature invalid');

  if (evidence.body.provider_id !== expectedProviderId) {
    throw new Error('provider evidence provider mismatch');
  }
  if (evidence.body.operation_id !== expectedOperationId) {
    throw new Error('provider evidence operation mismatch');
  }
  if (evidence.body.status !== 'committed') {
    throw new Error('provider evidence does not prove committed effect');
  }

  const expectedDigest = actionDigest(expectedAction);
  if (evidence.body.action_digest !== expectedDigest) {
    throw new Error('provider evidence action digest mismatch');
  }
  const expectedEffect = effectProjection(
    expectedAction,
    `provider-effect:${expectedOperationId}`,
  );
  if (canonicalize(evidence.body.effect) !== canonicalize(expectedEffect)) {
    throw new Error('provider evidence effect mismatch');
  }

  return Object.freeze({
    ok: true,
    action_digest: expectedDigest,
    evidence_digest: evidenceDigest(evidence),
    effect_id: evidence.body.effect.effect_id,
    committed_at: evidence.body.committed_at,
  });
}

// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import {
  ConsequenceActuator,
  type ConsequenceActuatorPins,
  type ConsequenceActuatorStore,
  type ConsequenceExecutionEnvelopePayload,
} from '@emilia-protocol/gate/consequence-actuator';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

import {
  CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
  type ConsequenceActuatorObservationPayload,
} from './observation.js';
import {
  CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION as RECONCILIATION_OBSERVATION_VERSION,
  createSignedObservationEvidence,
} from './evidence.js';

const REQUEST_KEYS = Object.freeze([
  'action', 'action_digest', 'attempt_id', 'idempotency_key', 'envelope',
]);
const ENVELOPE_KEYS = Object.freeze(['payload', 'signature']);
const OBSERVE_KEYS = Object.freeze(['action', 'expected', 'operation']);
const EXPECTED_KEYS = Object.freeze([
  'operation_id',
  'caid',
  'action_digest',
  'tenant_id',
  'request_digest',
  'provider_id',
  'provider_account_id',
  'environment',
  'attempt_id',
]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

type JsonObject = Record<string, any>;

export interface ConsequenceActuatorRuntimeConfig {
  tenantId: string;
  providerId: string;
  providerAccountId: string;
  targetDigest: string;
  envelopeIssuerId: string;
  envelopeKeyId: string;
  envelopePublicKey: ConsequenceActuatorPins['envelopePublicKey'];
  maxEnvelopeTtlMs?: number;
  clockSkewMs?: number;
  store: ConsequenceActuatorStore;
  normalizeAction(action: unknown): {
    action: JsonObject;
    actionDigest: string;
    caid: string;
    targetDigest: string;
  };
  operations: Readonly<Record<string, (
    input: {
      action: JsonObject;
      binding: Readonly<ConsequenceExecutionEnvelopePayload>;
    },
  ) => unknown | Promise<unknown>>>;
  observationSigner: {
    sign(
      payload: Omit<
        ConsequenceActuatorObservationPayload,
        '@version' | 'issuer_id'
      >,
    ): unknown;
  };
  reconciliationEvidence: {
    privateKey: crypto.KeyObject | string | Buffer;
    keyId: string;
  };
  observeProvider(input: {
    action: JsonObject;
    expected: JsonObject;
  }): Promise<JsonObject>;
  authenticateRequest(authorization: unknown): boolean | Promise<boolean>;
  readiness?(): Promise<{ ok: boolean }>;
  close?(): Promise<void>;
  now?: () => number;
}

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, expected: readonly string[]): value is JsonObject {
  if (!plainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function currentTime(now: () => number): number {
  const value = Number(now());
  if (!Number.isSafeInteger(value)) throw new Error('actuator_clock_invalid');
  return value;
}

function response(status: number, body: JsonObject) {
  return Object.freeze({
    status,
    body: structuredClone(body),
  });
}

function refused(status: number, reason: string, invoked = false) {
  return response(status, {
    '@version': CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
    ok: false,
    invoked,
    reason,
  });
}

function providerReference(
  result: unknown,
  providerId: string,
  providerAccountId: string,
  targetDigest: string,
): string {
  if (plainObject(result)
      && typeof result.provider_reference === 'string'
      && result.provider_reference.length >= 1
      && result.provider_reference.length <= 512
      && !result.provider_reference.includes('\0')) {
    return result.provider_reference;
  }
  return `${providerId}:${providerAccountId}:${targetDigest}`;
}

export function createConsequenceActuatorRuntime(
  config: ConsequenceActuatorRuntimeConfig,
) {
  if (!config || !IDENTIFIER.test(config.tenantId)
      || !IDENTIFIER.test(config.providerId)
      || !IDENTIFIER.test(config.providerAccountId)
      || !DIGEST.test(config.targetDigest)
      || !IDENTIFIER.test(config.envelopeIssuerId)
      || !IDENTIFIER.test(config.envelopeKeyId)
      || !config.store
      || typeof config.store.reserve !== 'function'
      || typeof config.store.consume !== 'function'
      || typeof config.normalizeAction !== 'function'
      || !plainObject(config.operations)
      || Object.keys(config.operations).length < 1
      || Object.entries(config.operations).some(([operation, perform]) => (
        !IDENTIFIER.test(operation) || typeof perform !== 'function'
      ))
      || typeof config.observationSigner?.sign !== 'function'
      || !plainObject(config.reconciliationEvidence)
      || !IDENTIFIER.test(config.reconciliationEvidence.keyId)
      || typeof config.observeProvider !== 'function'
      || typeof config.authenticateRequest !== 'function') {
    throw new TypeError('consequence_actuator_runtime_config_invalid');
  }
  const now = config.now ?? Date.now;
  const operations = Object.freeze({ ...config.operations });

  async function authenticate(authorization: unknown): Promise<boolean> {
    try {
      return await config.authenticateRequest(authorization) === true;
    } catch {
      return false;
    }
  }

  async function execute(body: unknown) {
    if (!exactKeys(body, REQUEST_KEYS)
        || !IDENTIFIER.test(body.attempt_id)
        || !DIGEST.test(body.action_digest)
        || !IDENTIFIER.test(body.idempotency_key)
        || !exactKeys(body.envelope, ENVELOPE_KEYS)
        || !plainObject(body.envelope.payload)) {
      return refused(400, 'request_fields_invalid');
    }
    let normalized: ReturnType<ConsequenceActuatorRuntimeConfig['normalizeAction']>;
    try {
      normalized = config.normalizeAction(body.action);
    } catch {
      return refused(422, 'action_refused');
    }
    if (!plainObject(normalized)
        || !plainObject(normalized.action)
        || normalized.actionDigest !== body.action_digest
        || digestAeb(normalized.action) !== body.action_digest
        || !DIGEST.test(normalized.actionDigest)
        || typeof normalized.caid !== 'string'
        || normalized.targetDigest !== config.targetDigest) {
      return refused(422, 'action_digest_mismatch');
    }
    const operation = body.envelope.payload.operation;
    const perform = typeof operation === 'string' ? operations[operation] : null;
    if (!perform) return refused(422, 'operation_refused');

    const actuator = new ConsequenceActuator({
      pins: {
        tenantId: config.tenantId,
        caid: normalized.caid,
        providerAccountId: config.providerAccountId,
        targetDigest: config.targetDigest,
        operation,
        envelopeIssuerId: config.envelopeIssuerId,
        envelopeKeyId: config.envelopeKeyId,
        envelopePublicKey: config.envelopePublicKey,
        maxEnvelopeTtlMs: config.maxEnvelopeTtlMs,
        clockSkewMs: config.clockSkewMs,
      },
      store: config.store,
      now,
      perform: (binding) => perform({
        action: structuredClone(normalized.action),
        binding,
      }),
    });
    const result = await actuator.execute({
      envelope: body.envelope,
      attemptId: body.attempt_id,
      actionDigest: body.action_digest,
      idempotencyKey: body.idempotency_key,
    });
    if (!result.invoked) {
      const status = result.reason === 'envelope_replayed' ? 409 : 422;
      return refused(status, result.reason);
    }

    const payload = body.envelope.payload as ConsequenceExecutionEnvelopePayload;
    const committed = result.ok === true;
    const providerResult = committed ? result.result : null;
    const observation = config.observationSigner.sign({
      tenant_id: config.tenantId,
      attempt_id: body.attempt_id,
      action_digest: body.action_digest,
      caid: normalized.caid,
      provider_id: config.providerId,
      provider_account_id: config.providerAccountId,
      target_digest: config.targetDigest,
      operation,
      idempotency_key: body.idempotency_key,
      nonce: payload.nonce,
      envelope_digest: result.envelopeDigest!,
      outcome: committed ? 'COMMITTED' : 'INDETERMINATE',
      observed_at: new Date(currentTime(now)).toISOString(),
      reason: committed ? 'provider_committed' : result.reason,
      provider_reference: providerReference(
        providerResult,
        config.providerId,
        config.providerAccountId,
        config.targetDigest,
      ),
      provider_result_digest: committed ? digestAeb(providerResult) : null,
    });
    return response(committed ? 200 : 202, {
      '@version': CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
      ok: committed,
      outcome: committed ? 'COMMITTED' : 'INDETERMINATE',
      observation,
    });
  }

  async function observe(body: unknown) {
    if (!exactKeys(body, OBSERVE_KEYS)
        || !exactKeys(body.expected, EXPECTED_KEYS)
        || !IDENTIFIER.test(body.operation)
        || !operations[body.operation]) {
      return refused(400, 'observation_fields_invalid');
    }
    let normalized: ReturnType<ConsequenceActuatorRuntimeConfig['normalizeAction']>;
    try {
      normalized = config.normalizeAction(body.action);
    } catch {
      return refused(422, 'action_refused');
    }
    const expected = body.expected;
    if (normalized.actionDigest !== expected.action_digest
        || normalized.caid !== expected.caid
        || normalized.targetDigest !== config.targetDigest
        || expected.tenant_id !== config.tenantId
        || expected.provider_id !== config.providerId
        || expected.provider_account_id !== config.providerAccountId
        || !DIGEST.test(expected.request_digest)
        || !IDENTIFIER.test(expected.environment)
        || !IDENTIFIER.test(expected.operation_id)
        || !IDENTIFIER.test(expected.attempt_id)) {
      return refused(422, 'observation_binding_mismatch');
    }
    let providerObservation: JsonObject;
    try {
      providerObservation = await config.observeProvider({
        action: structuredClone(normalized.action),
        expected: structuredClone(expected),
      });
    } catch {
      return refused(503, 'provider_observation_unavailable');
    }
    if (!plainObject(providerObservation)
        || !['COMMITTED', 'NOT_COMMITTED', 'ESCALATED']
          .includes(providerObservation.outcome)
        || !IDENTIFIER.test(providerObservation.reason)
        || typeof providerObservation.observed_at !== 'string'
        || !DIGEST.test(providerObservation.provider_observation_digest)) {
      return refused(503, 'provider_observation_invalid');
    }
    const evidenceId = `observation:${crypto.createHash('sha256')
      .update(digestAeb({
        expected,
        operation: body.operation,
        provider_observation_digest:
          providerObservation.provider_observation_digest,
        observed_at: providerObservation.observed_at,
      }))
      .digest('hex')}`;
    try {
      const signed = createSignedObservationEvidence({
        observation: {
          '@version': RECONCILIATION_OBSERVATION_VERSION,
          evidence_id: evidenceId,
          observed_at: providerObservation.observed_at,
          outcome: providerObservation.outcome,
          reason: providerObservation.reason,
          tenant_id: expected.tenant_id,
          request_digest: expected.request_digest,
          provider_id: expected.provider_id,
          provider_account_id: expected.provider_account_id,
          environment: expected.environment,
          attempt_id: expected.attempt_id,
          operation_id: expected.operation_id,
          caid: expected.caid,
          action_digest: expected.action_digest,
          target_digest: config.targetDigest,
          operation: body.operation,
          provider_observation_digest:
            providerObservation.provider_observation_digest,
        },
        privateKey: config.reconciliationEvidence.privateKey,
        keyId: config.reconciliationEvidence.keyId,
      });
      return response(200, signed as unknown as JsonObject);
    } catch {
      return refused(503, 'observation_signing_failed');
    }
  }

  return Object.freeze({
    authenticate,
    execute,
    observe,
    live: () => response(200, { status: 'ok' }),
    ready: async () => {
      if (typeof config.readiness !== 'function') {
        return response(200, { status: 'ok' });
      }
      try {
        const ready = await config.readiness();
        return ready?.ok === true
          ? response(200, { status: 'ok' })
          : response(503, { status: 'unavailable' });
      } catch {
        return response(503, { status: 'unavailable' });
      }
    },
    close: async () => {
      if (typeof config.close === 'function') await config.close();
    },
  });
}

export default Object.freeze({ createConsequenceActuatorRuntime });

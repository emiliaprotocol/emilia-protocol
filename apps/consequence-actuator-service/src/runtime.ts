// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { canonicalize } from '@emilia-protocol/gate';
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
  'action', 'action_digest', 'attempt_id', 'attribution', 'idempotency_key',
  'envelope',
]);
const ENVELOPE_KEYS = Object.freeze(['payload', 'signature']);
const ATTRIBUTION_KEYS = Object.freeze(['payload', 'signature']);
const ATTRIBUTION_PAYLOAD_KEYS = Object.freeze([
  '@version',
  'issuer_id',
  'tenant_id',
  'provider_id',
  'provider_account_id',
  'environment',
  'request_digest',
  'attempt_id',
  'operation_id',
  'caid',
  'action_digest',
  'target_digest',
  'operation',
  'nonce',
  'envelope_digest',
  'effect_digest',
  'issued_at',
]);
const SIGNATURE_KEYS = Object.freeze(['algorithm', 'key_id', 'value']);
const PROVIDER_ATTRIBUTION_VERSION =
  'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1';
const PROVIDER_ATTRIBUTION_SIGNATURE_DOMAIN =
  'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1';
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
const BASE64URL = /^[A-Za-z0-9_-]+$/;

type JsonObject = Record<string, any>;

export interface ConsequenceActuatorRuntimeConfig {
  /**
   * Explicitly permits the non-durable memory store in tests.
   */
  testOnly?: true;
  tenantId: string;
  providerId: string;
  providerAccountId: string;
  environment: string;
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
      attribution: Readonly<JsonObject>;
      signedAttribution: Readonly<JsonObject>;
      providerAttributionDigest: string;
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
    operation: string;
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

function attributionSignatureInput(payload: JsonObject): Buffer {
  return Buffer.concat([
    Buffer.from(PROVIDER_ATTRIBUTION_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from([0]),
    Buffer.from(canonicalize(payload), 'utf8'),
  ]);
}

function githubIssueEffectDigest({
  action,
  attribution,
  targetDigest,
}: {
  action: JsonObject;
  attribution: JsonObject;
  targetDigest: string;
}) {
  return digestAeb({
    domain: 'EP-GITHUB-ISSUE-EFFECT-v1',
    tenant_id: attribution.tenant_id,
    provider_id: attribution.provider_id,
    provider_account_id: attribution.provider_account_id,
    environment: attribution.environment,
    target_digest: targetDigest,
    target: {
      owner: action.owner,
      repo: action.repo,
      issue_number: action.issue_number,
    },
    effect: {
      title: action.title,
      body: action.body,
    },
  });
}

function normalizeAttributionPublicKey(
  value: ConsequenceActuatorPins['envelopePublicKey'],
): crypto.KeyObject {
  let key: crypto.KeyObject;
  try {
    key = value instanceof crypto.KeyObject
      ? value
      : crypto.createPublicKey(value);
  } catch {
    throw new TypeError('consequence_actuator_runtime_config_invalid');
  }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('consequence_actuator_runtime_config_invalid');
  }
  return key;
}

function verifyProviderAttribution({
  attribution,
  envelope,
  normalized,
  config,
  operation,
  publicKey,
}: {
  attribution: unknown;
  envelope: JsonObject;
  normalized: ReturnType<ConsequenceActuatorRuntimeConfig['normalizeAction']>;
  config: ConsequenceActuatorRuntimeConfig;
  operation: string;
  publicKey: crypto.KeyObject;
}): JsonObject | null {
  if (!exactKeys(attribution, ATTRIBUTION_KEYS)
      || !exactKeys(attribution.payload, ATTRIBUTION_PAYLOAD_KEYS)
      || !exactKeys(attribution.signature, SIGNATURE_KEYS)
      || attribution.signature.algorithm !== 'Ed25519'
      || attribution.signature.key_id !== config.envelopeKeyId
      || typeof attribution.signature.value !== 'string'
      || !BASE64URL.test(attribution.signature.value)) {
    return null;
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(attribution.signature.value, 'base64url');
  } catch {
    return null;
  }
  const payload = attribution.payload;
  if (signature.byteLength !== 64
      || signature.toString('base64url') !== attribution.signature.value
      || !crypto.verify(
        null,
        attributionSignatureInput(payload),
        publicKey,
        signature,
      )
      || payload['@version'] !== PROVIDER_ATTRIBUTION_VERSION
      || payload.issuer_id !== config.envelopeIssuerId
      || payload.tenant_id !== config.tenantId
      || payload.provider_id !== config.providerId
      || payload.provider_account_id !== config.providerAccountId
      || payload.environment !== config.environment
      || !DIGEST.test(payload.request_digest)
      || payload.attempt_id !== envelope.payload?.attempt_id
      || payload.operation_id !== envelope.payload?.idempotency_key
      || payload.caid !== normalized.caid
      || payload.action_digest !== normalized.actionDigest
      || payload.target_digest !== config.targetDigest
      || payload.operation !== operation
      || payload.nonce !== envelope.payload?.nonce
      || payload.envelope_digest !== digestAeb(envelope)
      || payload.issued_at !== envelope.payload?.issued_at
      || payload.effect_digest !== githubIssueEffectDigest({
        action: normalized.action,
        attribution: payload,
        targetDigest: config.targetDigest,
      })) {
    return null;
  }
  return structuredClone(payload);
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
      || !IDENTIFIER.test(config.environment)
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
  const attributionPublicKey = normalizeAttributionPublicKey(
    config.envelopePublicKey,
  );

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
    const attribution = verifyProviderAttribution({
      attribution: body.attribution,
      envelope: body.envelope,
      normalized,
      config,
      operation,
      publicKey: attributionPublicKey,
    });
    if (!attribution) return refused(422, 'attribution_binding_mismatch');

    const actuator = new ConsequenceActuator({
      testOnly: config.testOnly,
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
        attribution: structuredClone(attribution),
        signedAttribution: structuredClone(body.attribution),
        providerAttributionDigest: digestAeb(body.attribution),
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
      request_digest: attribution.request_digest,
      environment: attribution.environment,
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
      provider_attribution_digest: digestAeb(body.attribution),
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
        || expected.environment !== config.environment
        || !IDENTIFIER.test(expected.operation_id)
        || !IDENTIFIER.test(expected.attempt_id)) {
      return refused(422, 'observation_binding_mismatch');
    }
    let providerObservation: JsonObject;
    try {
      providerObservation = await config.observeProvider({
        action: structuredClone(normalized.action),
        expected: structuredClone(expected),
        operation: body.operation,
      });
    } catch {
      return refused(503, 'provider_observation_unavailable');
    }
    if (!plainObject(providerObservation)
        || !['COMMITTED', 'NOT_COMMITTED']
          .includes(providerObservation.outcome)
        || !IDENTIFIER.test(providerObservation.reason)
        || typeof providerObservation.observed_at !== 'string'
        || providerObservation.tenant_id !== expected.tenant_id
        || providerObservation.request_digest !== expected.request_digest
        || providerObservation.provider_id !== expected.provider_id
        || providerObservation.provider_account_id
          !== expected.provider_account_id
        || providerObservation.environment !== expected.environment
        || providerObservation.attempt_id !== expected.attempt_id
        || providerObservation.operation_id !== expected.operation_id
        || providerObservation.caid !== expected.caid
        || providerObservation.action_digest !== expected.action_digest
        || providerObservation.target_digest !== config.targetDigest
        || providerObservation.operation !== body.operation
        || typeof providerObservation.nonce !== 'string'
        || providerObservation.nonce.length < 22
        || providerObservation.nonce.length > 128
        || !BASE64URL.test(providerObservation.nonce)
        || !DIGEST.test(providerObservation.envelope_digest)
        || !DIGEST.test(providerObservation.provider_attribution_digest)
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
          tenant_id: providerObservation.tenant_id,
          request_digest: providerObservation.request_digest,
          provider_id: providerObservation.provider_id,
          provider_account_id: providerObservation.provider_account_id,
          environment: providerObservation.environment,
          attempt_id: providerObservation.attempt_id,
          operation_id: providerObservation.operation_id,
          caid: providerObservation.caid,
          action_digest: providerObservation.action_digest,
          target_digest: providerObservation.target_digest,
          operation: providerObservation.operation,
          nonce: providerObservation.nonce,
          envelope_digest: providerObservation.envelope_digest,
          provider_attribution_digest:
            providerObservation.provider_attribution_digest,
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
    // Readiness is a PROOF, not a default. A config with no probe has told us
    // nothing about the durable dependencies this service owns credentials for,
    // so it is NOT ready: answering 200 here would make the startup gate in
    // server.ts (which only checks `status !== 200`) pass vacuously and would
    // let an orchestrator route traffic to a service that never proved its
    // store, role membership, or stored procedures exist. Every branch below
    // carries a named reason so an operator can tell the three cases apart.
    ready: async () => {
      if (typeof config.readiness !== 'function') {
        return response(503, {
          status: 'unavailable',
          reason: 'readiness_probe_not_configured',
        });
      }
      try {
        const ready = await config.readiness();
        return ready?.ok === true
          ? response(200, { status: 'ok' })
          : response(503, {
            status: 'unavailable',
            reason: 'readiness_probe_refused',
          });
      } catch {
        return response(503, {
          status: 'unavailable',
          reason: 'readiness_probe_failed',
        });
      }
    },
    close: async () => {
      if (typeof config.close === 'function') await config.close();
    },
  });
}

export default Object.freeze({ createConsequenceActuatorRuntime });

// SPDX-License-Identifier: Apache-2.0
import {
  GRACE_COSA_ACK_VERSION,
  GRACE_DISPATCH_VERSION,
  GRACE_METER_VERSION,
  graceDigest,
  signGraceArtifact,
  validateCurtailmentAction,
  verifyGraceArtifact,
} from './mobile-grid.js';

const ACK_MEMBERS = new Set([
  '@version', 'adapter', 'adapter_version', 'actuator_id', 'event_id',
  'action_hash', 'request_digest', 'idempotency_key', 'status',
  'dispatched_at', 'simulation', 'signer_key_id', 'signature',
]);
const METER_MEMBERS = new Set([
  '@version', 'meter_id', 'event_id', 'action_hash', 'window', 'unit',
  'baseline_mw', 'intervals', 'measurement_class', 'simulation',
  'observed_at', 'signer_key_id', 'signature',
]);
const INTERVAL_MEMBERS = new Set(['sequence', 'at', 'load_mw', 'quality']);
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?$/;

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exact(value, members) {
  return record(value) && Object.keys(value).every((key) => members.has(key));
}

function canonicalInstant(value) {
  return typeof value === 'string' && INSTANT.test(value) && Number.isFinite(Date.parse(value));
}

function fixed(value) {
  return Number(value).toFixed(3);
}

export function createFencedMemoryStore() {
  const states = new Map();
  return {
    durable: true,
    ownershipFenced: true,
    async reserve(key) {
      if (states.has(key)) return false;
      states.set(key, 'reserved');
      return true;
    },
    async commit(key) {
      if (states.get(key) !== 'reserved') return false;
      states.set(key, 'committed');
      return true;
    },
    state(key) { return states.get(key) || null; },
  };
}

export function verifyCosaReferenceAcknowledgment(ack, trust, expected = {}) {
  return exact(ack, ACK_MEMBERS)
    && ack.adapter === 'cosa-reference'
    && ack.adapter_version === '1.0.0'
    && ack.status === 'dispatched'
    && ack.simulation === true
    && canonicalInstant(ack.dispatched_at)
    && verifyGraceArtifact(ack, {
      publicKeySpkiB64u: trust?.public_key_spki,
      keyId: trust?.key_id,
      version: GRACE_COSA_ACK_VERSION,
    })
    && (expected.event_id === undefined || ack.event_id === expected.event_id)
    && (expected.action_hash === undefined || ack.action_hash === expected.action_hash)
    && (expected.request_digest === undefined || ack.request_digest === expected.request_digest);
}

/**
 * @param {object} [opts]
 * @param {*} [opts.privateKey]
 * @param {string} [opts.keyId]
 * @param {string} [opts.actuatorId]
 * @param {() => string} [opts.clock]
 */
export function createCosaReferenceActuator({
  privateKey,
  keyId,
  actuatorId = 'cosa:reference:actuator-1',
  clock = () => new Date().toISOString(),
} = {}) {
  const invocations = new Map();
  return {
    kind: 'cosa-reference',
    simulation: true,
    verify: verifyCosaReferenceAcknowledgment,
    async dispatch(request) {
      if (!record(request) || request['@version'] !== GRACE_DISPATCH_VERSION
          || !validateCurtailmentAction(request.action).valid
          || request.action_hash !== graceDigest(request.action)
          || request.idempotency_key !== `grace:${request.action.action_id}:${request.action_hash}`) {
        throw new Error('COSA reference adapter refused malformed dispatch');
      }
      const requestDigest = graceDigest(request);
      const prior = invocations.get(request.idempotency_key);
      if (prior) {
        if (prior.request_digest !== requestDigest) throw new Error('COSA idempotency key was reused for different bytes');
        return structuredClone(prior.ack);
      }
      const dispatchedAt = clock();
      if (!canonicalInstant(dispatchedAt)) throw new Error('COSA adapter clock is not canonical UTC');
      const ack = signGraceArtifact({
        '@version': GRACE_COSA_ACK_VERSION,
        adapter: 'cosa-reference',
        adapter_version: '1.0.0',
        actuator_id: actuatorId,
        event_id: request.action.action_id,
        action_hash: request.action_hash,
        request_digest: requestDigest,
        idempotency_key: request.idempotency_key,
        status: 'dispatched',
        dispatched_at: dispatchedAt,
        simulation: true,
      }, { privateKey, keyId });
      invocations.set(request.idempotency_key, { request_digest: requestDigest, ack });
      return structuredClone(ack);
    },
    invocationCount() { return invocations.size; },
  };
}

export function verifyReferenceMeterStatement(statement, trust, expected = {}) {
  if (!exact(statement, METER_MEMBERS)
      || statement.measurement_class !== 'reference_simulation'
      || statement.simulation !== true
      || statement.unit !== 'MW'
      || !DECIMAL.test(statement.baseline_mw || '')
      || !canonicalInstant(statement.observed_at)
      || !record(statement.window)
      || Object.hasOwn(statement, 'baseline_method_hash')
      || !Array.isArray(statement.intervals) || statement.intervals.length < 2
      || !statement.intervals.every((item, index) => exact(item, INTERVAL_MEMBERS)
        && item.sequence === index + 1
        && canonicalInstant(item.at)
        && DECIMAL.test(item.load_mw || '')
        && item.quality === 'simulated')) return false;
  return verifyGraceArtifact(statement, {
    publicKeySpkiB64u: trust?.public_key_spki,
    keyId: trust?.key_id,
    version: GRACE_METER_VERSION,
  })
    && (expected.event_id === undefined || statement.event_id === expected.event_id)
    && (expected.action_hash === undefined || statement.action_hash === expected.action_hash);
}

/**
 * @param {object} [opts]
 * @param {*} [opts.privateKey]
 * @param {string} [opts.keyId]
 * @param {string} [opts.meterId]
 * @param {string} [opts.baselineMw]
 * @param {number} [opts.complianceFactor]
 * @param {() => string} [opts.clock]
 */
export function createReferenceMeter({
  privateKey,
  keyId,
  meterId = 'meter:reference:facility-1',
  baselineMw = '64.000',
  complianceFactor = 0.996,
  clock = () => new Date().toISOString(),
} = {}) {
  if (!DECIMAL.test(baselineMw) || !Number.isFinite(complianceFactor)
      || complianceFactor < 0 || complianceFactor > 1.2) {
    throw new TypeError('reference meter configuration is invalid');
  }
  return {
    kind: 'reference-meter',
    simulation: true,
    verify: verifyReferenceMeterStatement,
    /**
     * @param {object} [opts]
     * @param {*} [opts.action]
     * @param {*} [opts.acknowledgment]
     */
    async observe({ action, acknowledgment } = {}) {
      if (!validateCurtailmentAction(action).valid
          || acknowledgment?.event_id !== action.action_id
          || acknowledgment?.action_hash !== graceDigest(action)
          || acknowledgment?.status !== 'dispatched') {
        throw new Error('reference meter refused unbound dispatch');
      }
      const baseline = Number(baselineMw);
      const ordered = Number(action.target_delta_kw) / 1000;
      const delivered = ordered * complianceFactor;
      const finalLoad = Math.max(0, baseline - delivered);
      const start = Date.parse(action.window.not_before);
      const end = Date.parse(action.window.not_after);
      const count = 4;
      const intervals = Array.from({ length: count }, (_, index) => ({
        sequence: index + 1,
        at: new Date(start + ((end - start) * index) / (count - 1)).toISOString(),
        load_mw: fixed(finalLoad + (count - index - 1) * ordered * 0.003),
        quality: 'simulated',
      }));
      const observedAt = clock();
      if (!canonicalInstant(observedAt)) throw new Error('reference meter clock is not canonical UTC');
      return signGraceArtifact({
        '@version': GRACE_METER_VERSION,
        meter_id: meterId,
        event_id: action.action_id,
        action_hash: graceDigest(action),
        window: structuredClone(action.window),
        unit: 'MW',
        baseline_mw: fixed(baseline),
        intervals,
        measurement_class: 'reference_simulation',
        simulation: true,
        observed_at: observedAt,
      }, { privateKey, keyId });
    },
  };
}

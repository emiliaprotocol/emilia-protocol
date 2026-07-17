// SPDX-License-Identifier: Apache-2.0
/**
 * Independent, privacy-minimized observation evidence for EMILIA Gate.
 *
 * A network witness is deliberately NOT an enforcement point. It can prove a
 * pinned sensor observed bytes associated with an action digest at a named
 * capture point. It cannot prove the action was authorized, blocked, executed,
 * or physically completed. Keeping that boundary in the artifact prevents a
 * passive TAP from being marketed as a firewall.
 */
import crypto from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import { strictJsonGate } from './strict-json.js';

export const NETWORK_WITNESS_VERSION = 'EP-GATE-NETWORK-WITNESS-v1';
export const NETWORK_WITNESS_ACCEPTANCE_VERSION = 'EP-GATE-NETWORK-WITNESS-ACCEPTANCE-v1';
export const NETWORK_WITNESS_DOMAIN = `${NETWORK_WITNESS_VERSION}\0`;
export const NETWORK_WITNESS_EVENTS = Object.freeze([
  'request_observed',
  'response_observed',
  'effect_observed',
]);

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const DIRECTIONS = new Set(['ingress', 'egress', 'internal']);
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second] = match;
  const base = new Date(0);
  base.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  base.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (base.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, allowed) {
  return isPlainObject(value) && Object.keys(value).every((key) => allowed.has(key));
}

function nonEmptyString(value, max = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
}

function digest(value) {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function decodeBase64Url(value, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== value) return null;
    return bytes;
  } catch { return null; }
}

function keyIdFor(key) {
  const der = crypto.createPublicKey(key).export({ type: 'spki', format: 'der' });
  return `ep:witness-key:sha256:${sha256(der).slice(0, 16)}`;
}

function signingBytes(body) {
  return Buffer.from(NETWORK_WITNESS_DOMAIN + canonicalize(body), 'utf8');
}

function unsigned(statement) {
  if (!isPlainObject(statement)) throw new TypeError('network witness statement must be an object');
  const { signature: _signature, ...body } = statement;
  return body;
}

export function networkWitnessDigest(statement) {
  return `sha256:${sha256(signingBytes(unsigned(statement)))}`;
}

/** Duplicate-key-safe parser for an untrusted serialized witness artifact. */
export function parseNetworkWitnessStatement(raw, { maxBytes = 64 * 1024 } = {}) {
  if (typeof raw !== 'string' || !Number.isSafeInteger(maxBytes) || maxBytes < 1
      || Buffer.byteLength(raw, 'utf8') > maxBytes) return null;
  const gated = strictJsonGate(raw);
  if (!gated.ok) return null;
  try {
    const parsed = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch { return null; }
}

function validateBody(body) {
  if (!exactKeys(body, new Set(['@version', 'witness', 'observation', 'deployment', 'privacy', 'limitations']))) {
    return 'statement_shape_invalid';
  }
  if (body['@version'] !== NETWORK_WITNESS_VERSION) return 'version_invalid';
  if (!exactKeys(body.witness, new Set(['id', 'key_id', 'capture_point_id']))) return 'witness_shape_invalid';
  if (!nonEmptyString(body.witness.id) || !nonEmptyString(body.witness.key_id)
      || !nonEmptyString(body.witness.capture_point_id)) return 'witness_identity_invalid';
  if (!exactKeys(body.observation, new Set([
    'sequence', 'observed_at', 'event', 'direction', 'action_digest', 'flow_digest', 'byte_count',
  ]))) return 'observation_shape_invalid';
  if (!Number.isSafeInteger(body.observation.sequence) || body.observation.sequence < 0) return 'sequence_invalid';
  if (!Number.isFinite(strictInstantMs(body.observation.observed_at))) return 'observed_at_invalid';
  if (!NETWORK_WITNESS_EVENTS.includes(body.observation.event)) return 'event_invalid';
  if (!DIRECTIONS.has(body.observation.direction)) return 'direction_invalid';
  if (!digest(body.observation.action_digest)) return 'action_digest_invalid';
  if (body.observation.flow_digest !== undefined && !digest(body.observation.flow_digest)) return 'flow_digest_invalid';
  if (body.observation.byte_count !== undefined
      && (!Number.isSafeInteger(body.observation.byte_count) || body.observation.byte_count < 0)) return 'byte_count_invalid';
  if (!exactKeys(body.deployment, new Set(['config_digest', 'attestation_ref']))) return 'deployment_shape_invalid';
  if (!digest(body.deployment.config_digest)) return 'config_digest_invalid';
  if (body.deployment.attestation_ref !== undefined && !digest(body.deployment.attestation_ref)) {
    return 'attestation_ref_invalid';
  }
  if (!exactKeys(body.privacy, new Set(['payload_captured']))) return 'privacy_shape_invalid';
  if (body.privacy.payload_captured !== false) return 'payload_capture_forbidden';
  if (!Array.isArray(body.limitations) || body.limitations.length < 2 || body.limitations.length > 8
      || body.limitations.some((item) => !nonEmptyString(item, 512))) return 'limitations_invalid';
  try { canonicalize(body); } catch { return 'canonical_body_invalid'; }
  return null;
}

/** Create a signed observation. The public key is intentionally not embedded. */
export function signNetworkWitnessStatement(input, privateKey) {
  if (!privateKey) throw new TypeError('privateKey is required');
  const keyId = input?.key_id ?? keyIdFor(privateKey);
  const body = {
    '@version': NETWORK_WITNESS_VERSION,
    witness: {
      id: input?.witness_id,
      key_id: keyId,
      capture_point_id: input?.capture_point_id,
    },
    observation: {
      sequence: input?.sequence,
      observed_at: input?.observed_at,
      event: input?.event,
      direction: input?.direction,
      action_digest: input?.action_digest,
      ...(input?.flow_digest !== undefined ? { flow_digest: input.flow_digest } : {}),
      ...(input?.byte_count !== undefined ? { byte_count: input.byte_count } : {}),
    },
    deployment: {
      config_digest: input?.config_digest,
      ...(input?.attestation_ref !== undefined ? { attestation_ref: input.attestation_ref } : {}),
    },
    privacy: { payload_captured: false },
    limitations: [
      'This artifact proves only that a pinned witness key signed an observation at a named capture point.',
      'A passive network witness does not authorize, block, execute, or prove the physical outcome of an action.',
      'Coverage and completeness depend on the relying party pinning the capture topology and expected witness set.',
      'Rollback detection begins at a relying-party-pinned stream checkpoint; first-seen sequence numbers are not self-authenticating history.',
    ],
  };
  const invalid = validateBody(body);
  if (invalid) throw new TypeError(invalid);
  const statementDigest = networkWitnessDigest(body);
  return Object.freeze({
    ...body,
    signature: Object.freeze({
      algorithm: 'Ed25519',
      key_id: keyId,
      statement_digest: statementDigest,
      signature_b64u: crypto.sign(null, signingBytes(body), privateKey).toString('base64url'),
    }),
  });
}

function findPin(pins, witness) {
  if (!Array.isArray(pins)) return null;
  return pins.find((pin) => isPlainObject(pin)
    && pin.witness_id === witness.id
    && pin.key_id === witness.key_id
    && Array.isArray(pin.capture_point_ids)
    && pin.capture_point_ids.includes(witness.capture_point_id)) ?? null;
}

/**
 * Offline signature and context verification. This function never throws on a
 * presenter-controlled statement. Sequence consumption is a separate online
 * operation performed by acceptNetworkWitnessStatement.
 */
export function verifyNetworkWitnessStatement(statement, options = {}) {
  const fail = (reason, checks = {}) => ({
    verified: false,
    accepted: false,
    reason,
    checks: {
      shape: false,
      pin: false,
      signature: false,
      action_binding: false,
      freshness: false,
      config_binding: false,
      ...checks,
    },
  });
  try {
    if (!isPlainObject(statement)
        || !exactKeys(statement, new Set(['@version', 'witness', 'observation', 'deployment', 'privacy', 'limitations', 'signature']))) {
      return fail('statement_shape_invalid');
    }
    const body = unsigned(statement);
    const invalid = validateBody(body);
    if (invalid) return fail(invalid);
    if (!exactKeys(statement.signature, new Set(['algorithm', 'key_id', 'statement_digest', 'signature_b64u']))) {
      return fail('signature_shape_invalid', { shape: true });
    }
    if (statement.signature.algorithm !== 'Ed25519'
        || statement.signature.key_id !== body.witness.key_id
        || !digest(statement.signature.statement_digest)
        || !nonEmptyString(statement.signature.signature_b64u, 512)) {
      return fail('signature_envelope_invalid', { shape: true });
    }
    const pin = findPin(options.pinnedWitnesses, body.witness);
    if (!pin || !nonEmptyString(pin.public_key, 4096)) return fail('witness_key_unpinned', { shape: true });
    if (!Array.isArray(pin.config_digests) || pin.config_digests.length === 0
        || !pin.config_digests.includes(body.deployment.config_digest)) {
      return fail('witness_config_unpinned', { shape: true, pin: true });
    }
    if (options.expectedActionDigest !== undefined
        && body.observation.action_digest !== options.expectedActionDigest) {
      return fail('action_digest_mismatch', { shape: true, pin: true, config_binding: true });
    }
    if (options.expectedEvent !== undefined && body.observation.event !== options.expectedEvent) {
      return fail('event_mismatch', { shape: true, pin: true, config_binding: true });
    }
    const now = options.now === undefined ? Date.now() : Number(options.now);
    const maxAgeSec = options.maxAgeSec === undefined ? 300 : options.maxAgeSec;
    const maxFutureSkewSec = options.maxFutureSkewSec === undefined ? 30 : options.maxFutureSkewSec;
    if (!Number.isFinite(now) || !Number.isSafeInteger(maxAgeSec) || maxAgeSec < 0
        || !Number.isSafeInteger(maxFutureSkewSec) || maxFutureSkewSec < 0) {
      return fail('verification_profile_invalid', { shape: true, pin: true, config_binding: true });
    }
    const observedMs = strictInstantMs(body.observation.observed_at);
    if (observedMs > now + (maxFutureSkewSec * 1000)) {
      return fail('observation_from_future', { shape: true, pin: true, action_binding: true, config_binding: true });
    }
    if (now - observedMs > maxAgeSec * 1000) {
      return fail('observation_stale', { shape: true, pin: true, action_binding: true, config_binding: true });
    }
    const computedDigest = networkWitnessDigest(body);
    if (computedDigest !== statement.signature.statement_digest) {
      return fail('statement_digest_mismatch', {
        shape: true, pin: true, action_binding: true, freshness: true, config_binding: true,
      });
    }
    let publicKey;
    try {
      const keyBytes = decodeBase64Url(pin.public_key, 4096);
      if (!keyBytes) throw new TypeError('invalid base64url key');
      publicKey = crypto.createPublicKey({
        key: keyBytes,
        type: 'spki',
        format: 'der',
      });
      if (publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError('witness key must be Ed25519');
    } catch {
      return fail('pinned_key_invalid', {
        shape: true, pin: true, action_binding: true, freshness: true, config_binding: true,
      });
    }
    const signature = decodeBase64Url(statement.signature.signature_b64u, 64);
    if (!signature || signature.length !== 64) {
      return fail('signature_invalid', {
        shape: true, pin: true, action_binding: true, freshness: true, config_binding: true,
      });
    }
    if (!crypto.verify(null, signingBytes(body), publicKey, signature)) {
      return fail('signature_invalid', {
        shape: true, pin: true, action_binding: true, freshness: true, config_binding: true,
      });
    }
    return {
      verified: true,
      accepted: true,
      reason: null,
      statement_digest: computedDigest,
      stream_id: `${body.witness.id}\0${body.witness.capture_point_id}`,
      sequence: body.observation.sequence,
      action_digest: body.observation.action_digest,
      event: body.observation.event,
      observed_at: body.observation.observed_at,
      witness_id: body.witness.id,
      capture_point_id: body.witness.capture_point_id,
      checks: {
        shape: true,
        pin: true,
        signature: true,
        action_binding: true,
        freshness: true,
        config_binding: true,
      },
      limitation: 'Observation is not authorization, enforcement, execution, or physical truth.',
    };
  } catch {
    return fail('hostile_input_refused');
  }
}

export function createMemoryWitnessSequenceStore() {
  const streams = new Map();
  return {
    durable: false,
    async advance(streamId, sequence, statementDigest) {
      const previous = streams.get(streamId);
      if (previous) {
        if (sequence < previous.sequence) return { accepted: false, reason: 'sequence_rollback' };
        if (sequence === previous.sequence) {
          return { accepted: false, reason: previous.digest === statementDigest ? 'statement_replay' : 'sequence_equivocation' };
        }
      }
      streams.set(streamId, { sequence, digest: statementDigest });
      return { accepted: true, reason: null };
    },
    snapshot() { return [...streams.entries()].map(([stream_id, value]) => ({ stream_id, ...value })); },
  };
}

function acceptanceResult(verified, {
  accepted,
  consumed,
  reason,
  sequenceStoreDurable,
}) {
  return Object.freeze({
    ...verified,
    acceptance_version: NETWORK_WITNESS_ACCEPTANCE_VERSION,
    accepted,
    consumed,
    reason,
    sequence_store_durable: sequenceStoreDurable === true,
    ...(isPlainObject(verified.checks) ? { checks: Object.freeze({ ...verified.checks }) } : {}),
  });
}

/**
 * Validate an ingestion result supplied through a relying-party-trusted option.
 * This does not authenticate presenter-controlled JSON; callers must never move
 * an untrusted bundle field into this trust channel.
 */
export function validateTrustedNetworkWitnessAcceptance(result, options = {}) {
  const fail = (reason, fields = {}) => ({
    verified: false,
    accepted: false,
    consumed: false,
    reason,
    ...fields,
  });
  try {
    if (!isPlainObject(result)
        || result.acceptance_version !== NETWORK_WITNESS_ACCEPTANCE_VERSION) {
      return fail('trusted_witness_acceptance_invalid');
    }

    const common = {
      acceptance_version: NETWORK_WITNESS_ACCEPTANCE_VERSION,
      statement_digest: result.statement_digest,
      stream_id: result.stream_id,
      sequence: result.sequence,
      action_digest: result.action_digest,
      event: result.event,
      observed_at: result.observed_at,
      witness_id: result.witness_id,
      capture_point_id: result.capture_point_id,
      sequence_store_durable: result.sequence_store_durable === true,
    };
    if (result.accepted !== true || result.consumed !== true) {
      return fail(
        nonEmptyString(result.reason) ? result.reason : 'trusted_witness_acceptance_rejected',
        common,
      );
    }
    if (result.verified !== true || result.reason !== null
        || !digest(common.statement_digest) || !digest(common.action_digest)
        || !Number.isSafeInteger(common.sequence) || common.sequence < 0
        || !nonEmptyString(common.witness_id) || !nonEmptyString(common.capture_point_id)
        || common.stream_id !== `${common.witness_id}\0${common.capture_point_id}`
        || !NETWORK_WITNESS_EVENTS.includes(common.event)
        || !Number.isFinite(strictInstantMs(common.observed_at))) {
      return fail('trusted_witness_acceptance_invalid');
    }
    if (!common.sequence_store_durable && options.allowEphemeralStore !== true) {
      return fail('durable_sequence_store_required', common);
    }
    if (options.expectedStatementDigest !== undefined) {
      if (!digest(options.expectedStatementDigest)) return fail('verification_profile_invalid', common);
      if (common.statement_digest !== options.expectedStatementDigest) {
        return fail('witness_acceptance_digest_mismatch', common);
      }
    }
    if (options.expectedActionDigest !== undefined
        && common.action_digest !== options.expectedActionDigest) {
      return fail('action_digest_mismatch', common);
    }
    if (options.expectedEvent !== undefined && common.event !== options.expectedEvent) {
      return fail('event_mismatch', common);
    }
    const now = options.now === undefined ? Date.now() : Number(options.now);
    const maxAgeSec = options.maxAgeSec === undefined ? 300 : options.maxAgeSec;
    const maxFutureSkewSec = options.maxFutureSkewSec === undefined ? 30 : options.maxFutureSkewSec;
    if (!Number.isFinite(now) || !Number.isSafeInteger(maxAgeSec) || maxAgeSec < 0
        || !Number.isSafeInteger(maxFutureSkewSec) || maxFutureSkewSec < 0) {
      return fail('verification_profile_invalid', common);
    }
    const observedMs = strictInstantMs(common.observed_at);
    if (observedMs > now + (maxFutureSkewSec * 1000)) return fail('observation_from_future', common);
    if (now - observedMs > maxAgeSec * 1000) return fail('observation_stale', common);
    return {
      ...common,
      verified: true,
      accepted: true,
      consumed: true,
      reason: null,
    };
  } catch {
    return fail('trusted_witness_acceptance_invalid');
  }
}

/** Verify and atomically advance a witness stream for online ingestion. */
export async function acceptNetworkWitnessStatement(statement, options = {}) {
  const verified = verifyNetworkWitnessStatement(statement, options);
  if (!verified.accepted) {
    return acceptanceResult(verified, {
      accepted: false,
      consumed: false,
      reason: verified.reason,
      sequenceStoreDurable: false,
    });
  }
  const store = options.sequenceStore;
  if (!store || typeof store.advance !== 'function'
      || (store.durable !== true && options.allowEphemeralStore !== true)) {
    return acceptanceResult(verified, {
      accepted: false,
      consumed: false,
      reason: 'durable_sequence_store_required',
      sequenceStoreDurable: false,
    });
  }
  try {
    const advanced = await store.advance(verified.stream_id, verified.sequence, verified.statement_digest);
    if (!isPlainObject(advanced) || advanced.accepted !== true || advanced.reason !== null) {
      return acceptanceResult(verified, {
        accepted: false,
        consumed: false,
        reason: nonEmptyString(advanced?.reason) ? advanced.reason : 'sequence_store_refused',
        sequenceStoreDurable: store.durable === true,
      });
    }
    return acceptanceResult(verified, {
      accepted: true,
      consumed: true,
      reason: null,
      sequenceStoreDurable: store.durable === true,
    });
  } catch {
    return acceptanceResult(verified, {
      accepted: false,
      consumed: false,
      reason: 'sequence_store_unavailable',
      sequenceStoreDurable: store.durable === true,
    });
  }
}

export default {
  NETWORK_WITNESS_VERSION,
  NETWORK_WITNESS_ACCEPTANCE_VERSION,
  NETWORK_WITNESS_EVENTS,
  parseNetworkWitnessStatement,
  networkWitnessDigest,
  signNetworkWitnessStatement,
  verifyNetworkWitnessStatement,
  acceptNetworkWitnessStatement,
  validateTrustedNetworkWitnessAcceptance,
  createMemoryWitnessSequenceStore,
};

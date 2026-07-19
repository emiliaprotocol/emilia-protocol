// SPDX-License-Identifier: Apache-2.0
/**
 * EP-MODEL-TO-MATTER-PROFILE-v1.
 *
 * A relying-party profile for the point where a frontier model's digital
 * proposal may cause a physical experiment. This module does not evaluate a
 * biological sequence, certify a model, or replace a laboratory safety system.
 * It composes separately signed evidence about one exact, executor-computed
 * action and fails closed when any required leg is absent, stale, revoked,
 * unpinned, or bound to different inputs.
 *
 * Sensitive experiment content stays outside the portable action. Only
 * commitments and digests cross the evidence boundary.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';
import {
  createRegisteredEvidenceChallenge,
  evaluateRegisteredPresentation,
} from '../negotiate/evidence-challenge.js';
import {
  artifactDigest,
  EVIDENCE_GRAPH_VERSION,
} from '../evidence/evidence-graph.js';
import { computeCaid, verifyCaid } from '../../caid/impl/js/caid.mjs';

export const M2M_ACTION_VERSION = 'EP-MODEL-TO-MATTER-ACTION-v1';
export const M2M_PROFILE_VERSION = 'EP-MODEL-TO-MATTER-PROFILE-v1';
export const M2M_EVIDENCE_VERSION = 'EP-MODEL-TO-MATTER-EVIDENCE-v1';
export const M2M_CLEARANCE_VERSION = 'EP-MODEL-TO-MATTER-CLEARANCE-v1';
export const M2M_EFFECT_VERSION = 'EP-MODEL-TO-MATTER-EFFECT-v1';
export const M2M_CAID_ACTION_TYPE = 'science.bio.experiment.execute.1';

export const M2M_CAID_DEFINITION = Object.freeze({
  action_type: M2M_CAID_ACTION_TYPE,
  status: 'active',
  risk_class: 'safety-critical',
  summary: 'Execution of a model-directed physical experiment under an executor-owned evidence profile.',
  required_fields: Object.freeze([
    Object.freeze({ name: '@version', type: 'enum', values_ref: `inline: ${M2M_ACTION_VERSION}` }),
    Object.freeze({ name: 'model', type: 'object' }),
    Object.freeze({ name: 'experiment', type: 'object' }),
    Object.freeze({ name: 'principal', type: 'object' }),
    Object.freeze({ name: 'executor', type: 'object' }),
    Object.freeze({ name: 'purpose', type: 'object' }),
    Object.freeze({ name: 'destination_digest', type: 'digest' }),
    Object.freeze({ name: 'requested_at', type: 'string', notes: 'RFC 3339 instant validated by the Model-to-Matter profile' }),
    Object.freeze({ name: 'max_executions', type: 'integer' }),
  ]),
  optional_fields: Object.freeze([]),
  digest_notes: 'All nested object members are material. The Model-to-Matter closed-shape validator runs before CAID computation.',
  references: Object.freeze(['draft-schrock-model-to-matter-00']),
});

export const M2M_EVIDENCE_TYPES = Object.freeze([
  'model_attestation',
  'safety_case_attestation',
  'institutional_authority',
  'biosafety_review',
  'domain_screening',
  'human_authorization',
]);

const EVIDENCE_DOMAIN = `${M2M_EVIDENCE_VERSION}\0`;
const EFFECT_DOMAIN = `${M2M_EFFECT_VERSION}\0`;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const M2M_CAID_RE = /^caid:1:science\.bio\.experiment\.execute\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const FORBIDDEN_CONTENT_FIELDS = new Set([
  'sequence', 'sequences', 'fasta', 'raw_sequence', 'raw_sequences',
  'raw_protocol', 'prompt', 'completion', 'chain_of_thought', 'reasoning_trace',
]);
const ACTION_TYPES = Object.freeze([M2M_CAID_ACTION_TYPE]);
const EFFECT_STATUSES = new Set(['completed', 'failed', 'aborted']);
// Receipt assurance wire values map to Classes S, V, and Q respectively.
// There is deliberately no `class_b`: it has no registered proof semantics.
const ASSURANCE_RANK = Object.freeze({ software: 0, class_a: 1, quorum: 2 });

const CLAIM_KEYS = Object.freeze({
  model_attestation: new Set([
    'provider', 'model_id', 'manifest_digest', 'harness_digest', 'safeguards_digest',
  ]),
  safety_case_attestation: new Set([
    'manifest_digest', 'harness_digest', 'safeguards_digest', 'safety_case_digest', 'assessment',
  ]),
  institutional_authority: new Set([
    'organization_id', 'principal_id', 'action_type', 'purpose_code', 'decision',
  ]),
  biosafety_review: new Set([
    'protocol_digest', 'materials_commitment', 'facility_id', 'decision',
  ]),
  domain_screening: new Set([
    'materials_commitment', 'destination_digest', 'screening_profile_digest', 'decision',
  ]),
  human_authorization: new Set(['approver_id', 'decision', 'assurance_class']),
});

const DEFAULT_FRESHNESS_SEC = Object.freeze({
  model_attestation: 86400,
  safety_case_attestation: 604800,
  institutional_authority: 3600,
  biosafety_review: 86400,
  domain_screening: 300,
  human_authorization: 300,
});

function sha256hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validDigest(value) {
  return typeof value === 'string' && SHA256_RE.test(value);
}

function strictInstantMs(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const local = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== local) return NaN;
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function assertString(value, field) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${field} must be a non-empty string`);
}

function assertDigest(value, field) {
  if (!validDigest(value)) throw new Error(`${field} must be a lowercase sha256 digest`);
}

function assertOnlyKeys(value, allowed, field) {
  if (!isObject(value)) throw new Error(`${field} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${field}.${key} is not allowed`);
  }
}

function assertNoRawContent(value, path = '$') {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawContent(item, `${path}[${index}]`));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_CONTENT_FIELDS.has(key.toLowerCase())) {
      throw new Error(`${path}.${key} is forbidden; portable Model-to-Matter objects carry commitments and digests, not raw biological content`);
    }
    assertNoRawContent(child, `${path}.${key}`);
  }
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object') return value;
  if (!Object.isFrozen(value)) Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function publicKeyToB64u(privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('Model-to-Matter evidence requires an Ed25519 key');
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function keyIdFor(publicKeyB64u) {
  return `ep:m2m:key:sha256:${sha256hex(Buffer.from(publicKeyB64u, 'base64url')).slice(0, 16)}`;
}

function unsigned(document) {
  if (!isObject(document)) throw new Error('signed document must be an object');
  const { signature: _signature, ...body } = document;
  return body;
}

function signingBytes(domain, body) {
  return Buffer.from(domain + canonicalize(body), 'utf8');
}

function signedBodyDigest(domain, document) {
  return `sha256:${sha256hex(signingBytes(domain, unsigned(document)))}`;
}

function verifySignature(document, domain, digestField) {
  const sig = document?.signature;
  const fail = (reason) => ({ verified: false, reason });
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string'
    || typeof sig.signature_b64u !== 'string' || !validDigest(sig[digestField])) {
    return fail('signature_missing_or_malformed');
  }
  let digest;
  try { digest = signedBodyDigest(domain, document); } catch { return fail('uncanonicalizable'); }
  if (digest !== sig[digestField]) return fail('digest_mismatch');
  const keyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== keyId) return fail('key_id_mismatch');
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der',
    });
    if (key.asymmetricKeyType !== 'ed25519') return fail('signature_invalid');
    const ok = crypto.verify(
      null,
      signingBytes(domain, unsigned(document)),
      key,
      Buffer.from(sig.signature_b64u, 'base64url'),
    );
    return ok ? { verified: true, digest, key_id: keyId } : fail('signature_invalid');
  } catch {
    return fail('signature_invalid');
  }
}

function assertAction(action) {
  assertNoRawContent(action);
  assertOnlyKeys(action, new Set([
    '@version', 'action_type', 'model', 'experiment', 'principal', 'executor',
    'purpose', 'destination_digest', 'requested_at', 'max_executions',
  ]), 'action');
  if (action['@version'] !== M2M_ACTION_VERSION) throw new Error(`action @version must be ${M2M_ACTION_VERSION}`);
  assertString(action.action_type, 'action_type');
  if (!ACTION_TYPES.includes(action.action_type)) throw new Error(`unsupported action_type ${action.action_type}`);

  assertOnlyKeys(action.model, new Set([
    'provider', 'model_id', 'manifest_digest', 'harness_digest', 'safeguards_digest',
  ]), 'model');
  assertString(action.model.provider, 'model.provider');
  assertString(action.model.model_id, 'model.model_id');
  assertDigest(action.model.manifest_digest, 'model.manifest_digest');
  assertDigest(action.model.harness_digest, 'model.harness_digest');
  assertDigest(action.model.safeguards_digest, 'model.safeguards_digest');

  assertOnlyKeys(action.experiment, new Set([
    'protocol_digest', 'materials_commitment', 'expected_effects_digest',
  ]), 'experiment');
  assertDigest(action.experiment.protocol_digest, 'experiment.protocol_digest');
  assertDigest(action.experiment.materials_commitment, 'experiment.materials_commitment');
  assertDigest(action.experiment.expected_effects_digest, 'experiment.expected_effects_digest');

  assertOnlyKeys(action.principal, new Set(['organization_id', 'principal_id']), 'principal');
  assertString(action.principal.organization_id, 'principal.organization_id');
  assertString(action.principal.principal_id, 'principal.principal_id');

  assertOnlyKeys(action.executor, new Set(['executor_id', 'facility_id']), 'executor');
  assertString(action.executor.executor_id, 'executor.executor_id');
  assertString(action.executor.facility_id, 'executor.facility_id');

  assertOnlyKeys(action.purpose, new Set(['code', 'jurisdiction']), 'purpose');
  assertString(action.purpose.code, 'purpose.code');
  assertString(action.purpose.jurisdiction, 'purpose.jurisdiction');
  assertDigest(action.destination_digest, 'destination_digest');
  if (Number.isNaN(strictInstantMs(action.requested_at))) throw new Error('requested_at must be a valid RFC 3339 instant');
  if (action.max_executions !== 1) throw new Error('max_executions must equal 1');
  return action;
}

/** Construct a strict, digest-only action. Raw sequences and protocols fail closed. */
export function createModelToMatterAction(input) {
  if (!isObject(input)) throw new Error('action input must be an object');
  const action = { ...clone(input), '@version': M2M_ACTION_VERSION };
  assertAction(action);
  return deepFreeze(action);
}

export function modelToMatterActionDigest(action) {
  assertAction(action);
  return artifactDigest(action);
}

/** Compute the CAID over the same closed action bytes used by every M2M join. */
export function modelToMatterCaid(action) {
  assertAction(action);
  const result = computeCaid(action, {
    suite: 'jcs-sha256',
    definitions: [M2M_CAID_DEFINITION],
  });
  if (!result.caid || result.digest !== modelToMatterActionDigest(action)) {
    throw new Error(`Model-to-Matter CAID computation refused: ${(result.refusals || ['digest_mismatch']).join(',')}`);
  }
  return deepFreeze(result);
}

export function verifyModelToMatterCaid(action, caid) {
  try { assertAction(action); } catch { return { valid: false, reasons: ['invalid_object'] }; }
  return verifyCaid(action, caid, { definitions: [M2M_CAID_DEFINITION] });
}

function validatePin(pin, type) {
  if (!isObject(pin)) throw new Error(`accepted_issuers.${type} pin must be an object`);
  assertOnlyKeys(pin, new Set(['issuer_id', 'public_key']), `accepted_issuers.${type} pin`);
  assertString(pin.issuer_id, `accepted_issuers.${type}.issuer_id`);
  assertString(pin.public_key, `accepted_issuers.${type}.public_key`);
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(pin.public_key, 'base64url'), type: 'spki', format: 'der',
    });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    const canonical = key.export({ type: 'spki', format: 'der' }).toString('base64url');
    if (canonical !== pin.public_key) throw new Error('non-canonical key encoding');
  } catch {
    throw new Error(`accepted_issuers.${type}.public_key must be an Ed25519 SPKI key`);
  }
}

function assertProfile(profile) {
  if (!isObject(profile) || profile['@version'] !== M2M_PROFILE_VERSION) {
    throw new Error(`profile @version must be ${M2M_PROFILE_VERSION}`);
  }
  assertOnlyKeys(profile, new Set([
    '@version', 'profile_id', 'policy_id', 'reliance_purpose', 'requirement',
    'allowed_action_types', 'required_human_assurance', 'freshness_sec',
    'revocation_required', 'accepted_issuers', 'require_action_agreement',
  ]), 'profile');
  assertString(profile.profile_id, 'profile_id');
  if (profile.policy_id !== profile.profile_id) throw new Error('policy_id must equal profile_id');
  if (profile.reliance_purpose !== 'frontier_science_execution') {
    throw new Error('reliance_purpose must be frontier_science_execution');
  }
  const expectedRequirement = M2M_EVIDENCE_TYPES.join(' AND ');
  if (profile.requirement !== expectedRequirement) throw new Error('profile requirement cannot be weakened');
  if (!Array.isArray(profile.allowed_action_types) || profile.allowed_action_types.length === 0
    || profile.allowed_action_types.some((type) => !ACTION_TYPES.includes(type))) {
    throw new Error('allowed_action_types contains an unsupported action');
  }
  if (!Object.hasOwn(ASSURANCE_RANK, profile.required_human_assurance)) throw new Error('required_human_assurance is invalid');
  if (profile.require_action_agreement !== true) throw new Error('profile action agreement cannot be weakened');
  if (!isObject(profile.accepted_issuers)) throw new Error('accepted_issuers must be an object');
  assertOnlyKeys(profile.accepted_issuers, new Set(M2M_EVIDENCE_TYPES), 'accepted_issuers');
  assertOnlyKeys(profile.freshness_sec, new Set(M2M_EVIDENCE_TYPES), 'freshness_sec');
  for (const type of M2M_EVIDENCE_TYPES) {
    const pins = profile.accepted_issuers[type];
    if (!Array.isArray(pins) || pins.length === 0) throw new Error(`accepted_issuers.${type} requires at least one pin`);
    pins.forEach((pin) => validatePin(pin, type));
    if (!Number.isFinite(profile.freshness_sec?.[type]) || profile.freshness_sec[type] < 0) {
      throw new Error(`freshness_sec.${type} must be a non-negative number`);
    }
  }
  if (!Array.isArray(profile.revocation_required)
    || profile.revocation_required.length !== M2M_EVIDENCE_TYPES.length
    || M2M_EVIDENCE_TYPES.some((type) => !profile.revocation_required.includes(type))) {
    throw new Error('all Model-to-Matter evidence types require revocation state');
  }
  return profile;
}

/** Build the fixed relying-party profile. The required evidence expression cannot be weakened. */
export function createModelToMatterProfile(input) {
  if (!isObject(input)) throw new Error('profile input must be an object');
  const profile = {
    '@version': M2M_PROFILE_VERSION,
    profile_id: input.profile_id,
    policy_id: input.profile_id,
    reliance_purpose: 'frontier_science_execution',
    requirement: M2M_EVIDENCE_TYPES.join(' AND '),
    allowed_action_types: clone(input.allowed_action_types ?? ACTION_TYPES),
    required_human_assurance: input.required_human_assurance ?? 'class_a',
    freshness_sec: { ...DEFAULT_FRESHNESS_SEC, ...(clone(input.freshness_sec ?? {})) },
    revocation_required: clone(input.revocation_required ?? M2M_EVIDENCE_TYPES),
    accepted_issuers: clone(input.accepted_issuers ?? {}),
    require_action_agreement: true,
  };
  assertProfile(profile);
  return deepFreeze(profile);
}

function assertEvidenceBody(body) {
  assertNoRawContent(body);
  assertOnlyKeys(body, new Set([
    '@version', 'evidence_type', 'action_digest', 'issuer_id', 'issued_at',
    'expires_at', 'claims', 'outcome',
  ]), 'evidence');
  if (body['@version'] !== M2M_EVIDENCE_VERSION) throw new Error(`evidence @version must be ${M2M_EVIDENCE_VERSION}`);
  if (!M2M_EVIDENCE_TYPES.includes(body.evidence_type)) throw new Error('unsupported evidence_type');
  assertDigest(body.action_digest, 'action_digest');
  assertString(body.issuer_id, 'issuer_id');
  assertString(body.issued_at, 'issued_at');
  assertString(body.expires_at, 'expires_at');
  if (!isObject(body.claims)) throw new Error('claims must be an object');
  assertOnlyKeys(body.claims, CLAIM_KEYS[body.evidence_type], `${body.evidence_type}.claims`);

  const claims = body.claims;
  switch (body.evidence_type) {
    case 'model_attestation':
      assertString(claims.provider, 'claims.provider');
      assertString(claims.model_id, 'claims.model_id');
      assertDigest(claims.manifest_digest, 'claims.manifest_digest');
      assertDigest(claims.harness_digest, 'claims.harness_digest');
      assertDigest(claims.safeguards_digest, 'claims.safeguards_digest');
      break;
    case 'safety_case_attestation':
      assertDigest(claims.manifest_digest, 'claims.manifest_digest');
      assertDigest(claims.harness_digest, 'claims.harness_digest');
      assertDigest(claims.safeguards_digest, 'claims.safeguards_digest');
      assertDigest(claims.safety_case_digest, 'claims.safety_case_digest');
      assertString(claims.assessment, 'claims.assessment');
      break;
    case 'institutional_authority':
      assertString(claims.organization_id, 'claims.organization_id');
      assertString(claims.principal_id, 'claims.principal_id');
      assertString(claims.action_type, 'claims.action_type');
      assertString(claims.purpose_code, 'claims.purpose_code');
      assertString(claims.decision, 'claims.decision');
      break;
    case 'biosafety_review':
      assertDigest(claims.protocol_digest, 'claims.protocol_digest');
      assertDigest(claims.materials_commitment, 'claims.materials_commitment');
      assertString(claims.facility_id, 'claims.facility_id');
      assertString(claims.decision, 'claims.decision');
      break;
    case 'domain_screening':
      assertDigest(claims.materials_commitment, 'claims.materials_commitment');
      assertDigest(claims.destination_digest, 'claims.destination_digest');
      assertDigest(claims.screening_profile_digest, 'claims.screening_profile_digest');
      assertString(claims.decision, 'claims.decision');
      break;
    case 'human_authorization':
      assertString(claims.approver_id, 'claims.approver_id');
      assertString(claims.decision, 'claims.decision');
      if (!Object.hasOwn(ASSURANCE_RANK, claims.assurance_class)) throw new Error('claims.assurance_class is invalid');
      break;
    default:
      throw new Error('unsupported evidence_type');
  }
  if (body.outcome !== undefined && !['allow', 'deny', 'denied', 'refused'].includes(body.outcome)) {
    throw new Error('outcome is invalid');
  }
}

/** Sign a normalized evidence adapter output. The adapter is evidence, never certification. */
export function signModelToMatterEvidence(input, privateKey) {
  if (!isObject(input)) throw new Error('evidence input must be an object');
  const body = { ...clone(input), '@version': M2M_EVIDENCE_VERSION };
  assertEvidenceBody(body);
  const publicKey = publicKeyToB64u(privateKey);
  const evidenceDigest = `sha256:${sha256hex(signingBytes(EVIDENCE_DOMAIN, body))}`;
  return deepFreeze({
    ...body,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyIdFor(publicKey),
      public_key: publicKey,
      evidence_digest: evidenceDigest,
      signature_b64u: crypto.sign(null, signingBytes(EVIDENCE_DOMAIN, body), privateKey).toString('base64url'),
    },
  });
}

function claimsMatchAction(type, claims, action, requiredHumanAssurance) {
  if (!isObject(claims)) return false;
  switch (type) {
    case 'model_attestation':
      return claims.provider === action.model.provider
        && claims.model_id === action.model.model_id
        && claims.manifest_digest === action.model.manifest_digest
        && claims.harness_digest === action.model.harness_digest
        && claims.safeguards_digest === action.model.safeguards_digest;
    case 'safety_case_attestation':
      return claims.manifest_digest === action.model.manifest_digest
        && claims.harness_digest === action.model.harness_digest
        && claims.safeguards_digest === action.model.safeguards_digest
        && validDigest(claims.safety_case_digest)
        && claims.assessment === 'acceptable';
    case 'institutional_authority':
      return claims.organization_id === action.principal.organization_id
        && claims.principal_id === action.principal.principal_id
        && claims.action_type === action.action_type
        && claims.purpose_code === action.purpose.code
        && claims.decision === 'allow';
    case 'biosafety_review':
      return claims.protocol_digest === action.experiment.protocol_digest
        && claims.materials_commitment === action.experiment.materials_commitment
        && claims.facility_id === action.executor.facility_id
        && claims.decision === 'approve';
    case 'domain_screening':
      return claims.materials_commitment === action.experiment.materials_commitment
        && claims.destination_digest === action.destination_digest
        && validDigest(claims.screening_profile_digest)
        && claims.decision === 'pass';
    case 'human_authorization':
      return typeof claims.approver_id === 'string' && claims.approver_id.length > 0
        && claims.decision === 'approve'
        && Object.hasOwn(ASSURANCE_RANK, claims.assurance_class)
        && ASSURANCE_RANK[claims.assurance_class] >= ASSURANCE_RANK[requiredHumanAssurance];
    default:
      return false;
  }
}

/**
 * Verify signature first, then acceptance under caller-pinned issuer identity,
 * action, time, claims, and revocation state.
 */
export function verifyModelToMatterEvidence(artifact, opts = {}) {
  const output = (overrides = {}) => ({
    verified: false,
    accepted: false,
    revoked: false,
    reason: null,
    ...overrides,
  });
  if (!isObject(artifact) || artifact['@version'] !== M2M_EVIDENCE_VERSION) {
    return output({ reason: 'unsupported_version' });
  }
  const sig = verifySignature(artifact, EVIDENCE_DOMAIN, 'evidence_digest');
  if (!sig.verified) return output({ reason: sig.reason });
  const verified = output({
    verified: true,
    evidence_digest: sig.digest,
    issuer_id: artifact.issuer_id,
    evidence_type: artifact.evidence_type,
  });
  try { assertEvidenceBody(unsigned(artifact)); } catch { return { ...verified, reason: 'evidence_body_invalid' }; }
  if (opts.expectedType && artifact.evidence_type !== opts.expectedType) {
    return { ...verified, reason: 'wrong_type' };
  }
  let expectedAction;
  try {
    expectedAction = opts.expectedAction;
    assertAction(expectedAction);
  } catch {
    return { ...verified, reason: 'expected_action_invalid' };
  }
  if (artifact.action_digest !== modelToMatterActionDigest(expectedAction)) {
    return { ...verified, reason: 'action_binding_mismatch' };
  }
  const issuedAt = strictInstantMs(artifact.issued_at);
  const expiresAt = strictInstantMs(artifact.expires_at);
  const asOf = strictInstantMs(opts.as_of);
  if ([issuedAt, expiresAt, asOf].some(Number.isNaN) || expiresAt <= issuedAt) {
    return { ...verified, reason: 'invalid_time_window' };
  }
  if (issuedAt > asOf) return { ...verified, reason: 'not_yet_valid' };
  if (asOf >= expiresAt) return { ...verified, reason: 'expired' };

  const pins = Array.isArray(opts.pinnedIssuerKeys) ? opts.pinnedIssuerKeys : [];
  const keyMatches = pins.filter((pin) => pin?.public_key === artifact.signature.public_key);
  const acceptedPin = keyMatches.find((pin) => pin?.issuer_id === artifact.issuer_id);
  if (!acceptedPin) {
    return {
      ...verified,
      reason: keyMatches.length ? 'pin_missing_or_mismatched_issuer_id' : 'issuer_key_not_pinned',
    };
  }
  if (!claimsMatchAction(
    artifact.evidence_type,
    artifact.claims,
    expectedAction,
    opts.requiredHumanAssurance ?? 'class_a',
  )) {
    return { ...verified, reason: 'claims_do_not_match_action' };
  }
  const revoked = opts.revokedEvidenceDigests instanceof Set
    && opts.revokedEvidenceDigests.has(artifact.signature.evidence_digest);
  if (revoked) return { ...verified, revoked: true, reason: 'revoked' };
  return { ...verified, accepted: true, reason: null };
}

/** Build an EP-AEG graph whose identity is unchanged by any external storage choice. */
export function buildModelToMatterGraph(action, evidenceArtifacts) {
  const actionDigest = modelToMatterActionDigest(action);
  if (!Array.isArray(evidenceArtifacts)) throw new Error('evidenceArtifacts must be an array');
  const seen = new Set();
  const nodes = evidenceArtifacts.map((artifact) => {
    const type = artifact?.evidence_type;
    if (!M2M_EVIDENCE_TYPES.includes(type)) throw new Error(`unsupported evidence type ${type}`);
    if (seen.has(type)) throw new Error(`duplicate evidence type ${type}`);
    seen.add(type);
    return { id: artifactDigest(artifact), type, artifact: clone(artifact) };
  });
  return deepFreeze({
    '@version': EVIDENCE_GRAPH_VERSION,
    action_digest: actionDigest,
    nodes,
    edges: [],
  });
}

function graphIsSafeToEvaluate(graph) {
  try {
    if (!isObject(graph) || graph['@version'] !== EVIDENCE_GRAPH_VERSION) return false;
    assertOnlyKeys(graph, new Set(['@version', 'action_digest', 'nodes', 'edges']), 'graph');
    if (!validDigest(graph.action_digest) || !Array.isArray(graph.nodes)
      || !Array.isArray(graph.edges) || graph.edges.length !== 0) return false;
    const seen = new Set();
    for (const node of graph.nodes) {
      if (!isObject(node)) return false;
      assertOnlyKeys(node, new Set(['id', 'type', 'artifact']), 'graph node');
      if (!validDigest(node.id) || !M2M_EVIDENCE_TYPES.includes(node.type)
        || seen.has(node.type) || !isObject(node.artifact)) return false;
      seen.add(node.type);
      if (artifactDigest(node.artifact) !== node.id) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Mint and durably register the downstream executor's signed-over policy challenge. */
export async function createRegisteredModelToMatterChallenge(action, profile, opts = {}) {
  assertAction(action);
  assertProfile(profile);
  if (!profile.allowed_action_types.includes(action.action_type)) throw new Error('action_type is not allowed by the profile');
  return createRegisteredEvidenceChallenge(action, profile, opts);
}

function graphVerifiers(action, profile, asOf, revokedEvidenceDigests) {
  return Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, (artifact) => {
    const result = verifyModelToMatterEvidence(artifact, {
      expectedType: type,
      expectedAction: action,
      as_of: asOf,
      pinnedIssuerKeys: profile.accepted_issuers[type],
      requiredHumanAssurance: profile.required_human_assurance,
      revokedEvidenceDigests,
    });
    // Revocation is a verified fact about otherwise accepted evidence. Preserve
    // signature validity so the admissibility layer classifies it as stale /
    // revoked instead of confusing it with a broken signature.
    const valid = result.accepted || (result.verified && result.revoked);
    return {
      valid,
      action_digest: artifact?.action_digest ?? null,
      issued_at: artifact?.issued_at,
      outcome: artifact?.outcome,
      revoked: result.revoked,
    };
  }]));
}

const CLEARANCE_VERDICTS = Object.freeze({
  admissible: 'clear_to_execute',
  missing_evidence: 'do_not_execute_missing_evidence',
  stale: 'do_not_execute_stale_evidence',
  conflicted: 'do_not_execute_conflicted',
  unverifiable: 'do_not_execute_unverifiable',
  refused: 'do_not_execute_refused',
});

function clearanceResult(baseVerdict, data = {}) {
  return {
    '@version': M2M_CLEARANCE_VERSION,
    verdict: CLEARANCE_VERDICTS[baseVerdict] ?? 'do_not_execute_malformed',
    clear_to_execute: baseVerdict === 'admissible',
    base_verdict: baseVerdict,
    action_digest: data.action_digest ?? null,
    action_caid: data.action_caid ?? null,
    replay_digest: data.replay_digest ?? null,
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    next_challenge: data.next_challenge ?? null,
    reconciliation_required: data.reconciliation_required === true,
    graph: data.result?.graph ?? null,
  };
}

/**
 * Recompute the execution action, atomically consume the registered challenge,
 * verify every evidence leg under relying-party pins, then atomically consume
 * the action digest itself so separate challenges cannot clear it twice.
 * Storage errors map to a closed refusal with reconciliation required; there is
 * no in-memory fallback and no execution while the outcome is indeterminate.
 */
export async function evaluateRegisteredModelToMatterPresentation(input = {}) {
  let action;
  let profile;
  let challenge;
  let presentedGraph;
  let actionDigest;
  let actionCaid;
  try {
    action = deepFreeze(clone(input.action));
    profile = deepFreeze(clone(input.profile));
    challenge = deepFreeze(clone(input.challenge));
    presentedGraph = deepFreeze(clone(input.graph));
    assertAction(action);
    assertProfile(profile);
    actionDigest = modelToMatterActionDigest(action);
    actionCaid = modelToMatterCaid(action).caid;
  } catch (error) {
    return clearanceResult('malformed', { reasons: [`malformed input: ${error.message}`] });
  }
  const resultForAction = (baseVerdict, data = {}) => clearanceResult(baseVerdict, {
    action_digest: actionDigest,
    action_caid: actionCaid,
    ...data,
  });
  if (!profile.allowed_action_types.includes(action.action_type)) {
    return resultForAction('malformed', { reasons: ['action_type is not allowed by the profile'] });
  }
  if (challenge?.action_digest !== actionDigest) {
    return {
      ...resultForAction('action_mismatch', {
        reasons: ['execution action does not match the server-computed challenge action'],
      }),
      verdict: 'do_not_execute_action_mismatch',
    };
  }
  if (!(input.revokedEvidenceDigests instanceof Set)) {
    return resultForAction('refused', {
      reasons: ['explicit revocation state is required; absence is not proof of non-revocation'],
    });
  }
  if (typeof input.clearanceStore?.consume !== 'function') {
    return resultForAction('refused', {
      reasons: ['durable clearanceStore with atomic consume() is required'],
    });
  }
  const revokedEvidenceDigests = new Set(input.revokedEvidenceDigests);
  if ([...revokedEvidenceDigests].some((digest) => !validDigest(digest))) {
    return resultForAction('malformed', {
      reasons: ['revocation state contains a malformed evidence digest'],
    });
  }
  // The shared graph evaluator supports an open graph vocabulary. This profile
  // deliberately accepts only its closed, edge-free graph shape. Normalize any
  // structurally dangerous object to a refusal path before the generic digestor
  // sees it; the durable challenge is still consumed by that path.
  const graph = graphIsSafeToEvaluate(presentedGraph) ? presentedGraph : null;
  let base;
  try {
    base = await evaluateRegisteredPresentation(
      challenge,
      graph,
      profile,
      {
        challengeStore: input.challengeStore,
        verifiers: graphVerifiers(
          action,
          profile,
          input.as_of,
          revokedEvidenceDigests,
        ),
        as_of: input.as_of,
        nonce: input.next_nonce,
        next_expires_at: input.next_expires_at,
      },
    );
  } catch {
    return resultForAction('refused', {
      reasons: ['challenge storage is unavailable or its consumption outcome is indeterminate; execution is frozen pending reconciliation'],
      reconciliation_required: true,
    });
  }
  if (base.verdict === 'admissible') {
    let firstClearance;
    try {
      firstClearance = await input.clearanceStore.consume(`model-to-matter:${actionCaid}`);
    } catch {
      return resultForAction('refused', {
        replay_digest: base.replay_digest,
        reasons: ['action-consumption storage is unavailable or its outcome is indeterminate; execution is frozen pending reconciliation'],
        reconciliation_required: true,
        result: base.result,
      });
    }
    if (firstClearance !== true && firstClearance !== false) {
      return resultForAction('refused', {
        replay_digest: base.replay_digest,
        reasons: ['action-consumption store returned an ambiguous result; execution is frozen pending reconciliation'],
        reconciliation_required: true,
        result: base.result,
      });
    }
    if (firstClearance !== true) {
      return resultForAction('refused', {
        replay_digest: base.replay_digest,
        reasons: ['action has already received its one permitted clearance'],
        result: base.result,
      });
    }
  }
  return resultForAction(base.verdict, {
    replay_digest: base.replay_digest,
    reasons: base.reasons,
    next_challenge: base.next_challenge,
    result: base.result,
  });
}

/**
 * Production executor boundary. Trust configuration is captured once and can
 * never travel beside presenter-controlled action/challenge/graph input.
 */
export function createModelToMatterExecutor({
  profile,
  challengeStore,
  clearanceStore,
  revocationProvider,
  challengeTtlSec = 300,
  now = Date.now,
  allowEphemeralState = false,
} = {}) {
  let pinnedProfile;
  try {
    pinnedProfile = deepFreeze(clone(profile));
    assertProfile(pinnedProfile);
  } catch {
    throw new Error('Model-to-Matter executor requires a valid relying-party profile');
  }
  if (typeof challengeStore?.register !== 'function' || typeof challengeStore?.consume !== 'function') {
    throw new Error('Model-to-Matter executor requires a challenge store with register() and consume()');
  }
  if (typeof clearanceStore?.consume !== 'function') {
    throw new Error('Model-to-Matter executor requires an action clearance store with consume()');
  }
  if (!allowEphemeralState && (challengeStore.durable !== true
      || challengeStore.atomicRegistration !== true || challengeStore.bodyBound !== true
      || challengeStore.permanentConsumption !== true)) {
    throw new Error('Model-to-Matter executor requires durable body-bound atomic challenge custody');
  }
  if (!allowEphemeralState && (clearanceStore.durable !== true
      || clearanceStore.ownershipFenced !== true || clearanceStore.permanentConsumption !== true)) {
    throw new Error('Model-to-Matter executor requires durable non-expiring action consumption');
  }
  if (typeof revocationProvider !== 'function') {
    throw new Error('Model-to-Matter executor requires a relying-party revocation provider');
  }
  if (!Number.isSafeInteger(challengeTtlSec) || challengeTtlSec < 1 || challengeTtlSec > 86400) {
    throw new Error('Model-to-Matter challengeTtlSec must be an integer from 1 to 86400');
  }

  const registerChallenge = challengeStore.register.bind(challengeStore);
  const consumeChallenge = challengeStore.consume.bind(challengeStore);
  const consumeClearance = clearanceStore.consume.bind(clearanceStore);
  const getRevocations = revocationProvider;
  const pinnedChallengeStore = Object.freeze({
    durable: challengeStore.durable === true,
    atomicRegistration: true,
    bodyBound: true,
    permanentConsumption: true,
    register: registerChallenge,
    consume: consumeChallenge,
  });
  const pinnedClearanceStore = Object.freeze({
    durable: clearanceStore.durable === true,
    ownershipFenced: clearanceStore.ownershipFenced === true,
    permanentConsumption: clearanceStore.permanentConsumption === true,
    consume: consumeClearance,
  });
  let reconciliationFreeze = null;

  function frozenClearance() {
    return clearanceResult('refused', {
      reasons: [reconciliationFreeze ?? 'executor is frozen pending storage reconciliation'],
      reconciliation_required: true,
    });
  }

  function currentInstant() {
    try {
      const value = typeof now === 'function' ? now() : now;
      const date = value instanceof Date ? value : new Date(value);
      return Number.isFinite(date.getTime()) ? date.toISOString() : null;
    } catch {
      return null;
    }
  }

  function transactionTrustField(presentation) {
    for (const field of [
      'profile', 'challengeStore', 'clearanceStore', 'revokedEvidenceDigests',
      'revocationProvider', 'as_of', 'next_expires_at', 'next_nonce',
    ]) {
      if (Object.prototype.hasOwnProperty.call(presentation, field)) return field;
    }
    return null;
  }

  async function issueChallenge(action, options = {}) {
    if (reconciliationFreeze) {
      throw new Error('Model-to-Matter executor is frozen pending storage reconciliation');
    }
    if (!isObject(options)) throw new Error('Model-to-Matter challenge options must be an object');
    assertOnlyKeys(options, new Set(['nonce', 'challenge_id', 'obtain_hints']), 'challenge options');
    const asOf = currentInstant();
    if (!asOf) throw new Error('Model-to-Matter executor clock is invalid');
    let actionSnapshot;
    try {
      actionSnapshot = deepFreeze(clone(action));
      assertAction(actionSnapshot);
    } catch {
      throw new Error('Model-to-Matter executor action is invalid');
    }
    try {
      return await createRegisteredModelToMatterChallenge(actionSnapshot, pinnedProfile, {
        ...clone(options),
        expires_at: new Date(Date.parse(asOf) + challengeTtlSec * 1000).toISOString(),
        challengeStore: pinnedChallengeStore,
      });
    } catch {
      reconciliationFreeze = 'challenge registration storage failed; executor is frozen pending reconciliation';
      throw new Error('Model-to-Matter challenge registration failed; executor frozen pending storage reconciliation');
    }
  }

  async function evaluate(presentation = {}) {
    if (reconciliationFreeze) return frozenClearance();
    const asOf = currentInstant();
    if (!asOf) return clearanceResult('refused', { reasons: ['executor clock is unavailable or invalid'] });
    try {
      if (!isObject(presentation)) {
        return clearanceResult('malformed', { reasons: ['presentation must be an object'] });
      }
      const injected = transactionTrustField(presentation);
      if (injected) return clearanceResult('refused', {
        reasons: [`transaction-scoped trust configuration refused: ${injected}`],
      });
    } catch {
      return clearanceResult('malformed', { reasons: ['presentation inspection failed'] });
    }

    let actionSnapshot;
    let challengeSnapshot;
    let graphSnapshot;
    try {
      actionSnapshot = deepFreeze(clone(presentation.action));
      challengeSnapshot = deepFreeze(clone(presentation.challenge));
      graphSnapshot = deepFreeze(clone(presentation.graph));
      assertAction(actionSnapshot);
    } catch (error) {
      return clearanceResult('malformed', { reasons: [`malformed presentation: ${error.message}`] });
    }

    let revokedEvidenceDigests;
    try {
      const provided = await getRevocations({
        action_digest: modelToMatterActionDigest(actionSnapshot),
        challenge: challengeSnapshot,
        as_of: asOf,
      });
      if (!(provided instanceof Set)) throw new Error('revocation provider did not return a Set');
      revokedEvidenceDigests = new Set(provided);
    } catch {
      return clearanceResult('refused', {
        action_digest: modelToMatterActionDigest(actionSnapshot),
        reasons: ['revocation state is unavailable or malformed'],
      });
    }

    let result;
    try {
      result = await evaluateRegisteredModelToMatterPresentation({
        action: actionSnapshot,
        challenge: challengeSnapshot,
        graph: graphSnapshot,
        profile: pinnedProfile,
        as_of: asOf,
        challengeStore: pinnedChallengeStore,
        clearanceStore: pinnedClearanceStore,
        revokedEvidenceDigests,
        next_expires_at: new Date(Date.parse(asOf) + challengeTtlSec * 1000).toISOString(),
      });
    } catch {
      result = clearanceResult('refused', {
        reasons: ['clearance evaluation failed; executor is frozen pending storage reconciliation'],
        reconciliation_required: true,
      });
    }
    if (result.reconciliation_required === true) {
      reconciliationFreeze = result.reasons[0] ?? 'executor is frozen pending storage reconciliation';
    }
    return result;
  }

  async function run(presentation, effect) {
    if (typeof effect !== 'function') throw new Error('Model-to-Matter run() requires an effect function');
    let actionSnapshot;
    let challengeSnapshot;
    let graphSnapshot;
    try {
      if (!isObject(presentation)) throw new Error('presentation must be an object');
      const injected = transactionTrustField(presentation);
      if (injected) {
        return {
          ok: false,
          allow: false,
          clearance: clearanceResult('refused', {
            reasons: [`transaction-scoped trust configuration refused: ${injected}`],
          }),
        };
      }
      actionSnapshot = deepFreeze(clone(presentation?.action));
      challengeSnapshot = deepFreeze(clone(presentation?.challenge));
      graphSnapshot = deepFreeze(clone(presentation?.graph));
      assertAction(actionSnapshot);
    } catch {
      return { ok: false, allow: false, clearance: clearanceResult('malformed', { reasons: ['execution action is invalid'] }) };
    }
    const clearance = await evaluate({
      action: actionSnapshot,
      challenge: challengeSnapshot,
      graph: graphSnapshot,
    });
    if (clearance.clear_to_execute !== true || clearance.verdict !== 'clear_to_execute') {
      return { ok: false, allow: false, clearance };
    }
    const value = await effect({ action: actionSnapshot, clearance });
    return { ok: true, allow: true, clearance, value };
  }

  return Object.freeze({
    issueChallenge,
    evaluate,
    run,
    status: () => Object.freeze({
      frozen: reconciliationFreeze !== null,
      reconciliation_required: reconciliationFreeze !== null,
      reason: reconciliationFreeze,
    }),
    profile: pinnedProfile,
  });
}

function assertEffectBody(body) {
  assertNoRawContent(body);
  assertOnlyKeys(body, new Set([
    '@version', 'action_digest', 'action_caid', 'clearance_replay_digest',
    'executor_id', 'executed_at', 'status', 'observed_effect_digest',
  ]), 'effect');
  if (body['@version'] !== M2M_EFFECT_VERSION) throw new Error(`effect @version must be ${M2M_EFFECT_VERSION}`);
  assertDigest(body.action_digest, 'action_digest');
  if (typeof body.action_caid !== 'string' || !M2M_CAID_RE.test(body.action_caid)) {
    throw new Error('action_caid must be a Model-to-Matter CAID');
  }
  assertDigest(body.clearance_replay_digest, 'clearance_replay_digest');
  assertString(body.executor_id, 'executor_id');
  if (Number.isNaN(strictInstantMs(body.executed_at))) throw new Error('executed_at must be a valid RFC 3339 instant');
  if (!EFFECT_STATUSES.has(body.status)) throw new Error('effect status must be completed, failed, or aborted');
  assertDigest(body.observed_effect_digest, 'observed_effect_digest');
}

/** Sign what the executor states happened. This does not prove sensor truth. */
export function signModelToMatterEffect(input, privateKey) {
  if (!isObject(input)) throw new Error('effect input must be an object');
  assertAction(input.action);
  if (input.clearance?.['@version'] !== M2M_CLEARANCE_VERSION
    || input.clearance?.verdict !== 'clear_to_execute') {
    throw new Error('effect receipt requires a clear_to_execute clearance');
  }
  const actionDigest = modelToMatterActionDigest(input.action);
  const actionCaid = modelToMatterCaid(input.action).caid;
  if (input.clearance.action_digest !== actionDigest) throw new Error('clearance binds a different action');
  if (input.clearance.action_caid !== actionCaid) throw new Error('clearance binds a different CAID');
  if (input.executor_id !== input.action.executor.executor_id) throw new Error('executor_id does not match the action');
  const body = {
    '@version': M2M_EFFECT_VERSION,
    action_digest: actionDigest,
    action_caid: actionCaid,
    clearance_replay_digest: input.clearance.replay_digest,
    executor_id: input.executor_id,
    executed_at: input.executed_at,
    status: input.status,
    observed_effect_digest: input.observed_effect_digest,
  };
  assertEffectBody(body);
  if (strictInstantMs(body.executed_at) < strictInstantMs(input.action.requested_at)) {
    throw new Error('executed_at cannot be before the action was requested');
  }
  const publicKey = publicKeyToB64u(privateKey);
  const effectDigest = `sha256:${sha256hex(signingBytes(EFFECT_DOMAIN, body))}`;
  return deepFreeze({
    ...body,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyIdFor(publicKey),
      public_key: publicKey,
      effect_digest: effectDigest,
      signature_b64u: crypto.sign(null, signingBytes(EFFECT_DOMAIN, body), privateKey).toString('base64url'),
    },
  });
}

/** Verify the executor statement and keep the physical-truth limitation explicit. */
export function verifyModelToMatterEffect(effect, opts = {}) {
  const output = (overrides = {}) => ({
    verified: false,
    accepted: false,
    establishes_physical_truth: false,
    reason: null,
    ...overrides,
  });
  if (!isObject(effect) || effect['@version'] !== M2M_EFFECT_VERSION) return output({ reason: 'unsupported_version' });
  const sig = verifySignature(effect, EFFECT_DOMAIN, 'effect_digest');
  if (!sig.verified) return output({ reason: sig.reason });
  const verified = output({ verified: true, effect_digest: sig.digest });
  try { assertEffectBody(unsigned(effect)); } catch { return { ...verified, reason: 'effect_body_invalid' }; }
  let expectedAction;
  let expectedCaid;
  try {
    expectedAction = modelToMatterActionDigest(opts.expectedAction);
    expectedCaid = modelToMatterCaid(opts.expectedAction).caid;
  } catch { return { ...verified, reason: 'expected_action_invalid' }; }
  if (effect.action_digest !== expectedAction) return { ...verified, reason: 'action_binding_mismatch' };
  if (effect.action_caid !== expectedCaid) return { ...verified, reason: 'caid_binding_mismatch' };
  if (effect.clearance_replay_digest !== opts.expectedClearanceReplayDigest) {
    return { ...verified, reason: 'clearance_binding_mismatch' };
  }
  if (effect.executor_id !== opts.expectedAction.executor.executor_id) {
    return { ...verified, reason: 'executor_mismatch' };
  }
  if (strictInstantMs(effect.executed_at) < strictInstantMs(opts.expectedAction.requested_at)) {
    return { ...verified, reason: 'execution_before_action' };
  }
  const pins = Array.isArray(opts.pinnedExecutorKeys) ? opts.pinnedExecutorKeys : [];
  const pin = pins.find((candidate) => candidate?.executor_id === effect.executor_id
    && candidate?.public_key === effect.signature.public_key);
  if (!pin) return { ...verified, reason: 'executor_key_not_pinned' };
  return {
    ...verified,
    accepted: true,
    reason: null,
    limitation: 'The receipt proves what the pinned executor signed; it does not independently prove sensor accuracy or physical truth.',
  };
}

// Mutation and differential-test surface. These helpers are not protocol API;
// exporting them prevents security tests from reimplementing the decision math.
export const __modelToMatterSecurityInternals = Object.freeze({
  isObject,
  validDigest,
  strictInstantMs,
  deepFreeze,
  claimsMatchAction,
  graphIsSafeToEvaluate,
  clearanceResult,
});

const modelToMatter = {
  M2M_ACTION_VERSION,
  M2M_PROFILE_VERSION,
  M2M_EVIDENCE_VERSION,
  M2M_CLEARANCE_VERSION,
  M2M_EFFECT_VERSION,
  M2M_CAID_ACTION_TYPE,
  M2M_CAID_DEFINITION,
  M2M_EVIDENCE_TYPES,
  createModelToMatterAction,
  modelToMatterActionDigest,
  modelToMatterCaid,
  verifyModelToMatterCaid,
  createModelToMatterProfile,
  signModelToMatterEvidence,
  verifyModelToMatterEvidence,
  buildModelToMatterGraph,
  createRegisteredModelToMatterChallenge,
  evaluateRegisteredModelToMatterPresentation,
  createModelToMatterExecutor,
  signModelToMatterEffect,
  verifyModelToMatterEffect,
};

export default modelToMatter;

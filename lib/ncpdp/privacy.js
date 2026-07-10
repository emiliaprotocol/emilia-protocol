// SPDX-License-Identifier: Apache-2.0
/**
 * EP-NCPDP-RX-PRIVACY-PROFILE-v1
 *
 * The portable Rx sidecar carries pairwise references and keyed commitments,
 * never source patient or clinical records. This module is intentionally
 * strict: signed artifacts have exact field sets and the appeal bundle is a
 * projection, not a recursive copy of caller-controlled transaction objects.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';

export const RX_PRIVACY_VERSION = 'EP-NCPDP-RX-PRIVACY-PROFILE-v1';
export const RX_PRIVATE_BUNDLE_VERSION = 'EP-RX-RELIANCE-BUNDLE-v2';
export const RX_PAIRWISE_REF_RE = /^ep:patient-pairwise:v1:[A-Za-z0-9_-]{43}$/;
export const RX_PRIVATE_DIGEST_RE = /^hmac-sha256:[0-9a-f]{64}$/;

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const TOKEN_RE = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const ACTION_TOKEN_RE = /^[a-z][a-z0-9._-]{0,127}$/;
const MIN_SECRET_BYTES = 32;
const DOMAIN = Buffer.from('EP-NCPDP-RX-PRIVACY-v1\0', 'utf8');

const ARTIFACT_FIELDS = Object.freeze({
  'EP-RX-CONSENT-v1': new Set(['@type', 'action_hash', 'privacy_key_id', 'subject_ref', 'consent_digest', 'issued_at']),
  'EP-RX-CLINICAL-v1': new Set(['@type', 'action_hash', 'privacy_key_id', 'evidence_digest', 'criteria', 'issued_at']),
  'EP-RX-DENIAL-v1': new Set(['@type', 'action_hash', 'privacy_key_id', 'reason_code', 'reason_digest', 'appeal_url', 'issued_at']),
});
const SIGNATURE_FIELDS = new Set(['algorithm', 'public_key', 'digest', 'signature_b64u']);

function secretBytes(secret) {
  const bytes = Buffer.isBuffer(secret)
    ? Buffer.from(secret)
    : secret instanceof Uint8Array
      ? Buffer.from(secret)
      : null;
  if (!bytes || bytes.length < MIN_SECRET_BYTES) {
    throw new Error(`sector privacy key must be at least ${MIN_SECRET_BYTES} bytes`);
  }
  return bytes;
}

function keyedDigest(secret, purpose, value) {
  const key = secretBytes(secret);
  const bytes = Buffer.from(canonicalize(value), 'utf8');
  return `hmac-sha256:${crypto.createHmac('sha256', key).update(DOMAIN).update(purpose, 'utf8').update('\0').update(bytes).digest('hex')}`;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
}

function assertExactFields(value, allowed) {
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) throw new Error(`privacy profile forbids artifact field: ${field}`);
  }
}

function assertPrivacyKeyId(value) {
  if (typeof value !== 'string' || !TOKEN_RE.test(value)) throw new Error('privacy_key_id must be a stable token');
}

function assertInstant(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a canonical UTC instant`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC instant`);
  }
}

function assertSafeAppealUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('appeal_url must be a generic HTTPS route'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('appeal_url must be a generic HTTPS route without identity-bearing components');
  }
  // Generic route names only. Identifiers belong in the authenticated portal,
  // not in a portable evidence artifact.
  if (!/^\/(?:[A-Za-z][A-Za-z-]*\/?)*$/.test(url.pathname)) {
    throw new Error('appeal_url path must not contain an instance identifier');
  }
}

/** Derive a stable reference that cannot be correlated across relying parties. */
export function derivePairwisePatientRef({ patientIdentifier, relyingPartyId, privacyKeyId, sectorSecret } = {}) {
  if (typeof patientIdentifier !== 'string' || patientIdentifier.length === 0) throw new Error('patientIdentifier is required');
  if (typeof relyingPartyId !== 'string' || relyingPartyId.length === 0) throw new Error('relyingPartyId is required');
  assertPrivacyKeyId(privacyKeyId);
  const key = secretBytes(sectorSecret);
  const material = `${privacyKeyId}\0${relyingPartyId.normalize('NFC')}\0${patientIdentifier.normalize('NFC')}`;
  const digest = crypto.createHmac('sha256', key).update(DOMAIN).update('pairwise-patient-ref\0').update(material, 'utf8').digest('base64url');
  return `ep:patient-pairwise:v1:${digest}`;
}

/** Make a keyed commitment to a source record without exposing low-entropy data. */
export function commitRxEvidence({ evidenceType, record, privacyKeyId, sectorSecret } = {}) {
  if (typeof evidenceType !== 'string' || !TOKEN_RE.test(evidenceType)) throw new Error('evidenceType must be a stable token');
  assertPrivacyKeyId(privacyKeyId);
  if (record === undefined) throw new Error('record is required');
  return keyedDigest(sectorSecret, `evidence:${privacyKeyId}:${evidenceType}`, record);
}

/** Validate the exact privacy-safe wire shape before an artifact is signed or accepted. */
export function assertRxArtifactPrivacy(body) {
  assertPlainObject(body, 'artifact');
  const type = body['@type'];
  const allowed = ARTIFACT_FIELDS[type];
  if (!allowed) throw new Error('unsupported Rx artifact type');
  assertExactFields(body, allowed);
  if (!SHA256_RE.test(body.action_hash || '')) throw new Error('action_hash must be sha256');
  assertPrivacyKeyId(body.privacy_key_id);
  assertInstant(body.issued_at, 'issued_at');

  if (type === 'EP-RX-CONSENT-v1') {
    if (!RX_PAIRWISE_REF_RE.test(body.subject_ref || '')) throw new Error('subject_ref must be pairwise');
    if (!RX_PRIVATE_DIGEST_RE.test(body.consent_digest || '')) throw new Error('consent_digest must be a keyed commitment');
  } else if (type === 'EP-RX-CLINICAL-v1') {
    if (!RX_PRIVATE_DIGEST_RE.test(body.evidence_digest || '')) throw new Error('evidence_digest must be a keyed commitment');
    if (typeof body.criteria !== 'string' || !TOKEN_RE.test(body.criteria)) throw new Error('criteria must be a coded token');
  } else {
    if (!RX_PRIVATE_DIGEST_RE.test(body.reason_digest || '')) throw new Error('reason_digest must be a keyed commitment');
    if (typeof body.reason_code !== 'string' || !TOKEN_RE.test(body.reason_code)) throw new Error('reason_code must be a coded token');
    assertSafeAppealUrl(body.appeal_url);
  }
  return true;
}

/** The signature envelope is exact too; extensions cannot become a data tunnel. */
export function assertRxSignedArtifactPrivacy(artifact) {
  assertPlainObject(artifact, 'signed artifact');
  const { signature, ...body } = artifact;
  assertRxArtifactPrivacy(body);
  assertPlainObject(signature, 'signature');
  assertExactFields(signature, SIGNATURE_FIELDS);
  if (signature.algorithm !== 'Ed25519'
    || typeof signature.public_key !== 'string'
    || !/^[A-Za-z0-9_-]+$/.test(signature.public_key)
    || !SHA256_RE.test(signature.digest || '')
    || typeof signature.signature_b64u !== 'string'
    || !/^[A-Za-z0-9_-]+$/.test(signature.signature_b64u)) {
    throw new Error('signature envelope is not privacy-safe');
  }
  return true;
}

function safeArtifact(artifact) {
  if (artifact == null) return null;
  assertRxSignedArtifactPrivacy(artifact);
  return structuredClone(artifact);
}

function projectChecks(checks) {
  const source = checks && typeof checks === 'object' && !Array.isArray(checks) ? checks : {};
  const allowedKeys = ['base', 'prescriber_authority', 'patient_consent', 'clinical_evidence', 'benefit', 'signed_denial'];
  const allowedValues = new Set([null, true, false, 'fresh', 'stale', 'policy_mismatch']);
  const out = {};
  for (const key of allowedKeys) {
    const value = source[key] ?? null;
    out[key] = allowedValues.has(value) || (typeof value === 'string' && /^rx_(?:do_not_rely_[a-z_]+|rely)$/.test(value)) ? value : null;
  }
  return out;
}

function finiteNonNegative(value) {
  return Number.isFinite(value) && value >= 0 ? value : null;
}

/**
 * Build a PHI-minimized appeal bundle. Source records remain in the holder's
 * evidence vault; the portable bundle contains keyed references and the three
 * exact privacy-safe signed artifacts only.
 */
export function buildPrivateRxAppealBundle({ challenge, packet, result, now = Date.now(), privacyKey, privacyKeyId, retentionDays = 30 } = {}) {
  assertPlainObject(challenge, 'challenge');
  assertPlainObject(packet, 'packet');
  assertPlainObject(result, 'result');
  const nowMs = typeof now === 'number' ? now : Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error('now must be a valid instant');
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new Error('retentionDays must be an integer from 1 to 3650');
  }
  if (!/^rx_(?:do_not_rely_[a-z_]+|rely)$/.test(result.verdict || '')) throw new Error('result verdict is not closed');
  assertPrivacyKeyId(privacyKeyId);

  const action = packet.action && typeof packet.action === 'object' && !Array.isArray(packet.action) ? packet.action : {};
  if (!ACTION_TOKEN_RE.test(action.action_type || '')) throw new Error('action_type must be a stable token');
  if (!SHA256_RE.test(action.action_hash || '')) throw new Error('action_hash must be sha256');
  if (action.policy_hash != null && !SHA256_RE.test(action.policy_hash)) throw new Error('policy_hash must be sha256');

  const required = challenge.required && typeof challenge.required === 'object' && !Array.isArray(challenge.required) ? challenge.required : {};
  const generatedAt = new Date(nowMs).toISOString();
  const body = {
    '@type': RX_PRIVATE_BUNDLE_VERSION,
    privacy_profile: RX_PRIVACY_VERSION,
    projection_key_id: privacyKeyId,
    generated_at: generatedAt,
    purge_after: new Date(nowMs + retentionDays * 86400000).toISOString(),
    transaction: ACTION_TOKEN_RE.test(challenge.transaction || '') ? challenge.transaction : null,
    action: {
      action_type: action.action_type,
      action_hash: action.action_hash,
      policy_hash: action.policy_hash ?? null,
    },
    requirement_profile: {
      required_assurance: TOKEN_RE.test(challenge.required_assurance || '') ? challenge.required_assurance : null,
      prescriber_authority: required.prescriber_authority === true,
      patient_consent: required.patient_consent === true,
      clinical_evidence: required.clinical_evidence === true,
      signed_denial_required: required.signed_denial_required !== false,
      benefit_policy_hash: SHA256_RE.test(required.benefit_policy_hash || '') ? required.benefit_policy_hash : null,
      benefit_freshness_sec: finiteNonNegative(required.benefit_freshness_sec),
      revocation_freshness_sec: finiteNonNegative(required.revocation_freshness_sec),
    },
    verdict: result.verdict,
    determination: result.determination === 'deny' ? 'deny' : 'approve',
    checks: projectChecks(result.checks),
    evidence_refs: {
      challenge: keyedDigest(privacyKey, `${privacyKeyId}:challenge`, challenge),
      packet: keyedDigest(privacyKey, `${privacyKeyId}:packet`, packet),
      receipt: packet.receipt == null ? null : keyedDigest(privacyKey, `${privacyKeyId}:receipt`, packet.receipt),
      authority_proof: packet.authority_proof == null ? null : keyedDigest(privacyKey, `${privacyKeyId}:authority-proof`, packet.authority_proof),
      trust_roots: keyedDigest(privacyKey, `${privacyKeyId}:trust-roots`, {
        registry: challenge.accepted_registry_keys ?? [],
        receipt: challenge.accepted_issuer_keys ?? [],
        consent: challenge.accepted_consent_keys ?? [],
        clinical: challenge.accepted_clinical_keys ?? [],
        payer: challenge.accepted_payer_keys ?? [],
      }),
    },
    signed_artifacts: {
      patient_consent: safeArtifact(packet.patient_consent),
      clinical_evidence: safeArtifact(packet.clinical_evidence),
      signed_denial: safeArtifact(packet.signed_denial),
    },
  };
  return { ...body, bundle_digest: `sha256:${crypto.createHash('sha256').update(canonicalize(body), 'utf8').digest('hex')}` };
}

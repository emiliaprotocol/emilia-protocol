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
export const RX_DISCLOSURE_PROFILE_VERSION = 'EP-HEALTH-DISCLOSURE-PROFILE-v1';
export const RX_DISCLOSURE_VERDICTS = Object.freeze([
  'disclose',
  'refuse_no_profile',
  'refuse_malformed_bundle',
  'refuse_audience_mismatch',
  'refuse_purpose_mismatch',
  'refuse_policy_mismatch',
  'refuse_retention_exceeded',
  'refuse_expired',
  'refuse_artifact_not_allowed',
  'refuse_key_scope_mismatch',
]);
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
  'EP-RX-BENEFIT-v1': new Set(['@type', 'action_hash', 'privacy_key_id', 'policy_hash', 'issued_at']),
  'EP-RX-DENIAL-v1': new Set(['@type', 'action_hash', 'privacy_key_id', 'reason_code', 'reason_digest', 'appeal_url', 'issued_at']),
});
const SIGNATURE_FIELDS = new Set(['algorithm', 'public_key', 'digest', 'signature_b64u']);
const DISCLOSURE_PROFILE_FIELDS = new Set([
  '@type', 'audience', 'purpose_of_use', 'privacy_policy_hash',
  'max_retention_days', 'allowed_artifact_types',
]);
const BUNDLE_FIELDS = new Set([
  '@type', 'privacy_profile', 'projection_key_id', 'generated_at', 'purge_after',
  'transaction', 'action', 'requirement_profile', 'privacy_context', 'verdict',
  'determination', 'checks', 'evidence_refs', 'signed_artifacts', 'bundle_digest',
]);
const ACTION_FIELDS = new Set(['action_type', 'action_hash', 'policy_hash']);
const REQUIREMENT_FIELDS = new Set([
  'required_assurance', 'prescriber_authority', 'patient_consent', 'clinical_evidence',
  'signed_denial_required', 'benefit_policy_hash', 'benefit_freshness_sec',
  'revocation_freshness_sec',
]);
const PRIVACY_CONTEXT_FIELDS = new Set(['audience', 'purpose_of_use', 'privacy_policy_hash']);
const CHECK_FIELDS = new Set(['base', 'prescriber_authority', 'patient_consent', 'clinical_evidence', 'benefit', 'signed_denial']);
const EVIDENCE_REF_FIELDS = new Set(['challenge', 'packet', 'receipt', 'authority_proof', 'trust_roots']);
const SIGNED_ARTIFACT_FIELDS = new Set(['patient_consent', 'clinical_evidence', 'benefit_check', 'signed_denial']);
const RX_ARTIFACT_TYPES = new Set(ARTIFACT_FIELDS ? Object.keys(ARTIFACT_FIELDS) : []);
const PROJECTED_CHECK_VALUES = new Set([null, true, false, 'fresh', 'stale', 'policy_mismatch']);

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

function canonicalUtcMs(value) {
  if (typeof value !== 'string') return NaN;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value ? ms : NaN;
}

function assertInstant(value, label) {
  if (!Number.isFinite(canonicalUtcMs(value))) throw new Error(`${label} must be a canonical UTC instant`);
}

function assertSafeAppealUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('appeal_url must be a generic HTTPS route'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('appeal_url must be a generic HTTPS route without identity-bearing components');
  }
  // Generic route names only. Identifiers belong in the authenticated portal,
  // not in a portable evidence artifact.
  const segments = url.pathname.split('/').slice(1);
  if (segments.at(-1) === '') segments.pop();
  if (segments.some((segment) => !/^[A-Za-z][A-Za-z-]*$/.test(segment))) {
    throw new Error('appeal_url path must not contain an instance identifier');
  }
}

/** Derive a stable reference that cannot be correlated across relying parties. */
export function derivePairwisePatientRef({ patientIdentifier, relyingPartyId, privacyKeyId, sectorSecret } = {}) {
  if (typeof patientIdentifier !== 'string' || patientIdentifier.length === 0) throw new Error('patientIdentifier is required');
  if (typeof relyingPartyId !== 'string' || relyingPartyId.length === 0) throw new Error('relyingPartyId is required');
  assertPrivacyKeyId(privacyKeyId);
  const key = secretBytes(sectorSecret);
  const material = canonicalize({
    privacy_key_id: privacyKeyId,
    relying_party_id: relyingPartyId.normalize('NFC'),
    patient_identifier: patientIdentifier.normalize('NFC'),
  });
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
  } else if (type === 'EP-RX-BENEFIT-v1') {
    if (!SHA256_RE.test(body.policy_hash || '')) throw new Error('policy_hash must be sha256');
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
  const out = {};
  for (const key of allowedKeys) {
    const value = source[key] ?? null;
    out[key] = PROJECTED_CHECK_VALUES.has(value) || (typeof value === 'string' && /^rx_(?:do_not_rely_[a-z_]+|rely)$/.test(value)) ? value : null;
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
  if (result.determination !== 'approve' && result.determination !== 'deny') throw new Error('result determination must be approve or deny');
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
    privacy_context: {
      audience: TOKEN_RE.test(challenge.privacy_context?.audience || '') ? challenge.privacy_context.audience : null,
      purpose_of_use: TOKEN_RE.test(challenge.privacy_context?.purpose_of_use || '') ? challenge.privacy_context.purpose_of_use : null,
      privacy_policy_hash: SHA256_RE.test(challenge.privacy_context?.privacy_policy_hash || '')
        ? challenge.privacy_context.privacy_policy_hash
        : null,
    },
    verdict: result.verdict,
    determination: result.determination,
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
        benefit: challenge.accepted_benefit_keys ?? [],
        payer: challenge.accepted_payer_keys ?? [],
      }),
    },
    signed_artifacts: {
      patient_consent: safeArtifact(packet.patient_consent),
      clinical_evidence: safeArtifact(packet.clinical_evidence),
      benefit_check: safeArtifact(packet.benefit_check),
      signed_denial: safeArtifact(packet.signed_denial),
    },
  };
  return { ...body, bundle_digest: `sha256:${crypto.createHash('sha256').update(canonicalize(body), 'utf8').digest('hex')}` };
}

/**
 * Decide whether a PHI-minimized bundle may leave its holder for one pinned
 * audience and purpose. This is a disclosure decision, not a HIPAA-compliance
 * conclusion. It accepts only the exact projection produced above and never a
 * recursively copied transaction object.
 */
export function evaluateRxDisclosure({ bundle, profile, now = Date.now() } = {}) {
  const checks = {
    shape: false, digest: false, audience: false, purpose: false,
    policy: false, retention: false, artifacts: false, key_scope: false,
  };
  const deny = (verdict, reason) => ({ verdict, disclose: false, reasons: [reason], checks });
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)
    || profile['@type'] !== RX_DISCLOSURE_PROFILE_VERSION) {
    return deny('refuse_no_profile', 'no pinned EP-HEALTH-DISCLOSURE-PROFILE-v1 supplied');
  }
  try {
    assertExactFields(profile, DISCLOSURE_PROFILE_FIELDS);
  } catch (error) {
    return deny('refuse_no_profile', error.message);
  }
  if (!TOKEN_RE.test(profile.audience || '')
    || !TOKEN_RE.test(profile.purpose_of_use || '')
    || !SHA256_RE.test(profile.privacy_policy_hash || '')
    || !Number.isSafeInteger(profile.max_retention_days)
    || profile.max_retention_days < 1
    || profile.max_retention_days > 3650
    || !Array.isArray(profile.allowed_artifact_types)
    || new Set(profile.allowed_artifact_types).size !== profile.allowed_artifact_types.length
    || profile.allowed_artifact_types.some((type) => !RX_ARTIFACT_TYPES.has(type))) {
    return deny('refuse_no_profile', 'disclosure profile is malformed');
  }

  let body;
  try {
    assertPlainObject(bundle, 'bundle');
    assertExactFields(bundle, BUNDLE_FIELDS);
    if (bundle['@type'] !== RX_PRIVATE_BUNDLE_VERSION || bundle.privacy_profile !== RX_PRIVACY_VERSION) {
      throw new Error('bundle type or privacy profile is unsupported');
    }
    for (const [value, fields] of [
      [bundle.action, ACTION_FIELDS],
      [bundle.requirement_profile, REQUIREMENT_FIELDS],
      [bundle.privacy_context, PRIVACY_CONTEXT_FIELDS],
      [bundle.checks, CHECK_FIELDS],
      [bundle.evidence_refs, EVIDENCE_REF_FIELDS],
      [bundle.signed_artifacts, SIGNED_ARTIFACT_FIELDS],
    ]) {
      assertPlainObject(value, 'bundle member');
      assertExactFields(value, fields);
    }
    if (!ACTION_TOKEN_RE.test(bundle.action.action_type || '')
      || !SHA256_RE.test(bundle.action.action_hash || '')
      || (bundle.action.policy_hash != null && !SHA256_RE.test(bundle.action.policy_hash))
      || (bundle.transaction != null && !ACTION_TOKEN_RE.test(bundle.transaction))
      || !/^rx_(?:do_not_rely_[a-z_]+|rely)$/.test(bundle.verdict || '')
      || (bundle.determination !== 'approve' && bundle.determination !== 'deny')
      || !SHA256_RE.test(bundle.bundle_digest || '')
      || !TOKEN_RE.test(bundle.projection_key_id || '')) {
      throw new Error('bundle carries malformed binding fields');
    }
    const req = bundle.requirement_profile;
    if ((req.required_assurance != null && !TOKEN_RE.test(req.required_assurance))
      || !['prescriber_authority', 'patient_consent', 'clinical_evidence', 'signed_denial_required']
        .every((field) => typeof req[field] === 'boolean')
      || (req.benefit_policy_hash != null && !SHA256_RE.test(req.benefit_policy_hash))
      || !['benefit_freshness_sec', 'revocation_freshness_sec']
        .every((field) => req[field] == null || finiteNonNegative(req[field]) !== null)) {
      throw new Error('bundle requirement profile is malformed');
    }
    if (Object.values(bundle.checks).some((value) => !PROJECTED_CHECK_VALUES.has(value)
      && !(typeof value === 'string' && /^rx_(?:do_not_rely_[a-z_]+|rely)$/.test(value)))) {
      throw new Error('bundle checks are not closed values');
    }
    for (const value of Object.values(bundle.evidence_refs)) {
      if (value !== null && !RX_PRIVATE_DIGEST_RE.test(value || '')) throw new Error('bundle evidence reference is not keyed');
    }
    assertInstant(bundle.generated_at, 'generated_at');
    assertInstant(bundle.purge_after, 'purge_after');
    body = structuredClone(bundle);
    delete body.bundle_digest;
    const expectedDigest = `sha256:${crypto.createHash('sha256').update(canonicalize(body), 'utf8').digest('hex')}`;
    if (expectedDigest !== bundle.bundle_digest) throw new Error('bundle digest mismatch');
    checks.shape = true;
    checks.digest = true;
  } catch (error) {
    return deny('refuse_malformed_bundle', error.message);
  }

  if (bundle.privacy_context.audience !== profile.audience) {
    return deny('refuse_audience_mismatch', 'bundle audience does not match the pinned disclosure audience');
  }
  checks.audience = true;
  if (bundle.privacy_context.purpose_of_use !== profile.purpose_of_use) {
    return deny('refuse_purpose_mismatch', 'bundle purpose does not match the pinned purpose of use');
  }
  checks.purpose = true;
  if (bundle.privacy_context.privacy_policy_hash !== profile.privacy_policy_hash) {
    return deny('refuse_policy_mismatch', 'bundle privacy policy does not match the pinned policy');
  }
  checks.policy = true;

  const nowMs = typeof now === 'number' ? now : canonicalUtcMs(now);
  const generatedAt = canonicalUtcMs(bundle.generated_at);
  const purgeAfter = canonicalUtcMs(bundle.purge_after);
  const maxRetentionMs = profile.max_retention_days * 86400000;
  if (!Number.isFinite(nowMs) || nowMs < generatedAt || purgeAfter < generatedAt || (purgeAfter - generatedAt) > maxRetentionMs) {
    return deny('refuse_retention_exceeded', 'bundle retention exceeds the pinned disclosure limit');
  }
  checks.retention = true;
  if (nowMs >= purgeAfter) return deny('refuse_expired', 'bundle is at or past its purge boundary');

  const allowed = new Set(profile.allowed_artifact_types);
  for (const artifact of Object.values(bundle.signed_artifacts)) {
    if (artifact == null) continue;
    try { assertRxSignedArtifactPrivacy(artifact); } catch (error) {
      return deny('refuse_malformed_bundle', error.message);
    }
    if (!allowed.has(artifact['@type'])) {
      return deny('refuse_artifact_not_allowed', `artifact ${artifact['@type']} is outside the minimum-necessary profile`);
    }
    if (artifact.action_hash !== bundle.action.action_hash) {
      return deny('refuse_malformed_bundle', 'artifact action differs from the bundle action');
    }
    if (artifact.privacy_key_id !== bundle.projection_key_id) {
      return deny('refuse_key_scope_mismatch', 'artifact privacy key scope differs from the projection key scope');
    }
  }
  checks.artifacts = true;
  checks.key_scope = true;
  return { verdict: 'disclose', disclose: true, reasons: ['bundle satisfies the pinned minimum-necessary disclosure profile'], checks };
}

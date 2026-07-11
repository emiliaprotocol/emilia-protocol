// SPDX-License-Identifier: Apache-2.0
/**
 * @license Apache-2.0
 * EP-NCPDP-RX-RELIANCE-PROFILE-v1 — a companion reliance profile for pharmacy
 * transactions.
 *
 * We are NOT replacing NCPDP SCRIPT, Telecom, RTBP, ePA, Specialty Medication
 * Enrollment, or the Audit Transaction Standard. This is a portable evidence
 * SIDECAR: it rides beside an existing NCPDP transaction (bound to it by an
 * action digest) and lets every party — prescriber, pharmacy, hub, PBM, payer,
 * auditor — compute the SAME reliance verdict before approving, denying,
 * dispensing, transferring, or auditing a drug transaction.
 *
 * It composes the shipped EP-RELIANCE-KERNEL-v1 (packages/verify/reliance.js)
 * for the crypto-backed legs (prescriber authority, benefit policy pin,
 * revocation freshness, the device-bound ceremony) and adds the Rx-specific
 * evidence legs a drug prior-auth needs (patient consent, diagnosis/lab
 * evidence, RTBP benefit freshness, and a signed denial reason). Every
 * Rx-specific leg is an Ed25519-signed artifact carrying a keyed commitment to
 * the underlying record, never the record itself. Fail-closed throughout; VERIFIED (signature
 * checks) is kept separate from ACCEPTED (pinned issuer key).
 *
 * The wedge: CMS-0057-F pushes medical prior auth through FHIR APIs but
 * repeatedly EXCLUDES drugs from those requirements, leaving drug PA / pharmacy
 * benefit authorization as the NCPDP-owned gap. This profile is a concrete,
 * respectful candidate for that gap.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../../packages/verify/index.js';
import { evaluateReliance, RELIANCE_PROFILE_VERSION } from '../../packages/verify/reliance.js';
import {
  assertRxArtifactPrivacy,
  assertRxSignedArtifactPrivacy,
  buildPrivateRxAppealBundle,
  commitRxEvidence,
  derivePairwisePatientRef,
  evaluateRxDisclosure,
  RX_DISCLOSURE_PROFILE_VERSION,
  RX_DISCLOSURE_VERDICTS,
  RX_PRIVATE_BUNDLE_VERSION,
  RX_PRIVACY_VERSION,
} from './privacy.js';

export const RX_RELIANCE_VERSION = 'EP-NCPDP-RX-RELIANCE-PROFILE-v1';
export const RX_CHALLENGE_VERSION = 'EP-RX-EVIDENCE-CHALLENGE-v1';
export const RX_PACKET_VERSION = 'EP-RX-RELIANCE-PACKET-v1';
export const RX_BUNDLE_VERSION = RX_PRIVATE_BUNDLE_VERSION;
export const RX_ARTIFACT_DOMAIN = 'EP-RX-EVIDENCE-ARTIFACT-v1\0';

/** The CLOSED Rx reliance verdict set. `rx_rely` is the only success. */
export const RX_VERDICTS = Object.freeze([
  'rx_rely',
  'rx_do_not_rely_missing_prescriber_authority',
  'rx_do_not_rely_missing_patient_consent',
  'rx_do_not_rely_missing_clinical_evidence',
  'rx_do_not_rely_policy_mismatch',
  'rx_do_not_rely_stale_benefit',
  'rx_do_not_rely_signed_denial_required',
  'rx_do_not_rely_malformed_packet',
]);

// Base-kernel verdict -> Rx verdict. Every non-policy failure of the composed
// EP-RELIANCE-KERNEL (unsigned receipt, wrong/absent/revoked/expired/out-of-scope
// prescriber authority, unpinned registry, stale revocation of the authority)
// reads, in the Rx frame, as "the prescriber's authority for this exact request
// could not be relied on." Policy mismatch keeps its own Rx verdict.
const BASE_TO_RX = Object.freeze({
  do_not_rely_policy_mismatch: 'rx_do_not_rely_policy_mismatch',
});
const mapBaseToRx = (v) => BASE_TO_RX[v] || 'rx_do_not_rely_missing_prescriber_authority';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

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

function artifactSigningBytes(unsigned) {
  return Buffer.from(RX_ARTIFACT_DOMAIN + canonicalize(unsigned), 'utf8');
}

/**
 * Sign an Rx evidence artifact (patient consent / clinical evidence / signed
 * denial). The body carries a DIGEST of the underlying record and no PHI.
 * `privateKey` is a Node Ed25519 KeyObject held by the issuer (consent service,
 * EHR, payer). For issuers and test/demo use.
 */
export function signRxArtifact(body, privateKey) {
  if (!body || typeof body !== 'object' || typeof body['@type'] !== 'string') {
    throw new Error('artifact body needs an @type');
  }
  assertRxArtifactPrivacy(body);
  const publicKeyObject = crypto.createPublicKey(privateKey);
  if (publicKeyObject.asymmetricKeyType !== 'ed25519') throw new Error('Rx artifacts require an Ed25519 signing key');
  const publicKey = publicKeyObject.export({ type: 'spki', format: 'der' }).toString('base64url');
  const digest = `sha256:${sha256hex(artifactSigningBytes(body))}`;
  const signature_b64u = crypto.sign(null, artifactSigningBytes(body), privateKey).toString('base64url');
  // Deep-copy body into the signed artifact (same fix as the reliance-profile
  // registry sibling): a shallow spread would leave the caller's nested objects
  // live, so mutating them after signing would diverge the artifact from its digest.
  return { ...structuredClone(body), signature: { algorithm: 'Ed25519', public_key: publicKey, digest, signature_b64u } };
}

/**
 * Verify an Rx evidence artifact. FAIL-CLOSED, VERIFIED vs ACCEPTED kept
 * separate: `verified` = signature + digest hold and the artifact binds the
 * expected type and action hash; `accepted` = verified AND the issuer key is
 * pinned by the relying party AND (if a staleness bound is supplied) fresh.
 */
export function verifyRxArtifact(artifact, opts = {}) {
  const out = { verified: false, accepted: false, reason: null };
  if (!artifact || typeof artifact !== 'object') return { ...out, reason: 'absent' };
  if (opts.expectType && artifact['@type'] !== opts.expectType) return { ...out, reason: 'wrong_type' };
  const sig = artifact.signature;
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string' || typeof sig.signature_b64u !== 'string' || !SHA256_RE.test(sig.digest || '')) {
    return { ...out, reason: 'signature_malformed' };
  }
  try { assertRxSignedArtifactPrivacy(artifact); } catch { return { ...out, reason: 'privacy_profile_violation' }; }
  const { signature: _s, ...body } = artifact;
  let digest;
  try { digest = `sha256:${sha256hex(artifactSigningBytes(body))}`; } catch { return { ...out, reason: 'uncanonicalizable' }; }
  if (digest !== sig.digest) return { ...out, reason: 'digest_mismatch' };
  if (opts.expectActionHash && artifact.action_hash !== opts.expectActionHash) return { ...out, reason: 'action_binding_mismatch' };

  let ok = false;
  try {
    const pk = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    if (pk.asymmetricKeyType !== 'ed25519') return { ...out, reason: 'signature_invalid' };
    ok = crypto.verify(null, artifactSigningBytes(body), pk, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch { ok = false; }
  if (!ok) return { ...out, reason: 'signature_invalid' };
  out.verified = true;

  const pinned = Array.isArray(opts.pinnedKeys) ? opts.pinnedKeys : [];
  if (pinned.length === 0 || !pinned.includes(sig.public_key)) return { ...out, reason: 'issuer_key_not_pinned' };
  if (opts.now !== undefined || opts.maxStalenessSec !== undefined) {
    const at = strictInstantMs(artifact.issued_at);
    const bounded = opts.maxStalenessSec !== undefined;
    if (!Number.isFinite(opts.now) || Number.isNaN(at) || at > opts.now
      || (bounded && (!Number.isFinite(opts.maxStalenessSec) || opts.maxStalenessSec < 0
        || (opts.now - at) > opts.maxStalenessSec * 1000))) {
      return { ...out, reason: 'stale' };
    }
  }
  out.accepted = true;
  return out;
}

function toMs(t) {
  if (t == null) return Date.now();
  if (typeof t === 'number') return Number.isFinite(t) ? t : NaN;
  if (t instanceof Date) return t.getTime();
  if (typeof t !== 'string') return NaN;
  return strictInstantMs(t);
}

/**
 * Evaluate an EP-RX-RELIANCE-PACKET-v1 against an EP-RX-EVIDENCE-CHALLENGE-v1.
 * Returns one CLOSED rx verdict. Deterministic precedence, fail-closed.
 *
 * `rx_rely` covers BOTH a reliable APPROVE (all evidence composes -> dispense)
 * and a reliable DENY (a signed, reasoned denial that another party may rely on
 * and appeal against). Reliance is not approval; a signed denial is equally
 * relyable. `result.determination` says which.
 *
 * @param {object} input { challenge, packet, now }
 * @param {object} [opts] verifier options for the base kernel { approverKeys, logPublicKey, rpId, revokerKeys }
 */
export function evaluateRxReliance({ challenge, packet, now } = {}, opts = {}) {
  const nowMs = toMs(now);
  const reasons = [];
  const checks = { base: null, prescriber_authority: null, patient_consent: null, clinical_evidence: null, benefit: null, signed_denial: null };
  const determination = packet?.determination === 'approve' || packet?.determination === 'deny'
    ? packet.determination
    : null;
  const deny = (verdict, reason, extra = {}) => { reasons.push(reason); return { verdict, rely: false, reasons, checks, base_verdict: extra.base ?? null, determination }; };

  if (!challenge || challenge['@type'] !== RX_CHALLENGE_VERSION) return deny('rx_do_not_rely_missing_prescriber_authority', 'no pinned EP-RX-EVIDENCE-CHALLENGE-v1');
  if (!packet || challenge && packet['@type'] !== RX_PACKET_VERSION) return deny('rx_do_not_rely_missing_prescriber_authority', 'no EP-RX-RELIANCE-PACKET-v1 supplied');
  if (!determination) return deny('rx_do_not_rely_malformed_packet', 'packet determination must be approve or deny');
  if (challenge.required != null && (typeof challenge.required !== 'object' || Array.isArray(challenge.required))) {
    return deny('rx_do_not_rely_malformed_packet', 'challenge required profile must be an object');
  }
  if (challenge.required === null) return deny('rx_do_not_rely_malformed_packet', 'challenge required profile must not be null');
  const req = challenge.required ?? {};

  const actionHash = packet.action?.action_hash;

  // ── 1. Base kernel: receipt + prescriber authority + policy + revocation ───
  const baseProfile = {
    '@type': RELIANCE_PROFILE_VERSION,
    required_assurance: challenge.required_assurance || 'class_a',
    required_authority: req.prescriber_authority === true,
    max_revocation_staleness_sec: req.revocation_freshness_sec ?? null,
    accepted_registry_keys: challenge.accepted_registry_keys || [],
    accepted_issuer_keys: challenge.accepted_issuer_keys || [],
    accepted_policy_hashes: req.benefit_policy_hash ? [req.benefit_policy_hash] : [],
    required_evidence: ['receipt', 'authority_proof']
      .concat(req.revocation_freshness_sec != null ? ['revocation_freshness'] : []),
  };
  const base = evaluateReliance({
    action: packet.action,
    receipt: packet.receipt,
    authority_proof: packet.authority_proof,
    revocation_state: packet.revocation_state,
    relying_party_profile: baseProfile,
    now: nowMs,
  }, opts);
  checks.base = base.verdict;
  if (base.verdict !== 'rely') {
    const rx = mapBaseToRx(base.verdict);
    checks[rx === 'rx_do_not_rely_policy_mismatch' ? 'benefit' : 'prescriber_authority'] = false;
    return deny(rx, `base kernel: ${base.verdict} — ${(base.reasons || []).slice(-1)[0] || ''}`, { base: base.verdict });
  }
  checks.prescriber_authority = true;

  // ── 2. A DENY is relyable only if the denial reason is signed and bound ────
  if (determination === 'deny') {
    if (req.signed_denial_required !== false) {
      const d = verifyRxArtifact(packet.signed_denial, {
        expectType: 'EP-RX-DENIAL-v1', expectActionHash: actionHash,
        pinnedKeys: challenge.accepted_payer_keys || [], now: nowMs,
      });
      checks.signed_denial = d.accepted;
      if (!d.accepted) return deny('rx_do_not_rely_signed_denial_required', `denial reason not signed/accepted: ${d.reason}`, { base: base.verdict });
    }
    reasons.push('denial is signed, reasoned, and bound to this action: admissible and appeal-ready');
    return { verdict: 'rx_rely', rely: true, reasons, checks, base_verdict: base.verdict, determination: 'deny' };
  }

  // ── 3. APPROVE path: patient consent, clinical evidence, benefit freshness ─
  if (req.patient_consent) {
    const c = verifyRxArtifact(packet.patient_consent, { expectType: 'EP-RX-CONSENT-v1', expectActionHash: actionHash, pinnedKeys: challenge.accepted_consent_keys || [], now: nowMs });
    checks.patient_consent = c.accepted;
    if (!c.accepted) return deny('rx_do_not_rely_missing_patient_consent', `patient consent not present/accepted: ${c.reason}`, { base: base.verdict });
  }
  if (req.clinical_evidence) {
    const c = verifyRxArtifact(packet.clinical_evidence, { expectType: 'EP-RX-CLINICAL-v1', expectActionHash: actionHash, pinnedKeys: challenge.accepted_clinical_keys || [], now: nowMs });
    checks.clinical_evidence = c.accepted;
    if (!c.accepted) return deny('rx_do_not_rely_missing_clinical_evidence', `diagnosis/lab evidence not present/accepted: ${c.reason}`, { base: base.verdict });
  }
  if (req.benefit_policy_hash) {
    const b = packet.benefit_check;
    const at = b?.checked_at ? strictInstantMs(b.checked_at) : NaN;
    const fresh = !Number.isNaN(at) && (req.benefit_freshness_sec == null || (nowMs - at) <= req.benefit_freshness_sec * 1000) && at <= nowMs;
    if (!b || !fresh) { checks.benefit = 'stale'; return deny('rx_do_not_rely_stale_benefit', 'RTBP benefit/formulary check is missing or older than the pinned freshness bound', { base: base.verdict }); }
    if (b.policy_hash !== req.benefit_policy_hash) { checks.benefit = 'policy_mismatch'; return deny('rx_do_not_rely_policy_mismatch', 'the RTBP benefit check cites a different formulary policy than the challenge', { base: base.verdict }); }
    checks.benefit = 'fresh';
  }

  reasons.push('prescriber authority, patient consent, diagnosis/lab evidence, pinned formulary policy, and a fresh benefit check all compose');
  return { verdict: 'rx_rely', rely: true, reasons, checks, base_verdict: base.verdict, determination: 'approve' };
}

/**
 * Export a portable audit / appeal bundle as a privacy-safe projection. The
 * submitted challenge, receipt, authority proof, and packet remain in the
 * holder's evidence vault; the bundle carries keyed references plus the exact
 * privacy-safe signed artifacts needed for selective re-performance.
 */
export function buildRxAppealBundle(input) {
  return buildPrivateRxAppealBundle(input);
}

export {
  commitRxEvidence,
  derivePairwisePatientRef,
  evaluateRxDisclosure,
  RX_DISCLOSURE_PROFILE_VERSION,
  RX_DISCLOSURE_VERDICTS,
  RX_PRIVACY_VERSION,
};

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
 * Rx-specific leg is an Ed25519-signed artifact carrying a DIGEST of the
 * underlying record, never PHI. Fail-closed throughout; VERIFIED (signature
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

export const RX_RELIANCE_VERSION = 'EP-NCPDP-RX-RELIANCE-PROFILE-v1';
export const RX_CHALLENGE_VERSION = 'EP-RX-EVIDENCE-CHALLENGE-v1';
export const RX_PACKET_VERSION = 'EP-RX-RELIANCE-PACKET-v1';
export const RX_BUNDLE_VERSION = 'EP-RX-RELIANCE-BUNDLE-v1';
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
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

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
  const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  const digest = `sha256:${sha256hex(artifactSigningBytes(body))}`;
  const signature_b64u = crypto.sign(null, artifactSigningBytes(body), privateKey).toString('base64url');
  return { ...body, signature: { algorithm: 'Ed25519', public_key: publicKey, digest, signature_b64u } };
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
  const { signature: _s, ...body } = artifact;
  let digest;
  try { digest = `sha256:${sha256hex(artifactSigningBytes(body))}`; } catch { return { ...out, reason: 'uncanonicalizable' }; }
  if (digest !== sig.digest) return { ...out, reason: 'digest_mismatch' };
  if (opts.expectActionHash && artifact.action_hash !== opts.expectActionHash) return { ...out, reason: 'action_binding_mismatch' };

  let ok = false;
  try {
    const pk = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    ok = crypto.verify(null, artifactSigningBytes(body), pk, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch { ok = false; }
  if (!ok) return { ...out, reason: 'signature_invalid' };
  out.verified = true;

  const pinned = Array.isArray(opts.pinnedKeys) ? opts.pinnedKeys : [];
  if (pinned.length > 0 && !pinned.includes(sig.public_key)) return { ...out, reason: 'issuer_key_not_pinned' };
  if (Number.isFinite(opts.maxStalenessSec) && Number.isFinite(opts.now)) {
    const at = artifact.issued_at ? Date.parse(artifact.issued_at) : NaN;
    if (Number.isNaN(at) || (opts.now - at) > opts.maxStalenessSec * 1000) return { ...out, reason: 'stale' };
  }
  out.accepted = true;
  return out;
}

function toMs(t) {
  if (t == null) return Date.now();
  if (typeof t === 'number') return t;
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? Date.now() : ms;
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
  // typeof null === 'object', so guard null explicitly: a challenge with
  // required:null must fall back to {}, not become req=null and throw downstream.
  const req = (challenge && challenge.required !== null && typeof challenge.required === 'object') ? challenge.required : {};
  const deny = (verdict, reason, extra = {}) => { reasons.push(reason); return { verdict, rely: false, reasons, checks, base_verdict: extra.base ?? null, determination: packet?.determination ?? 'approve' }; };

  if (!challenge || challenge['@type'] !== RX_CHALLENGE_VERSION) return deny('rx_do_not_rely_missing_prescriber_authority', 'no pinned EP-RX-EVIDENCE-CHALLENGE-v1');
  if (!packet || challenge && packet['@type'] !== RX_PACKET_VERSION) return deny('rx_do_not_rely_missing_prescriber_authority', 'no EP-RX-RELIANCE-PACKET-v1 supplied');

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
      .concat(req.revocation_freshness_sec ? ['revocation_freshness'] : []),
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

  const determination = packet.determination === 'deny' ? 'deny' : 'approve';

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
    const at = b?.checked_at ? Date.parse(b.checked_at) : NaN;
    const fresh = !Number.isNaN(at) && (req.benefit_freshness_sec == null || (nowMs - at) <= req.benefit_freshness_sec * 1000) && at <= nowMs;
    if (!b || !fresh) { checks.benefit = 'stale'; return deny('rx_do_not_rely_stale_benefit', 'RTBP benefit/formulary check is missing or older than the pinned freshness bound', { base: base.verdict }); }
    if (b.policy_hash !== req.benefit_policy_hash) { checks.benefit = 'policy_mismatch'; return deny('rx_do_not_rely_policy_mismatch', 'the RTBP benefit check cites a different formulary policy than the challenge', { base: base.verdict }); }
    checks.benefit = 'fresh';
  }

  reasons.push('prescriber authority, patient consent, diagnosis/lab evidence, pinned formulary policy, and a fresh benefit check all compose');
  return { verdict: 'rx_rely', rely: true, reasons, checks, base_verdict: base.verdict, determination: 'approve' };
}

/**
 * Export a portable audit / appeal bundle: the challenge, the packet, the
 * verdict, and its reasons, content-addressed so any party (pharmacy, hub, PBM,
 * payer, auditor, or the patient's advocate on appeal) can re-verify the same
 * verdict offline. Carries digests, not PHI.
 */
export function buildRxAppealBundle({ challenge, packet, result, now = null }) {
  const body = {
    '@type': RX_BUNDLE_VERSION,
    generated_at: now,
    transaction: challenge?.transaction ?? null,
    action_hash: packet?.action?.action_hash ?? null,
    challenge,
    packet,
    verdict: result?.verdict ?? null,
    determination: result?.determination ?? null,
    reasons: result?.reasons ?? [],
    checks: result?.checks ?? null,
  };
  return { ...body, bundle_digest: `sha256:${sha256hex(Buffer.from(canonicalize(body), 'utf8'))}` };
}

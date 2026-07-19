// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-DOC-v1 — explicit issuer-key introduction and rotation.
 *
 * This component does not create trust. It lets a relying party bind its own
 * trust inputs to a reproducible issuer-key history and keep verification
 * separate from acceptance.
 *
 * THE DESIGN
 * 1. Make the bootstrap CHECKABLE: an Authority Document — a signed,
 *    hash-chained, sequence-numbered declaration of an org's issuer keys
 *    (with validity windows and custody classes), served from the org's own
 *    domain and registrable to a transparency log. Rotations chain by
 *    prev_doc_digest and carry a continuity signature by a key from the
 *    PREVIOUS document (TUF-style root continuity).
 * 2. Make history LOAD-BEARING: keys carry validity windows and optional
 *    revocation; verification of an artifact resolves the key that was valid
 *    AT ISSUANCE, so rotation never breaks old receipts and compromise never
 *    retroactively voids honest history.
 * 3. Make acceptance a GRADED, REPLAYABLE VERDICT, not a config file:
 *    introduction evidence (chain consistency, domain binding, log inclusion
 *    and age, endorsements by the relying party's pinned anchors) is
 *    evaluated under a RELYING-PARTY policy per action class, reusing the
 *    admissibility layer. Additional evidence can satisfy an unchanged policy;
 *    it never changes the policy or compels acceptance.
 */
import crypto from 'node:crypto';
import { evaluateAdmissibility } from '../evidence/admissibility.js';

export const AUTHORITY_DOC_VERSION = 'EP-AUTHORITY-DOC-v1';

// Deterministic JCS-style canonicalization (I-JSON subset; no floats) —
// byte-identical to lib/evidence/admissibility.js canon().
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const toKey = (b64url) => crypto.createPublicKey({ key: Buffer.from(b64url, 'base64url'), type: 'spki', format: 'der' });
const keyId = (b64url) => sha256hex(Buffer.from(b64url, 'base64url')).slice(0, 16);

/** Digest of a document's signed core (everything except sig + endorsements). */
export function docCoreDigest(doc) {
  const { sig, continuity_sig, endorsements, ...core } = doc;
  return `sha256:${sha256hex(canon(core))}`;
}

/**
 * Create (or rotate) an authority document.
 * @param {object} p {org:{name,domain}, issuer_keys:[{key,usages?,custody_class?,valid_from,valid_to,roles?,revoked_at?}], issued_at}
 * @param {import('node:crypto').KeyObject} rootPrivateKey    signs THIS document
 * @param {object} [prev]               {doc, continuityPrivateKey} — required for rotations:
 *                                      continuityPrivateKey must correspond to a key in prev.doc
 */
export function createAuthorityDoc(p, rootPrivateKey, prev = null) {
  const rootPub = crypto.createPublicKey(/** @type {*} */ (rootPrivateKey)).export({ type: 'spki', format: 'der' }).toString('base64url');
  const core = {
    '@version': AUTHORITY_DOC_VERSION,
    org: p.org,
    seq: prev ? prev.doc.seq + 1 : 0,
    prev_doc_digest: prev ? docCoreDigest(prev.doc) : null,
    root_key: rootPub,
    issuer_keys: p.issuer_keys.map((k) => ({ kid: k.kid ?? keyId(k.key), ...k })),
    issued_at: p.issued_at,
  };
  /** @type {typeof core & { sig: string, continuity_sig?: string }} */
  const doc = { ...core, sig: crypto.sign(null, Buffer.from(canon(core), 'utf8'), rootPrivateKey).toString('base64url') };
  if (prev) {
    doc.continuity_sig = crypto.sign(null, Buffer.from(docCoreDigest(doc), 'utf8'), prev.continuityPrivateKey).toString('base64url');
  }
  return doc;
}

/** Endorse a document: another authority countersigns its core digest. */
export function endorseAuthorityDoc(doc, endorserOrg, endorserPrivateKey) {
  const endorserKey = crypto.createPublicKey(endorserPrivateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    by_org: endorserOrg,
    by_key: endorserKey,
    doc_digest: docCoreDigest(doc),
    sig: crypto.sign(null, Buffer.from(docCoreDigest(doc), 'utf8'), endorserPrivateKey).toString('base64url'),
  };
}

/**
 * Verify an authority chain (docs ordered by seq). FAIL-CLOSED.
 * Checks: version, sequence, hash chaining, self-signatures, and continuity
 * signatures (each rotation signed by a key that was valid in the previous
 * document). A rotation WITHOUT valid continuity is flagged, not silently
 * accepted — the relying party's policy decides whether endorsements can
 * substitute (the compromise-recovery path).
 */
export function verifyAuthorityChain(docs) {
  const reasons = [];
  if (!Array.isArray(docs) || docs.length === 0) return { verified: false, head: null, breaks: [], reasons: ['empty chain'] };
  const breaks = [];
  for (let i = 0; i < docs.length; i++) {
    const d = docs[i];
    if (d['@version'] !== AUTHORITY_DOC_VERSION) { reasons.push(`doc ${i}: bad version`); return { verified: false, head: null, breaks, reasons }; }
    if (d.seq !== i) { reasons.push(`doc ${i}: seq ${d.seq} != ${i}`); return { verified: false, head: null, breaks, reasons }; }
    const { sig, continuity_sig, endorsements, ...core } = d;
    let selfOk = false;
    try { selfOk = crypto.verify(null, Buffer.from(canon(core), 'utf8'), toKey(d.root_key), Buffer.from(sig, 'base64url')); } catch { selfOk = false; }
    if (!selfOk) { reasons.push(`doc ${i}: self-signature invalid`); return { verified: false, head: null, breaks, reasons }; }
    if (i === 0) {
      if (d.prev_doc_digest !== null) { reasons.push('doc 0: unexpected prev digest'); return { verified: false, head: null, breaks, reasons }; }
      continue;
    }
    const prev = docs[i - 1];
    if (d.prev_doc_digest !== docCoreDigest(prev)) { reasons.push(`doc ${i}: prev digest mismatch (fork/equivocation)`); return { verified: false, head: null, breaks, reasons }; }
    // Continuity: signed by prev root key OR any non-revoked prev issuer key.
    const prevKeys = [prev.root_key, ...prev.issuer_keys.filter((k) => !k.revoked_at).map((k) => k.key)];
    const digest = Buffer.from(docCoreDigest(d), 'utf8');
    const contOk = typeof continuity_sig === 'string' && prevKeys.some((k) => {
      try { return crypto.verify(null, digest, toKey(k), Buffer.from(continuity_sig, 'base64url')); } catch { return false; }
    });
    if (!contOk) { breaks.push(i); reasons.push(`doc ${i}: NO valid continuity from doc ${i - 1} (compromise-recovery path; policy decides)`); }
  }
  return { verified: true, head: docs[docs.length - 1], breaks, reasons };
}

/**
 * Resolve the issuer key valid AT a given time — the invariant that makes
 * rotation safe: an artifact verifies against the key that was valid when it
 * was issued, and a later revocation voids the key only for signatures
 * claimed AFTER revoked_at (honest history survives compromise).
 */
export function resolveIssuerKeyAt(docs, kid, atISO) {
  const at = Date.parse(atISO);
  if (Number.isNaN(at)) return null;
  // Newest-first, and the NEWEST document that mentions a kid is
  // authoritative for it: a revocation recorded in doc N must not be
  // undone by falling through to the pre-revocation entry in doc N-1.
  for (let i = docs.length - 1; i >= 0; i--) {
    const entries = docs[i].issuer_keys.filter((k) => k.kid === kid);
    if (entries.length === 0) continue;
    for (const k of entries) {
      const from = Date.parse(k.valid_from), to = Date.parse(k.valid_to);
      if (at < from || at > to) continue;
      if (k.revoked_at && at >= Date.parse(k.revoked_at)) continue;
      return {
        key: k.key,
        usages: Array.isArray(k.usages) ? [...k.usages] : [],
        custody_class: k.custody_class ?? null,
        doc_seq: docs[i].seq,
      };
    }
    return null; // kid known to this doc, no valid entry — do NOT consult older docs
  }
  return null;
}

/** Verify one endorsement against the doc it claims to endorse. */
export function verifyEndorsement(e, doc) {
  if (e?.doc_digest !== docCoreDigest(doc)) return false;
  try { return crypto.verify(null, Buffer.from(e.doc_digest, 'utf8'), toKey(e.by_key), Buffer.from(e.sig, 'base64url')); }
  catch { return false; }
}

/**
 * Introduction as evidence: acceptance is a graded, replayable verdict.
 *
 * @param {object[]} docs      the authority chain
 * @param {object} observations relying-party-attested facts about its OWN checks:
 *   { domain_binding?: {verified, observed_at},          // fetched head digest from https://<org.domain>
 *     log_inclusion?:  {verified, first_logged_at},      // head registered to a transparency log
 *   }
 * @param {object} policy      RELYING-PARTY introduction policy (an evidence
 *   policy; requirement over: authority_chain, domain_binding, log_inclusion,
 *   endorsement_pinned; freshness via first_logged_at ages the history).
 * @param {object} [opts]      {anchors?: [b64url endorser keys], as_of?: ISO}
 * @returns evaluateAdmissibility result (verdict + reasons + replay_digest)
 */
export function evaluateIntroduction(docs, observations, policy, opts = {}) {
  const chain = verifyAuthorityChain(docs);
  const head = chain.head;
  const anchors = new Set(opts.anchors ?? []);
  // Observations the relying party did not make are ABSENT facts, not
  // failed ones: absence degrades to missing_evidence when the policy
  // requires the type; a present-but-false observation is a failure.
  const facts = [
    { type: 'authority_chain', verified: chain.verified && chain.breaks.length === 0, issued_at: head?.issued_at },
    ...(observations?.domain_binding
      ? [{ type: 'domain_binding', verified: observations.domain_binding.verified === true, issued_at: observations.domain_binding.observed_at }] : []),
    ...(observations?.log_inclusion
      ? [{ type: 'log_inclusion', verified: observations.log_inclusion.verified === true, issued_at: observations.log_inclusion.first_logged_at }] : []),
    ...((head?.endorsements ?? []).map((e) => ({
      type: anchors.has(e.by_key) ? 'endorsement_pinned' : 'endorsement',
      verified: verifyEndorsement(e, head),
      label: e.by_org,
    }))),
  ];
  const result = evaluateAdmissibility(
    { components: facts },
    { require_action_agreement: false, ...policy },
    { as_of: opts.as_of },
  );
  result.reasons = [...chain.reasons, ...result.reasons];
  /** @type {{ authority?: object }} */ (result).authority = { org: head?.org ?? null, head_digest: head ? docCoreDigest(head) : null, continuity_breaks: chain.breaks };
  return result;
}

// SPDX-License-Identifier: Apache-2.0
// Generated from authority-doc.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
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
 *    prev_doc_digest and carry a continuity signature by the previous root or
 *    a valid previous key explicitly authorized for authority_doc_rotation
 *    (TUF-style root continuity).
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
    if (v === null || typeof v !== 'object')
        return JSON.stringify(v);
    if (Array.isArray(v))
        return `[${v.map(canon).join(',')}]`;
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const toKey = (b64url) => crypto.createPublicKey({ key: Buffer.from(b64url, 'base64url'), type: 'spki', format: 'der' });
export const authorityIssuerKeyId = (b64url) => (`ep:authority-issuer-key:sha256:${sha256hex(Buffer.from(b64url, 'base64url'))}`);
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const UNSTABLE_IDENTIFIER_CHAR = /[\s\u0000-\u001f\u007f]/u;
/** Parse a strict RFC 3339 instant, returning NaN for malformed input. */
export function authorityInstantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_INSTANT);
    if (!match)
        return NaN;
    const [, y, mo, d, h, mi, s, , oh, om] = match;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(y), Number(mo) - 1, Number(d));
    calendar.setUTCHours(Number(h), Number(mi), Number(s), 0);
    if (calendar.toISOString().slice(0, 19) !== `${y}-${mo}-${d}T${h}:${mi}:${s}`)
        return NaN;
    if (oh !== undefined && (Number(oh) > 23 || Number(om) > 59))
        return NaN;
    return Date.parse(value);
}
/** Stable protocol identifiers are non-empty, bounded, and whitespace-free. */
export function isStableAuthorityIdentifier(value) {
    return typeof value === 'string'
        && value.length > 0
        && Array.from(value).length <= 512
        && !UNSTABLE_IDENTIFIER_CHAR.test(value);
}
function terminalRevocationMs(docs, kid) {
    let revokedAt = Infinity;
    for (const doc of docs) {
        if (!Array.isArray(doc?.issuer_keys))
            continue;
        for (const entry of doc.issuer_keys) {
            if (entry?.kid !== kid || entry.revoked_at === undefined)
                continue;
            const candidate = authorityInstantMs(entry.revoked_at);
            if (Number.isFinite(candidate))
                revokedAt = Math.min(revokedAt, candidate);
        }
    }
    return revokedAt;
}
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
    const rootPub = crypto.createPublicKey(rootPrivateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
    const core = {
        '@version': AUTHORITY_DOC_VERSION,
        org: p.org,
        seq: prev ? prev.doc.seq + 1 : 0,
        prev_doc_digest: prev ? docCoreDigest(prev.doc) : null,
        root_key: rootPub,
        issuer_keys: p.issuer_keys.map((k) => ({ kid: k.kid ?? authorityIssuerKeyId(k.key), ...k })),
        issued_at: p.issued_at,
    };
    const doc = {
        ...core,
        sig: crypto.sign(null, Buffer.from(canon(core), 'utf8'), rootPrivateKey).toString('base64url'),
    };
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
 * signatures (each rotation signed by the previous root or a previous key
 * explicitly authorized and valid for authority_doc_rotation). A rotation
 * WITHOUT valid continuity is flagged, not silently
 * accepted — the relying party's policy decides whether endorsements can
 * substitute (the compromise-recovery path).
 */
export function verifyAuthorityChain(docs) {
    const reasons = [];
    if (!Array.isArray(docs) || docs.length === 0)
        return { verified: false, head: null, breaks: [], reasons: ['empty chain'] };
    const breaks = [];
    const registryIdentityByKid = new Map();
    for (let i = 0; i < docs.length; i++) {
        const d = docs[i];
        if (!d || typeof d !== 'object' || Array.isArray(d)) {
            reasons.push(`doc ${i}: document is not an object`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (d['@version'] !== AUTHORITY_DOC_VERSION) {
            reasons.push(`doc ${i}: bad version`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (d.seq !== i) {
            reasons.push(`doc ${i}: seq ${d.seq} != ${i}`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (!d.org || !isStableAuthorityIdentifier(d.org.domain)
            || (d.org.id !== undefined && !isStableAuthorityIdentifier(d.org.id))) {
            reasons.push(`doc ${i}: organization identifier or domain is unstable`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (i > 0 && (d.org.domain !== docs[0].org.domain
            || d.org.id !== docs[0].org.id)) {
            reasons.push(`doc ${i}: organization identity changed across rotation`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (!Number.isFinite(authorityInstantMs(d.issued_at))) {
            reasons.push(`doc ${i}: issued_at is not a strict RFC 3339 instant`);
            return { verified: false, head: null, breaks, reasons };
        }
        try {
            if (toKey(d.root_key).asymmetricKeyType !== 'ed25519')
                throw new Error('wrong algorithm');
        }
        catch {
            reasons.push(`doc ${i}: root_key is not an Ed25519 SPKI key`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (!Array.isArray(d.issuer_keys)) {
            reasons.push(`doc ${i}: issuer_keys is not an array`);
            return { verified: false, head: null, breaks, reasons };
        }
        const kids = new Set();
        for (const entry of d.issuer_keys) {
            if (typeof entry?.kid !== 'string' || entry.kid.length === 0 || kids.has(entry.kid)) {
                reasons.push(`doc ${i}: issuer key identifiers must be non-empty and unique`);
                return { verified: false, head: null, breaks, reasons };
            }
            kids.add(entry.kid);
            if (!Number.isFinite(authorityInstantMs(entry.valid_from))
                || !Number.isFinite(authorityInstantMs(entry.valid_to))
                || authorityInstantMs(entry.valid_from) > authorityInstantMs(entry.valid_to)
                || (entry.revoked_at !== undefined && !Number.isFinite(authorityInstantMs(entry.revoked_at)))) {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" has an invalid time window`);
                return { verified: false, head: null, breaks, reasons };
            }
            try {
                if (toKey(entry.key).asymmetricKeyType !== 'ed25519')
                    throw new Error('wrong algorithm');
            }
            catch {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" is not an Ed25519 SPKI key`);
                return { verified: false, head: null, breaks, reasons };
            }
            if (entry.kid !== authorityIssuerKeyId(entry.key)) {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" does not match its full public-key digest`);
                return { verified: false, head: null, breaks, reasons };
            }
            if (entry.registry_issuer_id !== undefined
                && !isStableAuthorityIdentifier(entry.registry_issuer_id)) {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" has an unstable registry issuer identifier`);
                return { verified: false, head: null, breaks, reasons };
            }
            const registryIdentity = entry.registry_issuer_id ?? null;
            if (registryIdentityByKid.has(entry.kid)
                && registryIdentityByKid.get(entry.kid) !== registryIdentity) {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" registry issuer identity changed`);
                return { verified: false, head: null, breaks, reasons };
            }
            registryIdentityByKid.set(entry.kid, registryIdentity);
            if (entry.usages !== undefined
                && (!Array.isArray(entry.usages)
                    || entry.usages.some((usage) => !isStableAuthorityIdentifier(usage))
                    || new Set(entry.usages).size !== entry.usages.length)) {
                reasons.push(`doc ${i}: issuer key "${entry.kid}" has invalid usages`);
                return { verified: false, head: null, breaks, reasons };
            }
        }
        const { sig, continuity_sig, endorsements, ...core } = d;
        let selfOk = false;
        try {
            selfOk = crypto.verify(null, Buffer.from(canon(core), 'utf8'), toKey(d.root_key), Buffer.from(sig, 'base64url'));
        }
        catch {
            selfOk = false;
        }
        if (!selfOk) {
            reasons.push(`doc ${i}: self-signature invalid`);
            return { verified: false, head: null, breaks, reasons };
        }
        if (i === 0) {
            if (d.prev_doc_digest !== null) {
                reasons.push('doc 0: unexpected prev digest');
                return { verified: false, head: null, breaks, reasons };
            }
            continue;
        }
        const prev = docs[i - 1];
        if (d.prev_doc_digest !== docCoreDigest(prev)) {
            reasons.push(`doc ${i}: prev digest mismatch (fork/equivocation)`);
            return { verified: false, head: null, breaks, reasons };
        }
        const issuedAt = authorityInstantMs(d.issued_at);
        const previousIssuedAt = authorityInstantMs(prev.issued_at);
        if (!(issuedAt > previousIssuedAt)) {
            reasons.push(`doc ${i}: issued_at must be later than doc ${i - 1}`);
            return { verified: false, head: null, breaks, reasons };
        }
        // Continuity: the previous root is dedicated rotation authority. A previous
        // issuer key counts only when it was explicitly authorized for rotation and
        // valid at the successor document's issuance instant.
        const rotationKeys = prev.issuer_keys.filter((k) => {
            const from = authorityInstantMs(k.valid_from);
            const to = authorityInstantMs(k.valid_to);
            const revokedAt = terminalRevocationMs(docs, k.kid);
            return Array.isArray(k.usages)
                && k.usages.includes('authority_doc_rotation')
                && Number.isFinite(from) && Number.isFinite(to)
                && issuedAt >= from && issuedAt <= to
                && issuedAt < revokedAt;
        }).map((k) => k.key);
        const prevKeys = [prev.root_key, ...rotationKeys];
        const digest = Buffer.from(docCoreDigest(d), 'utf8');
        const contOk = typeof continuity_sig === 'string' && prevKeys.some((k) => {
            try {
                return crypto.verify(null, digest, toKey(k), Buffer.from(continuity_sig, 'base64url'));
            }
            catch {
                return false;
            }
        });
        if (!contOk) {
            breaks.push(i);
            reasons.push(`doc ${i}: NO valid continuity from doc ${i - 1} (compromise-recovery path; policy decides)`);
        }
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
    const at = authorityInstantMs(atISO);
    if (!Array.isArray(docs) || !Number.isFinite(at))
        return null;
    // Revocation is terminal across the whole observed chain, including a later
    // document that records an effective instant in the past. Other attributes
    // (especially usages) take effect only from the document's own issued_at;
    // a later document cannot retroactively grant an old key a new usage.
    if (at >= terminalRevocationMs(docs, kid))
        return null;
    // The newest document effective at the authenticated instant is the entire
    // issuer-key state. Omission is removal; never fall through to an older doc.
    let effectiveDoc = null;
    for (let i = docs.length - 1; i >= 0; i--) {
        if (authorityInstantMs(docs[i]?.issued_at) <= at) {
            effectiveDoc = docs[i];
            break;
        }
    }
    if (!effectiveDoc || !Array.isArray(effectiveDoc.issuer_keys))
        return null;
    const entry = effectiveDoc.issuer_keys.find((candidate) => candidate.kid === kid);
    if (!entry)
        return null;
    const from = authorityInstantMs(entry.valid_from);
    const to = authorityInstantMs(entry.valid_to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || at < from || at > to)
        return null;
    return {
        key: entry.key,
        usages: Array.isArray(entry.usages) ? [...entry.usages] : [],
        custody_class: entry.custody_class ?? null,
        registry_issuer_id: entry.registry_issuer_id ?? null,
        kid: entry.kid,
        doc_seq: effectiveDoc.seq,
    };
}
/** Verify one endorsement against the doc it claims to endorse. */
export function verifyEndorsement(e, doc) {
    if (e?.doc_digest !== docCoreDigest(doc))
        return false;
    try {
        return crypto.verify(null, Buffer.from(e.doc_digest, 'utf8'), toKey(e.by_key), Buffer.from(e.sig, 'base64url'));
    }
    catch {
        return false;
    }
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
    const result = evaluateAdmissibility({ components: facts }, { require_action_agreement: false, ...policy }, { as_of: opts.as_of });
    result.reasons = [...chain.reasons, ...result.reasons];
    result.authority = { org: head?.org ?? null, head_digest: head ? docCoreDigest(head) : null, continuity_breaks: chain.breaks };
    return result;
}

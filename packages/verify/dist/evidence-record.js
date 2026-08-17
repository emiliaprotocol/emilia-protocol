// SPDX-License-Identifier: Apache-2.0
/**
 * EP-EVIDENCE-RECORD-v1 — long-term, crypto-agile preservation of an EP artifact.
 *
 * EP receipts must "verify years — even decades — later," and government
 * retention is 10-25+ years (see the GAGAS / Uniform Guidance mapping). But any
 * fixed algorithm (Ed25519, SHA-256) weakens over that horizon. Following the
 * approach of RFC 4998 (Evidence Record Syntax), an evidence record preserves a
 * protected artifact's non-repudiation across algorithm aging by a CHAIN of
 * renewals: each renewal re-timestamps the *previous* attestation under a fresh
 * (possibly stronger) hash, BEFORE the older algorithm is broken. Verifying the
 * chain proves the artifact has been continuously, independently time-anchored
 * from its first attestation to the latest renewal.
 *
 * Each renewal is an EP-TIME-ATTESTATION-v1 (already offline, asymmetric,
 * pinned-TSA, tri-language). This composes that verifier and adds the
 * hash-linkage between renewals.
 *
 *   { "@version": "EP-EVIDENCE-RECORD-v1",
 *     protected_hash: "sha256:<hex>",        // hash of the protected artifact (e.g. a receipt)
 *     archive_timestamps: [
 *       { time_attestation: <EP-TIME-ATTESTATION-v1> },   // [0] covers protected_hash
 *       { time_attestation: <EP-TIME-ATTESTATION-v1> },   // [i] covers hash(prior attestation), agile alg
 *       ...
 *     ] }
 *
 * FAIL-CLOSED. HONEST BOUNDARY: this proves the artifact was continuously
 * time-anchored by pinned authorities; it does not prove the artifact was
 * *correct*, nor that a renewal happened before a given algorithm actually broke
 * (that is an operational discipline the chain records, not one it can divine).
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { verifyTimeAttestation, timeAttestationSignedBytes } from './time-attestation.js';
import { AGILE_SIGNATURE_ALGORITHMS, signAgile, verifyAgileSignature, verifyAgileSignatureSet, } from './pq-signature-agility.js';
export const EVIDENCE_RECORD_VERSION = 'EP-EVIDENCE-RECORD-v1';
const SUPPORTED_HASH = new Set(['sha256', 'sha384', 'sha512']);
// Parse "sha384:<hex>" (or bare hex, defaulting to sha256) -> { alg, hex }.
function algOf(hashed) {
    const s = String(hashed ?? '');
    const i = s.indexOf(':');
    if (i < 0)
        return { alg: 'sha256', hex: s.toLowerCase() };
    return { alg: s.slice(0, i).toLowerCase(), hex: s.slice(i + 1).toLowerCase() };
}
function hashHexWith(alg, bytes) {
    return crypto.createHash(alg).update(bytes).digest('hex');
}
/**
 * @param {object} record  the EP-EVIDENCE-RECORD-v1 document.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.protectedHash]  the hash of the artifact the relying party HOLDS; binds the record to it.
 * @returns {{valid:boolean, checks:object, errors:string[], protected_since?:string, last_renewed?:string}}
 */
export function verifyEvidenceRecord(record, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const tsaKeys = opts.tsaKeys || {};
    // The v1 signature verdict: Ed25519 under a pinned TSA key, unchanged.
    return walkEvidenceRecord(record, opts, (ta) => verifyTimeAttestation(ta, { tsaKeys }).valid);
}
/**
 * The chain walk shared by the v1 verifier above and the algorithm-agile one
 * below. Everything except the per-attestation SIGNATURE verdict lives here:
 * version, protected-hash binding, hash linkage between renewals, and monotonic
 * time. The signature verdict is injected, so the two entry points can differ
 * in which algorithms they accept while provably walking the same chain -- the
 * alternative, a second copy of this loop, is how two verifiers drift apart.
 */
function walkEvidenceRecord(record, opts, attestationValid) {
    const checks = {
        version: false,
        protected_bound: true, // record.protected_hash == opts.protectedHash (vacuous if not supplied)
        chain_nonempty: false,
        all_timestamps_valid: true, // every renewal's TSA attestation verifies
        chain_linked: true, // ts[0] covers protected_hash; ts[i] covers hash(prior attestation)
        monotonic_time: true, // renewal times strictly increase
    };
    const errors = [];
    const fail = (k, m) => { checks[k] = false; errors.push(m); };
    try {
        if (record?.['@version'] !== EVIDENCE_RECORD_VERSION) {
            errors.push(`unsupported version: ${record?.['@version']}`);
            return { valid: false, checks, errors };
        }
        checks.version = true;
        const ats = Array.isArray(record.archive_timestamps) ? record.archive_timestamps : [];
        checks.chain_nonempty = ats.length > 0;
        if (!checks.chain_nonempty) {
            errors.push('no archive timestamps');
            return { valid: false, checks, errors };
        }
        if (typeof opts.protectedHash === 'string') {
            if (algOf(record.protected_hash).hex !== algOf(opts.protectedHash).hex) {
                fail('protected_bound', 'record protected_hash does not match the supplied artifact hash');
            }
        }
        let prevTime = null;
        let firstTime = null;
        for (let i = 0; i < ats.length; i++) {
            const ta = ats[i]?.time_attestation;
            if (!attestationValid(ta, i))
                fail('all_timestamps_valid', `archive timestamp ${i} TSA attestation does not verify`);
            const cur = algOf(ta?.hashed);
            if (i === 0) {
                if (cur.hex !== algOf(record.protected_hash).hex) {
                    fail('chain_linked', 'first archive timestamp does not cover protected_hash');
                }
            }
            else if (!SUPPORTED_HASH.has(cur.alg)) {
                fail('chain_linked', `renewal ${i} uses an unsupported hash algorithm "${cur.alg}"`);
            }
            else {
                const expected = hashHexWith(cur.alg, Buffer.from(canonicalize(ats[i - 1].time_attestation), 'utf8'));
                if (cur.hex !== expected)
                    fail('chain_linked', `renewal ${i} does not cover the previous attestation`);
            }
            const time = typeof ta?.time === 'string' ? ta.time : '';
            const t = Date.parse(time);
            if (Number.isNaN(t)) {
                fail('monotonic_time', `archive timestamp ${i} has no parseable time`);
            }
            else {
                if (prevTime !== null && !(t > prevTime))
                    fail('monotonic_time', `renewal ${i} time is not after the previous`);
                if (firstTime === null)
                    firstTime = time;
                prevTime = t;
            }
        }
        const valid = Object.values(checks).every(Boolean);
        const last = ats[ats.length - 1]?.time_attestation?.time;
        return { valid, checks, errors, protected_since: firstTime, last_renewed: last };
    }
    catch {
        return { valid: false, checks, errors };
    }
}
/**
 * The pinned key for ONE algorithm on a TSA pin, or null.
 *
 * `keys` is checked first because a chain that renews across an algorithm
 * transition needs BOTH keys pinned for the same authority: the Ed25519 leg
 * that was signed before the move and the ML-DSA-65 leg signed after it. The
 * flat `{alg, public_key}` form stays for the single-algorithm case. A pin that
 * does not name this algorithm is a refusal, never a fallback to whatever key
 * happens to be on the pin.
 */
function pinnedKeyForAlgorithm(pin, alg) {
    if (Array.isArray(pin.keys)) {
        const match = pin.keys.find((k) => k && k.alg === alg && k.public_key !== undefined && k.public_key !== null);
        if (match)
            return { public_key: match.public_key };
    }
    if (pin.alg === alg && pin.public_key !== undefined && pin.public_key !== null) {
        return { public_key: pin.public_key };
    }
    return null;
}
/** True when a proof needs the agile path rather than the v1 Ed25519 path. */
function isAgileShapedProof(proof) {
    if (!proof || typeof proof !== 'object' || Array.isArray(proof))
        return false;
    const p = proof;
    if (Array.isArray(p.signatures))
        return true;
    return typeof p.algorithm === 'string' && p.algorithm !== 'Ed25519';
}
/**
 * Verify ONE archive timestamp's proof under the agile rules above.
 * Never throws; every refusal is a false verdict the chain walk reports.
 */
async function agileAttestationValid(att, opts) {
    const tsaKeys = opts.tsaKeys || {};
    if (!att || typeof att !== 'object')
        return false;
    const proof = (att.proof || null);
    // v1 shape: unchanged path, unchanged verdict.
    if (!isAgileShapedProof(proof)) {
        return verifyTimeAttestation(att, { tsaKeys: tsaKeys }).valid;
    }
    // The agile path still requires everything the v1 path requires apart from
    // the signature itself: the right version, a pinned authority, a parseable
    // instant. A record that skipped these would be trading one check for another
    // rather than adding an algorithm.
    const authorityId = typeof att.ts_authority_id === 'string' ? att.ts_authority_id : '';
    const pin = tsaKeys[authorityId];
    if (att['@version'] !== 'EP-TIME-ATTESTATION-v1')
        return false;
    if (!pin || typeof pin !== 'object')
        return false;
    if (typeof att.time !== 'string' || Number.isNaN(Date.parse(att.time)))
        return false;
    let messageBytes;
    try {
        messageBytes = new Uint8Array(timeAttestationSignedBytes(att));
    }
    catch {
        return false;
    }
    // Set-shaped: every required algorithm present, every presented leg valid.
    if (Array.isArray(proof?.signatures)) {
        const pinnedKeys = Array.isArray(pin.keys) ? pin.keys : null;
        if (!pinnedKeys || pinnedKeys.length === 0)
            return false;
        const required = Array.isArray(opts.requiredAlgorithms) && opts.requiredAlgorithms.length > 0
            ? opts.requiredAlgorithms
            : AGILE_SIGNATURE_ALGORITHMS;
        const result = await verifyAgileSignatureSet(messageBytes, proof.signatures, pinnedKeys, {
            ...agilityPassthrough(opts),
            policy: 'hybrid_all',
            requiredAlgorithms: [...required],
        });
        return result.verified === true;
    }
    // Single agile signature under one pinned, algorithm-tagged key.
    if (!proof)
        return false;
    const alg = typeof proof.algorithm === 'string' ? proof.algorithm : null;
    if (alg === null)
        return false;
    const pinnedKey = pinnedKeyForAlgorithm(pin, alg);
    if (pinnedKey === null)
        return false;
    // Same discipline as verifyTimeAttestation: a presented key that disagrees
    // with the pinned one refuses, rather than being quietly ignored.
    if (proof.public_key !== undefined && proof.public_key !== null && proof.public_key !== pinnedKey.public_key) {
        return false;
    }
    const keyId = typeof proof.ts_key_id === 'string' ? proof.ts_key_id : undefined;
    const result = await verifyAgileSignature(messageBytes, { alg, sig: proof.signature_b64u ?? proof.sig, key_id: keyId }, { alg, public_key: pinnedKey.public_key, key_id: keyId }, agilityPassthrough(opts));
    return result.verified === true;
}
function agilityPassthrough(opts) {
    const out = {};
    if (opts.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    if (opts.deterministic !== undefined)
        out.deterministic = opts.deterministic;
    return out;
}
/**
 * Algorithm-agile verification of an EP-EVIDENCE-RECORD-v1 base record.
 *
 * Same result shape and same chain checks as verifyEvidenceRecord; the only
 * difference is which signature algorithms an archive timestamp may carry. v1
 * Ed25519 records are routed through the unchanged v1 path and get an identical
 * verdict. FAIL-CLOSED: an unpinned authority, an unknown algorithm, a missing
 * ML-DSA backend, or a set-shaped proof missing a required leg is a false
 * verdict with the chain's own error message, never a pass.
 */
export async function verifyEvidenceRecordAgile(record, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const ats = Array.isArray(record?.archive_timestamps) ? record.archive_timestamps : [];
    // Signature verdicts are computed up front so the shared (synchronous) chain
    // walk stays one implementation rather than gaining an async twin.
    const verdicts = [];
    for (let i = 0; i < ats.length; i++) {
        verdicts.push(await agileAttestationValid(ats[i]?.time_attestation, opts));
    }
    return walkEvidenceRecord(record, opts, (_ta, i) => verdicts[i] === true);
}
// =============================================================================
// EP-EVIDENCE-REATTESTATION-v1 -- signature re-anchoring across algorithm
// transitions (additive extension; nothing above this line changes behavior)
// =============================================================================
//
// The renewal chain above preserves WHEN-evidence (time attestations) across
// hash aging. This extension preserves SIGNATURE-evidence across signature-
// algorithm aging: evidence signed under an aging algorithm (e.g. Ed25519) is
// periodically RE-COMMITTED under a current one (e.g. ML-DSA-65, FIPS 204),
// in the renewal style of RFC 4998. Each re-attestation entry commits, via
// `prior_record_digest`, to the FULL bytes of what came before it: entry 0
// digests the protected record bytes themselves; entry i>0 digests the
// canonical bytes of entry i-1 (which committed to ITS predecessor, so the
// commitment is transitive down to the original bytes). A fresh signature
// under the entry's declared algorithm then covers that digest plus the
// entry's own metadata.
//
// Verification walks the chain NEWEST-TO-OLDEST and reports, per link, the
// algorithm used and whether the digest linkage and the signature hold. A
// broken link is a refusal naming the link index and the reason. FAIL-CLOSED
// throughout: malformed entries, unpinned keys, and unknown algorithms are
// refusals with reasons, never throws and never passes.
//
// HONEST BOUNDARY (substance, keep it): re-attestation preserves INTEGRITY
// continuity across algorithm transitions. It cannot resurrect a signature
// that was already forgeable at the moment it was re-attested -- if the old
// algorithm was broken before the re-anchor, the re-anchor faithfully
// preserves a claim that was already untrustworthy. The re-anchor must
// happen BEFORE the old algorithm breaks; the chain records that discipline,
// it cannot divine it (same operational boundary as the renewal chain above
// and as RFC 4998).
export const REATTESTATION_VERSION = 'EP-EVIDENCE-REATTESTATION-v1';
// The bytes each link's signature covers: every entry field except the
// signature itself, canonicalized so the verifier recomputes them
// independently of presentation order.
function reattestationSignedBytes(entry) {
    return Buffer.from(canonicalize({
        '@version': REATTESTATION_VERSION,
        digest_alg: entry.digest_alg ?? null,
        prior_record_digest: entry.prior_record_digest ?? null,
        reattested_at: entry.reattested_at ?? null,
    }), 'utf8');
}
// Digest the full prior link (including its signature) so each re-anchor
// commits to everything before it, transitively down to the record bytes.
function priorEntryDigestHex(alg, prior) {
    return hashHexWith(alg, Buffer.from(canonicalize(prior), 'utf8'));
}
/**
 * Issue one re-attestation link (issuer side; throws on misuse).
 *
 * @param prior  the protected record bytes (first link) or the previous
 *               ReattestationEntry (subsequent links).
 * @param opts.key         EP-SIG-AGILITY-v1 signing key ({ alg, private_key, key_id }).
 * @param opts.digestAlg   'sha256' (default) | 'sha384' | 'sha512'.
 * @param opts.reattestedAt RFC 3339 instant; defaults to now.
 */
export async function createReattestation(prior, opts) {
    if (!opts || typeof opts !== 'object' || !opts.key) {
        throw new TypeError('createReattestation: opts.key is required');
    }
    if (typeof opts.key.key_id !== 'string' || opts.key.key_id.length === 0) {
        throw new TypeError('createReattestation: opts.key.key_id is required (links are verified under pinned key ids)');
    }
    const digestAlg = opts.digestAlg === undefined ? 'sha256' : opts.digestAlg;
    if (!SUPPORTED_HASH.has(digestAlg)) {
        throw new Error(`createReattestation: unsupported digest algorithm "${digestAlg}"`);
    }
    let priorDigestHex;
    if (prior instanceof Uint8Array) {
        priorDigestHex = hashHexWith(digestAlg, Buffer.from(prior));
    }
    else if (prior && typeof prior === 'object' && prior['@version'] === REATTESTATION_VERSION) {
        priorDigestHex = priorEntryDigestHex(digestAlg, prior);
    }
    else {
        throw new TypeError('createReattestation: prior must be record bytes or a prior EP-EVIDENCE-REATTESTATION-v1 entry');
    }
    const reattested_at = typeof opts.reattestedAt === 'string' ? opts.reattestedAt : new Date().toISOString();
    const partial = {
        prior_record_digest: `${digestAlg}:${priorDigestHex}`,
        digest_alg: digestAlg,
        reattested_at,
    };
    const signature = await signAgile(reattestationSignedBytes(partial), opts.key, opts);
    return {
        '@version': REATTESTATION_VERSION,
        ...partial,
        new_signature: { alg: signature.alg, key_id: opts.key.key_id, sig: signature.sig },
    };
}
/**
 * Verify a re-attestation chain over the protected record bytes the relying
 * party HOLDS. Walks NEWEST-TO-OLDEST; reports per-link algorithm and
 * validity; a broken link refuses naming the link index and reason.
 *
 * verified:true means: every link's signature verifies under its pinned key,
 * every link's digest commits to the full prior link (link 0 to the record
 * bytes), and re-attestation times strictly increase. It does NOT mean the
 * original artifact was correct, nor that any re-anchor happened before its
 * predecessor algorithm actually broke (see the boundary note above).
 */
export async function verifyReattestationChain(recordBytes, entries, keys, opts = {}) {
    const links = [];
    const refuse = (reason) => ({ verified: false, reason, links, first_reattested_at: null, last_reattested_at: null });
    if (!(recordBytes instanceof Uint8Array))
        return refuse('protected record bytes missing (fail-closed)');
    if (!Array.isArray(entries))
        return refuse('re-attestation chain is not an array');
    if (entries.length === 0)
        return refuse('re-attestation chain is empty');
    const pinned = keys && typeof keys === 'object' ? keys : {};
    let firstFailure = null;
    const fail = (index, link, reason) => {
        if (link.reason === null)
            link.reason = reason; // keep the first per-link reason
        if (firstFailure === null)
            firstFailure = `link ${index}: ${reason}`;
    };
    // Newest-to-oldest walk. Each link i is checked against its predecessor
    // (entries[i-1], or the record bytes for i === 0).
    for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i];
        const link = {
            index: i,
            alg: typeof entry?.new_signature?.alg === 'string' ? entry.new_signature.alg : null,
            key_id: typeof entry?.new_signature?.key_id === 'string' ? entry.new_signature.key_id : null,
            reattested_at: typeof entry?.reattested_at === 'string' ? entry.reattested_at : null,
            digest_valid: null,
            signature_valid: null,
            reason: null,
        };
        links.push(link);
        if (!entry || typeof entry !== 'object' || entry['@version'] !== REATTESTATION_VERSION) {
            fail(i, link, 'unsupported or missing @version');
            continue;
        }
        const digestAlg = typeof entry.digest_alg === 'string' ? entry.digest_alg : '';
        if (!SUPPORTED_HASH.has(digestAlg)) {
            fail(i, link, `unsupported digest algorithm "${digestAlg}"`);
            continue;
        }
        // Digest linkage: this link must commit to the FULL prior link (or the
        // protected record bytes for the first link).
        const presented = algOf(entry.prior_record_digest);
        let expectedHex = null;
        if (presented.alg !== digestAlg) {
            link.digest_valid = false;
            fail(i, link, 'prior_record_digest algorithm tag does not match digest_alg');
        }
        else if (i === 0) {
            expectedHex = hashHexWith(digestAlg, Buffer.from(recordBytes));
        }
        else {
            const prev = entries[i - 1];
            if (!prev || typeof prev !== 'object' || prev['@version'] !== REATTESTATION_VERSION) {
                link.digest_valid = false;
                fail(i, link, 'previous link is not a well-formed re-attestation entry');
            }
            else {
                expectedHex = priorEntryDigestHex(digestAlg, prev);
            }
        }
        if (expectedHex !== null) {
            link.digest_valid = presented.hex === expectedHex;
            if (!link.digest_valid)
                fail(i, link, 'does not commit to the full prior record bytes');
        }
        // Signature under the pinned key for this link's key_id.
        const sig = entry.new_signature;
        const keyId = typeof sig?.key_id === 'string' ? sig.key_id : '';
        const pin = pinned[keyId];
        if (!pin) {
            link.signature_valid = false;
            fail(i, link, `no pinned key for key_id "${keyId}"`);
            continue;
        }
        const result = await verifyAgileSignature(reattestationSignedBytes(entry), { alg: sig?.alg, sig: sig?.sig, key_id: keyId }, { alg: pin.alg, public_key: pin.public_key, key_id: keyId }, opts);
        link.signature_valid = result.verified === true;
        if (!link.signature_valid)
            fail(i, link, result.reason ?? 'signature does not verify');
    }
    // Monotonic time across the chain (oldest to newest strictly increasing).
    let prevMs = null;
    for (let i = 0; i < entries.length; i++) {
        const t = typeof entries[i]?.reattested_at === 'string'
            ? Date.parse(entries[i].reattested_at)
            : NaN;
        const link = links.find((l) => l.index === i);
        if (Number.isNaN(t)) {
            fail(i, link, 'reattested_at is absent or not a well-formed instant');
            continue;
        }
        if (prevMs !== null && !(t > prevMs)) {
            fail(i, link, 'reattested_at is not after the previous link (chain out of order)');
        }
        prevMs = t;
    }
    if (firstFailure !== null) {
        return { verified: false, reason: firstFailure, links, first_reattested_at: null, last_reattested_at: null };
    }
    return {
        verified: true,
        reason: null,
        links,
        first_reattested_at: entries[0].reattested_at,
        last_reattested_at: entries[entries.length - 1].reattested_at,
    };
}
//# sourceMappingURL=evidence-record.js.map
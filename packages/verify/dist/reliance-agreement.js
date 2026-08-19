// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-AGREEMENT-v1 / EP-RELIANCE-EVENT-v1 — machine-readable, signed
 * reliance agreements and per-action reliance events.
 *
 * THE OBJECT
 * ----------
 * The reliance kernel (EP-RELIANCE-KERNEL-v1) answers "may I rely on this
 * evidence packet under MY pinned profile?" This module carries the layer the
 * insurance market writes in prose today: a signed, portable object in which
 * named parties condition a liability transfer or an indemnity on
 * authorization-evidence sufficiency — "if the presented evidence satisfies
 * reliance profile P, terms T (mode, caps, currency) apply between us." The
 * agreement references the evidence condition by DIGEST of a reliance profile
 * (EP-RELIANCE-PROFILE-v1); it never reinvents evidence policy. The per-action
 * RELIANCE EVENT then binds ONE action's reliance verdict to the agreement,
 * making both the commitment and the act of reliance cryptographically attributable to the
 * signing parties.
 *
 * WHAT VERIFICATION PROVES — AND DOES NOT
 * ---------------------------------------
 * verifyRelianceAgreement proves WHO agreed to WHAT terms over WHICH evidence
 * conditions: every signature required by the agreement's own required_signers
 * verifies under a key the verifier pinned out of band, over the JCS-canonical
 * agreement payload, inside the agreement's own validity window. It does NOT
 * prove enforceability (a jurisdiction question), does NOT escrow the cap
 * amounts (they are claims about intent), and CANNOT prevent a party from
 * dishonoring the commitment — it makes dishonor attributable and the record
 * portable to a dispute forum. The object is designed to be incorporated by
 * reference into a prose master agreement; it is the interoperable expression
 * of the agreement, not a substitute for contract law.
 *
 * PURE. OFFLINE. FAIL-CLOSED. No deps beyond node:crypto. Monetary amounts are
 * decimal STRINGS, never JSON numbers (floating-point representation of money
 * is a refusal, not a warning). All vocabularies are closed.
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { signAgileSet, verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, } from './pq-signature-agility.js';
export const RELIANCE_AGREEMENT_VERSION = 'EP-RELIANCE-AGREEMENT-v1';
export const RELIANCE_EVENT_VERSION = 'EP-RELIANCE-EVENT-v1';
export const RELIANCE_AGREEMENT_DOMAIN = 'EP-RELIANCE-AGREEMENT-v1\0';
export const RELIANCE_EVENT_DOMAIN = 'EP-RELIANCE-EVENT-v1\0';
/** The CLOSED set of agreement term modes. */
export const AGREEMENT_MODES = Object.freeze(['liability_shift', 'indemnity']);
/** The CLOSED set of party roles. */
export const AGREEMENT_ROLES = Object.freeze(['issuer', 'relying_party', 'underwriter']);
/** Profile-local closed vocabulary; not a shared protocol assurance taxonomy. */
const ASSURANCE_CLASSES = Object.freeze(['S', 'H', 'V', 'Q']);
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
/** Decimal money string: no sign, no exponent, no leading zeros, optional fraction. */
const AMOUNT_RE = /^(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
const RFC3339_OFFSET_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const sha256hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
function toMs(t) {
    if (t === undefined)
        return Date.now();
    if (typeof t === 'number')
        return Number.isFinite(t) ? t : NaN;
    if (t instanceof Date) {
        const ms = t.getTime();
        return Number.isFinite(ms) ? ms : NaN;
    }
    if (typeof t !== 'string' || !RFC3339_OFFSET_RE.test(t))
        return NaN;
    const ms = Date.parse(t);
    return Number.isFinite(ms) ? ms : NaN;
}
/** Strict timestamp parse for fields inside signed objects: NaN on anything malformed. */
function parseTs(t) {
    if (typeof t !== 'string' || t === '')
        return NaN;
    return Date.parse(t);
}
function pubKeyB64u(ref) {
    if (typeof ref === 'string')
        return ref;
    if (ref && typeof ref === 'object' && typeof ref.public_key === 'string')
        return ref.public_key;
    return null;
}
function importPinnedKey(b64u) {
    try {
        return crypto.createPublicKey({ key: Buffer.from(b64u, 'base64url'), type: 'spki', format: 'der' });
    }
    catch {
        return null;
    }
}
function stripSignatures(agreement) {
    const { signatures: _sigs, ...body } = agreement;
    return body;
}
function stripSignature(event) {
    const { signature: _sig, ...body } = event;
    return body;
}
function agreementSigningBytes(unsignedBody) {
    return Buffer.from(RELIANCE_AGREEMENT_DOMAIN + canonicalize(unsignedBody), 'utf8');
}
function eventSigningBytes(unsignedBody) {
    return Buffer.from(RELIANCE_EVENT_DOMAIN + canonicalize(unsignedBody), 'utf8');
}
/** Digest of the agreement body (domain-separated, signature envelope excluded). */
export function relianceAgreementDigest(agreement) {
    return `sha256:${sha256hex(agreementSigningBytes(stripSignatures(agreement)))}`;
}
/** Digest of the event body (domain-separated, signature envelope excluded). */
export function relianceEventDigest(event) {
    return `sha256:${sha256hex(eventSigningBytes(stripSignature(event)))}`;
}
/** Content digest of a reliance result record (plain JCS, no signing domain). */
export function relianceResultDigest(result) {
    return `sha256:${sha256hex(Buffer.from(canonicalize(result), 'utf8'))}`;
}
/**
 * Sign an agreement payload as one or more parties. Test/issuance convenience;
 * verification never trusts the carried public keys, only pinned ones.
 * @param {object} payload  the agreement WITHOUT signatures
 * @param {Array<{party:string, privateKey:import('node:crypto').KeyObject}>} signers
 * @returns {object} the agreement with a signatures[] envelope appended
 */
export function signRelianceAgreement(payload, signers = []) {
    const body = stripSignatures(payload);
    const bytes = agreementSigningBytes(body);
    const signatures = (signers || []).map(({ party, privateKey }) => {
        // @types/node omits KeyObject from createPublicKey's param union though the
        // runtime derives a public key from a private KeyObject (see its own docs).
        const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
        return {
            party,
            algorithm: 'Ed25519',
            key_id: body.parties?.[party]?.key_id ?? null,
            public_key: publicKey,
            signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
        };
    });
    return { ...body, signatures };
}
/**
 * Sign a reliance event payload as the relying party.
 * @param {object} payload  the event WITHOUT signature
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {object} the event with a signature envelope appended
 */
export function signRelianceEvent(payload, privateKey) {
    const body = stripSignature(payload);
    const bytes = eventSigningBytes(body);
    // @types/node omits KeyObject from createPublicKey's param union though the
    // runtime derives a public key from a private KeyObject (see its own docs).
    const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
    return {
        ...body,
        signature: {
            party: 'relying_party',
            algorithm: 'Ed25519',
            public_key: publicKey,
            signature_b64u: crypto.sign(null, bytes, privateKey).toString('base64url'),
        },
    };
}
/** Validate one money field. Returns a reason string on refusal, null when fine. */
function checkAmount(terms, field, required) {
    const v = terms[field];
    if (v === undefined || v === null) {
        return required ? `terms.${field} is required` : null;
    }
    if (typeof v === 'number') {
        return `terms.${field} must be a decimal string, not a JSON number (floating point cannot represent money exactly)`;
    }
    if (typeof v !== 'string' || !AMOUNT_RE.test(v)) {
        return `terms.${field} must be a decimal amount string`;
    }
    return null;
}
/**
 * Verify an EP-RELIANCE-AGREEMENT-v1 against pinned party keys.
 *
 * Proves: well-formed closed-vocabulary payload; the agreement is inside its
 * own validity window at `now`; every party named by the agreement's OWN
 * required_signers[] has exactly one Ed25519 signature that verifies under the
 * key pinned (out of band) for that party's key_id; any additional signature
 * present also verifies. Fail-closed: any missing pin, missing signature,
 * unknown vocabulary value, or amount-as-number is a refusal with a reason.
 *
 * @param {object} agreement
 * @param {object} [opts]
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]  key_id -> pinned base64url SPKI Ed25519 key
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], digest?:string, required_signers?:string[]}}
 */
export function verifyRelianceAgreement(agreement, opts = {}) {
    const reasons = [];
    const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
    const now = toMs(opts.now);
    const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};
    if (!Number.isFinite(now))
        return fail('verification time must be a finite epoch or RFC-3339 instant with an explicit offset');
    // ── 1. STRUCTURE — closed vocabularies, fail-closed ────────────────────────
    if (!agreement || typeof agreement !== 'object' || Array.isArray(agreement))
        return fail('agreement is not an object');
    if (agreement.version !== RELIANCE_AGREEMENT_VERSION)
        return fail(`version must be ${RELIANCE_AGREEMENT_VERSION}`);
    if (typeof agreement.agreement_id !== 'string' || agreement.agreement_id === '')
        return fail('agreement_id must be a non-empty string');
    const parties = agreement.parties;
    if (!parties || typeof parties !== 'object' || Array.isArray(parties))
        return fail('parties must be an object');
    for (const role of Object.keys(parties)) {
        if (!AGREEMENT_ROLES.includes(role))
            return fail(`unknown party role '${role}' (closed set: ${AGREEMENT_ROLES.join(', ')})`);
    }
    for (const role of ['issuer', 'relying_party']) {
        const p = parties[role];
        if (!p || typeof p !== 'object')
            return fail(`parties.${role} is required`);
        if (typeof p.id !== 'string' || p.id === '')
            return fail(`parties.${role}.id must be a non-empty string`);
        if (typeof p.key_id !== 'string' || p.key_id === '')
            return fail(`parties.${role}.key_id must be a non-empty string`);
    }
    if (parties.underwriter !== undefined) {
        const u = parties.underwriter;
        if (!u || typeof u !== 'object' || typeof u.id !== 'string' || u.id === '' || typeof u.key_id !== 'string' || u.key_id === '') {
            return fail('parties.underwriter, when present, must carry a non-empty id and key_id');
        }
    }
    const required = agreement.required_signers;
    if (!Array.isArray(required) || required.length === 0)
        return fail('required_signers must be a non-empty array');
    if (new Set(required).size !== required.length)
        return fail('required_signers must not contain duplicates');
    for (const role of required) {
        if (!AGREEMENT_ROLES.includes(role))
            return fail(`required_signers contains unknown role '${role}'`);
        if (!parties[role])
            return fail(`required_signers names '${role}' but the agreement declares no such party`);
    }
    if (!required.includes('issuer') || !required.includes('relying_party')) {
        return fail('required_signers must include both issuer and relying_party (an agreement neither issued nor accepted is not an agreement)');
    }
    const scope = agreement.scope;
    if (!scope || typeof scope !== 'object')
        return fail('scope is required');
    if (!Array.isArray(scope.action_families) || scope.action_families.length === 0
        || !scope.action_families.every((f) => typeof f === 'string' && f !== '')) {
        return fail('scope.action_families must be a non-empty array of non-empty strings');
    }
    if (scope.jurisdictions !== undefined
        && (!Array.isArray(scope.jurisdictions) || !scope.jurisdictions.every((j) => typeof j === 'string' && j !== ''))) {
        return fail('scope.jurisdictions, when present, must be an array of non-empty strings');
    }
    const validity = scope.validity;
    if (!validity || typeof validity !== 'object')
        return fail('scope.validity is required');
    const notBefore = parseTs(validity.not_before);
    const notAfter = parseTs(validity.not_after);
    if (Number.isNaN(notBefore) || Number.isNaN(notAfter))
        return fail('scope.validity.not_before and not_after must be parseable timestamps');
    if (notBefore >= notAfter)
        return fail('scope.validity.not_before must precede not_after');
    const condition = agreement.condition;
    if (!condition || typeof condition !== 'object')
        return fail('condition is required');
    if (typeof condition.reliance_profile_digest !== 'string' || !SHA256_RE.test(condition.reliance_profile_digest)) {
        return fail('condition.reliance_profile_digest must be a sha256:<64 hex> digest of the pinned reliance profile');
    }
    if (condition.min_assurance_class !== undefined && !ASSURANCE_CLASSES.includes(condition.min_assurance_class)) {
        return fail(`condition.min_assurance_class must be one of ${ASSURANCE_CLASSES.join(', ')}`);
    }
    if (condition.max_staleness_sec !== undefined
        && !(Number.isFinite(condition.max_staleness_sec) && condition.max_staleness_sec >= 0)) {
        return fail('condition.max_staleness_sec must be a non-negative finite number');
    }
    const terms = agreement.terms;
    if (!terms || typeof terms !== 'object')
        return fail('terms is required');
    if (!AGREEMENT_MODES.includes(terms.mode)) {
        return fail(`terms.mode '${String(terms.mode)}' is not in the closed set (${AGREEMENT_MODES.join(', ')})`);
    }
    const amountFields = [['cap_amount', true], ['per_action_cap', false], ['aggregate_cap', false], ['deductible', false]];
    for (const [field, req] of amountFields) {
        const r = checkAmount(terms, field, req);
        if (r)
            return fail(r);
    }
    if (typeof terms.currency !== 'string' || !CURRENCY_RE.test(terms.currency)) {
        return fail('terms.currency must be a three-letter uppercase currency code');
    }
    if (agreement.recourse_ref !== undefined && (typeof agreement.recourse_ref !== 'string' || agreement.recourse_ref === '')) {
        return fail('recourse_ref, when present, must be a non-empty string');
    }
    // ── 2. CANONICAL FORM — the exact bytes every signature covers ─────────────
    let bytes;
    try {
        bytes = agreementSigningBytes(stripSignatures(agreement));
    }
    catch {
        return fail('agreement is not JCS-canonicalizable');
    }
    const digest = `sha256:${sha256hex(bytes)}`;
    // ── 3. VALIDITY WINDOW ──────────────────────────────────────────────────────
    if (now < notBefore || now > notAfter)
        return fail('agreement is outside its validity window');
    // ── 4. SIGNATURES — every REQUIRED party, under PINNED keys only ────────────
    const sigs = Array.isArray(agreement.signatures) ? agreement.signatures : [];
    const byParty = new Map();
    for (const s of sigs) {
        if (!s || typeof s !== 'object' || !AGREEMENT_ROLES.includes(s.party))
            return fail('a signature entry names no known party role');
        if (!parties[s.party])
            return fail(`a signature is present for undeclared party '${s.party}'`);
        if (byParty.has(s.party))
            return fail(`duplicate signature entries for party '${s.party}'`);
        byParty.set(s.party, s);
    }
    for (const role of required) {
        if (!byParty.has(role))
            return fail(`required signature from '${role}' is missing (the agreement is not effective)`);
    }
    // Any signature PRESENT must verify — including non-required ones. A broken
    // signature on the object is never ignorable.
    for (const [role, s] of byParty) {
        if (s.algorithm !== 'Ed25519' || typeof s.signature_b64u !== 'string' || s.signature_b64u === '') {
            return fail(`signature from '${role}' is malformed (Ed25519 signature_b64u required)`);
        }
        const keyId = parties[role].key_id;
        const pinned = pubKeyB64u(trustedKeys[keyId]);
        if (!pinned)
            return fail(`no pinned key for '${role}' (key_id ${keyId}); an unpinned signer cannot make the agreement effective`);
        const keyObj = importPinnedKey(pinned);
        if (!keyObj)
            return fail(`the pinned key for '${role}' is not a valid Ed25519 SPKI key`);
        let ok = false;
        try {
            ok = crypto.verify(null, bytes, keyObj, Buffer.from(s.signature_b64u, 'base64url'));
        }
        catch {
            ok = false;
        }
        if (!ok)
            return fail(`signature from '${role}' does not verify over the canonical agreement payload`);
    }
    reasons.push('all required signatures verify under pinned keys and the agreement is inside its validity window');
    return { valid: true, reasons, digest, required_signers: [...required] };
}
/**
 * Verify an EP-RELIANCE-EVENT-v1: the per-action claim instrument binding one
 * action's reliance verdict to a reliance agreement.
 *
 * Proves: the referenced agreement verifies (all required signatures, pinned
 * keys) and was inside its validity window AT relied_at; the event's
 * agreement_digest matches the supplied agreement; the event's action_digest
 * is the action the supplied reliance result attests; the result digest
 * matches the supplied result byte-for-byte (JCS); the result's action family
 * is inside the agreement scope; when the result names the profile it was
 * evaluated under, it is the profile the agreement conditions on; and the
 * event is signed by the agreement's relying_party under its pinned key.
 *
 * Does NOT re-evaluate the evidence: whether the verdict inside the result is
 * honest is established by replaying the reliance kernel over the evidence,
 * not by this binding check.
 *
 * @param {object} event
 * @param {object} [opts]
 * @param {object} [opts.agreement]       the EP-RELIANCE-AGREEMENT-v1 relied on
 * @param {object} [opts.relianceResult]  the reliance result record the event binds
 *                                      (must carry action_digest and action_family;
 *                                      may carry profile_digest and verdict)
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], agreement_digest?:string, event_digest?:string}}
 */
export function verifyRelianceEvent(event, opts = {}) {
    const reasons = [];
    const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
    const now = toMs(opts.now);
    const { agreement, relianceResult } = opts;
    if (!Number.isFinite(now))
        return fail('verification time must be a finite epoch or RFC-3339 instant with an explicit offset');
    // ── 1. EVENT STRUCTURE ──────────────────────────────────────────────────────
    if (!event || typeof event !== 'object' || Array.isArray(event))
        return fail('event is not an object');
    if (event.version !== RELIANCE_EVENT_VERSION)
        return fail(`version must be ${RELIANCE_EVENT_VERSION}`);
    if (typeof event.event_id !== 'string' || event.event_id === '')
        return fail('event_id must be a non-empty string');
    for (const f of ['agreement_digest', 'action_digest', 'reliance_result_digest']) {
        if (typeof event[f] !== 'string' || !SHA256_RE.test(event[f]))
            return fail(`${f} must be a sha256:<64 hex> digest`);
    }
    const reliedAt = parseTs(event.relied_at);
    if (Number.isNaN(reliedAt))
        return fail('relied_at must be a parseable timestamp');
    if (reliedAt > now)
        return fail('relied_at is in the future relative to verification time');
    // ── 2. THE AGREEMENT — must verify, and must have been effective AT relied_at
    if (!agreement || typeof agreement !== 'object')
        return fail('no agreement supplied to bind the event against');
    const ag = verifyRelianceAgreement(agreement, { trustedKeys: opts.trustedKeys, now: reliedAt });
    if (!ag.valid)
        return fail(`the referenced agreement does not verify at relied_at: ${ag.reasons.join('; ')}`);
    if (event.agreement_digest !== ag.digest) {
        return fail('the event is bound to a different agreement (agreement_digest mismatch)');
    }
    // ── 3. THE RELIANCE RESULT — the verdict this event claims under ────────────
    if (!relianceResult || typeof relianceResult !== 'object' || Array.isArray(relianceResult)) {
        return fail('no reliance result supplied to bind the event against');
    }
    if (typeof relianceResult.action_digest !== 'string' || !SHA256_RE.test(relianceResult.action_digest)) {
        return fail('the reliance result carries no sha256 action_digest');
    }
    if (event.action_digest !== relianceResult.action_digest) {
        return fail('the reliance result attests a different action than the event claims (action_digest mismatch)');
    }
    let resultDigest;
    try {
        resultDigest = relianceResultDigest(relianceResult);
    }
    catch {
        return fail('the reliance result is not JCS-canonicalizable');
    }
    if (event.reliance_result_digest !== resultDigest) {
        return fail('reliance_result_digest does not match the supplied reliance result (the result was substituted or altered)');
    }
    // ── 4. SCOPE AND CONDITION BINDING ──────────────────────────────────────────
    const families = agreement.scope.action_families;
    if (typeof relianceResult.action_family !== 'string' || relianceResult.action_family === '') {
        return fail('the reliance result names no action_family; scope cannot be established');
    }
    if (!families.includes(relianceResult.action_family)) {
        return fail(`action family '${relianceResult.action_family}' is outside the agreement scope`);
    }
    if (relianceResult.profile_digest !== undefined
        && relianceResult.profile_digest !== agreement.condition.reliance_profile_digest) {
        return fail('the reliance result was evaluated under a different reliance profile than the agreement conditions on');
    }
    // ── 5. SIGNATURE — the RELYING PARTY, under its pinned key, or nothing ──────
    const sig = event.signature;
    if (!sig || typeof sig !== 'object' || sig.algorithm !== 'Ed25519' || typeof sig.signature_b64u !== 'string' || sig.signature_b64u === '') {
        return fail('event signature is missing or malformed (Ed25519 signature_b64u required)');
    }
    const rpKeyId = agreement.parties.relying_party.key_id;
    const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};
    const pinned = pubKeyB64u(trustedKeys[rpKeyId]);
    if (!pinned)
        return fail(`no pinned key for the agreement relying_party (key_id ${rpKeyId})`);
    const keyObj = importPinnedKey(pinned);
    if (!keyObj)
        return fail('the pinned relying_party key is not a valid Ed25519 SPKI key');
    let bytes;
    try {
        bytes = eventSigningBytes(stripSignature(event));
    }
    catch {
        return fail('event is not JCS-canonicalizable');
    }
    let ok = false;
    try {
        ok = crypto.verify(null, bytes, keyObj, Buffer.from(sig.signature_b64u, 'base64url'));
    }
    catch {
        ok = false;
    }
    if (!ok)
        return fail('event signature does not verify under the agreement relying_party pinned key');
    reasons.push('the event binds this action, this reliance result, and this agreement, signed by the relying party at a time the agreement was effective');
    return { valid: true, reasons, agreement_digest: ag.digest, event_digest: `sha256:${sha256hex(bytes)}` };
}
// ===========================================================================
// EP-RELIANCE-AGREEMENT-v2 / EP-RELIANCE-EVENT-v2 -- the hybrid (Ed25519 +
// ML-DSA-65) variants
// ===========================================================================
/**
 * HYBRID MIGRATION, following the same five moves as packages/verify/src/
 * revocation.ts's EP-REVOCATION-v2 addition (read that file's comment block
 * for the full write-up; this is the short form for this artifact pair):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second per-party leg changes the SHAPE
 *    of `signatures` / `signature`, which is a wire-format change, so each
 *    artifact takes a new `version` (EP-RELIANCE-AGREEMENT-v1 -> -v2,
 *    EP-RELIANCE-EVENT-v1 -> -v2) rather than growing an optional field on
 *    v1. verifyRelianceAgreement()/verifyRelianceEvent() above are untouched
 *    and refuse a v2 object on the version marker before inspecting any
 *    signature -- proven by the version-refusal tests below.
 *
 * 2. SET SHAPE. v1's `agreement.signatures` is already an array of one entry
 *    PER PARTY; v2 adds a second dimension by turning each party's own entry
 *    from a flat Ed25519 signature into a per-party AgileSignature SET
 *    ({party, signatures:[{alg,sig,key_id?}, ...]}), mirroring
 *    EP-SIG-AGILITY-v1's shape verbatim. v1's flat `event.signature` becomes
 *    `{party:'relying_party', signatures:[...]}` the same way. Neither shape
 *    carries a public key any more (v1 did, but the verifier only ever
 *    trusted the PINNED key -- see the "signs nothing away" invariant test in
 *    tests/reliance-agreement.test.ts); v2 drops the carried key entirely and
 *    resolves both halves from `opts.trustedKeys[party's key_id]`.
 *
 * 3. ANTI-STRIPPING BYTES. `agreementV2SigningBytes`/`eventV2SigningBytes`
 *    recompute the canonical body bytes from the PRESENTED fields with
 *    `required_algorithms` forced to the REGISTERED set (never the value the
 *    object happens to carry), under a v2-only domain separator distinct from
 *    v1's. The registered-set guard means a caller can never trick these
 *    functions into signing/verifying over a narrowed set; a narrowed
 *    `required_algorithms` on the wire is instead caught structurally, up
 *    front, by name.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous and unchanged. v2 verification is
 *    ASYNC (ML-DSA verification is async), so it is a separate entry point.
 *    v2's non-signature structural checks (closed vocabularies, amount
 *    strings, validity window, required_signers completeness, event-to-
 *    agreement binding) are a deliberate DUPLICATE of v1's, not a shared
 *    refactor: this file's harness only runs tests/reliance-agreement-v2.test.ts
 *    for this change, so v1's own conformance suite cannot be re-run here to
 *    prove a refactor left it byte-for-byte identical. Duplicating is the
 *    honest choice under that constraint -- v1's existing body above is
 *    untouched and unreachable from any v2 code path.
 *
 * 5. NAMED REFUSALS. Same house style as v1 in this file: an ordered
 *    `reasons` array and a `fail(reason)` early-return helper (not
 *    revocation.ts's `checks` object -- this file's own convention already
 *    differs from that one, so v2 follows v1's local style rather than
 *    importing a second one). Nothing throws on caller-controlled content; an
 *    unavailable ML-DSA backend surfaces as a named refusal via
 *    verifyAgileSignatureSet's own reason, never a silent pass.
 */
export const RELIANCE_AGREEMENT_V2_VERSION = 'EP-RELIANCE-AGREEMENT-v2';
export const RELIANCE_EVENT_V2_VERSION = 'EP-RELIANCE-EVENT-v2';
export const RELIANCE_AGREEMENT_V2_DOMAIN = 'EP-RELIANCE-AGREEMENT-v2\0';
export const RELIANCE_EVENT_V2_DOMAIN = 'EP-RELIANCE-EVENT-v2\0';
/** The registered required algorithm set, in canonical order (agreement side). */
export const RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
/** The registered required algorithm set, in canonical order (event side). */
export const RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
function algorithmSetMatches(candidate, registered) {
    return Array.isArray(candidate)
        && candidate.length === registered.length
        && candidate.every((a, i) => a === registered[i]);
}
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
/** Normalize + strictly length-check raw key material for the honesty gate at signing time. */
function toRawKeyBytesB64u(value, expectedLength, label) {
    let bytes;
    if (value instanceof Uint8Array) {
        bytes = Buffer.from(value);
    }
    else if (typeof value === 'string' && B64URL_RE.test(value)) {
        bytes = Buffer.from(value, 'base64url');
    }
    else {
        bytes = Buffer.alloc(0);
    }
    if (bytes.length !== expectedLength) {
        throw new Error(`${label} must be ${expectedLength} raw bytes (or base64url of them)`);
    }
    return bytes.toString('base64url');
}
/** Forward only the ML-DSA backend override knobs; never `deterministic` (a signing-only knob). */
function agilityPassthrough(opts) {
    const out = {};
    if (opts.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    return out;
}
/**
 * Structural check for one party's (or the event's) AgileSignature set: exact
 * shape, no duplicates, no missing legs, no extra algorithms. Returns an error
 * fragment, or null when the set is well-formed (signature MATH is checked
 * separately by verifyAgileSignatureSet).
 */
function signatureSetStructuralError(entrySignatures, requiredAlgorithms) {
    if (!Array.isArray(entrySignatures) || entrySignatures.length === 0) {
        return 'signatures[] must carry one signature per required algorithm';
    }
    const presented = new Set();
    for (const sig of entrySignatures) {
        if (!sig || typeof sig !== 'object' || Array.isArray(sig)
            || typeof sig.alg !== 'string' || typeof sig.sig !== 'string') {
            return 'each signatures[] entry must be { alg, sig, key_id? }';
        }
        const alg = sig.alg;
        if (presented.has(alg))
            return `duplicate signature for algorithm "${alg}"`;
        presented.add(alg);
    }
    for (const alg of requiredAlgorithms) {
        if (!presented.has(alg))
            return `missing required ${alg} signature (leg stripped)`;
    }
    for (const alg of presented) {
        if (!requiredAlgorithms.includes(alg))
            return `unexpected algorithm "${alg}" outside the registered set`;
    }
    return null;
}
/**
 * The bytes EVERY party's signature set covers for an EP-RELIANCE-AGREEMENT-v2
 * agreement: the whole unsigned body (same whole-body convention as v1's
 * agreementSigningBytes), with `required_algorithms` forced to the REGISTERED
 * set, under a v2-only domain separator. Narrowing `required_algorithms` on
 * the wire, or stripping any party's leg, changes nothing about these bytes
 * (they are always computed over the true registered set); it is instead
 * caught structurally, by name, before signature verification is attempted.
 */
export function agreementV2SigningBytes(unsignedBodyV2, requiredAlgorithms = RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatches(requiredAlgorithms, RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS)) {
        throw new Error('agreementV2SigningBytes: algorithm set is not the registered EP-RELIANCE-AGREEMENT-v2 set');
    }
    return Buffer.from(RELIANCE_AGREEMENT_V2_DOMAIN + canonicalize({ ...unsignedBodyV2, required_algorithms: [...requiredAlgorithms] }), 'utf8');
}
/** The bytes the relying party's signature set covers for an EP-RELIANCE-EVENT-v2 event. */
export function eventV2SigningBytes(unsignedBodyV2, requiredAlgorithms = RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatches(requiredAlgorithms, RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS)) {
        throw new Error('eventV2SigningBytes: algorithm set is not the registered EP-RELIANCE-EVENT-v2 set');
    }
    return Buffer.from(RELIANCE_EVENT_V2_DOMAIN + canonicalize({ ...unsignedBodyV2, required_algorithms: [...requiredAlgorithms] }), 'utf8');
}
/** Digest of the v2 agreement body (domain-separated, signature envelope excluded). */
export function relianceAgreementV2Digest(agreement) {
    return `sha256:${sha256hex(agreementV2SigningBytes(stripSignatures(agreement)))}`;
}
/** Digest of the v2 event body (domain-separated, signature envelope excluded). */
export function relianceEventV2Digest(event) {
    return `sha256:${sha256hex(eventV2SigningBytes(stripSignature(event)))}`;
}
/**
 * Sign an EP-RELIANCE-AGREEMENT-v2 payload as one or more parties, each under
 * BOTH Ed25519 and ML-DSA-65 over the SAME bytes. Issuer-side test/reference
 * tooling; verification never trusts carried key material, only pinned keys
 * (opts.trustedKeys). THROWS rather than emit a half-hybrid agreement: a
 * signer missing either half, or a signing pass that fails to produce both
 * legs, is a programming error, not attacker input.
 */
export async function signRelianceAgreementV2(payload, signers = []) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('signRelianceAgreementV2 requires a payload object');
    }
    if (!Array.isArray(signers) || signers.length === 0) {
        throw new Error('signRelianceAgreementV2 requires a non-empty signers array');
    }
    const body = stripSignatures(payload);
    const bytes = agreementV2SigningBytes(body);
    const signatures = [];
    for (const s of signers) {
        if (!s || typeof s.party !== 'string' || s.party === '') {
            throw new Error('signRelianceAgreementV2: each signer requires a non-empty party role');
        }
        if (!s.privateKey || !s.pqSecretKey || !s.pqPublicKeyB64u) {
            throw new Error(`signRelianceAgreementV2: signer for '${s.party}' requires privateKey, pqSecretKey, and pqPublicKeyB64u (refusing to emit a half-hybrid agreement)`);
        }
        const pqSecretB64u = toRawKeyBytesB64u(s.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, `signer '${s.party}' pqSecretKey`);
        toRawKeyBytesB64u(s.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, `signer '${s.party}' pqPublicKeyB64u`);
        const agile = await signAgileSet(new Uint8Array(bytes), [
            { alg: 'Ed25519', private_key: s.privateKey },
            { alg: 'ML-DSA-65', private_key: pqSecretB64u },
        ]);
        const byAlg = new Map(agile.map((a) => [a.alg, a]));
        const ordered = RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS.map((alg) => {
            const entry = byAlg.get(alg);
            if (!entry)
                throw new Error(`signRelianceAgreementV2: signing produced no ${alg} leg for '${s.party}' (refusing to emit a half-hybrid agreement)`);
            return { alg: entry.alg, sig: entry.sig };
        });
        signatures.push({ party: s.party, signatures: ordered });
    }
    return { ...body, required_algorithms: [...RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS], signatures };
}
/**
 * Sign an EP-RELIANCE-EVENT-v2 payload as the relying party, under BOTH
 * Ed25519 and ML-DSA-65 over the SAME bytes. THROWS rather than emit a
 * half-hybrid event.
 */
export async function signRelianceEventV2(payload, signer) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('signRelianceEventV2 requires a payload object');
    }
    if (!signer || !signer.privateKey || !signer.pqSecretKey || !signer.pqPublicKeyB64u) {
        throw new Error('signRelianceEventV2 requires signer.{privateKey,pqSecretKey,pqPublicKeyB64u} (refusing to emit a half-hybrid event)');
    }
    const body = stripSignature(payload);
    const bytes = eventV2SigningBytes(body);
    const pqSecretB64u = toRawKeyBytesB64u(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer pqSecretKey');
    toRawKeyBytesB64u(signer.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer pqPublicKeyB64u');
    const agile = await signAgileSet(new Uint8Array(bytes), [
        { alg: 'Ed25519', private_key: signer.privateKey },
        { alg: 'ML-DSA-65', private_key: pqSecretB64u },
    ]);
    const byAlg = new Map(agile.map((a) => [a.alg, a]));
    const ordered = RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS.map((alg) => {
        const entry = byAlg.get(alg);
        if (!entry)
            throw new Error(`signRelianceEventV2: signing produced no ${alg} leg (refusing to emit a half-hybrid event)`);
        return { alg: entry.alg, sig: entry.sig };
    });
    return {
        ...body,
        required_algorithms: [...RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS],
        signature: { party: 'relying_party', signatures: ordered },
    };
}
/**
 * Verify an EP-RELIANCE-AGREEMENT-v2 against pinned party key PAIRS (Ed25519 +
 * ML-DSA-65 per party). Same non-signature structural proof as
 * verifyRelianceAgreement (v1) -- see that function's doc comment -- except
 * every REQUIRED party must carry a full hybrid signature SET that verifies
 * under BOTH pinned halves. ASYNC (ML-DSA verification is async). Fail-closed:
 * never throws on caller input; a v1 object refuses immediately on the
 * version marker.
 *
 * @param {object} agreement
 * @param {object} [opts]
 * @param {Object<string,{public_key?:string, pq_public_key?:string}>} [opts.trustedKeys]
 *   key_id -> pinned {Ed25519 SPKI b64u, ML-DSA-65 raw b64u} pair
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], digest?:string, required_signers?:string[]}}
 */
export async function verifyRelianceAgreementV2(agreement, opts = {}) {
    const reasons = [];
    const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
    const now = toMs(opts.now);
    const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};
    if (!Number.isFinite(now))
        return fail('verification time must be a finite epoch or RFC-3339 instant with an explicit offset');
    // -- 1. STRUCTURE - closed vocabularies, fail-closed (duplicated from v1;
    //    see move 4 in the comment block above for why this is a duplicate and
    //    not a shared refactor) --
    if (!agreement || typeof agreement !== 'object' || Array.isArray(agreement))
        return fail('agreement is not an object');
    if (agreement.version !== RELIANCE_AGREEMENT_V2_VERSION)
        return fail(`version must be ${RELIANCE_AGREEMENT_V2_VERSION}`);
    if (typeof agreement.agreement_id !== 'string' || agreement.agreement_id === '')
        return fail('agreement_id must be a non-empty string');
    const parties = agreement.parties;
    if (!parties || typeof parties !== 'object' || Array.isArray(parties))
        return fail('parties must be an object');
    for (const role of Object.keys(parties)) {
        if (!AGREEMENT_ROLES.includes(role))
            return fail(`unknown party role '${role}' (closed set: ${AGREEMENT_ROLES.join(', ')})`);
    }
    for (const role of ['issuer', 'relying_party']) {
        const p = parties[role];
        if (!p || typeof p !== 'object')
            return fail(`parties.${role} is required`);
        if (typeof p.id !== 'string' || p.id === '')
            return fail(`parties.${role}.id must be a non-empty string`);
        if (typeof p.key_id !== 'string' || p.key_id === '')
            return fail(`parties.${role}.key_id must be a non-empty string`);
    }
    if (parties.underwriter !== undefined) {
        const u = parties.underwriter;
        if (!u || typeof u !== 'object' || typeof u.id !== 'string' || u.id === '' || typeof u.key_id !== 'string' || u.key_id === '') {
            return fail('parties.underwriter, when present, must carry a non-empty id and key_id');
        }
    }
    const required = agreement.required_signers;
    if (!Array.isArray(required) || required.length === 0)
        return fail('required_signers must be a non-empty array');
    if (new Set(required).size !== required.length)
        return fail('required_signers must not contain duplicates');
    for (const role of required) {
        if (!AGREEMENT_ROLES.includes(role))
            return fail(`required_signers contains unknown role '${role}'`);
        if (!parties[role])
            return fail(`required_signers names '${role}' but the agreement declares no such party`);
    }
    if (!required.includes('issuer') || !required.includes('relying_party')) {
        return fail('required_signers must include both issuer and relying_party (an agreement neither issued nor accepted is not an agreement)');
    }
    const scope = agreement.scope;
    if (!scope || typeof scope !== 'object')
        return fail('scope is required');
    if (!Array.isArray(scope.action_families) || scope.action_families.length === 0
        || !scope.action_families.every((f) => typeof f === 'string' && f !== '')) {
        return fail('scope.action_families must be a non-empty array of non-empty strings');
    }
    if (scope.jurisdictions !== undefined
        && (!Array.isArray(scope.jurisdictions) || !scope.jurisdictions.every((j) => typeof j === 'string' && j !== ''))) {
        return fail('scope.jurisdictions, when present, must be an array of non-empty strings');
    }
    const validity = scope.validity;
    if (!validity || typeof validity !== 'object')
        return fail('scope.validity is required');
    const notBefore = parseTs(validity.not_before);
    const notAfter = parseTs(validity.not_after);
    if (Number.isNaN(notBefore) || Number.isNaN(notAfter))
        return fail('scope.validity.not_before and not_after must be parseable timestamps');
    if (notBefore >= notAfter)
        return fail('scope.validity.not_before must precede not_after');
    const condition = agreement.condition;
    if (!condition || typeof condition !== 'object')
        return fail('condition is required');
    if (typeof condition.reliance_profile_digest !== 'string' || !SHA256_RE.test(condition.reliance_profile_digest)) {
        return fail('condition.reliance_profile_digest must be a sha256:<64 hex> digest of the pinned reliance profile');
    }
    if (condition.min_assurance_class !== undefined && !ASSURANCE_CLASSES.includes(condition.min_assurance_class)) {
        return fail(`condition.min_assurance_class must be one of ${ASSURANCE_CLASSES.join(', ')}`);
    }
    if (condition.max_staleness_sec !== undefined
        && !(Number.isFinite(condition.max_staleness_sec) && condition.max_staleness_sec >= 0)) {
        return fail('condition.max_staleness_sec must be a non-negative finite number');
    }
    const terms = agreement.terms;
    if (!terms || typeof terms !== 'object')
        return fail('terms is required');
    if (!AGREEMENT_MODES.includes(terms.mode)) {
        return fail(`terms.mode '${String(terms.mode)}' is not in the closed set (${AGREEMENT_MODES.join(', ')})`);
    }
    const amountFields = [['cap_amount', true], ['per_action_cap', false], ['aggregate_cap', false], ['deductible', false]];
    for (const [field, req] of amountFields) {
        const r = checkAmount(terms, field, req);
        if (r)
            return fail(r);
    }
    if (typeof terms.currency !== 'string' || !CURRENCY_RE.test(terms.currency)) {
        return fail('terms.currency must be a three-letter uppercase currency code');
    }
    if (agreement.recourse_ref !== undefined && (typeof agreement.recourse_ref !== 'string' || agreement.recourse_ref === '')) {
        return fail('recourse_ref, when present, must be a non-empty string');
    }
    // -- 1b. V2-ONLY: the committed algorithm set, exact and order-sensitive.
    //    A narrowed or widened set is refused HERE, structurally, before any
    //    signature is even attempted (never a signature-math surprise). --
    if (!algorithmSetMatches(agreement.required_algorithms, RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS)) {
        return fail(`required_algorithms must be exactly ${JSON.stringify([...RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    // -- 2. CANONICAL FORM - the exact bytes every party's signature set covers --
    let bytes;
    try {
        bytes = agreementV2SigningBytes(stripSignatures(agreement));
    }
    catch {
        return fail('agreement is not JCS-canonicalizable');
    }
    const digest = `sha256:${sha256hex(bytes)}`;
    // -- 3. VALIDITY WINDOW --
    if (now < notBefore || now > notAfter)
        return fail('agreement is outside its validity window');
    // -- 4. SIGNATURE SETS - every REQUIRED party, both algorithms, under PINNED
    //    key PAIRS only. Any signature set PRESENT must verify, including
    //    non-required ones (never ignorable), same as v1. --
    const sigs = Array.isArray(agreement.signatures) ? agreement.signatures : [];
    const byParty = new Map();
    for (const s of sigs) {
        if (!s || typeof s !== 'object' || !AGREEMENT_ROLES.includes(s.party))
            return fail('a signature entry names no known party role');
        if (!parties[s.party])
            return fail(`a signature is present for undeclared party '${s.party}'`);
        if (byParty.has(s.party))
            return fail(`duplicate signature entries for party '${s.party}'`);
        byParty.set(s.party, s);
    }
    for (const role of required) {
        if (!byParty.has(role))
            return fail(`required signature set from '${role}' is missing (the agreement is not effective)`);
    }
    for (const [role, s] of byParty) {
        const shapeError = signatureSetStructuralError(s.signatures, RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS);
        if (shapeError)
            return fail(`signature set from '${role}' is malformed: ${shapeError}`);
        const keyId = parties[role].key_id;
        const pin = trustedKeys[keyId] || {};
        if (!pin.public_key || !pin.pq_public_key) {
            return fail(`no pinned Ed25519 + ML-DSA-65 key pair for '${role}' (key_id ${keyId}); an unpinned signer cannot make the agreement effective`);
        }
        let setResult;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), s.signatures, [
                { alg: 'Ed25519', public_key: pin.public_key },
                { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
            ], {
                ...agilityPassthrough(opts),
                policy: 'hybrid_all',
                requiredAlgorithms: [...RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS],
            });
        }
        catch {
            // verifyAgileSignatureSet documents that it never throws; an injected
            // backend that does is still a refusal here, never a pass.
            setResult = null;
        }
        if (setResult?.verified !== true) {
            const reason = String(setResult?.reason ?? 'signature_set_unverified');
            return fail(`signature set from '${role}' does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
        }
    }
    reasons.push('all required signature sets verify under pinned keys and the agreement is inside its validity window');
    return { valid: true, reasons, digest, required_signers: [...required] };
}
/**
 * Verify an EP-RELIANCE-EVENT-v2: the per-action claim instrument binding one
 * action's reliance verdict to an EP-RELIANCE-AGREEMENT-v2. Same proof shape
 * as verifyRelianceEvent (v1) -- see that function's doc comment -- except
 * the referenced agreement is checked with verifyRelianceAgreementV2 and the
 * event's own signature is a hybrid SET verified under the agreement's
 * relying_party pinned key PAIR. ASYNC. Fail-closed; never throws.
 *
 * @param {object} event
 * @param {object} [opts]
 * @param {object} [opts.agreement]       the EP-RELIANCE-AGREEMENT-v2 relied on
 * @param {object} [opts.relianceResult]  the reliance result record the event binds
 * @param {Object<string,{public_key?:string, pq_public_key?:string}>} [opts.trustedKeys]
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], agreement_digest?:string, event_digest?:string}}
 */
export async function verifyRelianceEventV2(event, opts = {}) {
    const reasons = [];
    const fail = (reason) => { reasons.push(reason); return { valid: false, reasons }; };
    const now = toMs(opts.now);
    const { agreement, relianceResult } = opts;
    if (!Number.isFinite(now))
        return fail('verification time must be a finite epoch or RFC-3339 instant with an explicit offset');
    // -- 1. EVENT STRUCTURE (duplicated from v1; see move 4 above) --
    if (!event || typeof event !== 'object' || Array.isArray(event))
        return fail('event is not an object');
    if (event.version !== RELIANCE_EVENT_V2_VERSION)
        return fail(`version must be ${RELIANCE_EVENT_V2_VERSION}`);
    if (typeof event.event_id !== 'string' || event.event_id === '')
        return fail('event_id must be a non-empty string');
    for (const f of ['agreement_digest', 'action_digest', 'reliance_result_digest']) {
        if (typeof event[f] !== 'string' || !SHA256_RE.test(event[f]))
            return fail(`${f} must be a sha256:<64 hex> digest`);
    }
    const reliedAt = parseTs(event.relied_at);
    if (Number.isNaN(reliedAt))
        return fail('relied_at must be a parseable timestamp');
    if (reliedAt > now)
        return fail('relied_at is in the future relative to verification time');
    // -- 1b. V2-ONLY: the committed algorithm set --
    if (!algorithmSetMatches(event.required_algorithms, RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS)) {
        return fail(`required_algorithms must be exactly ${JSON.stringify([...RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    // -- 2. THE AGREEMENT - must verify (v2), and must have been effective AT relied_at
    if (!agreement || typeof agreement !== 'object')
        return fail('no agreement supplied to bind the event against');
    const ag = await verifyRelianceAgreementV2(agreement, {
        trustedKeys: opts.trustedKeys,
        now: reliedAt,
        ...agilityPassthrough(opts),
    });
    if (!ag.valid)
        return fail(`the referenced agreement does not verify at relied_at: ${ag.reasons.join('; ')}`);
    if (event.agreement_digest !== ag.digest) {
        return fail('the event is bound to a different agreement (agreement_digest mismatch)');
    }
    // -- 3. THE RELIANCE RESULT - the verdict this event claims under --
    if (!relianceResult || typeof relianceResult !== 'object' || Array.isArray(relianceResult)) {
        return fail('no reliance result supplied to bind the event against');
    }
    if (typeof relianceResult.action_digest !== 'string' || !SHA256_RE.test(relianceResult.action_digest)) {
        return fail('the reliance result carries no sha256 action_digest');
    }
    if (event.action_digest !== relianceResult.action_digest) {
        return fail('the reliance result attests a different action than the event claims (action_digest mismatch)');
    }
    let resultDigest;
    try {
        resultDigest = relianceResultDigest(relianceResult);
    }
    catch {
        return fail('the reliance result is not JCS-canonicalizable');
    }
    if (event.reliance_result_digest !== resultDigest) {
        return fail('reliance_result_digest does not match the supplied reliance result (the result was substituted or altered)');
    }
    // -- 4. SCOPE AND CONDITION BINDING --
    const families = agreement.scope.action_families;
    if (typeof relianceResult.action_family !== 'string' || relianceResult.action_family === '') {
        return fail('the reliance result names no action_family; scope cannot be established');
    }
    if (!families.includes(relianceResult.action_family)) {
        return fail(`action family '${relianceResult.action_family}' is outside the agreement scope`);
    }
    if (relianceResult.profile_digest !== undefined
        && relianceResult.profile_digest !== agreement.condition.reliance_profile_digest) {
        return fail('the reliance result was evaluated under a different reliance profile than the agreement conditions on');
    }
    // -- 5. SIGNATURE SET - the RELYING PARTY, under its pinned key PAIR, or nothing --
    const sig = event.signature;
    if (!sig || typeof sig !== 'object' || sig.party !== 'relying_party') {
        return fail('event signature set is missing or malformed (party must be relying_party)');
    }
    const shapeError = signatureSetStructuralError(sig.signatures, RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS);
    if (shapeError)
        return fail(`event signature set is malformed: ${shapeError}`);
    const rpKeyId = agreement.parties.relying_party.key_id;
    const trustedKeys = opts.trustedKeys && typeof opts.trustedKeys === 'object' ? opts.trustedKeys : {};
    const pin = trustedKeys[rpKeyId] || {};
    if (!pin.public_key || !pin.pq_public_key) {
        return fail(`no pinned Ed25519 + ML-DSA-65 key pair for the agreement relying_party (key_id ${rpKeyId})`);
    }
    let bytes;
    try {
        bytes = eventV2SigningBytes(stripSignature(event));
    }
    catch {
        return fail('event is not JCS-canonicalizable');
    }
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), sig.signatures, [
            { alg: 'Ed25519', public_key: pin.public_key },
            { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
        ], {
            ...agilityPassthrough(opts),
            policy: 'hybrid_all',
            requiredAlgorithms: [...RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        return fail(`event signature set does not verify under the agreement relying_party pinned Ed25519 + ML-DSA-65 keys (${reason})`);
    }
    reasons.push('the event binds this action, this reliance result, and this agreement, signed (hybrid) by the relying party at a time the agreement was effective');
    return { valid: true, reasons, agreement_digest: ag.digest, event_digest: `sha256:${sha256hex(bytes)}` };
}
/**
 * Route an agreement of EITHER version to its verifier. v1 agreements get the
 * exact v1 verdict (unchanged, synchronous body); v2 agreements get the
 * hybrid check. Mirrors verifyRevocationStatement in revocation.ts.
 */
export async function verifyRelianceAgreementStatement(agreement, opts = {}) {
    if (agreement && typeof agreement === 'object' && !Array.isArray(agreement)
        && agreement.version === RELIANCE_AGREEMENT_V2_VERSION) {
        return verifyRelianceAgreementV2(agreement, opts);
    }
    return verifyRelianceAgreement(agreement, opts);
}
/** Route an event of EITHER version to its verifier. Mirrors verifyRevocationStatement. */
export async function verifyRelianceEventStatement(event, opts = {}) {
    if (event && typeof event === 'object' && !Array.isArray(event)
        && event.version === RELIANCE_EVENT_V2_VERSION) {
        return verifyRelianceEventV2(event, opts);
    }
    return verifyRelianceEvent(event, opts);
}
//# sourceMappingURL=reliance-agreement.js.map
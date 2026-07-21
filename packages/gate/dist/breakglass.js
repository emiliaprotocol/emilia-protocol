// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — break-glass as EVIDENCE, never a bypass (EP-GATE-BREAKGLASS-v1).
 *
 * An emergency override is a FIRST-CLASS SIGNED ARTIFACT, not a config flag.
 * There is no "disable the gate" switch anywhere in this module: to act outside
 * the normal receipt path, operators mint a break-glass authorization — an
 * M-of-N Ed25519 multi-signature over canonical JSON (sorted keys, same idiom
 * as receipts/entitlements/evidence) of ONE shared grant:
 *
 *   { grant_id, scope: { action_types[] }, window: { not_before, expires_at },
 *     reason, incident_ref, threshold }
 *
 * Every signer signs the SAME payload, so the artifact proves that `threshold`
 * DISTINCT pinned principals authorized exactly this scope, for exactly this
 * window, for exactly this incident. The grant is:
 *   - SCOPED     — valid only for the listed action_types; anything else refuses;
 *   - BOUNDED    — valid only inside [not_before, expires_at];
 *   - ATTRIBUTED — reason + incident_ref are REQUIRED; an override with no
 *                  stated cause is refused, not logged-and-allowed;
 *   - SINGLE-USE — consumed through the same consumption-store contract as
 *                  receipts (store.js); consumption is committed BEFORE use, so
 *                  a crash mid-override burns the grant instead of leaving it
 *                  replayable (fail direction: unusable, never reusable);
 *   - LOGGED     — `buildBreakGlassEvidence` shapes a kind:'breakglass' entry
 *                  for the tamper-evident evidence log.
 *
 * THE MODULE'S EXECUTION CONTRACT: use `runBreakGlass`. It is the one high-level
 * path that enforces pinned-policy verification, permanent fleet-safe
 * consumption, strict evidence acknowledgement, and only then effect invocation.
 * The lower-level verify/consume/evidence helpers are composable primitives; no
 * one of them alone authorizes or executes an override.
 *
 * Verification FAILS CLOSED with machine-readable reasons: threshold unmet,
 * non-distinct signer kids, expired, not-yet-valid, out-of-scope action_type,
 * tampered payload, unknown kid, malformed anything → { valid:false, reason }.
 * A grant carrying ANY signature that does not verify is refused outright —
 * we never "count the good ones" past a bad one.
 *
 * Pure functions: inputs in, verdict out. Time is injected (`now`), never read
 * from the wall clock implicitly, so verification is deterministic.
 */
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
import { canonicalize as canonical } from './execution-binding.js';
import { verifyEvidenceRecord } from './evidence.js';
import { isSecureConsumptionStore } from './store.js';
export const BREAKGLASS_VERSION = 'EP-GATE-BREAKGLASS-v1';
export const BREAKGLASS_EVIDENCE_KIND = 'breakglass';
function sha256hex(s) {
    return crypto.createHash('sha256').update(s).digest('hex');
}
function toMs(t) {
    if (t == null)
        return null;
    const ms = typeof t === 'number' ? t : Date.parse(t);
    return Number.isFinite(ms) ? ms : null;
}
/** Every refusal shape is identical and machine-readable. Fail closed. */
function refuse(reason, extra = {}) {
    return { valid: false, reason, ...extra };
}
function isNonEmptyString(s) {
    return typeof s === 'string' && s.length > 0;
}
function isActionTypeList(a) {
    return Array.isArray(a) && a.length > 0 && a.every(isNonEmptyString);
}
/**
 * Mint a break-glass authorization: every signer signs the canonical JSON of
 * the SAME grant payload. Throws on invalid fields — a malformed grant must
 * never be issued, only refused. Signer kids must already be distinct at mint
 * time: one key can never pre-fill two threshold slots. Relying-party principal
 * uniqueness is enforced at verification through the pinned policy roster.
 *
 * grant_id is CONTENT-DERIVED (sha-256 of the canonical grant fields), so the
 * id is deterministic and re-minting the identical grant yields the identical
 * single-use consumption key — the same emergency authorization cannot be
 * "refreshed" into extra uses by minting it twice.
 *
 * @param {Array<{ privateKey: crypto.KeyObject, kid: string }>} signers
 * @param {object} fields { scope: { action_types: string[] }, window: { not_before, expires_at }, reason, incident_ref, threshold }
 * @returns {{ '@version': string, payload: object, signatures: Array<{ kid: string, algorithm: 'Ed25519', value: string }> }}
 */
export function mintBreakGlassAuthorization(signers, { scope, window: win, reason, incident_ref, threshold, } = {}) {
    if (!Array.isArray(signers) || signers.length === 0) {
        throw new Error('breakglass: signers must be a non-empty array of { privateKey, kid }');
    }
    for (const s of signers) {
        if (!s || !s.privateKey || !isNonEmptyString(s.kid)) {
            throw new Error('breakglass: each signer needs a privateKey and a kid');
        }
    }
    const kids = signers.map((s) => s.kid);
    if (new Set(kids).size !== kids.length) {
        throw new Error('breakglass: signer kids must be distinct — one principal cannot fill two threshold slots');
    }
    let signerFingerprints;
    try {
        signerFingerprints = signers.map((s) => {
            // @types/node's createPublicKey overloads omit KeyObject input even
            // though Node derives a public key from a private KeyObject at runtime.
            const publicKey = crypto.createPublicKey(/** @type {any} */ (s.privateKey));
            if (publicKey.asymmetricKeyType !== 'ed25519')
                throw new Error('not Ed25519');
            const spki = publicKey.export({ type: 'spki', format: 'der' });
            return sha256hex(spki);
        });
    }
    catch {
        throw new Error('breakglass: every signer privateKey must be an Ed25519 key');
    }
    if (new Set(signerFingerprints).size !== signerFingerprints.length) {
        throw new Error('breakglass: signer SPKI keys must be distinct — one key cannot fill two threshold slots');
    }
    if (!scope || !isActionTypeList(scope.action_types)) {
        throw new Error('breakglass: scope.action_types must be a non-empty array of action-type strings');
    }
    if (typeof threshold !== 'number' || !Number.isInteger(threshold) || threshold < 2) {
        throw new Error('breakglass: threshold must be an integer >= 2');
    }
    if (threshold > signers.length) {
        throw new Error(`breakglass: threshold ${threshold} exceeds signer count ${signers.length} — the grant could never verify`);
    }
    const nbf = toMs(win?.not_before);
    const exp = toMs(win?.expires_at);
    if (nbf == null || exp == null) {
        throw new Error('breakglass: window.not_before and window.expires_at are required (ISO or ms)');
    }
    if (exp <= nbf)
        throw new Error('breakglass: window.expires_at must be after window.not_before');
    // An override with no stated cause must never exist — attribution is the deal.
    if (!isNonEmptyString(reason))
        throw new Error('breakglass: reason is required');
    if (!isNonEmptyString(incident_ref))
        throw new Error('breakglass: incident_ref is required');
    const core = {
        scope: { action_types: scope.action_types.slice() },
        // win is guaranteed defined here: nbf/exp are non-null only when
        // win?.not_before / win?.expires_at parsed successfully above.
        window: { not_before: win.not_before, expires_at: win.expires_at },
        reason,
        incident_ref,
        threshold,
    };
    const grant_id = `bg_${sha256hex(canonical(core))}`;
    const payload = { grant_id, ...core };
    const msg = Buffer.from(canonical(payload), 'utf8');
    const signatures = signers.map(({ privateKey, kid }) => ({
        kid,
        algorithm: /** @type {'Ed25519'} */ ('Ed25519'),
        value: crypto.sign(null, msg, privateKey).toString('base64url'),
    }));
    return { '@version': BREAKGLASS_VERSION, payload, signatures };
}
/** Resolve a base64url SPKI-DER key for `kid` from a map or an entry list. */
function issuerKeyFor(issuerKeys, kid) {
    if (!issuerKeys)
        return null;
    if (Array.isArray(issuerKeys)) {
        const e = issuerKeys.find((x) => x && x.kid === kid && typeof x.key === 'string');
        return e ? e.key : null;
    }
    const k = issuerKeys[kid];
    return typeof k === 'string' ? k : null;
}
function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function pinnedKey(key) {
    if (typeof key !== 'string' || !/^[A-Za-z0-9_-]+$/.test(key)) {
        throw new Error('invalid pinned key encoding');
    }
    const bytes = Buffer.from(key, 'base64url');
    if (bytes.length === 0 || bytes.toString('base64url') !== key) {
        throw new Error('non-canonical pinned key encoding');
    }
    const publicKey = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    if (publicKey.asymmetricKeyType !== 'ed25519')
        throw new Error('pinned key is not Ed25519');
    const canonicalSpki = publicKey.export({ type: 'spki', format: 'der' });
    return {
        publicKey,
        fingerprint: `sha256:${sha256hex(canonicalSpki)}`,
    };
}
/**
 * Normalize the relying-party trust policy; presenter material is never used.
 * @returns {{ok:false, reason:string}|{ok:true, minimum_threshold:number, roster:Map<string,{kid:string, principal_id:string, publicKey:import('crypto').KeyObject, fingerprint:string}>}}
 */
function normalizePinnedPolicy(policy, issuerKeys) {
    if (!isPlainObject(policy))
        return { ok: false, reason: 'missing_policy' };
    if (!Number.isSafeInteger(policy.minimum_threshold) || policy.minimum_threshold < 2
        || !Array.isArray(policy.roster)) {
        return { ok: false, reason: 'invalid_policy' };
    }
    try {
        const roster = new Map();
        for (const entry of policy.roster) {
            if (!isPlainObject(entry) || !isNonEmptyString(entry.kid)
                || !isNonEmptyString(entry.principal_id) || roster.has(entry.kid)) {
                return { ok: false, reason: 'invalid_policy' };
            }
            const key = isNonEmptyString(entry.key) ? entry.key : issuerKeyFor(issuerKeys, entry.kid);
            const keyInfo = pinnedKey(key);
            roster.set(entry.kid, {
                kid: entry.kid,
                principal_id: entry.principal_id,
                ...keyInfo,
            });
        }
        const members = [...roster.values()];
        if (new Set(members.map((entry) => entry.principal_id)).size < policy.minimum_threshold
            || new Set(members.map((entry) => entry.fingerprint)).size < policy.minimum_threshold) {
            return { ok: false, reason: 'invalid_policy' };
        }
        return {
            ok: true,
            minimum_threshold: policy.minimum_threshold,
            roster,
        };
    }
    catch {
        return { ok: false, reason: 'invalid_policy' };
    }
}
/**
 * Verify a break-glass grant against a relying-party-pinned policy. NEVER throws for a
 * bad artifact — every failure resolves to { valid:false, reason } so the
 * refusal itself is loggable. FAILS CLOSED on every path:
 *   no_grant | grant_unparseable | grant_malformed | unsupported_version |
 *   unsupported_algorithm | invalid_threshold | invalid_scope |
 *   missing_reason | missing_incident_ref | missing_policy | invalid_policy |
 *   duplicate_signer | duplicate_signer_principal | duplicate_signer_key |
 *   policy_threshold_unmet | threshold_unmet | signer_not_in_roster | bad_signature |
 *   invalid_validity_window | not_yet_valid | expired |
 *   action_type_required | out_of_scope
 *
 * A grant can never nominate its own threshold, roster, identities, or keys.
 * EVERY listed signature must verify against its pinned roster entry — one
 * tampered or unrostered signature refuses the whole grant. The validity window is checked
 * only AFTER the signatures, so the timestamps themselves are authenticated.
 *
 * @param {object|string|null} grantJson the artifact (object or JSON string)
 * @param {object} [o]
 * @param {{minimum_threshold:number,roster:Array<{kid:string,principal_id:string,key?:string}>}} [o.policy] relying-party policy (a missing policy refuses, never throws)
 * @param {object|Array<{kid:string,key:string}>} [o.issuerKeys] optional pinned keys when roster entries omit key
 * @param {number|string|function} [o.now=Date.now] injected clock (ms, ISO, or () => ms)
 * @param {string} [o.actionType] the action the caller wants to override (a missing actionType refuses, never throws)
 * @returns {{ valid: boolean, reason: string, grant_id?: string, incident_ref?: string, scope?: object, window?: object, threshold?: number, required_threshold?: number, policy_minimum_threshold?: number, signer_kids?: string[], signer_principal_ids?: string[], signer_spki_fingerprints?: string[] }}
 */
function verifyBreakGlassInternal(grantJson, { policy, issuerKeys, now = Date.now, actionType, } = {}) {
    if (grantJson == null || grantJson === '')
        return refuse('no_grant');
    let doc = grantJson;
    if (typeof doc === 'string') {
        try {
            if (Buffer.byteLength(doc, 'utf8') > 1024 * 1024 || !strictJsonGate(doc).ok)
                return refuse('grant_unparseable');
            doc = JSON.parse(doc);
        }
        catch {
            return refuse('grant_unparseable');
        }
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc))
        return refuse('grant_malformed');
    if (doc['@version'] !== BREAKGLASS_VERSION)
        return refuse('unsupported_version');
    const p = doc.payload;
    const sigs = doc.signatures;
    if (!p || typeof p !== 'object' || !Array.isArray(sigs) || sigs.length === 0) {
        return refuse('grant_malformed');
    }
    if (!isNonEmptyString(p.grant_id))
        return refuse('grant_malformed');
    if (!Number.isInteger(p.threshold) || p.threshold < 1)
        return refuse('invalid_threshold');
    if (!p.scope || !isActionTypeList(p.scope.action_types))
        return refuse('invalid_scope');
    // Attribution is non-optional: an anonymous or causeless override is refused.
    if (!isNonEmptyString(p.reason))
        return refuse('missing_reason');
    if (!isNonEmptyString(p.incident_ref))
        return refuse('missing_incident_ref');
    const pinned = normalizePinnedPolicy(policy, issuerKeys);
    if (!pinned.ok)
        return refuse(pinned.reason);
    for (const s of sigs) {
        if (!s || typeof s !== 'object' || !isNonEmptyString(s.kid) || typeof s.value !== 'string') {
            return refuse('grant_malformed');
        }
        if (s.algorithm !== 'Ed25519')
            return refuse('unsupported_algorithm', { kid: s.kid });
    }
    // Distinct roster slots, pinned human principals, and canonical SPKI keys are
    // independent predicates. Aliases cannot satisfy separation of duties.
    const kids = sigs.map((s) => s.kid);
    if (new Set(kids).size !== kids.length) {
        const dup = kids.find((k, i) => kids.indexOf(k) !== i);
        return refuse('duplicate_signer', { kid: dup });
    }
    const signerEntries = [];
    for (const kid of kids) {
        const entry = pinned.roster.get(kid);
        if (!entry)
            return refuse('signer_not_in_roster', { kid });
        signerEntries.push(entry);
    }
    const principalIds = signerEntries.map((entry) => entry.principal_id);
    if (new Set(principalIds).size !== principalIds.length) {
        const principalId = principalIds.find((id, i) => principalIds.indexOf(id) !== i);
        return refuse('duplicate_signer_principal', { principal_id: principalId });
    }
    const fingerprints = signerEntries.map((entry) => entry.fingerprint);
    if (new Set(fingerprints).size !== fingerprints.length) {
        const fingerprint = fingerprints.find((value, i) => fingerprints.indexOf(value) !== i);
        return refuse('duplicate_signer_key', { spki_fingerprint: fingerprint });
    }
    if (sigs.length < p.threshold) {
        return refuse('threshold_unmet', { threshold: p.threshold, signatures: sigs.length });
    }
    if (sigs.length < pinned.minimum_threshold) {
        return refuse('policy_threshold_unmet', {
            required_threshold: pinned.minimum_threshold,
            presented_threshold: p.threshold,
            signatures: sigs.length,
        });
    }
    // Every listed signature must verify against its pinned roster key. Never
    // count past one failure.
    let msg;
    try {
        msg = Buffer.from(canonical(p), 'utf8');
    }
    catch {
        return refuse('grant_malformed');
    }
    for (let i = 0; i < sigs.length; i++) {
        const s = sigs[i];
        let ok;
        try {
            ok = crypto.verify(null, msg, signerEntries[i].publicKey, Buffer.from(s.value, 'base64url'));
        }
        catch {
            return refuse('bad_signature', { kid: s.kid });
        }
        if (ok !== true)
            return refuse('bad_signature', { kid: s.kid });
    }
    // Validity window — checked only AFTER the signatures, so the timestamps
    // themselves are authenticated. Both bounds are required; unparseable fails closed.
    let nowMs;
    try {
        nowMs = typeof now === 'function' ? toMs(now()) : toMs(now);
    }
    catch {
        nowMs = null;
    }
    const nbf = toMs(p.window?.not_before);
    const exp = toMs(p.window?.expires_at);
    if (nbf == null || exp == null || nowMs == null)
        return refuse('invalid_validity_window');
    if (nowMs < nbf)
        return refuse('not_yet_valid', { not_before: p.window.not_before });
    if (nowMs > exp)
        return refuse('expired', { expires_at: p.window.expires_at });
    // Scope: without knowing the action there is nothing to authorize — refuse.
    if (!isNonEmptyString(actionType))
        return refuse('action_type_required');
    if (!p.scope.action_types.includes(actionType)) {
        return refuse('out_of_scope', { action_type: actionType, scope: p.scope.action_types.slice() });
    }
    return {
        valid: true,
        reason: 'breakglass_verified',
        grant_id: p.grant_id,
        incident_ref: p.incident_ref,
        scope: { action_types: p.scope.action_types.slice() },
        window: { not_before: p.window.not_before, expires_at: p.window.expires_at },
        threshold: p.threshold,
        required_threshold: Math.max(p.threshold, pinned.minimum_threshold),
        policy_minimum_threshold: pinned.minimum_threshold,
        signer_kids: kids.slice(),
        signer_principal_ids: principalIds.slice(),
        signer_spki_fingerprints: fingerprints.slice(),
    };
}
export function verifyBreakGlass(grantJson, options = {}) {
    try {
        return verifyBreakGlassInternal(grantJson, options);
    }
    catch {
        return refuse('grant_malformed');
    }
}
/**
 * SINGLE-USE consumption via the consumption-store contract (store.js):
 * `consume(key)` returns true the FIRST time, false on every replay, and marks
 * the key seen BEFORE the caller acts — consumption is committed before use.
 * If the process crashes after consume() and before the override, the grant is
 * burned, not replayable: the fail direction is unusable, never reusable.
 *
 * Accepts the grant document ({ payload: { grant_id } }) or a verified result
 * ({ grant_id }). NEVER throws — a missing store, missing grant_id, or a store
 * error all refuse with a machine-readable reason. This is a low-level primitive;
 * only runBreakGlass also enforces store capabilities, evidence, and execution order.
 *
 * @param {object} grant break-glass grant document or verifyBreakGlass result
 * @param {{ consume(key: string): Promise<boolean> }} store consumption store (store.js contract)
 * @returns {Promise<{ consumed: boolean, reason: string, key?: string }>}
 */
export async function consumeBreakGlass(grant, store) {
    const grantId = grant?.payload?.grant_id ?? grant?.grant_id;
    if (!isNonEmptyString(grantId))
        return { consumed: false, reason: 'missing_grant_id' };
    if (!store || typeof store.consume !== 'function') {
        return { consumed: false, reason: 'no_consumption_store' };
    }
    const key = `breakglass:${grantId}`;
    let first = false;
    try {
        first = (await store.consume(key)) === true;
    }
    catch {
        // The store could not commit the consumption — fail CLOSED: we cannot
        // prove single-use, so the override must not run.
        return { consumed: false, reason: 'store_error', key };
    }
    if (!first)
        return { consumed: false, reason: 'already_consumed', key };
    return { consumed: true, reason: 'consumed', key };
}
/**
 * Shape an evidence-log entry (kind 'breakglass') committing to the EXACT
 * grant artifact (grant_hash = sha-256 of canonical grant) and the decision
 * taken under it. Append it via the hash-chained evidence log — with
 * { strict: true } so a sink failure refuses the override.
 *
 * This builder does not execute or authorize anything. runBreakGlass is the
 * enforcing path that requires a strict, independently validated record
 * acknowledgement before invoking an effect. This function never throws, even
 * for a malformed grant or missing decision; an uncanonicalizable artifact has
 * a null grant_hash and cannot pass runBreakGlass verification.
 *
 * @param {object} grant the break-glass grant document as presented (even if invalid)
 * @param {object} decision e.g. { allow, reason, action_type } from verify/consume
 * @param {object} [o]
 * @param {number|string|function} [o.now=Date.now] injected clock for the entry timestamp
 * @returns {object} entry ready for createEvidenceLog().record()
 */
function buildBreakGlassEvidenceInternal(grant, decision, { now = Date.now } = {}) {
    let nowMs;
    try {
        nowMs = typeof now === 'function' ? toMs(now()) : toMs(now);
    }
    catch {
        nowMs = null;
    }
    const p = (grant && typeof grant === 'object' && grant.payload && typeof grant.payload === 'object')
        ? grant.payload : null;
    const sigs = (grant && Array.isArray(grant.signatures)) ? grant.signatures : [];
    const d = (decision && typeof decision === 'object') ? decision : {};
    let grantHash = null;
    try {
        grantHash = sha256hex(canonical(grant ?? null));
    }
    catch { /* uncanonicalizable artifacts stay unbound */ }
    const principalIds = Array.isArray(d.signer_principal_ids)
        && d.signer_principal_ids.every(isNonEmptyString) ? d.signer_principal_ids.slice() : null;
    const fingerprints = Array.isArray(d.signer_spki_fingerprints)
        && d.signer_spki_fingerprints.every(isNonEmptyString) ? d.signer_spki_fingerprints.slice() : null;
    return {
        kind: BREAKGLASS_EVIDENCE_KIND,
        '@version': BREAKGLASS_VERSION,
        at: new Date(nowMs ?? 0).toISOString(),
        grant_id: p?.grant_id ?? null,
        incident_ref: p?.incident_ref ?? null,
        grant_reason: p?.reason ?? null,
        scope: p?.scope?.action_types?.slice?.() ?? null,
        threshold: p?.threshold ?? null,
        policy_minimum_threshold: Number.isSafeInteger(d.policy_minimum_threshold)
            ? d.policy_minimum_threshold : null,
        required_threshold: Number.isSafeInteger(d.required_threshold) ? d.required_threshold : null,
        signer_kids: sigs.map((s) => s?.kid ?? null),
        signer_principal_ids: principalIds,
        signer_spki_fingerprints: fingerprints,
        // Commits the log entry to the exact artifact presented — a later dispute
        // can prove which grant (tampered or not) the decision was taken under.
        grant_hash: grantHash,
        decision: {
            allow: d.allow === true, // fail closed: anything else records a refusal
            reason: isNonEmptyString(d.reason) ? d.reason : 'unspecified',
            action_type: d.action_type ?? null,
        },
    };
}
export function buildBreakGlassEvidence(grant, decision, options = {}) {
    try {
        return buildBreakGlassEvidenceInternal(grant, decision, options);
    }
    catch {
        return {
            kind: BREAKGLASS_EVIDENCE_KIND,
            '@version': BREAKGLASS_VERSION,
            at: new Date(0).toISOString(),
            grant_id: null,
            incident_ref: null,
            grant_reason: null,
            scope: null,
            threshold: null,
            policy_minimum_threshold: null,
            required_threshold: null,
            signer_kids: [],
            signer_principal_ids: null,
            signer_spki_fingerprints: null,
            grant_hash: null,
            decision: { allow: false, reason: 'unspecified', action_type: null },
        };
    }
}
/**
 * The sole high-level break-glass execution path. It snapshots the presented
 * artifact, verifies it against relying-party policy, atomically consumes the
 * grant in a capability-marked permanent store, validates a strict evidence
 * acknowledgement, and only then invokes `effect`.
 *
 * @param {object} [args]
 * @param {object|string} [args.grant] the presented break-glass artifact
 * @param {{minimum_threshold:number,roster:Array<{kid:string,principal_id:string,key?:string}>}} [args.policy]
 * @param {object|Array<{kid:string,key:string}>} [args.issuerKeys]
 * @param {string} [args.actionType]
 * @param {{ consume(key: string): Promise<boolean> }} [args.store]
 * @param {{ strict?: boolean, atomicAppend?: boolean, record?: Function }} [args.evidence]
 * @param {number|string|function} [args.now=Date.now]
 * @param {Function} [effect] required at runtime; a missing effect throws
 */
export async function runBreakGlass({ grant, policy, issuerKeys, actionType, store, evidence, now = Date.now, } = {}, effect) {
    if (typeof effect !== 'function')
        throw new Error('runBreakGlass: effect function is required');
    let snapshot;
    try {
        const parsed = typeof grant === 'string' ? JSON.parse(grant) : grant;
        snapshot = JSON.parse(canonical(parsed));
    }
    catch {
        const verification = verifyBreakGlass(grant, { policy, issuerKeys, actionType, now });
        return { ok: false, reason: verification.reason, verification, consumption: null, evidence: null };
    }
    const verification = verifyBreakGlass(snapshot, { policy, issuerKeys, actionType, now });
    if (!verification.valid) {
        return { ok: false, reason: verification.reason, verification, consumption: null, evidence: null };
    }
    if (!isSecureConsumptionStore(store)) {
        return {
            ok: false,
            reason: 'secure_consumption_store_required',
            verification,
            consumption: null,
            evidence: null,
        };
    }
    if (!evidence || evidence.strict !== true || typeof evidence.record !== 'function') {
        return {
            ok: false,
            reason: 'strict_evidence_required',
            verification,
            consumption: null,
            evidence: null,
        };
    }
    // store is guaranteed defined here: isSecureConsumptionStore(store) returned
    // true above, which only holds for a store with a callable consume().
    const consume = store.consume.bind(store);
    const record = evidence.record.bind(evidence);
    const consumption = await consumeBreakGlass(verification, { consume });
    if (!consumption.consumed) {
        return { ok: false, reason: consumption.reason, verification, consumption, evidence: null };
    }
    const entry = buildBreakGlassEvidence(snapshot, {
        ...verification,
        allow: true,
        action_type: actionType,
    }, { now });
    let evidenceRecord;
    try {
        evidenceRecord = await record(entry);
        if (!verifyEvidenceRecord(evidenceRecord, /** @type {{atomicRequired?: boolean, expectedEntry?: object}} */ ({
            atomicRequired: evidence.atomicAppend === true,
            expectedEntry: entry,
        })))
            throw new Error('malformed evidence acknowledgement');
    }
    catch {
        return {
            ok: false,
            reason: 'evidence_record_failed',
            verification,
            consumption,
            evidence: null,
        };
    }
    const result = await effect({ verification, consumption, evidence: evidenceRecord });
    return {
        ok: true,
        reason: 'breakglass_executed',
        result,
        verification,
        consumption,
        evidence: evidenceRecord,
    };
}
export default {
    mintBreakGlassAuthorization,
    verifyBreakGlass,
    consumeBreakGlass,
    buildBreakGlassEvidence,
    runBreakGlass,
    BREAKGLASS_VERSION,
    BREAKGLASS_EVIDENCE_KIND,
};
//# sourceMappingURL=breakglass.js.map
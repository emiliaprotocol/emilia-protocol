// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AEC-v1 — Authorization Evidence Chain (EXPERIMENTAL reference verifier).
 *
 * THE GAP THIS FILLS
 * ------------------
 * The agent-authorization-receipt space has fragmented into ~14 IETF drafts —
 * delegation receipts (draft-nelson-agent-delegation-receipts), policy-permit
 * receipts (draft-lee-orprg-permit-receipts), decision receipts
 * (draft-farley-acta-signed-receipts), compliance receipts
 * (draft-marques-asqav-compliance-receipts), route authorization
 * (draft-nivalto-agentroa-route-authorization), and others. Each defines its own
 * signed receipt about an agent action, and the mature ones all bind the action
 * with an RFC 8785 (JCS) digest + a signature.
 *
 * NONE defines how a relying party verifies that, for ONE action, the several
 * heterogeneous receipts (a) all bind the SAME canonical action and (b) each
 * verify under its own rules — producing a single, offline, fail-closed
 * SATISFIED/UNSATISFIED. In practice people are hand-rolling ad-hoc "composite proofs"
 * (see the 2026 arXiv literature). That composition layer is the gap.
 *
 * EP-AEC is that thin layer. It is deliberately NOT another receipt type: it
 * references existing receipts, checks they all bind one canonical action digest,
 * dispatches each to its type verifier, and evaluates a fail-closed requirement
 * expression. EP supplies the one leg none of the other efforts do — a named
 * human's (or a distinct-human quorum's) authorization — via the built-in
 * `ep-receipt` / `ep-quorum` verifiers; every other receipt type plugs in through
 * `opts.verifiers`, so DRP / Permit Receipts / ACTA compose without EP owning them.
 *
 * This turns EP from "receipt #N" into the verifier-side convergence point — the
 * executable form of the multi-effort survey matrix.
 */
import crypto from 'node:crypto';
import { canonicalize, verifyTrustReceipt, verifyQuorum } from '../index.js';
import { EP_PLATFORM_ATTESTATION_COMPONENT, verifyPlatformAttestation, } from './platform-attestation.js';
import { strictJsonGate } from './strict-json.js';
export const AEC_VERSION = 'EP-AEC-v1';
const MAX_COMPONENTS = 64;
const MAX_REQUIREMENT_LENGTH = 4096;
const MAX_REQUIREMENT_TOKENS = 256;
const MAX_REQUIREMENT_DEPTH = 32;
const MAX_QUORUM_MEMBERS = 32;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;
const RESERVED_COMPONENT_TYPES = new Set(['ep-quorum', 'ep-receipt', EP_PLATFORM_ATTESTATION_COMPONENT]);
const IDENT_CHAR = /[A-Za-z0-9_.:-]/;
const IDENT = /^[A-Za-z0-9_.:-]+$/;
const HEX_256 = /^[0-9a-f]{64}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const isRecord = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (obj, key) => isRecord(obj) && Object.prototype.hasOwnProperty.call(obj, key);
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
/** Canonical action digest (hex). NOTE: uses EP's canonicalize(); see the JCS
 *  conformance note in the spec — the shared substrate MUST be true RFC 8785. */
export function actionDigest(action) {
    return sha256hex(canonicalize(action));
}
/** Normalize a digest claim to bare lowercase hex (strip any "sha256:" prefix). */
function normDigest(d) {
    if (typeof d !== 'string')
        return null;
    const bare = d.replace(/^sha256:/i, '').toLowerCase();
    return HEX_256.test(bare) ? bare : null;
}
function strictInstantMs(value) {
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
function freshAt(context, verificationTime, maxAgeSec) {
    const at = strictInstantMs(verificationTime);
    const issued = strictInstantMs(context?.issued_at);
    const expires = strictInstantMs(context?.expires_at);
    return Number.isFinite(at) && Number.isFinite(issued) && Number.isFinite(expires)
        && Number.isInteger(maxAgeSec) && maxAgeSec >= 0
        && issued <= at && at <= expires && (at - issued) <= maxAgeSec * 1000;
}
function freshRegistrySnapshot(profile, verificationTime) {
    const at = strictInstantMs(verificationTime);
    const checked = strictInstantMs(profile?.registry_checked_at);
    return Number.isFinite(at) && Number.isFinite(checked)
        && Number.isInteger(profile?.max_registry_age_sec) && profile.max_registry_age_sec >= 0
        && checked <= at && (at - checked) <= profile.max_registry_age_sec * 1000;
}
function activeDirectoryEntry(entry, verificationTime) {
    if (!isRecord(entry) || entry.status !== 'active')
        return false;
    const at = strictInstantMs(verificationTime);
    const from = strictInstantMs(entry.valid_from);
    const to = strictInstantMs(entry.valid_to);
    if (!Number.isFinite(at) || !Number.isFinite(from) || !Number.isFinite(to) || at < from || at > to)
        return false;
    if (entry.revoked_at === undefined || entry.revoked_at === null)
        return true;
    const revoked = strictInstantMs(entry.revoked_at);
    return Number.isFinite(revoked) && at < revoked;
}
function allowedOriginSet(profile) {
    if (!Array.isArray(profile?.allowed_origins) || profile.allowed_origins.length === 0
        || profile.allowed_origins.length > 16)
        return null;
    const origins = new Set();
    for (const origin of profile.allowed_origins) {
        if (typeof origin !== 'string' || !origin || origin.length > 2048)
            return null;
        origins.add(origin);
    }
    return origins;
}
function webauthnOrigin(webauthn) {
    try {
        const encoded = webauthn?.client_data_json;
        if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]+$/.test(encoded))
            return null;
        const bytes = Buffer.from(encoded, 'base64url');
        if (bytes.toString('base64url') !== encoded)
            return null;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!strictJsonGate(text).ok)
            return null;
        const clientData = JSON.parse(text);
        return typeof clientData?.origin === 'string' ? clientData.origin : null;
    }
    catch {
        return null;
    }
}
function validUnicodeString(value) {
    for (let i = 0; i < value.length; i++) {
        const unit = value.charCodeAt(i);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
        }
        else if (unit >= 0xdc00 && unit <= 0xdfff)
            return false;
    }
    return true;
}
function boundedJson(value) {
    const stack = [{ value, depth: 0 }];
    const seen = new WeakSet();
    let nodes = 0;
    let stringBytes = 0;
    while (stack.length) {
        // `stack.length` in the loop guard guarantees a non-empty array, so
        // `.pop()` always returns an element here — the compiler can't see that.
        const current = stack.pop();
        nodes++;
        if (nodes > MAX_JSON_NODES || current.depth > MAX_JSON_DEPTH)
            return false;
        const v = current.value;
        if (v === null || typeof v === 'boolean')
            continue;
        if (typeof v === 'string') {
            if (!validUnicodeString(v))
                return false;
            stringBytes += Buffer.byteLength(v, 'utf8');
            if (stringBytes > MAX_JSON_STRING_BYTES)
                return false;
            continue;
        }
        if (typeof v === 'number') {
            if (!Number.isSafeInteger(v))
                return false;
            continue;
        }
        if (!isRecord(v) && !Array.isArray(v))
            return false;
        if (seen.has(v))
            return false;
        seen.add(v);
        if (Array.isArray(v)) {
            for (const child of v)
                stack.push({ value: child, depth: current.depth + 1 });
        }
        else {
            for (const [key, child] of Object.entries(v)) {
                if (!validUnicodeString(key))
                    return false;
                stringBytes += Buffer.byteLength(key, 'utf8');
                if (stringBytes > MAX_JSON_STRING_BYTES)
                    return false;
                stack.push({ value: child, depth: current.depth + 1 });
            }
        }
    }
    return true;
}
/**
 * Built-in component verifiers. Each takes (evidence, ctx) and returns
 * { valid: boolean, action_digest: string|null, detail?: any }.
 * `action_digest` is the digest the component ITSELF attests it authorized — the
 * chain then checks every component's attested digest equals the chain's digest.
 */
function builtinVerifiers() {
    return {
        // A signed platform attestation result consumed under a relying-party-owned
        // profile. Trust keys, nonce, profile, audience, build references, and
        // freshness all come from opts; the presenter supplies only the token.
        [EP_PLATFORM_ATTESTATION_COMPONENT]: (evidence, ctx) => {
            const profile = ctx?.policiesByType?.[EP_PLATFORM_ATTESTATION_COMPONENT];
            const trustedAttesters = ctx?.keysByType?.[EP_PLATFORM_ATTESTATION_COMPONENT];
            if (!isRecord(profile)) {
                return { valid: false, action_digest: null, detail: { reason: 'missing relying-party platform-attestation profile' } };
            }
            let expectedActionDigest;
            try {
                expectedActionDigest = `sha256:${actionDigest(ctx?.action)}`;
            }
            catch {
                return { valid: false, action_digest: null, detail: { reason: 'platform-attestation action is not canonicalizable' } };
            }
            return verifyPlatformAttestation(evidence, {
                trustedAttesters,
                expectedProfile: profile.expected_profile,
                expectedAudience: profile.expected_audience,
                expectedNonce: profile.expected_nonce,
                expectedActionDigest,
                referenceMeasurements: profile.reference_measurements,
                verificationTime: ctx?.verificationTime,
                maxAgeSeconds: profile.max_age_sec,
            });
        },
        // A distinct-human quorum (EP-QUORUM-v1) — the two-person-rule leg.
        'ep-quorum': (evidence, ctx) => {
            // `verifyQuorum` proves internal consistency only. Acceptance additionally
            // requires an RP-owned profile that pins the exact policy, WebAuthn RP ID,
            // context policy identifier, and key -> approver -> role directory.
            const profile = ctx?.policiesByType?.['ep-quorum'];
            const allowedOrigins = allowedOriginSet(profile);
            const members = Array.isArray(evidence?.members) ? evidence.members : null;
            if (!isRecord(profile) || !isRecord(profile.policy)
                || typeof profile.rp_id !== 'string' || !profile.rp_id
                || typeof profile.context_policy !== 'string' || !profile.context_policy
                || !allowedOrigins
                || !Number.isInteger(profile.max_age_sec) || profile.max_age_sec < 0
                || !freshRegistrySnapshot(profile, ctx?.verificationTime)
                || !isRecord(profile.approvers)
                || !members || members.length === 0 || members.length > MAX_QUORUM_MEMBERS) {
                return { valid: false, action_digest: null, detail: { reason: 'missing or malformed relying-party quorum profile' } };
            }
            const mode = profile.policy.mode;
            if (mode !== 'threshold' && mode !== 'ordered') {
                return { valid: false, action_digest: null, detail: { reason: 'quorum policy mode must be threshold or ordered' } };
            }
            const required = profile.policy.required;
            const approverCount = Array.isArray(profile.policy.approvers)
                ? profile.policy.approvers.length
                : 0;
            if (!Number.isInteger(required) || required < 2 || required > approverCount
                || profile.policy.distinct_humans !== true) {
                return { valid: false, action_digest: null, detail: { reason: 'ep-quorum requires at least two distinct humans' } };
            }
            if (mode === 'ordered' && profile.policy.ordered_chain !== true) {
                return { valid: false, action_digest: null, detail: { reason: 'ordered ep-quorum requires a signed predecessor chain' } };
            }
            try {
                if (!isRecord(evidence?.policy) || canonicalize(evidence.policy) !== canonicalize(profile.policy)) {
                    return { valid: false, action_digest: null, detail: { reason: 'presented quorum policy does not equal the relying-party-pinned policy' } };
                }
            }
            catch {
                return { valid: false, action_digest: null, detail: { reason: 'quorum policy is not canonicalizable' } };
            }
            for (const m of members) {
                if (!isRecord(m) || !isRecord(m.signoff) || !isRecord(m.signoff.context)) {
                    return { valid: false, action_digest: null, detail: { reason: 'malformed quorum member' } };
                }
                const k = m?.approver_public_key;
                const entry = typeof k === 'string' && own(profile.approvers, k) ? profile.approvers[k] : null;
                if (!activeDirectoryEntry(entry, ctx?.verificationTime) || entry.public_key !== k
                    || typeof entry.approver_id !== 'string' || entry.approver_id !== m.signoff.context.approver
                    || !Array.isArray(entry.roles) || !entry.roles.includes(m.role)
                    || m.signoff.context.policy !== profile.context_policy
                    || !webauthnOrigin(m.signoff.webauthn)
                    || !allowedOrigins.has(webauthnOrigin(m.signoff.webauthn))
                    || !freshAt(m.signoff.context, ctx?.verificationTime, profile.max_age_sec)) {
                    return { valid: false, action_digest: null, detail: { reason: 'quorum member is not bound to the pinned approver directory and policy' } };
                }
            }
            const r = /** @type {{valid?:boolean, checks?:any}} */ (verifyQuorum(evidence, {
                rpId: profile.rp_id,
                allowedOrigins: [...allowedOrigins],
            }) || {});
            return { valid: !!r.valid, action_digest: r.valid ? (evidence?.action_hash ?? null) : null, detail: r.checks };
        },
        // A Section 6.2 human-authorization Trust Receipt. A bare operator-signed
        // EP-RECEIPT-v1 envelope is not human evidence. Acceptance requires a fresh
        // Class-A WebAuthn ceremony plus relying-party-pinned identity, audience,
        // policy, and log trust.
        'ep-receipt': (evidence, ctx) => {
            const profile = ctx?.policiesByType?.['ep-receipt'];
            const allowedOrigins = allowedOriginSet(profile);
            const contexts = Array.isArray(evidence?.contexts) ? evidence.contexts : null;
            const signoffs = Array.isArray(evidence?.signoffs) ? evidence.signoffs : null;
            if (!isRecord(profile) || !isRecord(profile.approver_keys)
                || typeof profile.log_public_key !== 'string' || !profile.log_public_key
                || typeof profile.rp_id !== 'string' || !profile.rp_id
                || !allowedOrigins
                || !normDigest(profile.expected_policy_hash)
                || !Number.isInteger(profile.max_age_sec) || profile.max_age_sec < 0
                || !freshRegistrySnapshot(profile, ctx?.verificationTime)
                || !contexts?.length || !signoffs?.length) {
                return { valid: false, action_digest: null, detail: { reason: 'missing or malformed relying-party receipt profile' } };
            }
            const contextByHash = new Map();
            try {
                for (const c of contexts) {
                    if (!isRecord(c) || normDigest(c.policy_hash) !== normDigest(profile.expected_policy_hash)) {
                        return { valid: false, action_digest: null, detail: { reason: 'receipt context is outside the pinned policy' } };
                    }
                    contextByHash.set(sha256hex(canonicalize(c)), c);
                }
            }
            catch {
                return { valid: false, action_digest: null, detail: { reason: 'receipt context is not canonicalizable' } };
            }
            const expectedRpHash = crypto.createHash('sha256').update(profile.rp_id, 'utf8').digest();
            for (const s of signoffs) {
                const keyEntry = isRecord(s) && own(profile.approver_keys, s.approver_key_id)
                    ? profile.approver_keys[s.approver_key_id] : null;
                const signedContext = contextByHash.get(normDigest(s?.context_hash) ?? '');
                let authData;
                try {
                    authData = Buffer.from(s?.webauthn?.authenticator_data ?? '', 'base64url');
                }
                catch {
                    authData = null;
                }
                if (!activeDirectoryEntry(keyEntry, ctx?.verificationTime) || keyEntry.key_class !== 'A'
                    || !signedContext || keyEntry.approver_id !== signedContext.approver
                    || !authData || authData.length < 37 || !authData.subarray(0, 32).equals(expectedRpHash)
                    || !webauthnOrigin(s.webauthn)
                    || !allowedOrigins.has(webauthnOrigin(s.webauthn))
                    || !freshAt(signedContext, ctx?.verificationTime, profile.max_age_sec)) {
                    return { valid: false, action_digest: null, detail: { reason: 'receipt signoff is not a fresh pinned Class-A human ceremony' } };
                }
            }
            let r = {};
            try {
                r = verifyTrustReceipt(evidence, {
                    approverKeys: profile.approver_keys,
                    logPublicKey: profile.log_public_key,
                    rpId: profile.rp_id,
                    allowedOrigins: [...allowedOrigins],
                    expectedPolicyHash: profile.expected_policy_hash,
                }) || {};
            }
            catch {
                r = { valid: false };
            }
            return { valid: r.valid === true, action_digest: r.valid ? evidence.action_hash : null, detail: r.checks };
        },
    };
}
/**
 * Evaluate a tiny boolean requirement expression over the SET of verified
 * component types. Grammar (safe, no eval):
 *   expr = term *(("AND"/"OR"/"&&"/"||") term)
 *   term = "(" expr ")" / IDENT
 * IDENT matches a verified component `type`. Labels are display-only.
 */
function tokenizeRequirement(expr) {
    if (typeof expr !== 'string' || expr.length === 0 || expr.length > MAX_REQUIREMENT_LENGTH)
        return null;
    const toks = [];
    let i = 0;
    while (i < expr.length) {
        const ch = expr[i];
        if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
            i++;
            continue;
        }
        if (ch === '(' || ch === ')') {
            toks.push(ch);
            i++;
        }
        else if ((ch === '&' && expr[i + 1] === '&') || (ch === '|' && expr[i + 1] === '|')) {
            toks.push(ch + expr[i + 1]);
            i += 2;
        }
        else if (IDENT_CHAR.test(ch)) {
            let j = i + 1;
            while (j < expr.length && IDENT_CHAR.test(expr[j]))
                j++;
            toks.push(expr.slice(i, j));
            i = j;
        }
        else
            return null;
        if (toks.length > MAX_REQUIREMENT_TOKENS)
            return null;
    }
    return toks.length > 0 ? toks : null;
}
function evalRequirement(expr, satisfied) {
    const toks = tokenizeRequirement(expr);
    if (!toks)
        return { valid: false, value: false };
    let i = 0;
    const peek = () => toks[i];
    const eat = () => toks[i++];
    function parseExpr(depth = 0) {
        if (depth > MAX_REQUIREMENT_DEPTH)
            throw new Error('requirement nesting limit exceeded');
        let v = parseTerm(depth);
        while (peek() === 'AND' || peek() === 'OR' || peek() === '&&' || peek() === '||') {
            const op = eat();
            const r = parseTerm(depth);
            v = (op === 'AND' || op === '&&') ? (v && r) : (v || r);
        }
        return v;
    }
    function parseTerm(depth) {
        if (peek() === '(') {
            eat();
            const v = parseExpr(depth + 1);
            if (peek() !== ')')
                throw new Error('unclosed requirement group');
            eat();
            return v;
        }
        const id = eat();
        if (id === undefined || id === ')' || id === 'AND' || id === 'OR' || id === '&&' || id === '||' || !IDENT.test(id)) {
            throw new Error('invalid requirement term');
        }
        return satisfied.has(id);
    }
    try {
        const value = parseExpr();
        return { valid: i === toks.length, value: i === toks.length ? value === true : false };
    }
    catch {
        return { valid: false, value: false };
    }
}
/**
 * Verify an Authorization Evidence Chain. FAIL-CLOSED: anything missing,
 * malformed, unverifiable, or binding a different action yields satisfied=false.
 *
 * TRUST BOUNDARY — whose requirement is it? The chain document's `requirement`
 * is PRESENTER-supplied: it is the presenter's claim of what the bundle
 * satisfies, and a presenter must never choose its own sufficiency bar. A
 * relying party MUST pin its own bar via `opts.requirement` before `satisfied` can
 * ever be true. The presenter expression remains self-describing metadata; the
 * result records which source was evaluated
 * (`requirement_source: 'relying_party' | 'presenter'`). Same discipline as
 * pinned quorum policies and pinned federation issuers.
 *
 * TRUST ANCHORS ARE ROLE-SCOPED. `opts.keysByType` maps a component type to the
 * keys the relying party accepts FOR THAT ROLE ONLY, e.g.
 * `{ 'ep-receipt': { [humanSpki]: humanSpki } }`. A key pinned for one role (a
 * policy engine's key) can never satisfy another (the human-authorization role):
 * that would be cross-role key confusion. There is deliberately no flat global
 * key bag for the built-in verifiers.
 *
 * @param {object} aec  { '@version', action, action_digest?, components:[{type,label?,evidence}], requirement }
 * @param {object} opts { verifiers?: {[type]:fn}, keysByType?: object, policiesByType?: object,
 *                        requirement?: string, expectedAction?: object, expectedActionDigest?: string,
 *                        verificationTime?: string }
 * @returns {{satisfied:boolean, allow:boolean, action_digest:string|null, expected_action_bound:boolean, components:Array, reasons:string[], requirement_source:string}}
 */
function verifyAuthorizationChainInternal(aec, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const reasons = [];
    const pinned = typeof opts.requirement === 'string' && opts.requirement.trim() ? opts.requirement : null;
    const requirementSource = pinned ? 'relying_party' : 'presenter';
    const fail = (why) => {
        reasons.push(why);
        return { satisfied: false, allow: false, action_digest: null, expected_action_bound: false, components: [], reasons, requirement_source: requirementSource };
    };
    if (!isRecord(aec))
        return fail('chain is not an object');
    if (!boundedJson(aec))
        return fail('chain exceeds the canonical JSON safety profile or resource limits');
    if (aec['@version'] !== AEC_VERSION)
        return fail(`unexpected @version (want ${AEC_VERSION})`);
    if (!isRecord(aec.action))
        return fail('missing action object');
    if (!Array.isArray(aec.components) || aec.components.length === 0)
        return fail('no components');
    if (aec.components.length > MAX_COMPONENTS)
        return fail(`too many components (maximum ${MAX_COMPONENTS})`);
    const requirement = pinned ?? aec.requirement;
    if (typeof requirement !== 'string' || !requirement.trim())
        return fail('missing requirement expression');
    if (requirement.length > MAX_REQUIREMENT_LENGTH)
        return fail('requirement expression exceeds size limit');
    let chainDigest;
    try {
        chainDigest = actionDigest(aec.action);
    }
    catch {
        return fail('action is not canonicalizable');
    }
    // Internal agreement is insufficient: a presenter can make every component
    // agree on the wrong action. Bind the chain to the executor's independently
    // constructed action (or digest) before this result can authorize anything.
    let expectedDigest = null;
    if (opts.expectedAction !== undefined) {
        if (!isRecord(opts.expectedAction) || !boundedJson(opts.expectedAction))
            return fail('expectedAction is not a bounded canonical JSON object');
        try {
            expectedDigest = actionDigest(opts.expectedAction);
        }
        catch {
            return fail('expectedAction is not canonicalizable');
        }
    }
    if (opts.expectedActionDigest !== undefined) {
        const supplied = normDigest(opts.expectedActionDigest);
        if (!supplied)
            return fail('expectedActionDigest is malformed');
        if (expectedDigest && supplied !== expectedDigest)
            return fail('expectedAction and expectedActionDigest disagree');
        expectedDigest = supplied;
    }
    if (expectedDigest && expectedDigest !== chainDigest) {
        return fail('chain action does not match the relying-party expected action');
    }
    if (aec.action_digest != null && normDigest(aec.action_digest) !== chainDigest) {
        return fail('declared action_digest does not match canonical digest of the action');
    }
    const verifiers = new Map(Object.entries(builtinVerifiers()));
    if (isRecord(opts.verifiers)) {
        for (const [type, verifier] of Object.entries(opts.verifiers)) {
            if (!RESERVED_COMPONENT_TYPES.has(type) && typeof verifier === 'function')
                verifiers.set(type, verifier);
        }
    }
    const satisfied = new Set();
    const components = aec.components.map((c, idx) => {
        if (!isRecord(c))
            return { type: null, label: `#${idx}`, valid: false, bound: false, reason: 'component is not an object' };
        const label = typeof c.label === 'string' && c.label ? c.label : (c.type || `#${idx}`);
        const row = { type: c.type, label, valid: false, bound: false, reason: null };
        if (typeof c.type !== 'string' || !IDENT.test(c.type) || c.type.length > 128 || !isRecord(c.evidence)) {
            row.reason = 'component type or evidence is malformed';
            return row;
        }
        const v = verifiers.get(c.type);
        if (typeof v !== 'function') {
            row.reason = `no verifier registered for type "${c.type}"`;
            return row;
        }
        let res;
        try {
            res = v(c.evidence, {
                keysByType: opts.keysByType,
                policiesByType: opts.policiesByType,
                verificationTime: opts.verificationTime,
                action: aec.action,
            }) || {};
        }
        catch (e) {
            row.reason = `verifier threw: ${e instanceof Error ? e.message : String(e)}`;
            return row;
        }
        row.valid = isRecord(res) && res.valid === true;
        row.bound = normDigest(res.action_digest) === chainDigest;
        if (!row.valid)
            row.reason = 'component evidence did not verify';
        else if (!row.bound)
            row.reason = 'component binds a DIFFERENT action than the chain';
        if (row.valid && row.bound) {
            satisfied.add(c.type);
            // Labels are presenter-controlled display metadata. They never satisfy an
            // RP requirement. Named authority belongs inside a typed verifier whose
            // policy and trust anchors are relying-party owned.
        }
        return row;
    });
    const evaluated = evalRequirement(requirement, satisfied);
    const satisfiedResult = requirementSource === 'relying_party' && expectedDigest !== null && evaluated.valid && evaluated.value;
    if (!evaluated.valid)
        reasons.push('requirement expression is malformed or exceeds parser limits');
    else if (!evaluated.value)
        reasons.push(`requirement not satisfied: "${requirement}" over {${[...satisfied].join(', ') || '∅'}}`);
    if (requirementSource !== 'relying_party')
        reasons.push('presenter requirement is descriptive only; relying-party requirement is required for satisfaction');
    if (expectedDigest === null)
        reasons.push('relying-party expected action is required for satisfaction');
    if (pinned && typeof aec.requirement === 'string' && aec.requirement.trim() && aec.requirement !== pinned) {
        reasons.push(`presenter requirement ignored in favor of relying-party requirement (presenter claimed: "${aec.requirement}")`);
    }
    return {
        satisfied: satisfiedResult,
        // Compatibility alias. AEC establishes evidence satisfaction; the
        // enforcement point makes the separate local authorization decision.
        allow: satisfiedResult,
        action_digest: chainDigest,
        expected_action_bound: expectedDigest === chainDigest,
        components,
        reasons,
        requirement_source: requirementSource,
    };
}
/** Public fail-closed boundary. Parsed JSON is the intended wire input, but
 * framework callers can still supply proxies/getters that throw during shape
 * inspection. No host-language exception may turn verification into a crash.
 * @param {object} aec
 * @param {{requirement?:string, [key:string]:any}} [opts]
 */
export function verifyAuthorizationChain(aec, opts = {}) {
    let requirementSource = 'presenter';
    try {
        if (opts && typeof opts === 'object'
            && typeof opts.requirement === 'string' && opts.requirement.trim()) {
            requirementSource = 'relying_party';
        }
    }
    catch { /* hostile options remain presenter/default */ }
    try {
        return verifyAuthorizationChainInternal(aec, opts);
    }
    catch {
        return {
            satisfied: false,
            allow: false,
            action_digest: null,
            expected_action_bound: false,
            components: [],
            reasons: ['unexpected verification error'],
            requirement_source: requirementSource,
        };
    }
}
// Mutation and differential-test surface. These helpers are not protocol API;
// exporting them keeps boundary tests from reimplementing the acceptance math.
export const __aecSecurityInternals = Object.freeze({
    normDigest,
    strictInstantMs,
    freshAt,
    freshRegistrySnapshot,
    activeDirectoryEntry,
    allowedOriginSet,
    webauthnOrigin,
    validUnicodeString,
    boundedJson,
    tokenizeRequirement,
    evalRequirement,
});
//# sourceMappingURL=evidence-chain.js.map
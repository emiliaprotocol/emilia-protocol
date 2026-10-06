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
import { canonicalize, verifyTrustReceipt, verifyQuorum, verifyWebAuthnSignoff } from './index.js';
import { EP_PLATFORM_ATTESTATION_COMPONENT, verifyPlatformAttestation, } from './platform-attestation.js';
import { strictJsonGate, canonicalizeStrictJson } from './strict-json.js';
import { verifyAuthorizationBundle } from './authorization-bundle.js';
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
function isHex256(value) {
    return /^[0-9a-f]{64}$/.test(value);
}
function rfc3339Match(value) {
    return value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/);
}
function isRecord(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function own(obj, key) {
    return isRecord(obj) && Object.prototype.hasOwnProperty.call(obj, key);
}
function sha256hex(s) {
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}
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
    return isHex256(bare) ? bare : null;
}
function strictInstantMs(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = rfc3339Match(value);
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
                expectedPolicy: profile.policy,
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
 * Requirement expressions (AEC -08, evaluator EP-AEC-EVALUATOR-08-v1).
 *
 * Case-sensitive grammar (RFC 5234 with RFC 7405 %s literals):
 *   expression = *WSP term *( *WSP operator *WSP term ) *WSP
 *   term       = "(" *WSP expression *WSP ")" / identifier
 *   operator   = %s"AND" / %s"OR" / "&&" / "||"
 *   identifier = 1*( ALPHA / DIGIT / "_" / "." / ":" / "-" )
 *   WSP        = SP / HTAB / CR / LF
 *
 * Token boundaries: the lexer takes the LONGEST run of identifier characters
 * and only then classifies the complete run. A run that is exactly AND or OR
 * is an operator; every other run, including `and`, `Or`, `aORb` and `ORb`,
 * is an identifier. Identifiers are case-sensitive. AND and OR are reserved
 * only inside expressions; they stay valid native component types.
 *
 * Operators have equal precedence and group left to right:
 * `a OR b AND c` is `((a OR b) AND c)`.
 *
 * Validity is separate from truth. A syntactically valid identifier naming no
 * eligible component type is false. Malformed syntax or an exceeded limit makes
 * the expression INVALID. Both evaluate UNSATISFIED; diagnostics keep them
 * apart. The whole input is lexed and parsed before any value is computed, so
 * short-circuiting can never skip a syntax or limit check.
 *
 * Fixed caps (part of the evaluator revision, not relying-party configurable):
 * 4096 UTF-8 octets, 256 tokens (identifiers, operators and parentheses all
 * count), 32 levels of parenthesis nesting. Refusal order is deterministic:
 * the length cap, then the lexer left to right (an invalid character is a
 * syntax refusal; the 257th token is a limit refusal), then the parser left
 * to right (nesting beyond 32 is a limit refusal; anything else a syntax one).
 *
 * One parser produces one tree. The canonical parse, the parse identity and
 * the Boolean value are all computed from that tree; nothing re-reads the
 * expression text with its own grouping rules.
 */
export const AEC_EXPRESSION_LIMITS = Object.freeze({ maxOctets: MAX_REQUIREMENT_LENGTH, maxTokens: MAX_REQUIREMENT_TOKENS, maxDepth: MAX_REQUIREMENT_DEPTH });
/** Domain separator of the parse identity: SHA-256 over this ASCII string, one
 * 0x00 octet, then the ASCII canonical parse. */
export const AEC_EXPRESSION_PARSE_DOMAIN = 'EP-AEC-EXPRESSION-PARSE-v1';
/** UTF-8 octet length. A lone surrogate counts as the three octets of the
 * replacement character a UTF-8 encoder substitutes for it. */
function utf8Octets(value) {
    let octets = 0;
    for (let i = 0; i < value.length; i++) {
        const unit = value.charCodeAt(i);
        if (unit < 0x80)
            octets += 1;
        else if (unit < 0x800)
            octets += 2;
        else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < value.length
            && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) {
            octets += 4;
            i++;
        }
        else
            octets += 3;
    }
    return octets;
}
/** True when the string holds a character other than SP, HTAB, CR or LF. */
function hasExpressionContent(value) {
    return typeof value === 'string' && /[^ \t\r\n]/.test(value);
}
function lexAecExpression(expression) {
    if (typeof expression !== 'string')
        return { ok: false, invalid_class: 'syntax', detail: 'not_a_string' };
    if (utf8Octets(expression) > MAX_REQUIREMENT_LENGTH)
        return { ok: false, invalid_class: 'limit', detail: 'length_limit' };
    const tokens = [];
    let i = 0;
    while (i < expression.length) {
        const ch = expression[i];
        if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
            i++;
            continue;
        }
        if (ch === '(' || ch === ')') {
            tokens.push({ kind: ch, text: ch });
            i++;
        }
        else if ((ch === '&' && expression[i + 1] === '&') || (ch === '|' && expression[i + 1] === '|')) {
            tokens.push({ kind: 'operator', operator: ch === '&' ? 'AND' : 'OR', text: ch + ch });
            i += 2;
        }
        else if (IDENT_CHAR.test(ch)) {
            let j = i + 1;
            while (j < expression.length && IDENT_CHAR.test(expression[j]))
                j++;
            const run = expression.slice(i, j);
            // Classify only the complete maximal run.
            tokens.push(run === 'AND' || run === 'OR'
                ? { kind: 'operator', operator: run, text: run }
                : { kind: 'identifier', text: run });
            i = j;
        }
        else
            return { ok: false, invalid_class: 'syntax', detail: 'invalid_character' };
        if (tokens.length > MAX_REQUIREMENT_TOKENS)
            return { ok: false, invalid_class: 'limit', detail: 'token_limit' };
    }
    return tokens.length > 0 ? { ok: true, tokens } : { ok: false, invalid_class: 'syntax', detail: 'empty' };
}
class AecExpressionRefused extends Error {
    invalid_class;
    detail;
    constructor(invalid_class, detail) {
        super(detail);
        this.invalid_class = invalid_class;
        this.detail = detail;
    }
}
function parseAecExpression(expression) {
    const lexed = lexAecExpression(expression);
    if (!lexed.ok)
        return lexed;
    const tokens = lexed.tokens;
    let i = 0;
    function parseExpr(depth) {
        if (depth > MAX_REQUIREMENT_DEPTH)
            throw new AecExpressionRefused('limit', 'depth_limit');
        let node = parseTerm(depth);
        while (i < tokens.length) {
            const token = tokens[i];
            if (token.kind !== 'operator')
                break;
            i++;
            node = Object.freeze({ kind: 'operator', operator: token.operator, left: node, right: parseTerm(depth) });
        }
        return node;
    }
    function parseTerm(depth) {
        const token = tokens[i];
        if (token === undefined)
            throw new AecExpressionRefused('syntax', 'unexpected_end');
        if (token.kind === '(') {
            i++;
            const inner = parseExpr(depth + 1);
            if (tokens[i]?.kind !== ')')
                throw new AecExpressionRefused('syntax', tokens[i] === undefined ? 'unclosed_group' : 'unexpected_token');
            i++;
            return inner;
        }
        if (token.kind !== 'identifier')
            throw new AecExpressionRefused('syntax', 'unexpected_token');
        i++;
        return Object.freeze({ kind: 'identifier', name: token.text });
    }
    try {
        const tree = parseExpr(0);
        if (i !== tokens.length)
            return { ok: false, invalid_class: 'syntax', detail: 'trailing_input' };
        return { ok: true, tree, token_count: tokens.length };
    }
    catch (error) {
        if (error instanceof AecExpressionRefused)
            return { ok: false, invalid_class: error.invalid_class, detail: error.detail };
        throw error;
    }
}
/** Fully parenthesized ASCII rendering of the tree: every operator node is
 * `(` left SP AND|OR SP right `)`, `&&` and `||` render as AND and OR,
 * identifiers keep their exact case, source parentheses that do not change
 * grouping disappear, and operands are never commuted or reassociated. */
function renderAecExpression(node) {
    return node.kind === 'identifier'
        ? node.name
        : `(${renderAecExpression(node.left)} ${node.operator} ${renderAecExpression(node.right)})`;
}
function aecParseIdentity(canonical) {
    return `sha256:${crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from(AEC_EXPRESSION_PARSE_DOMAIN, 'ascii'), Buffer.from([0]), Buffer.from(canonical, 'ascii')]))
        .digest('hex')}`;
}
/** Evaluate the parsed tree. Only an exact, case-sensitive type match counts. */
function evaluateAecExpressionTree(node, eligible) {
    if (node.kind === 'identifier')
        return eligible.has(node.name);
    const left = evaluateAecExpressionTree(node.left, eligible);
    const right = evaluateAecExpressionTree(node.right, eligible);
    return node.operator === 'AND' ? left && right : left || right;
}
/**
 * Parse a requirement expression once and expose the tree's diagnostics.
 *
 * The parse identity names how this implementation grouped the expression.
 * It is an interpretation diagnostic, not an authorization result: two
 * evaluators that report the same parse identity can still return different
 * answers (one can mis-evaluate an operator, case-fold a role lookup, or credit
 * evidence that failed native verification). It is never carried in the v1
 * requirement or replay objects, and it does not replace the requirement
 * profile digest, which commits to the expression exactly as stored.
 */
export function compileAecRequirementExpression(expression) {
    const parsed = parseAecExpression(expression);
    if (!parsed.ok) {
        const refused = Object.freeze({
            syntax: 'INVALID', invalid_class: parsed.invalid_class, value: null, result: 'UNSATISFIED',
            canonical_parse: null, parse_identity: null,
        });
        return Object.freeze({
            valid: false, invalid_class: parsed.invalid_class, detail: parsed.detail,
            token_count: null, canonical_parse: null, parse_identity: null,
            evaluate: () => ({ ...refused }),
        });
    }
    const tree = parsed.tree;
    const canonical = renderAecExpression(tree);
    const identity = aecParseIdentity(canonical);
    return Object.freeze({
        valid: true, invalid_class: null, detail: null, token_count: parsed.token_count,
        canonical_parse: canonical, parse_identity: identity,
        evaluate(eligibleTypes) {
            const value = evaluateAecExpressionTree(tree, new Set(eligibleTypes));
            return { syntax: 'VALID', invalid_class: null, value, result: value ? 'SATISFIED' : 'UNSATISFIED',
                canonical_parse: canonical, parse_identity: identity };
        },
    });
}
/** Convenience diagnostic: compile once, then evaluate that tree. */
export function evaluateAecRequirementExpression(expression, eligibleTypes) {
    return compileAecRequirementExpression(expression).evaluate(eligibleTypes);
}
// Internal compatibility views used by the mutation-oracle tests.
function tokenizeRequirement(expr) {
    const lexed = lexAecExpression(expr);
    return lexed.ok ? lexed.tokens.map(t => t.text) : null;
}
function evalRequirement(expr, satisfied) {
    const compiled = typeof expr === 'object' && expr !== null ? expr : compileAecRequirementExpression(expr);
    const evaluated = compiled.evaluate(satisfied);
    return { valid: evaluated.syntax === 'VALID', value: evaluated.value === true };
}
/**
 * LEGACY expression-only API, not the structured AEC-05 requirement/replay
 * contract. Current-profile users must construct createAuthorizationChainEvaluator.
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
    // Only SP, HTAB, CR and LF are expression whitespace (AEC -08). A pinned
    // requirement is evaluated exactly as supplied, never trimmed.
    const pinned = hasExpressionContent(opts.requirement) ? opts.requirement : null;
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
    if (!hasExpressionContent(requirement))
        return fail('missing requirement expression');
    if (utf8Octets(requirement) > MAX_REQUIREMENT_LENGTH)
        return fail('requirement expression exceeds size limit');
    // Parse once, before any component work; the verdict is computed on this tree.
    const compiledRequirement = compileAecRequirementExpression(requirement);
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
    const evaluated = evalRequirement(compiledRequirement, satisfied);
    const satisfiedResult = requirementSource === 'relying_party' && expectedDigest !== null && evaluated.valid && evaluated.value;
    if (!evaluated.valid)
        reasons.push('requirement expression is malformed or exceeds parser limits');
    else if (!evaluated.value)
        reasons.push(`requirement not satisfied: "${requirement}" over {${[...satisfied].join(', ') || '∅'}}`);
    if (requirementSource !== 'relying_party')
        reasons.push('presenter requirement is descriptive only; relying-party requirement is required for satisfaction');
    if (expectedDigest === null)
        reasons.push('relying-party expected action is required for satisfaction');
    if (pinned && hasExpressionContent(aec.requirement) && aec.requirement !== pinned) {
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
            && hasExpressionContent(opts.requirement)) {
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
// ---------------------------------------------------------------------------
// Structured AEC-05 evaluation contract. No stateful authorization is performed.
// The optional ep-authorization-bundle role is an explicit AEC-06 addition;
// it is never aliased to the terminal ep-receipt / Trust Receipt role.
// AEC-07: every native result carries VERIFIED and ACCEPTED separately.
// The legacy string-requirement API above keeps one combined `valid` per row.
// ---------------------------------------------------------------------------
export const AEC_REQUIREMENT_VERSION = 'EP-AEC-REQUIREMENT-v1';
export const AEC_REPLAY_VERSION = 'EP-AEC-REPLAY-v1';
// 07: each normalized fact records native_verification and acceptance as
// separate results (AEC-07 Section 6), so replay digests differ from 05.
// 08: the requirement-expression algorithm is normative (maximal identifier
// runs, exact uppercase AND/OR, SP/HTAB/CR/LF only, whole-input validation,
// left-to-right grouping, fixed caps). -07 Section 10 requires a new revision
// when the algorithm changes, so replay digests differ from 07 even where the
// Boolean meaning is the same. The requirement and replay envelope versions
// and member sets are unchanged.
export const AEC_EVALUATOR_REVISION = 'EP-AEC-EVALUATOR-08-v1';
/** Revisions this evaluator has replaced. A record carrying one is reported
 * UNSUPPORTED_REVISION by replay(); it is never relabeled or compared as -08. */
export const AEC_SUPERSEDED_EVALUATOR_REVISIONS = Object.freeze(['EP-AEC-EVALUATOR-05-v1', 'EP-AEC-EVALUATOR-07-v1']);
export const AEC_BUNDLE_COMPONENT = 'ep-authorization-bundle';
const AEC_LIMITS = Object.freeze({
    maxDepth: 64, maxNodes: 50000, maxStringBytes: 1024 * 1024,
    maxWireBytes: 2 * 1024 * 1024, maxComponents: 64, maxBindings: 64,
    maxSubjects: 64, maxVerifierDurationMs: 1000,
});
const AEC_DIGEST = /^sha256:[0-9a-f]{64}$/;
const AEC_CAID = /^canactid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const structuredReserved = new Set([...RESERVED_COMPONENT_TYPES, AEC_BUNDLE_COMPONENT]);
const textValue = (v, maximum = 2048) => typeof v === 'string' && v.length > 0 && v.length <= maximum && !/[\u0000-\u001f\u007f]/.test(v);
const typeValue = (v) => textValue(v, 128) && IDENT.test(v);
const digestValue = (v) => typeof v === 'string' && AEC_DIGEST.test(v);
function closedKeys(v, required, optional = []) {
    return isRecord(v) && required.every(k => own(v, k))
        && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
}
function deepFreezeAec(value) {
    if (value !== null && typeof value === 'object') {
        for (const child of Object.values(value))
            deepFreezeAec(child);
        Object.freeze(value);
    }
    return value;
}
function strictSnapshot(value, limits) {
    return deepFreezeAec(JSON.parse(canonicalizeStrictJson(value, limits)));
}
function aecDigest(value) {
    return `sha256:${sha256hex(canonicalizeStrictJson(value))}`;
}
function validateAecRequirement(value, limits) {
    const r = strictSnapshot(value, limits);
    // The v1 member set is closed and unchanged in -08: parse metadata never
    // travels inside the requirement. The expression string is kept exactly as
    // supplied (RFC 8785 preserves string contents), so the requirement profile
    // digest commits to the stored bytes, while the tree compiled here is the
    // only thing evaluation reads.
    if (!closedKeys(r, ['@version', 'requirement_id', 'expression'], ['purpose', 'freshness_sec', 'status_required', 'role_constraints', 'required_bindings'])
        || r['@version'] !== AEC_REQUIREMENT_VERSION || !textValue(r.requirement_id)
        || (own(r, 'purpose') && typeof r.purpose !== 'string'))
        throw new TypeError('aec_requirement_invalid');
    const expression = compileAecRequirementExpression(r.expression);
    if (!expression.valid)
        throw new TypeError('aec_requirement_invalid');
    if (own(r, 'freshness_sec') && (!isRecord(r.freshness_sec)
        || Object.keys(r.freshness_sec).length > limits.maxComponents
        || Object.entries(r.freshness_sec).some(([key, age]) => !typeValue(key) || !Number.isSafeInteger(age) || Number(age) < 0))) {
        throw new TypeError('aec_freshness_requirement_invalid');
    }
    if (own(r, 'status_required') && (!Array.isArray(r.status_required)
        || r.status_required.length > limits.maxComponents
        || r.status_required.some((t) => !typeValue(t))
        || new Set(r.status_required).size !== r.status_required.length))
        throw new TypeError('aec_status_requirement_invalid');
    if (own(r, 'role_constraints') && (!Array.isArray(r.role_constraints)
        || r.role_constraints.length > limits.maxBindings
        || r.role_constraints.some((c) => !closedKeys(c, ['type', 'component_type', 'threshold', 'subject_id_source'])
            || c.type !== 'distinct-subject-quorum' || !typeValue(c.component_type)
            || !Number.isSafeInteger(c.threshold) || c.threshold <= 1
            || c.subject_id_source !== 'native-verifier')))
        throw new TypeError('aec_role_constraint_invalid');
    if (own(r, 'required_bindings') && (!Array.isArray(r.required_bindings)
        || r.required_bindings.length > limits.maxBindings
        || r.required_bindings.some((b) => !closedKeys(b, ['from_type', 'relation', 'to_type'])
            || !typeValue(b.from_type) || !typeValue(b.to_type) || !textValue(b.relation, 128)))) {
        throw new TypeError('aec_required_binding_invalid');
    }
    return { requirement: r, expression };
}
/** The component types a requirement expression may count: exactly the facts
 * marked eligible (VERIFIED, ACCEPTED, MATCH or EQUIVALENT_UNDER_PROFILE, and
 * every freshness and status condition met). A FAILED, REJECTED or
 * NOT_EVALUATED fact is never eligible. */
function eligibleFactTypes(facts) {
    return new Set(facts.filter(f => f.eligible === true).map(f => f.type));
}
/** Aggregate only fields already verified by the native human verifier. The
 * oldest issuance and earliest expiry conservatively enforce every signoff's
 * window. No label, key encoding or unsigned subject becomes an identity.
 * Called only after both native results are positive. */
function humanNativeFacts(result, contexts, revision) {
    // Defensive path: without signed contexts or protected times there is no
    // checked integrity claim to report, so the result is not VERIFIED.
    if (!result.valid || contexts.length === 0)
        return { verified: false, accepted: false, reason: 'native_human_evidence_invalid' };
    const times = contexts.map(c => ({ issued: strictInstantMs(c.issued_at), expires: strictInstantMs(c.expires_at) }));
    if (times.some(t => !Number.isFinite(t.issued) || !Number.isFinite(t.expires)))
        return { verified: false, accepted: false, reason: 'native_human_evidence_invalid' };
    return {
        verified: true, accepted: true, format_revision: revision, action_digest: result.action_digest,
        issued_at: new Date(Math.min(...times.map(t => t.issued))).toISOString(),
        expires_at: new Date(Math.min(...times.map(t => t.expires))).toISOString(),
        subject_ids: [...new Set(contexts.map(c => c.approver).filter(v => textValue(v)))],
        bindings: [],
    };
}
const NOT_EVALUATED_KEY = Object.freeze({ verified: null, accepted: false, reason: 'key_unresolved' });
const NOT_EVALUATED_VERIFIER = Object.freeze({ verified: null, accepted: false, reason: 'verifier_unavailable' });
const FAILED_INTEGRITY = (reason) => ({ verified: false, accepted: false, reason });
// A key window wide enough that only the signature itself decides; the real
// window, compromise marker and key class stay ACCEPTED inputs.
const INTEGRITY_KEY_FROM = '1970-01-01T00:00:00Z';
const INTEGRITY_KEY_TO = '9999-12-31T23:59:59Z';
const INTEGRITY_NOW = '9999-12-30T00:00:00Z';
/** Platform-attestation refusals the native verifier reaches only after the
 * JWT signature verified under the resolved attester key. Earlier structural
 * refusals and a bad signature leave the token not VERIFIED; an attester
 * issuer or key id absent from the relying party's key material leaves
 * VERIFIED unevaluated. */
const PLATFORM_POST_SIGNATURE_REFUSALS = new Set([
    'profile_mismatch', 'audience_mismatch', 'nonce_mismatch', 'action_digest_mismatch',
    'measurement_result_invalid', 'measurement_untrusted',
    'token_from_future', 'token_expired', 'token_too_old',
]);
const PLATFORM_KEY_UNRESOLVED = new Set(['attester_untrusted', 'attester_key_invalid', 'relying_party_policy_invalid']);
/** Map each context's canonical digest to the approver it names. */
function approverByContextDigest(contexts, digestOf) {
    const out = new Map();
    for (const c of contexts) {
        if (!isRecord(c))
            continue;
        const d = digestOf(c);
        if (d)
            out.set(d, c.approver);
    }
    return out;
}
/** VERIFIED for a quorum: its structure is intact, every member's context
 * commits to the quorum action_hash, and every member's WebAuthn assertion
 * verifies under the key that member carries, in offline-integrity mode (no
 * relying-party RP ID or origin pins). Whether those keys, roles, policy, RP ID
 * and origins are the pinned ones is the separate ACCEPTED check. */
function quorumIntegrity(evidence) {
    try {
        const members = Array.isArray(evidence?.members) ? evidence.members : null;
        if (!isRecord(evidence) || !isRecord(evidence.policy)
            || typeof evidence.action_hash !== 'string' || !evidence.action_hash
            || !members || members.length === 0 || members.length > MAX_QUORUM_MEMBERS)
            return false;
        return members.every((m) => isRecord(m)
            && typeof m.approver_public_key === 'string' && m.approver_public_key.length > 0
            && isRecord(m.signoff) && isRecord(m.signoff.context)
            && m.signoff.context.action_hash === evidence.action_hash
            && verifyWebAuthnSignoff(m.signoff, m.approver_public_key, { mode: 'offline-integrity' })?.valid === true);
    }
    catch {
        return false;
    }
}
/** VERIFIED for a Trust Receipt. The receipt names each signing key only by
 * approver_key_id, resolved from the relying party's key material. Its log
 * checkpoint names its key by log_key_id (receipts-13 Section 7.2), but that
 * id is not resolved here: as in the receipts-13 Section 7.3 offline
 * algorithm, the checkpoint signature is checked under the trusted log public
 * key the relying party supplies (profile.log_public_key). An approver id
 * with no public key there, or no log key, leaves VERIFIED unevaluated. The
 * check uses only the resolved public key bytes, with the signature form
 * each signoff carries. The directory entry's approver binding, key class,
 * validity window and compromise marker, and the RP ID, origin and policy
 * pins, are ACCEPTED inputs that the full native verifier checks afterwards.
 * Resolving the log key by log_key_id, which would make "pinned for this
 * role" an ACCEPTED input, is not implemented. */
function receiptIntegrity(evidence, profile) {
    if (!isRecord(profile) || !isRecord(profile.approver_keys)
        || typeof profile.log_public_key !== 'string' || !profile.log_public_key)
        return 'KEY_UNRESOLVED';
    try {
        if (!isRecord(evidence) || !Array.isArray(evidence.signoffs) || !Array.isArray(evidence.contexts)
            || evidence.signoffs.length === 0)
            return 'FAILED';
        const approvers = approverByContextDigest(evidence.contexts, c => sha256hex(canonicalize(c)));
        const resolved = Object.create(null);
        for (const s of evidence.signoffs) {
            if (!isRecord(s))
                return 'FAILED';
            const id = s.approver_key_id;
            const entry = typeof id === 'string' && own(profile.approver_keys, id) ? profile.approver_keys[id] : null;
            if (!isRecord(entry) || typeof entry.public_key !== 'string' || !entry.public_key)
                return 'KEY_UNRESOLVED';
            const approver = approvers.get(normDigest(s.context_hash) ?? '');
            // One key id naming two principals cannot be checked as one entry;
            // the failure is not attributable, so it is conservatively not VERIFIED.
            if (own(resolved, id) && resolved[id].approver_id !== approver)
                return 'FAILED';
            resolved[id] = { public_key: entry.public_key, approver_id: approver, key_class: isRecord(s.webauthn) ? 'A' : 'B' };
        }
        return verifyTrustReceipt(evidence, {
            approverKeys: resolved, logPublicKey: profile.log_public_key,
        })?.valid === true ? 'VERIFIED' : 'FAILED';
    }
    catch {
        return 'FAILED';
    }
}
/** VERIFIED for an Authorization Bundle: closed shape, action_hash and context
 * commitments, and every completed signoff signature under the public key its
 * approver_key_id resolves to. The directory entry's approver binding, key
 * class, validity window and compromise marker are ACCEPTED inputs; so are
 * the audience, approver selection, policy, status and the exact action. */
function bundleIntegrity(evidence, trust, hooks) {
    const directory = isRecord(trust.approverKeys) ? trust.approverKeys : null;
    if (!directory)
        return 'KEY_UNRESOLVED';
    try {
        if (!isRecord(evidence) || !Array.isArray(evidence.signoffs) || !Array.isArray(evidence.contexts)
            || evidence.signoffs.length === 0 || !isRecord(evidence.action))
            return 'FAILED';
        const approvers = approverByContextDigest(evidence.contexts, c => aecDigest(c));
        const resolved = Object.create(null);
        for (const s of evidence.signoffs) {
            if (!isRecord(s))
                return 'FAILED';
            const id = s.approver_key_id;
            const entry = typeof id === 'string' && own(directory, id) ? directory[id] : null;
            if (!isRecord(entry) || typeof entry.public_key !== 'string' || !entry.public_key)
                return 'KEY_UNRESOLVED';
            const approver = approvers.get(typeof s.context_hash === 'string' ? s.context_hash : '');
            if (own(resolved, id) && resolved[id].approver_id !== approver)
                return 'FAILED';
            resolved[id] = { approver_id: approver, public_key: entry.public_key, key_class: s.key_class,
                valid_from: INTEGRITY_KEY_FROM, valid_to: INTEGRITY_KEY_TO };
        }
        const r = verifyAuthorizationBundle(evidence, {
            now: INTEGRITY_NOW, audience: 'urn:ep:aec:integrity-check', approverKeys: resolved,
            expectedApprovers: [], acceptedKeyClasses: ['A', 'B', 'C'], expectedAction: evidence.action,
            ...(typeof hooks.verifyClassASignoff === 'function' ? { verifyClassASignoff: hooks.verifyClassASignoff } : {}),
        });
        if (r.checks.closed_shape === true && r.checks.contexts === true && r.checks.signatures === true
            && !r.reasons.includes('action_hash_mismatch'))
            return 'VERIFIED';
        const otherwiseIntact = r.checks.closed_shape === true && r.checks.contexts === true
            && !r.reasons.includes('action_hash_mismatch') && !r.reasons.includes('signoff_signature_invalid');
        return otherwiseIntact && r.reasons.includes('class_a_verifier_unavailable') ? 'UNAVAILABLE' : 'FAILED';
    }
    catch {
        return 'FAILED';
    }
}
/** The action digest a platform-attestation token claims, read only to be
 * handed back to the native verifier as the digest to compare; the verifier
 * checks it under the token signature. Undecodable tokens get a placeholder
 * and fail the verifier's own structural checks. */
function platformClaimedActionDigest(evidence) {
    try {
        const payload = JSON.parse(Buffer.from(String(evidence.token).split('.')[1], 'base64url').toString('utf8'));
        if (typeof payload?.ep_action_digest === 'string' && AEC_DIGEST.test(payload.ep_action_digest))
            return payload.ep_action_digest;
    }
    catch { /* placeholder below */ }
    return `sha256:${'0'.repeat(64)}`;
}
// Each built-in checks the relying party's pins against the action the
// artifact itself commits to, and returns that integrity-protected commitment
// as action_digest. Whether it is the expected action is decided afterwards by
// MATCH (AEC-07 Section 7), so a trusted artifact bound to another action is
// recorded as VERIFIED, ACCEPTED and not matched, never as unaccepted.
function structuredBuiltin(type, trust, hooks) {
    if (type === AEC_BUNDLE_COMPONENT)
        return (evidence, ctx) => {
            const ev = evidence;
            const integrity = bundleIntegrity(evidence, trust, hooks);
            if (integrity === 'KEY_UNRESOLVED')
                return NOT_EVALUATED_KEY;
            if (integrity === 'UNAVAILABLE')
                return NOT_EVALUATED_VERIFIER;
            if (integrity !== 'VERIFIED')
                return FAILED_INTEGRITY('native_bundle_integrity_failed');
            const result = verifyAuthorizationBundle(evidence, {
                ...trust, ...hooks, now: ctx.verification_time, expectedAction: ev.action,
            });
            if (result.verdict !== 'SATISFIED')
                return { verified: true, accepted: false, reason: 'native_bundle_pins_refused' };
            // Only SIGNED contexts contribute subjects. The bundle can contain a
            // wider selected roster than the actual threshold of completed signoffs.
            const signedDigests = new Set(ev.signoffs.map((s) => s.context_hash));
            const contexts = ev.contexts.filter((c) => signedDigests.has(aecDigest(c)));
            const native = humanNativeFacts({ valid: true, action_digest: ev.action_hash }, contexts, 'EP-AUTHORIZATION-BUNDLE-v1');
            if (trust.requireCurrentStatus === true && result.checks.current_status === true && isRecord(trust.currentStatus)) {
                native.status = { authenticated: true, status: 'active', snapshot_digest: aecDigest(trust.currentStatus),
                    checked_at: trust.currentStatus.checked_at, expires_at: trust.currentStatus.expires_at };
            }
            return native;
        };
    if (type === EP_PLATFORM_ATTESTATION_COMPONENT)
        return (evidence, ctx) => {
            const ev = evidence;
            const profile = isRecord(trust.policy) ? trust.policy : {};
            const result = verifyPlatformAttestation(evidence, {
                trustedAttesters: trust.keys ?? {},
                expectedProfile: profile.expected_profile,
                expectedAudience: profile.expected_audience,
                expectedNonce: profile.expected_nonce,
                expectedActionDigest: platformClaimedActionDigest(evidence),
                referenceMeasurements: profile.reference_measurements,
                verificationTime: ctx.verification_time,
                maxAgeSeconds: profile.max_age_sec,
            });
            const reason = result.valid === true ? null : result.detail?.reason;
            if (reason !== null && PLATFORM_KEY_UNRESOLVED.has(reason))
                return NOT_EVALUATED_KEY;
            if (reason !== null && !PLATFORM_POST_SIGNATURE_REFUSALS.has(reason))
                return FAILED_INTEGRITY('native_builtin_integrity_failed');
            if (result.valid !== true)
                return { verified: true, accepted: false, reason: 'native_builtin_pins_refused' };
            // Decode only AFTER the closed native JWT verifier accepted the bytes.
            const payload = JSON.parse(Buffer.from(ev.token.split('.')[1], 'base64url').toString('utf8'));
            return { verified: true, accepted: true, format_revision: ctx.profile.native_format_revision,
                action_digest: result.action_digest, issuer: payload.iss, audience: payload.aud,
                issued_at: new Date(payload.iat * 1000).toISOString(), expires_at: new Date(payload.exp * 1000).toISOString(),
                subject_ids: [], bindings: [] };
        };
    const built = builtinVerifiers()[type];
    return (evidence, ctx) => {
        const profile = trust.policy;
        const ev = evidence;
        let integrity;
        if (type === 'ep-quorum')
            integrity = quorumIntegrity(evidence) ? 'VERIFIED' : 'FAILED';
        else
            integrity = receiptIntegrity(evidence, profile);
        if (integrity === 'KEY_UNRESOLVED')
            return NOT_EVALUATED_KEY;
        if (integrity !== 'VERIFIED')
            return FAILED_INTEGRITY('native_builtin_integrity_failed');
        // The legacy receipt and quorum built-ins apply the relying-party pins and
        // the native cryptography together and do not compare the expected action;
        // after the integrity check above, their `valid` is the ACCEPTED result.
        const result = built(evidence, {
            keysByType: { [type]: trust.keys ?? {} }, policiesByType: { [type]: profile },
            verificationTime: ctx.verification_time, action: ctx.action,
        });
        if (result.valid !== true)
            return { verified: true, accepted: false, reason: 'native_builtin_pins_refused' };
        // A terminal receipt may log selected contexts without completed signoffs.
        // Inclusion is not human authorization: only contexts authenticated by the
        // successfully verified human signoffs can supply subjects or time claims.
        const signedDigests = type === 'ep-receipt'
            ? new Set(ev.signoffs.map((s) => normDigest(s.context_hash))) : null;
        const contexts = type === 'ep-quorum' ? ev.members.map((m) => m.signoff.context)
            : ev.contexts.filter((c) => signedDigests.has(sha256hex(canonicalize(c))));
        const native = humanNativeFacts(result, contexts, ctx.profile.native_format_revision);
        if (native.accepted && freshRegistrySnapshot(profile, ctx.verification_time)) {
            native.status = { authenticated: true, status: 'active', snapshot_digest: aecDigest(profile),
                checked_at: profile.registry_checked_at,
                expires_at: new Date(strictInstantMs(profile.registry_checked_at) + profile.max_registry_age_sec * 1000).toISOString() };
        }
        return native;
    };
}
/** Constructor-owned trust boundary for the structured current profile.
 * Callbacks are trusted native implementations, not code supplied by the
 * presentation. Input/work count is bounded and asynchronous work has an abort
 * deadline. Synchronous hostile code cannot be preempted by this process: host
 * untrusted verifier code in a worker/process with its own execution deadline.
 * A callback exceeding the deadline is refused even if it eventually returns.
 */
export function createAuthorizationChainEvaluator(configuration) {
    if (!closedKeys(configuration, ['requirement', 'nativeVerifiers'], ['limits']))
        throw new TypeError('aec_configuration_invalid');
    const suppliedLimits = configuration.limits ?? {};
    if (!isRecord(suppliedLimits) || Object.keys(suppliedLimits).some(k => !own(AEC_LIMITS, k)))
        throw new TypeError('aec_limits_invalid');
    const limits = Object.freeze({ ...AEC_LIMITS, ...suppliedLimits });
    for (const [key, value] of Object.entries(limits)) {
        if (!Number.isSafeInteger(value) || value < 1 || value > AEC_LIMITS[key])
            throw new TypeError('aec_limits_invalid');
    }
    const { requirement, expression: requirementExpression } = validateAecRequirement(configuration.requirement, limits);
    const requirementDigest = aecDigest(requirement);
    if (!isRecord(configuration.nativeVerifiers) || Object.keys(configuration.nativeVerifiers).length > MAX_COMPONENTS)
        throw new TypeError('aec_native_configuration_invalid');
    const nativeVerifiers = new Map();
    for (const [type, registration] of Object.entries(configuration.nativeVerifiers)) {
        if (!typeValue(type) || !closedKeys(registration, ['profile', 'trustSnapshot'], ['verify', 'mapping', 'statusMaxAgeSec', 'bundleHooks']))
            throw new TypeError('aec_native_configuration_invalid');
        const profile = strictSnapshot(registration.profile, limits);
        const trust = strictSnapshot(registration.trustSnapshot, limits);
        if (!isRecord(profile) || !textValue(profile.id) || !textValue(profile.revision)
            || !textValue(profile.native_format_revision) || !isRecord(trust))
            throw new TypeError('aec_native_profile_invalid');
        const hooks = {};
        if (registration.bundleHooks !== undefined) {
            if (type !== AEC_BUNDLE_COMPONENT || !closedKeys(registration.bundleHooks, [], ['verifyClassASignoff', 'verifyKeyProofs', 'verifyPresentationEvidence']))
                throw new TypeError('aec_native_hooks_invalid');
            for (const [name, hook] of Object.entries(registration.bundleHooks)) {
                if (typeof hook !== 'function')
                    throw new TypeError('aec_native_hooks_invalid');
                hooks[name] = hook;
            }
        }
        if (structuredReserved.has(type) && registration.verify !== undefined)
            throw new TypeError('aec_builtin_override_refused');
        const verify = structuredReserved.has(type) ? structuredBuiltin(type, trust, Object.freeze(hooks)) : registration.verify;
        if (typeof verify !== 'function')
            throw new TypeError('aec_native_verifier_missing');
        let mapping = null;
        if (registration.mapping !== undefined) {
            if (!closedKeys(registration.mapping, ['profile', 'map']) || typeof registration.mapping.map !== 'function')
                throw new TypeError('aec_mapping_invalid');
            const mappingProfile = strictSnapshot(registration.mapping.profile, limits);
            if (!isRecord(mappingProfile) || !textValue(mappingProfile.id) || !textValue(mappingProfile.revision))
                throw new TypeError('aec_mapping_invalid');
            mapping = Object.freeze({ profile: mappingProfile, map: registration.mapping.map });
        }
        const statusMaxAgeSec = registration.statusMaxAgeSec ?? null;
        if (statusMaxAgeSec !== null && (!Number.isSafeInteger(statusMaxAgeSec) || statusMaxAgeSec < 0))
            throw new TypeError('aec_status_configuration_invalid');
        nativeVerifiers.set(type, Object.freeze({ profile, trust, profileDigest: aecDigest(profile), trustDigest: aecDigest(trust),
            verify, mapping, mappingDigest: mapping ? aecDigest(mapping.profile) : null, statusMaxAgeSec }));
    }
    const evaluatorProfileDigest = aecDigest({ algorithm_revision: AEC_EVALUATOR_REVISION, limits,
        verifiers: Object.fromEntries([...nativeVerifiers].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([type, v]) => [type, {
                native_verifier_profile_digest: v.profileDigest, trust_snapshot_digest: v.trustDigest,
                mapping_profile_digest: v.mappingDigest, status_max_age_sec: v.statusMaxAgeSec,
            }])) });
    async function boundedInvoke(fn) {
        const controller = new AbortController();
        const started = performance.now();
        let timer;
        try {
            const timeout = new Promise((_, reject) => {
                timer = setTimeout(() => { controller.abort(); reject(new Error('aec_native_deadline')); }, limits.maxVerifierDurationMs);
            });
            const result = await Promise.race([Promise.resolve().then(() => fn(controller.signal)), timeout]);
            if (performance.now() - started >= limits.maxVerifierDurationMs)
                throw new Error('aec_native_deadline');
            return result;
        }
        finally {
            if (timer)
                clearTimeout(timer);
            controller.abort();
        }
    }
    async function evaluate(input, acceptance) {
        const replay = {
            '@version': AEC_REPLAY_VERSION, algorithm_revision: AEC_EVALUATOR_REVISION,
            evaluator_profile_digest: evaluatorProfileDigest, aec_digest: null,
            expected_action_digest: null, expected_caid: null,
            requirement_profile_digest: requirementDigest, verification_time: null,
            facts: [], satisfied: false, reasons: [],
        };
        const finish = (reason) => {
            if (reason)
                replay.reasons.push(reason);
            // Bounds apply to the aggregate replay, not just to each native result.
            // Canonicalize before freezing: a failed serialization must not leave a
            // frozen partial-success record that the fail-closed handler cannot fix.
            let replayBytes;
            try {
                replayBytes = canonicalizeStrictJson(replay, limits);
                if (Buffer.byteLength(replayBytes, 'utf8') > limits.maxWireBytes)
                    throw new Error('replay_size_limit');
            }
            catch {
                replay.satisfied = false;
                replay.facts = [];
                replay.reasons = ['aec_replay_resource_limit'];
                // The constant-size refusal envelope contains only fixed-length
                // digests and bounded metadata, not any oversized native output.
                replayBytes = canonicalizeStrictJson(replay);
            }
            const frozenReplay = deepFreezeAec(replay);
            return Object.freeze({ satisfied: replay.satisfied, allow: replay.satisfied,
                authorization_decision: false, requirement_source: 'relying_party',
                replay: frozenReplay, replay_digest: `sha256:${sha256hex(replayBytes)}`, reasons: replay.reasons });
        };
        try {
            if (typeof input === 'string') {
                if (Buffer.byteLength(input, 'utf8') > limits.maxWireBytes || !strictJsonGate(input).ok)
                    return finish('aec_wire_json_invalid');
                input = JSON.parse(input);
            }
            const chain = strictSnapshot(input, limits);
            replay.aec_digest = aecDigest(chain);
            if (!closedKeys(chain, ['@version', 'action', 'components'], ['action_digest', 'action_caid', 'requirement'])
                || chain['@version'] !== AEC_VERSION || !isRecord(chain.action)
                || (own(chain, 'requirement') && typeof chain.requirement !== 'string')
                || !Array.isArray(chain.components) || chain.components.length < 1
                || chain.components.length > limits.maxComponents)
                return finish('aec_chain_invalid');
            const boundary = strictSnapshot(acceptance, limits);
            if (!closedKeys(boundary, ['verificationTime'], ['expectedAction', 'expectedActionDigest', 'expectedCaid'])
                || !Number.isFinite(strictInstantMs(boundary.verificationTime)))
                return finish('aec_acceptance_inputs_invalid');
            replay.verification_time = boundary.verificationTime;
            let expected = null;
            if (own(boundary, 'expectedAction')) {
                if (!isRecord(boundary.expectedAction))
                    return finish('aec_expected_action_invalid');
                expected = aecDigest(boundary.expectedAction);
            }
            if (own(boundary, 'expectedActionDigest')) {
                if (!digestValue(boundary.expectedActionDigest) || (expected && expected !== boundary.expectedActionDigest))
                    return finish('aec_expected_action_invalid');
                expected = boundary.expectedActionDigest;
            }
            replay.expected_action_digest = expected;
            if (!expected || expected !== aecDigest(chain.action)
                || (own(chain, 'action_digest') && chain.action_digest !== expected))
                return finish('aec_action_mismatch');
            if (own(boundary, 'expectedCaid')) {
                if (typeof boundary.expectedCaid !== 'string' || !AEC_CAID.test(boundary.expectedCaid))
                    return finish('aec_expected_caid_invalid');
                replay.expected_caid = boundary.expectedCaid;
            }
            if (own(chain, 'action_caid') && (typeof chain.action_caid !== 'string' || !AEC_CAID.test(chain.action_caid)
                || (replay.expected_caid !== null && chain.action_caid !== replay.expected_caid)))
                return finish('aec_caid_mismatch');
            for (let index = 0; index < chain.components.length; index++) {
                const component = chain.components[index];
                const type = isRecord(component) && typeValue(component.type) ? component.type : null;
                const verifier = type ? nativeVerifiers.get(type) : undefined;
                const fact = {
                    component_index: index, type, evidence_digest: null,
                    native_verifier_profile_digest: verifier?.profileDigest ?? null,
                    trust_snapshot_digest: verifier?.trustDigest ?? null,
                    mapping_profile_digest: verifier?.mappingDigest ?? null,
                    // Two separate results, never collapsed (AEC-07 Section 6).
                    native_verification: 'NOT_EVALUATED', acceptance: 'NOT_EVALUATED',
                    native_action_digest: null, format_revision: null,
                    issuer: null, audience: null, mapping_verdict: 'INDETERMINATE',
                    freshness: { result: 'NOT_REQUIRED', issued_at: null, expires_at: null },
                    status: { result: 'NOT_REQUIRED', snapshot_digest: null, checked_at: null, expires_at: null },
                    subject_ids: [], bindings: [], eligible: false, reasons: [],
                };
                replay.facts.push(fact);
                if (!closedKeys(component, ['type', 'evidence'], ['label', 'evidence_digest']) || !type
                    || (own(component, 'label') && typeof component.label !== 'string')) {
                    fact.reasons.push('component_shape_invalid');
                    continue;
                }
                fact.evidence_digest = aecDigest(component.evidence);
                if (own(component, 'evidence_digest') && component.evidence_digest !== fact.evidence_digest) {
                    fact.reasons.push('evidence_digest_mismatch');
                    continue;
                }
                if (!verifier) {
                    fact.reasons.push('native_verifier_unavailable');
                    continue;
                }
                const context = (signal) => Object.freeze({
                    action: chain.action, expected_action_digest: expected, expected_caid: replay.expected_caid,
                    verification_time: boundary.verificationTime, profile: verifier.profile,
                    trust_snapshot: verifier.trust, signal,
                });
                let native;
                try {
                    native = strictSnapshot(await boundedInvoke(signal => verifier.verify(component.evidence, context(signal))), limits);
                }
                catch {
                    fact.reasons.push('native_verifier_error_or_deadline');
                    continue;
                }
                if (isRecord(native) && own(native, 'valid')) {
                    fact.reasons.push('native_result_legacy_valid_field');
                    continue;
                }
                if (!closedKeys(native, ['verified', 'accepted'], ['reason', 'format_revision', 'action_digest', 'native_payload', 'issued_at', 'expires_at', 'issuer', 'audience', 'subject_ids', 'bindings', 'status'])
                    || (native.verified !== null && typeof native.verified !== 'boolean') || typeof native.accepted !== 'boolean') {
                    fact.reasons.push('native_result_shape_invalid');
                    continue;
                }
                if (native.accepted && native.verified !== true) {
                    fact.reasons.push('native_result_inconsistent');
                    continue;
                }
                // The fact members of a positive result are checked before either
                // result is recorded: a malformed result records neither VERIFIED nor
                // ACCEPTED for an artifact the evaluator then discards.
                const subjects = native.subject_ids ?? [];
                const bindings = native.bindings ?? [];
                if (native.accepted && ((native.action_digest != null && !digestValue(native.action_digest))
                    || (native.issuer != null && !textValue(native.issuer))
                    || (native.audience != null && !(textValue(native.audience) || (Array.isArray(native.audience) && native.audience.length <= limits.maxSubjects && native.audience.every((v) => textValue(v)))))
                    || !Array.isArray(subjects) || subjects.length > limits.maxSubjects || subjects.some((v) => !textValue(v))
                    || !Array.isArray(bindings) || bindings.length > limits.maxBindings
                    || bindings.some((b) => !closedKeys(b, ['relation', 'target_evidence_digest']) || !textValue(b.relation, 128) || !digestValue(b.target_evidence_digest)))) {
                    fact.reasons.push('native_fact_shape_invalid');
                    continue;
                }
                // No resolvable verification key (or unusable relying-party key
                // material): VERIFIED was not evaluated, which is not a failed check.
                if (native.verified === null) {
                    fact.reasons.push(native.reason === 'key_unresolved' ? 'native_key_unresolved' : 'native_verification_not_evaluated');
                    continue;
                }
                if (!native.verified) {
                    fact.native_verification = 'FAILED';
                    fact.reasons.push('native_verification_failed');
                    continue;
                }
                fact.native_verification = 'VERIFIED';
                if (!native.accepted) {
                    fact.acceptance = 'REJECTED';
                    fact.reasons.push('native_acceptance_refused');
                    continue;
                }
                // The pinned native format revision is a relying-party acceptance input.
                if (native.format_revision !== verifier.profile.native_format_revision) {
                    fact.acceptance = 'REJECTED';
                    fact.reasons.push('native_format_revision_mismatch');
                    continue;
                }
                fact.acceptance = 'ACCEPTED';
                fact.native_action_digest = native.action_digest ?? null;
                fact.format_revision = native.format_revision;
                fact.issuer = native.issuer ?? null;
                fact.audience = native.audience ?? null;
                fact.subject_ids = [...new Set(subjects)].sort();
                fact.bindings = bindings;
                if (native.action_digest != null)
                    fact.mapping_verdict = native.action_digest === expected ? 'MATCH' : 'NOT_EQUIVALENT';
                else if (verifier.mapping && replay.expected_caid && own(native, 'native_payload')) {
                    try {
                        const mapped = strictSnapshot(await boundedInvoke(signal => verifier.mapping.map(native, context(signal))), limits);
                        if (closedKeys(mapped, ['verdict', 'caid']) && mapped.verdict === 'EQUIVALENT_UNDER_PROFILE'
                            && mapped.caid === replay.expected_caid)
                            fact.mapping_verdict = 'EQUIVALENT_UNDER_PROFILE';
                        else if (mapped.verdict === 'NOT_EQUIVALENT')
                            fact.mapping_verdict = 'NOT_EQUIVALENT';
                    }
                    catch {
                        fact.reasons.push('mapping_error_or_deadline');
                    }
                }
                if (!['MATCH', 'EQUIVALENT_UNDER_PROFILE'].includes(fact.mapping_verdict))
                    fact.reasons.push('material_action_not_matched');
                if (own(requirement.freshness_sec, type)) {
                    const at = strictInstantMs(boundary.verificationTime);
                    const issued = strictInstantMs(native.issued_at), expires = strictInstantMs(native.expires_at);
                    const fresh = Number.isFinite(issued) && Number.isFinite(expires) && issued <= at && at < expires
                        && (at - issued) / 1000 <= requirement.freshness_sec[type];
                    fact.freshness = { result: fresh ? 'FRESH' : 'REFUSED', issued_at: typeof native.issued_at === 'string' ? native.issued_at : null, expires_at: typeof native.expires_at === 'string' ? native.expires_at : null };
                    if (!fresh)
                        fact.reasons.push('freshness_requirement_failed');
                }
                if (requirement.status_required?.includes(type)) {
                    const status = native.status;
                    const at = strictInstantMs(boundary.verificationTime);
                    const checked = strictInstantMs(status?.checked_at), expires = strictInstantMs(status?.expires_at);
                    const validShape = closedKeys(status, ['authenticated', 'status', 'snapshot_digest', 'checked_at', 'expires_at']);
                    const fresh = validShape && status.authenticated === true && status.status === 'active'
                        && digestValue(status.snapshot_digest) && verifier.statusMaxAgeSec !== null
                        && Number.isFinite(checked) && Number.isFinite(expires) && checked <= at && at < expires
                        && (at - checked) / 1000 <= verifier.statusMaxAgeSec;
                    fact.status = { result: fresh ? 'CURRENT' : 'REFUSED',
                        snapshot_digest: digestValue(status?.snapshot_digest) ? status.snapshot_digest : null,
                        checked_at: typeof status?.checked_at === 'string' ? status.checked_at : null,
                        expires_at: typeof status?.expires_at === 'string' ? status.expires_at : null };
                    if (!fresh)
                        fact.reasons.push('status_requirement_failed');
                }
                fact.eligible = fact.reasons.length === 0;
            }
            const eligible = replay.facts.filter(f => f.eligible);
            // Evaluate the tree compiled at construction; the expression text is
            // not parsed again here.
            if (requirementExpression.evaluate(eligibleFactTypes(replay.facts)).value !== true)
                replay.reasons.push('expression_unsatisfied');
            for (let i = 0; i < (requirement.role_constraints?.length ?? 0); i++) {
                const constraint = requirement.role_constraints[i];
                const subjects = new Set(eligible.filter(f => f.type === constraint.component_type).flatMap(f => f.subject_ids));
                if (subjects.size < constraint.threshold)
                    replay.reasons.push(`role_constraint_unsatisfied:${i}`);
            }
            for (let i = 0; i < (requirement.required_bindings?.length ?? 0); i++) {
                const binding = requirement.required_bindings[i];
                const targets = new Set(eligible.filter(f => f.type === binding.to_type).map(f => f.evidence_digest));
                if (!eligible.some(f => f.type === binding.from_type && f.bindings.some((b) => b.relation === binding.relation && targets.has(b.target_evidence_digest))))
                    replay.reasons.push(`required_binding_unsatisfied:${i}`);
            }
            replay.satisfied = replay.reasons.length === 0;
            return finish();
        }
        catch {
            replay.satisfied = false;
            return finish('aec_invalid_input_or_evaluation_error');
        }
    }
    return Object.freeze({
        requirement_profile_digest: requirementDigest, evaluator_profile_digest: evaluatorProfileDigest,
        /** Interpretation diagnostic for the pinned expression, computed from the
         * one tree evaluation uses. Not part of any wire object, and a matching
         * parse identity does not guarantee a matching verdict. */
        requirement_expression: Object.freeze({
            canonical_parse: requirementExpression.canonical_parse,
            parse_identity: requirementExpression.parse_identity,
            token_count: requirementExpression.token_count,
        }),
        evaluate,
        /** Reverify original evidence under this constructor's pins. A presenter
         * cannot turn serialized facts or a previously true Boolean into evidence.
         *
         * Migration: only a record made by this evaluator revision is compared, and
         * the comparison is over the complete record digest. A record from any
         * other revision (a stored -07 record, say) is reported
         * UNSUPPORTED_REVISION: it is not relabeled, its digest is not recomputed
         * under -08, and `matches` is false. `result` is always a fresh
         * evaluation under this revision, a new and separately identified record. */
        async replay(chain, recorded, inputs) {
            const result = await evaluate(chain, inputs);
            let claimedDigest = null;
            let recordedRevision = null;
            try {
                const snapshot = strictSnapshot(recorded, limits);
                claimedDigest = aecDigest(snapshot);
                if (isRecord(snapshot) && snapshot['@version'] === AEC_REPLAY_VERSION && typeof snapshot.algorithm_revision === 'string') {
                    recordedRevision = snapshot.algorithm_revision;
                }
            }
            catch { /* refused below */ }
            const comparison = claimedDigest === null || recordedRevision === null ? 'RECORD_INVALID'
                : recordedRevision !== AEC_EVALUATOR_REVISION ? 'UNSUPPORTED_REVISION'
                    : claimedDigest === result.replay_digest ? 'MATCH' : 'MISMATCH';
            return Object.freeze({ matches: comparison === 'MATCH', comparison, recorded_revision: recordedRevision,
                claimed_replay_digest: claimedDigest, result });
        },
    });
}
// Mutation and differential-test surface. These helpers are not protocol API;
// exporting them keeps boundary tests from reimplementing the acceptance math.
export const __aecSecurityInternals = Object.freeze({
    builtinVerifiers,
    isRecord,
    own,
    sha256hex,
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
    lexAecExpression,
    parseAecExpression,
    renderAecExpression,
    aecParseIdentity,
    evaluateAecExpressionTree,
    eligibleFactTypes,
    utf8Octets,
});
//# sourceMappingURL=evidence-chain.js.map
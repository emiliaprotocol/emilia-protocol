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
import { type AgileSignature } from '@emilia-protocol/verify/pq-signature-agility';
export declare const BREAKGLASS_VERSION = "EP-GATE-BREAKGLASS-v1";
export declare const BREAKGLASS_EVIDENCE_KIND = "breakglass";
type Obj = Record<string, any>;
/** Relying-party break-glass trust policy: pinned roster + minimum threshold. */
type BreakGlassPolicy = {
    minimum_threshold: number;
    roster: Array<{
        kid: string;
        principal_id: string;
        key?: string;
    }>;
};
/** Optional pinned keys when roster entries omit their own `key`. */
type IssuerKeys = Record<string, string> | Array<{
    kid: string;
    key: string;
}>;
/** Injected clock: fixed ms/ISO value, or a () => ms function (default Date.now). */
type BreakGlassClock = number | string | (() => number);
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
export declare function mintBreakGlassAuthorization(signers: any, { scope, window: win, reason, incident_ref, threshold, }?: {
    scope?: {
        action_types: string[];
    };
    window?: {
        not_before: number | string;
        expires_at: number | string;
    };
    reason?: string;
    incident_ref?: string;
    threshold?: number;
}): {
    '@version': string;
    payload: {
        scope: {
            action_types: string[];
        };
        window: {
            not_before: string | number;
            expires_at: string | number;
        };
        reason: string | undefined;
        incident_ref: string | undefined;
        threshold: number;
        grant_id: string;
    };
    signatures: {
        kid: any;
        algorithm: string;
        value: string;
    }[];
};
export declare function verifyBreakGlass(grantJson: any, options?: {}): {
    valid: boolean;
    reason: any;
};
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
export declare function consumeBreakGlass(grant: any, store: any): Promise<{
    consumed: boolean;
    reason: string;
    key?: undefined;
} | {
    consumed: boolean;
    reason: string;
    key: string;
}>;
export declare function buildBreakGlassEvidence(grant: any, decision: any, options?: {}): {
    kind: string;
    '@version': string;
    at: string;
    grant_id: any;
    incident_ref: any;
    grant_reason: any;
    scope: any;
    threshold: any;
    policy_minimum_threshold: any;
    required_threshold: any;
    signer_kids: any;
    signer_principal_ids: any;
    signer_spki_fingerprints: any;
    grant_hash: string | null;
    decision: {
        allow: boolean;
        reason: any;
        action_type: any;
    };
};
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
export declare function runBreakGlass({ grant, policy, issuerKeys, actionType, store, evidence, now, }: {
    grant?: Obj | string;
    policy?: BreakGlassPolicy;
    issuerKeys?: IssuerKeys;
    actionType?: string;
    store?: {
        consume(key: string): Promise<boolean>;
    };
    evidence?: {
        strict?: boolean;
        atomicAppend?: boolean;
        record?: (entry: Obj) => any;
    };
    now?: BreakGlassClock;
} | undefined, effect: any): Promise<{
    ok: boolean;
    reason: any;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: null;
    evidence: null;
    result?: undefined;
} | {
    ok: boolean;
    reason: string;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: {
        consumed: boolean;
        reason: string;
        key?: undefined;
    } | {
        consumed: boolean;
        reason: string;
        key: string;
    };
    evidence: null;
    result?: undefined;
} | {
    ok: boolean;
    reason: string;
    result: any;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: {
        consumed: boolean;
        reason: string;
        key?: undefined;
    } | {
        consumed: boolean;
        reason: string;
        key: string;
    };
    evidence: any;
}>;
/**
 * Copies the five-move EP-REVOCATION-v2 template
 * (packages/verify/src/revocation.ts) onto the break-glass roster, with one
 * roster-specific twist noted in the P6 brief: the roster is ALREADY
 * set-shaped (`signatures: [{kid, algorithm, value}]`, one entry per
 * signer), so v2 does not add a second top-level array -- it makes EACH
 * signer's entry itself a small agile signature SET
 * (`{kid, signatures: [{alg, sig, key_id?}]}`, one leg per required
 * algorithm), with the SAME anti-stripping discipline per signer. M-of-N
 * THRESHOLD SEMANTICS ARE UNCHANGED: same distinct-kid / distinct-principal /
 * distinct-key checks, same "every listed signer must verify or the whole
 * grant refuses" discipline -- only what "verify" means for one signer grows
 * from one Ed25519 check to a hybrid signature-set check.
 *
 * 1. VERSION BUMP. `payload.threshold` etc. are unchanged, but
 *    `payload.required_algorithms` is a NEW field (see move 3) and every
 *    `signatures[]` entry's shape changes from `{kid, algorithm, value}` to
 *    `{kid, signatures: [...]}`, so this is a new `@version`
 *    (-v1 -> -v2). verifyBreakGlass above is UNCHANGED and refuses a v2 grant
 *    at `unsupported_version` before it inspects a single signature.
 * 2. SET SHAPE. Each signer's `signatures` sub-array is an EP-SIG-AGILITY-v1
 *    AgileSignature array, reused verbatim.
 * 3. ANTI-STRIPPING. `required_algorithms` is INSIDE `payload`, so it is part
 *    of the SAME bytes every signer already signs (`canonical(payload)`,
 *    unchanged from v1). Dropping a signer's ML-DSA leg while narrowing
 *    `payload.required_algorithms` to `["Ed25519"]` changes the signed bytes
 *    for EVERY signer at once, so every surviving Ed25519 signature stops
 *    verifying -- narrowing cannot be done selectively per signer.
 * 4. V1 COMPATIBILITY. verifyBreakGlass stays synchronous and untouched.
 *    verifyBreakGlassV2 is a SEPARATE async entry point (ML-DSA verification
 *    is inherently async); verifyBreakGlassStatement routes on `@version`.
 *    runBreakGlassStatement is the v2-aware twin of runBreakGlass, sharing
 *    consumeBreakGlass/buildBreakGlassEvidence unchanged (both already read
 *    only kid/grant_id/decision fields present under either version).
 * 5. NAMED REFUSALS. Every failure path returns `{valid:false, reason}`;
 *    nothing throws. A signer whose set is missing its ML-DSA leg is
 *    `signer_leg_missing`, never counted as a valid Ed25519-only signer.
 *
 * HONEST BOUNDARY, UNCHANGED FROM V1: this profile is evidence of an
 * emergency override, never a bypass -- runBreakGlassStatement enforces the
 * exact same pinned-policy verification, permanent consumption, and strict
 * evidence order as v1. The ML-DSA-65 backend remains @noble/post-quantum's
 * pure-JS FIPS 204 implementation, not independently audited and not a FIPS
 * validated module; verifying under this profile is not a certification
 * claim.
 */
export declare const BREAKGLASS_V2_VERSION = "EP-GATE-BREAKGLASS-v2";
export declare const BREAKGLASS_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
type BreakGlassV2Signer = {
    kid: string;
    ed: {
        privateKey: crypto.KeyObject;
    };
    pq: {
        secretKey: Uint8Array | string;
    };
};
type BreakGlassV2RosterEntry = {
    kid: string;
    principal_id: string;
    key?: string;
    pq_key?: string;
};
type BreakGlassV2Policy = {
    minimum_threshold: number;
    roster: BreakGlassV2RosterEntry[];
};
type BreakGlassV2IssuerKeys = Record<string, {
    key: string;
    pq_key: string;
}> | Array<{
    kid: string;
    key: string;
    pq_key: string;
}>;
/**
 * Mint a hybrid break-glass authorization: every signer signs the SAME
 * canonical payload bytes (now carrying `required_algorithms`) under BOTH
 * registered algorithms. Throws on invalid fields or an unavailable ML-DSA
 * backend -- a malformed or partially-signed grant must never be issued.
 */
export declare function mintBreakGlassAuthorizationV2(signers: BreakGlassV2Signer[], { scope, window: win, reason, incident_ref, threshold, }?: {
    scope?: {
        action_types: string[];
    };
    window?: {
        not_before: number | string;
        expires_at: number | string;
    };
    reason?: string;
    incident_ref?: string;
    threshold?: number;
}): Promise<{
    '@version': string;
    payload: {
        scope: {
            action_types: string[];
        };
        window: {
            not_before: string | number;
            expires_at: string | number;
        };
        reason: string | undefined;
        incident_ref: string | undefined;
        threshold: number;
        required_algorithms: ("Ed25519" | "ML-DSA-65")[];
        grant_id: string;
    };
    signatures: {
        kid: string;
        signatures: AgileSignature[];
    }[];
}>;
/**
 * Verify a hybrid break-glass grant. NEVER throws -- every failure resolves
 * to `{valid:false, reason}`. Same fail-closed discipline as verifyBreakGlass:
 * one bad or leg-incomplete signer set refuses the WHOLE grant.
 */
export declare function verifyBreakGlassV2(grantJson: any, options?: {
    policy?: BreakGlassV2Policy;
    issuerKeys?: BreakGlassV2IssuerKeys;
    now?: BreakGlassClock;
    actionType?: string;
}): Promise<{
    valid: boolean;
    reason: any;
}>;
/**
 * Route a grant of EITHER version to its verifier. A v1 grant keeps the
 * exact synchronous v1 verdict (wrapped in a resolved Promise); a v2 grant
 * gets the hybrid per-signer check.
 */
export declare function verifyBreakGlassStatement(grantJson: any, options?: {
    policy?: BreakGlassPolicy | BreakGlassV2Policy;
    issuerKeys?: IssuerKeys | BreakGlassV2IssuerKeys;
    now?: BreakGlassClock;
    actionType?: string;
}): Promise<{
    valid: boolean;
    reason: any;
}>;
/**
 * The v2-aware twin of runBreakGlass: identical orchestration (verify, then
 * atomically consume, then require strict evidence acknowledgement, then and
 * only then invoke `effect`), routed through verifyBreakGlassStatement so a
 * relying party accepts either a classical or a hybrid grant. Shares
 * consumeBreakGlass/buildBreakGlassEvidence unchanged: both already read only
 * `grant_id`/`kid`/decision fields present under either version.
 */
export declare function runBreakGlassStatement({ grant, policy, issuerKeys, actionType, store, evidence, now, }: {
    grant?: Obj | string;
    policy?: BreakGlassPolicy | BreakGlassV2Policy;
    issuerKeys?: IssuerKeys | BreakGlassV2IssuerKeys;
    actionType?: string;
    store?: {
        consume(key: string): Promise<boolean>;
    };
    evidence?: {
        strict?: boolean;
        atomicAppend?: boolean;
        record?: (entry: Obj) => any;
    };
    now?: BreakGlassClock;
} | undefined, effect: any): Promise<{
    ok: boolean;
    reason: any;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: null;
    evidence: null;
    result?: undefined;
} | {
    ok: boolean;
    reason: string;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: {
        consumed: boolean;
        reason: string;
        key?: undefined;
    } | {
        consumed: boolean;
        reason: string;
        key: string;
    };
    evidence: null;
    result?: undefined;
} | {
    ok: boolean;
    reason: string;
    result: any;
    verification: {
        valid: boolean;
        reason: any;
    };
    consumption: {
        consumed: boolean;
        reason: string;
        key?: undefined;
    } | {
        consumed: boolean;
        reason: string;
        key: string;
    };
    evidence: any;
}>;
declare const _default: {
    mintBreakGlassAuthorization: typeof mintBreakGlassAuthorization;
    verifyBreakGlass: typeof verifyBreakGlass;
    consumeBreakGlass: typeof consumeBreakGlass;
    buildBreakGlassEvidence: typeof buildBreakGlassEvidence;
    runBreakGlass: typeof runBreakGlass;
    mintBreakGlassAuthorizationV2: typeof mintBreakGlassAuthorizationV2;
    verifyBreakGlassV2: typeof verifyBreakGlassV2;
    verifyBreakGlassStatement: typeof verifyBreakGlassStatement;
    runBreakGlassStatement: typeof runBreakGlassStatement;
    BREAKGLASS_VERSION: string;
    BREAKGLASS_EVIDENCE_KIND: string;
    BREAKGLASS_V2_VERSION: string;
};
export default _default;
//# sourceMappingURL=breakglass.d.ts.map
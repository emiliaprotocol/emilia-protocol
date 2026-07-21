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
declare const _default: {
    mintBreakGlassAuthorization: typeof mintBreakGlassAuthorization;
    verifyBreakGlass: typeof verifyBreakGlass;
    consumeBreakGlass: typeof consumeBreakGlass;
    buildBreakGlassEvidence: typeof buildBreakGlassEvidence;
    runBreakGlass: typeof runBreakGlass;
    BREAKGLASS_VERSION: string;
    BREAKGLASS_EVIDENCE_KIND: string;
};
export default _default;
//# sourceMappingURL=breakglass.d.ts.map
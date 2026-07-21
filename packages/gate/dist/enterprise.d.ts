export declare const ENTITLEMENT_VERSION = "EP-GATE-ENTITLEMENT-v1";
export declare const ENTITLEMENT_TIERS: string[];
/**
 * Mint a signed entitlement (test/ops helper — the licensing service, not the
 * verifier, holds the private key). Throws on invalid fields: a malformed
 * license must never be issued, only refused.
 * @param {crypto.KeyObject} privateKey Ed25519 private key
 * @param {object} fields { org, tier, features?, limits?, not_before, expires_at, kid }
 * @returns {{ '@version': string, payload: object, signature: { algorithm: 'Ed25519', value: string } }}
 */
export declare function mintEntitlement(privateKey: any, { org, tier, features, limits, not_before, expires_at, kid, }: {
    org: string;
    tier: string;
    features?: string[];
    limits?: Record<string, any>;
    not_before: string | number;
    expires_at: string | number;
    kid: string;
}): {
    '@version': string;
    payload: {
        org: string;
        tier: string;
        features: string[];
        limits: Record<string, any>;
        not_before: string | number;
        expires_at: string | number;
        kid: string;
    };
    signature: {
        algorithm: string;
        value: string;
    };
};
/**
 * Verify an entitlement. NEVER throws for a bad artifact — every failure
 * resolves to the community tier with a machine-readable reason, so a licensing
 * problem degrades gracefully instead of bricking the gate. Enterprise features
 * remain gated by `requireFeature`, which fails closed on any non-valid result.
 *
 * @param {object|string|null} entitlementJson the artifact (object or JSON string); absence -> community
 * @param {object} [o]
 * @param {object|Array<{kid:string,key:string}>} [o.issuerKeys] pinned kid -> base64url SPKI-DER public key
 * @param {number|string|function} [o.now=Date.now] injected clock (ms, ISO, or () => ms)
 * @returns {{ valid: boolean, tier: string, features: string[], limits: object|null, reason: string, org?: string, kid?: string, not_before?: any, expires_at?: any }}
 */
export declare function verifyEntitlement(entitlementJson: any, { issuerKeys, now, }?: {
    issuerKeys?: Record<string, string> | Array<{
        kid: string;
        key: string;
    }>;
    now?: number | string | (() => number);
}): {
    valid: boolean;
    tier: string;
    features: never[];
    limits: null;
    reason: any;
} | {
    valid: boolean;
    tier: any;
    features: any;
    limits: any;
    reason: string;
    org: any;
    kid: any;
    not_before: any;
    expires_at: any;
};
/**
 * Is `feature` licensed? FAIL CLOSED: true only for a valid entitlement that
 * explicitly lists the feature. Community fallback, invalid/expired/tampered
 * artifacts, and unlisted features are all false — no enterprise code path
 * runs without a live license naming it.
 * @param {object} verified the result of verifyEntitlement
 * @param {string} feature
 * @returns {boolean}
 */
export declare function requireFeature(verified: any, feature: any): any;
declare const _default: {
    mintEntitlement: typeof mintEntitlement;
    verifyEntitlement: typeof verifyEntitlement;
    requireFeature: typeof requireFeature;
    ENTITLEMENT_VERSION: string;
    ENTITLEMENT_TIERS: string[];
};
export default _default;
//# sourceMappingURL=enterprise.d.ts.map
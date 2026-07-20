/**
 * EMILIA Gate — issuer key registry (production key custody for the VERIFIER).
 *
 * A flat `trustedKeys: string[]` cannot express the two things a production
 * deployment needs:
 *   1. ROTATION — an issuer key is valid only for a window; a new key overlaps
 *      the old one, then the old one retires, without rejecting receipts that
 *      were legitimately issued while it was current.
 *   2. REVOCATION — a COMPROMISED issuer key must be rejected immediately, for
 *      every receipt, regardless of the issuance time the (now-untrusted) key
 *      claims. Fail closed: once revoked, the key signs nothing the gate accepts.
 *
 * The registry resolves, for a given receipt issuance time, the set of public
 * keys the gate should verify against — excluding revoked keys entirely and
 * windowed keys whose [not_before, not_after] does not contain that time. The
 * gate passes that resolved set to the receipt verifier, so an excluded key's
 * signature simply does not verify and the action is refused.
 *
 * A key with no window and no revocation behaves exactly like a flat trustedKeys
 * entry (back-compatible).
 */
type RawKeyEntry = {
    kid?: string;
    key: string;
    not_before?: string;
    not_after?: string;
    revoked_at?: string;
};
/**
 * @param {Array<object>} entries each: {
 *   kid?: string, key: string (base64url SPKI-DER public key),
 *   not_before?: string, not_after?: string, revoked_at?: string (strict RFC3339)
 * }
 */
export declare function createKeyRegistry(entries?: RawKeyEntry[]): {
    /** The base64url public keys to verify a receipt issued at strict RFC3339 `at`. */
    keysValidAt(at: any): string[];
    /** Mark a kid revoked as of `at` (default: now-as-supplied). Fail-closed thereafter. */
    revoke(kid: string, at?: string): number;
    /** Add/rotate in a new key. */
    add(entry: any): /*elided*/ any;
    /** Operational snapshot (no private material; keys are public). */
    status(at: any): {
        kid: string;
        revoked: boolean;
        active: boolean;
        not_before: number | null;
        not_after: number | null;
        revoked_at: number | null;
    }[];
    readonly size: number;
};
/** Coerce a flat trustedKeys[] OR a registry into a registry (back-compat). */
export declare function asKeyRegistry(trustedKeysOrRegistry: any): any;
declare const _default: {
    createKeyRegistry: typeof createKeyRegistry;
    asKeyRegistry: typeof asKeyRegistry;
};
export default _default;
//# sourceMappingURL=key-registry.d.ts.map
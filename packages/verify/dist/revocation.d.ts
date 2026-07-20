export declare const REVOCATION_VERSION = "EP-REVOCATION-v1";
export type RevocationTargetType = 'receipt' | 'commit' | 'delegation';
export interface RevocationTarget {
    target_type: RevocationTargetType;
    target_id: string;
    action_hash: string;
}
export interface RevocationProof {
    algorithm?: unknown;
    revoker_key_id?: unknown;
    signature_b64u?: unknown;
    public_key?: unknown;
    [key: string]: unknown;
}
export interface RevocationStatement {
    '@version'?: unknown;
    target_type?: unknown;
    target_id?: unknown;
    action_hash?: unknown;
    revoker_id?: unknown;
    revoked_at?: unknown;
    reason?: unknown;
    proof?: RevocationProof | null;
    [key: string]: unknown;
}
export interface RevocationOptions {
    revokerKeys?: Record<string, {
        public_key?: string;
        key_id?: string;
    }>;
    maxAgeSeconds?: number;
    now?: number | string | Date;
}
/**
 * @param {{target_type:string, target_id:string, action_hash:string}} target
 *   the authorization the relying party HOLDS and wants to know the status of.
 * @param {object} statement  the presented EP-REVOCATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.revokerKeys]  pinned keys by revoker_id.
 * @param {number} [opts.maxAgeSeconds]  DEPRECATED and ignored. Terminal
 *   revocations do not age out; freshness belongs to separate status evidence.
 * @param {number|string|Date} [opts.now]  decision time used to reject a
 *   revocation whose effective instant is still in the future.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export declare function verifyRevocation(target: RevocationTarget | null | undefined, statement: RevocationStatement | null | undefined, opts?: RevocationOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
};
/**
 * Convenience: is `target` revoked by ANY of the presented statements? Fail-open
 * on an EMPTY list is the relying party's hazard (absence != not-revoked); this
 * only answers "do these statements revoke it?".
 */
export declare function isRevoked(target: RevocationTarget | null | undefined, statements: RevocationStatement[] | unknown, opts?: RevocationOptions): boolean;
//# sourceMappingURL=revocation.d.ts.map
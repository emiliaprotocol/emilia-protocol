interface QuorumContext {
    approver?: unknown;
    action_hash?: unknown;
    issued_at?: unknown;
    initiator?: unknown;
    prev_context_hash?: unknown;
    prev_signoff_hash?: unknown;
    [key: string]: unknown;
}
interface QuorumMember {
    role?: unknown;
    approver_public_key?: unknown;
    signoff?: {
        context?: QuorumContext;
        [key: string]: unknown;
    } | null;
    [key: string]: unknown;
}
interface QuorumPolicy {
    mode?: unknown;
    required?: unknown;
    approvers?: Array<{
        role?: unknown;
        approver?: unknown;
    }>;
    distinct_humans?: unknown;
    window_sec?: unknown;
    ordered_chain?: unknown;
    ordered_chain_profile?: unknown;
    /**
     * HYBRID HUMAN AUTHORIZATION (opt-in, absent = OFF). See the module header.
     * Each counted approver must produce a valid signoff under EVERY algorithm
     * named here, from a separately enrolled credential.
     */
    required_algorithms?: unknown;
    [key: string]: unknown;
}
interface QuorumDocument {
    policy?: QuorumPolicy | null;
    members?: QuorumMember[];
    action_hash?: unknown;
    [key: string]: unknown;
}
interface MemberResult {
    approver: unknown;
    role: unknown;
    valid: boolean;
}
export declare const SIGNOFF_CHAIN_PROFILE = "EP-QUORUM-SIGNOFF-CHAIN-v1";
/** Commits to the completed native signoff, including its signature bytes.
 * Unlike a precomputable context hash, this establishes a dependency on a
 * prior proof. It does not establish trusted wall-clock time or comprehension.
 */
export declare function completedSignoffHash(signoff: unknown): string;
/**
 * @param {object} quorum  EP-QUORUM-v1 document:
 *   {
 *     "@type": "ep.quorum",
 *     action_hash: string,                  // the action the whole quorum authorizes
 *     policy: {
 *       mode: "threshold" | "ordered",
 *       required: number,                   // M; ordered mode admits the first M roster slots
 *       approvers: [{ role: string, approver: string }],  // N eligible (role -> named human)
 *       distinct_humans?: boolean,          // default true
 *       window_sec?: number,                // default 900; max span across signatures
 *     },
 *     members: [{ role: string, approver_public_key: string, signoff: {context, webauthn} }],
 *   }
 * @param {object} [opts]  Per-signer options plus expectedPolicy: the complete
 *   out-of-band policy pin. Without a pin, valid means internal consistency,
 *   not that the artifact met the relying party's required approval floor.
 * @returns {{ valid: boolean, checks: object, members: Array<{approver:string|null, role:string|null, valid:boolean}> }}
 */
export declare function verifyQuorum(quorum: QuorumDocument | null | undefined, opts?: Record<string, unknown>): {
    valid: boolean;
    checks: Record<string, boolean>;
    members: MemberResult[];
    reason?: undefined;
} | {
    valid: boolean;
    checks: Record<string, boolean>;
    members: MemberResult[];
    reason: string;
};
export {};
//# sourceMappingURL=quorum.d.ts.map
interface QuorumContext {
    approver?: unknown;
    action_hash?: unknown;
    issued_at?: unknown;
    initiator?: unknown;
    prev_context_hash?: unknown;
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
/**
 * @param {object} quorum  EP-QUORUM-v1 document:
 *   {
 *     "@type": "ep.quorum",
 *     action_hash: string,                  // the action the whole quorum authorizes
 *     policy: {
 *       mode: "threshold" | "ordered",
 *       required: number,                   // M (threshold mode); ordered requires all listed
 *       approvers: [{ role: string, approver: string }],  // N eligible (role -> named human)
 *       distinct_humans?: boolean,          // default true
 *       window_sec?: number,                // default 900; max span across signatures
 *     },
 *     members: [{ role: string, approver_public_key: string, signoff: {context, webauthn} }],
 *   }
 * @param {object} [opts]  Passed through to each per-signer verify (e.g. { rpId }).
 * @returns {{ valid: boolean, checks: object, members: Array<{approver:string|null, role:string|null, valid:boolean}> }}
 */
export declare function verifyQuorum(quorum: QuorumDocument | null | undefined, opts?: Record<string, unknown>): {
    valid: boolean;
    checks: Record<string, boolean>;
    members: MemberResult[];
};
export {};
//# sourceMappingURL=quorum.d.ts.map
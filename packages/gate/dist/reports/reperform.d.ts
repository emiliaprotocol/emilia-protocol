export declare const REPERFORMANCE_VERSION = "EP-GATE-REPERFORMANCE-v1";
/**
 * Re-perform the evidence: rebuild the chain, re-verify carried cryptographic
 * material, recompute the counts. Async because the chain is rebuilt through
 * the evidence log's own (async) record().
 *
 * The entries MUST be the complete log from genesis (`evidence.all()` or a
 * full export). A partial slice fails the chain (fail closed) because its
 * first link cannot chain from 'genesis'.
 *
 * Chain method — drives evidence.js's REAL verify(), twice over:
 *   1. every supplied entry body (its own seq/prev_hash included, its hash
 *      stripped) is re-recorded into a fresh createEvidenceLog(), which
 *      recomputes the canonical-JSON sha256 for that exact body; a recomputed
 *      hash that differs from the SUPPLIED hash is a tampered/forged entry —
 *      broken from that point;
 *   2. the rebuilt log's own verify() then walks the whole chain, catching
 *      link-level attacks the per-entry recompute cannot (a removed entry, or
 *      an entry rewritten WITH a consistently recomputed hash — its successor's
 *      prev_hash no longer matches).
 *
 * @param {Array<object>} entries  the full evidence log (evidence.all())
 * @param {object} [o]
 * @param {string[]} [o.issuerKeys=[]]  pinned base64url SPKI issuer keys, sourced
 *   by the AUDITOR out of band — never from the entries themselves
 * @param {number|function} [o.now=Date.now]  clock for generated_at (pin for determinism)
 * @param {object} [o.approverKeys={}] auditor-pinned identity-bound approver keys
 * @param {string|null} [o.rpId] bind carried WebAuthn assertions to this relying-party id
 * @param {string[]} [o.allowedOrigins=[]] exact accepted WebAuthn origins
 * @param {object} [o.quorumPolicy] auditor-pinned global organizational quorum rule
 * @param {object} [o.quorumPolicies] action_type -> auditor-pinned quorum rule
 * @returns {Promise<object>} EP-GATE-REPERFORMANCE-v1 document:
 *   { chain: {ok, entries, head}, receipts: {reverified, failed, not_reverifiable},
 *     counts: {allows, denies, replays_blocked, by_action_type}, ... }
 */
export declare function reperformEvidence(entries?: any[], { issuerKeys, approverKeys, now, rpId, allowedOrigins, quorumPolicy, quorumPolicies, }?: {
    issuerKeys?: string[];
    approverKeys?: Record<string, any>;
    now?: number | (() => number);
    rpId?: string | null;
    allowedOrigins?: string[];
    quorumPolicy?: any;
    quorumPolicies?: Record<string, any>;
}): Promise<{
    '@version': string;
    product: string;
    generated_at: string;
    honesty: {
        reperforms: string;
        does_not_establish: string[];
        status: string;
    };
    input: {
        entries_supplied: number;
        issuer_keys_pinned: number;
        approver_keys_pinned: number;
        relying_party_scope_pinned: boolean;
        quorum_policies_pinned: number;
        expects: string;
    };
    chain: {
        broken_at?: number | null | undefined;
        broken_seq?: number | null | undefined;
        reason?: string | undefined;
        ok: boolean;
        entries: number;
        head: string | null;
    };
    receipts: {
        reverified: number;
        failed: {
            hash: string | null;
            reason: string;
        }[];
        not_reverifiable: number;
        no_receipt_presented: number;
    };
    counts: {
        allows: number;
        denies: number;
        replays_blocked: number;
        by_action_type: {};
    };
    integrity_warnings: {
        index: number;
        reason: string;
    }[];
}>;
/**
 * Diff recomputed counts against a reported pack — the auditor's tie-out.
 *
 * Accepts an EP-GATE-USAGE-v1 pack (meterUsage output or the signed-ready
 * buildUsageStatement body) or an EP-GATE-UNDERWRITER-ATTESTATION-v1 pack.
 * Only the OVERLAPPING NUMERIC fields are compared; an unknown pack @version
 * is refused (fail closed), never fuzzily matched. A reported field that is
 * missing or non-numeric is itself a named drift — a stripped pack can never
 * silently match.
 *
 * The comparison is meaningful only when the recomputation ran over exactly
 * the entries the reported pack was built from (same slice, same window);
 * scoping the slice is the auditor's procedure, not this function's.
 *
 * @param {object} recomputed  reperformEvidence() result (or its .counts)
 * @param {object} reportedPack  usage or underwriter pack
 * @returns {{match: boolean, pack_version: string, drift: Array<{field, reported, recomputed}>}}
 */
export declare function compareToReported(recomputed: any, reportedPack: any): {
    match: boolean;
    pack_version: any;
    drift: {
        field: string;
        reported: any;
        recomputed: any;
    }[];
};
declare const _default: {
    REPERFORMANCE_VERSION: string;
    reperformEvidence: typeof reperformEvidence;
    compareToReported: typeof compareToReported;
};
export default _default;
//# sourceMappingURL=reperform.d.ts.map
/**
 * EMILIA Gate — underwriter control attestation (AI-liability loss-run analogue).
 *
 * The artifact an AI-liability underwriter prices premium credit against — the
 * MFA-for-cyber analogue: evidence that a deny-by-default authorization control
 * was IN FORCE and OPERATING over the policy period, computed from the gate's
 * tamper-evident evidence log. Pure function: same entries + same options in,
 * identical JSON out (pin `now` for a byte-stable artifact).
 *
 * HONESTY BOUNDARY (carried inside the artifact): this attests CONTROL
 * OPERATION only. It does not attest the business correctness of any authorized
 * action, and it is not an insurance document until adopted by the carrier.
 * Near-miss / remediation narrative belongs to the broker — the builder emits
 * those fields as null and NEVER fabricates prose.
 *
 * Fail closed: a missing insured or an invalid period is an error, not a guess.
 * Entries that cannot be verified as log records (unparseable time, missing
 * hash, unknown kind, decision without an allow verdict) are EXCLUDED from every
 * attested count and surfaced as integrity_warnings — the attestation never
 * counts what it cannot account for. A zero-activity period is a valid (boring)
 * attestation, not an error.
 */
export declare const UNDERWRITER_ATTESTATION_VERSION = "EP-GATE-UNDERWRITER-ATTESTATION-v1";
/**
 * Build the underwriter attestation over a slice of the evidence log.
 * @param {Array<object>} entries  evidence.all() (or a durable export of it)
 * @param {object} [o]
 * @param {string} [o.insured]           named insured (required)
 * @param {string|null} [o.policyRef]  carrier policy/submission reference (null until bound)
 * @param {string|number} [o.periodStart]  inclusive period start (ISO or epoch ms)
 * @param {string|number} [o.periodEnd]    inclusive period end (ISO or epoch ms)
 * @param {number|Function} [o.now]    clock for generated_at (pin for determinism)
 * @returns {object} EP-GATE-UNDERWRITER-ATTESTATION-v1 document
 */
export declare function buildUnderwriterAttestation(entries?: any[], { insured, policyRef, periodStart, periodEnd, now, }?: {
    insured?: string;
    policyRef?: string | null;
    periodStart?: string | number;
    periodEnd?: string | number;
    now?: number | (() => number);
}): {
    '@version': string;
    product: string;
    generated_at: string;
    insured: string;
    policy_ref: string | null;
    period: {
        start: string;
        end: string;
    };
    honesty: {
        attests: string;
        does_not_attest: string[];
        status: string;
    };
    control_in_force: {
        control: string;
        mode: string;
        statement: string;
        guarded_decisions: number;
        first_decision_at: any;
        last_decision_at: any;
    };
    volume: {
        guarded_decisions: number;
        allowed: number;
        denied: number;
        by_action_family: Record<string, any>;
    };
    denials: {
        total: number;
        rate: number | null;
        reasons: Record<string, any>;
    };
    replay: {
        attempts_blocked: number;
    };
    assurance: {
        required_tier_distribution: Record<string, number>;
        credited_tier_distribution_on_allow: Record<string, number>;
    };
    quorum_usage: {
        hard_action_decisions: number;
        allowed: number;
        denied: number;
    };
    exceptions: {
        uncontrolled_passthroughs: number;
        uncontrolled_actions: any[];
        replay_defense_bypassed: number;
    };
    executions: {
        recorded: number;
        executed: number;
        failed: number;
    };
    narrative: {
        near_misses: null;
        remediation: null;
        completed_by: string;
    };
    evidence: {
        log_entries_supplied: number;
        in_scope: number;
        first_hash: any;
        last_hash: any;
        integrity_warnings: {
            index: number;
            seq: number | null;
            reason: string;
        }[];
    };
};
/**
 * Render the attestation for a submission packet. Refuses any document that is
 * not an EP-GATE-UNDERWRITER-ATTESTATION-v1 — never renders what it cannot
 * vouch the shape of. Narrative fields render exactly as present in the pack
 * (the broker fills them into the JSON); null renders as a placeholder.
 */
export declare function renderMarkdown(pack: any): string;
declare const _default: {
    UNDERWRITER_ATTESTATION_VERSION: string;
    buildUnderwriterAttestation: typeof buildUnderwriterAttestation;
    renderMarkdown: typeof renderMarkdown;
};
export default _default;
//# sourceMappingURL=underwriter.d.ts.map
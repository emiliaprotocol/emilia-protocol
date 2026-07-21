/**
 * EMILIA Gate — auditor control-testing workpaper (ITGC / SOX-shaped).
 *
 * The artifact an external auditor's control test consumes: a pinned population
 * of guarded gate decisions over a period, a deterministic (seed-reproducible,
 * RNG-free) attribute sample, per-item attribute observations tied to named
 * evidence-log fields, and an exception list — computed from the gate's
 * tamper-evident evidence log. Pure function: same entries + same options in,
 * identical JSON out (pin `now` for a byte-stable artifact).
 *
 * HONESTY BOUNDARY (carried inside the artifact): this workpaper SUPPORTS the
 * auditor's control test. It never performs, reviews, or concludes the test —
 * the sign-off fields are ALWAYS emitted null and rendered as blanks for the
 * auditor to complete. A refusal (deny decision) is the deny-by-default control
 * operating as designed and is NOT a control exception.
 *
 * Fail closed: missing client/engagement/control reference, an invalid or
 * inverted period, a non-integer sample size, or a missing sample seed is an
 * error, not a guess. Entries that cannot be verified as log records are
 * EXCLUDED from the population and surfaced as integrity_warnings — the
 * workpaper never samples what it cannot account for. Window is half-open
 * [periodStart, periodEnd): an entry stamped exactly at periodEnd belongs to
 * the NEXT period, so adjacent workpapers never double-count.
 */
type Obj = Record<string, any>;
export declare const AUDIT_WORKPAPER_VERSION = "EP-GATE-AUDIT-WORKPAPER-v1";
/**
 * Mandatory honesty header. Present verbatim in every workpaper and every
 * rendered view; a document without it is not an EP-GATE-AUDIT-WORKPAPER-v1.
 */
export declare const AUDIT_WORKPAPER_HONESTY_NOTICE: string;
/**
 * Refusal treatment is a structural statement of the format, not commentary:
 * a denial is the control WORKING, so it can never be a control exception.
 */
export declare const REFUSAL_TREATMENT: string;
/**
 * The attribute test plan. Each attribute names the evidence-log field(s) the
 * observation is read from, so the auditor can retrace every pass/fail to the
 * underlying record. Missing or malformed evidence FAILS the attribute — an
 * observation the log cannot support is never presumed to pass.
 */
export declare const AUDIT_ATTRIBUTES: {
    id: string;
    name: string;
    evidence_field: string;
    test: string;
}[];
/**
 * Build the control-testing workpaper over a slice of the evidence log.
 *
 * Population = every well-formed guarded decision entry in the half-open
 * window [periodStart, periodEnd). `population_hash` pins the population
 * itself: sha256 over the lexicographically sorted entry hashes, newline-
 * joined — the auditor can recompute it from the listed items.
 *
 * Sampling is deterministic and RNG-free: for each population entry compute
 * sha256(sampleSeed + entry_hash) as lowercase hex; order ascending (ties
 * broken by entry hash); select the first sampleSize entries. Reproducible by
 * the auditor from the same seed and the same population. sampleSize >= the
 * population size selects the full population ("100% examination").
 *
 * @param {Array<object>} entries  evidence.all() (or a durable export of it)
 * @param {object} [o]
 * @param {string} [o.client]       audit client / deploying organization (required)
 * @param {string} [o.engagement]   engagement reference (required)
 * @param {string} [o.controlRef]   control identifier under test (required)
 * @param {string|number} [o.periodStart]  inclusive window start (ISO or epoch ms)
 * @param {string|number} [o.periodEnd]    EXCLUSIVE window end (ISO or epoch ms)
 * @param {number} [o.sampleSize]   positive integer sample size (required)
 * @param {string} [o.sampleSeed]   seed pinning the sample selection (required)
 * @param {number|Function} [o.now=Date.now]  clock for generated_at (pin for determinism)
 * @returns {object} EP-GATE-AUDIT-WORKPAPER-v1 document
 */
export declare function buildAuditWorkpaper(entries?: Obj[], { client, engagement, controlRef, periodStart, periodEnd, sampleSize, sampleSeed, now, }?: {
    client?: string;
    engagement?: string;
    controlRef?: string;
    periodStart?: string | number;
    periodEnd?: string | number;
    sampleSize?: number;
    sampleSeed?: string;
    now?: number | (() => number);
}): {
    '@version': string;
    notice: string;
    client: string | undefined;
    engagement: string | undefined;
    control: {
        ref: string | undefined;
        name: string;
        statement: string;
    };
    period: {
        start: string;
        end: string;
        end_exclusive: boolean;
    };
    generated_at: string;
    population: {
        size: number;
        population_hash: string;
        hash_method: string;
        excluded: {
            outside_window: number;
            not_guarded_passthroughs: number;
            executions: number;
            integrity_warnings: number;
        };
        items: {
            hash: any;
            seq: any;
            at: any;
            action: any;
            allow: any;
            reason: any;
        }[];
    };
    sampling: {
        method: string;
        seed: string | undefined;
        requested_size: number | undefined;
        selected_size: number;
        full_population: boolean;
        basis: string;
        selected: any[];
    };
    attribute_testing: {
        plan: {
            id: string;
            name: string;
            evidence_field: string;
            test: string;
        }[];
        refusal_treatment: string;
        items: {
            hash: any;
            seq: any;
            at: any;
            action: any;
            verdict: string;
            reason: any;
            attributes: {
                id: string;
                name: string;
                evidence_field: string;
                result: string;
                observed: any;
            }[];
        }[];
    };
    exceptions: {
        total: number;
        refusals_are_not_exceptions: string;
        items: Obj[];
    };
    completeness: {
        entries_supplied: number;
        entries_in_window: number;
        population_size: number;
        first_population_hash: any;
        last_population_hash: any;
        chain_head: null;
    };
    integrity_warnings: Obj[];
    conclusion: {
        tested_by: null;
        reviewed_by: null;
        conclusion: null;
    };
};
/**
 * Render the workpaper for the audit file. Refuses any document that is not a
 * verbatim EP-GATE-AUDIT-WORKPAPER-v1: wrong @version, an altered or removed
 * honesty notice, or machine-filled sign-off fields (the format defines them
 * as always-null; a filled conclusion did not come from this module and must
 * never render as an apparently machine-supported conclusion).
 */
export declare function renderMarkdown(pack: any): string;
declare const _default: {
    AUDIT_WORKPAPER_VERSION: string;
    AUDIT_WORKPAPER_HONESTY_NOTICE: string;
    AUDIT_ATTRIBUTES: {
        id: string;
        name: string;
        evidence_field: string;
        test: string;
    }[];
    REFUSAL_TREATMENT: string;
    buildAuditWorkpaper: typeof buildAuditWorkpaper;
    renderMarkdown: typeof renderMarkdown;
};
export default _default;
//# sourceMappingURL=auditor-workpaper.d.ts.map
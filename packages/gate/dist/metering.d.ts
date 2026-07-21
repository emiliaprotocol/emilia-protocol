export declare const USAGE_VERSION = "EP-GATE-USAGE-v1";
/**
 * Meter a billing period over evidence entries.
 *
 * Billable = `kind: 'decision'` entries on GUARDED actions (`not_guarded`
 * pass-throughs are free; execution records are provenance, not enforcement).
 * Window is [periodStart, periodEnd): inclusive start, exclusive end.
 *
 * @param {Array<object>} entries  evidence.all()
 * @param {object} [o]
 * @param {string|number} [o.periodStart]  ISO or ms — required
 * @param {string|number} [o.periodEnd]    ISO or ms — required, >= periodStart
 * @param {number} [o.retentionYearsDefault=6]  applied when an entry states no retention
 * @returns {{'@version':string, protected_actions:number, allows:number, denies:number,
 *   replays_blocked:number, by_action_type:object, by_tier:object,
 *   receipt_years:number, retention_years_default:number, period:object, integrity_warnings:object[]}}
 */
export declare function meterUsage(entries?: any[], { periodStart, periodEnd, retentionYearsDefault, }?: {
    periodStart?: string | number;
    periodEnd?: string | number;
    retentionYearsDefault?: number;
}): {
    '@version': string;
    period: {
        start: string;
        end: string;
        bounds: string;
    };
    protected_actions: number;
    allows: number;
    denies: number;
    replays_blocked: number;
    by_action_type: {};
    by_tier: {};
    receipt_years: number;
    retention_years_default: number;
    integrity_warnings: {
        index: number;
        reason: string;
    }[];
};
/**
 * Build the signed-ready usage statement handed to billing reconciliation.
 * UNSIGNED — the deployer signs it; `content_hash` (sha256 over the canonical
 * JSON of everything else) binds that signature to exactly these numbers.
 * Deterministic: same usage + org → byte-identical statement, regardless of
 * the entry order the usage was metered from.
 * @param {object} usage  a USAGE_VERSION object from meterUsage
 * @param {{ org?: string }} [o]
 */
export declare function buildUsageStatement(usage: any, { org }?: {
    org?: string;
}): {
    content_hash: string;
    '@version': string;
    kind: string;
    org: string;
    period: {
        start: any;
        end: any;
        bounds: string;
    };
    protected_actions: any;
    allows: any;
    denies: any;
    replays_blocked: any;
    by_action_type: {};
    by_tier: {};
    receipt_years: any;
    retention_years_default: any;
    integrity_warning_count: any;
    complete: boolean;
};
declare const _default: {
    meterUsage: typeof meterUsage;
    buildUsageStatement: typeof buildUsageStatement;
    USAGE_VERSION: string;
};
export default _default;
//# sourceMappingURL=metering.d.ts.map
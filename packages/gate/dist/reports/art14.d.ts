/**
 * EMILIA Gate — EU AI Act Article 14 human-oversight evidence pack.
 *
 * Distills a period of the gate's tamper-evident evidence log into the artifact
 * an Article 14 assessment consumes: which named principal authorized which
 * action_type at which verified assurance tier (oversight exercised), which
 * refusals fired and on which failing predicate (interventions), which replay /
 * tamper attempts were blocked, which actions passed OUTSIDE the manifest
 * (uncontrolled-action exceptions), and the coverage ratio of guarded decisions.
 *
 * Pure over the entries (evidence.all() in, pack out); time enters only through
 * the period bounds and the optional `now` (generated_at). Malformed entries are
 * NEVER silently dropped — they are excluded from the tables and surfaced in
 * `integrity_warnings`, so the pack cannot quietly understate what the log holds.
 * The honesty notice is a structural part of the format: renderMarkdown refuses
 * a pack whose notice was altered or removed.
 */
export declare const ART14_PACK_VERSION = "EP-GATE-ART14-PACK-v1";
/**
 * Mandatory honesty header. Present verbatim in every pack and every rendered
 * view; a pack without it is not an EP-GATE-ART14-PACK-v1.
 */
export declare const ART14_HONESTY_NOTICE: string;
export declare function failingPredicate(reason: any): any;
type Art14Options = {
    organization?: string;
    system?: string;
    periodStart?: string | number;
    periodEnd?: string | number;
    now?: number | (() => number);
};
/**
 * Build the Article 14 evidence pack for a reporting period.
 *
 * Window is half-open [periodStart, periodEnd): an entry stamped exactly at
 * periodEnd belongs to the NEXT period, so adjacent packs never double-count.
 * An empty or inverted period is refused, not rendered as a vacuous pack.
 *
 * @param {Array<object>} entries  evidence.all() — decision/execution records
 * @param {object} [o]
 * @param {string} [o.organization]  deployer legal/organizational name
 * @param {string} [o.system]        the AI system this gate guards
 * @param {string|number} [o.periodStart]  inclusive (ISO or epoch ms)
 * @param {string|number} [o.periodEnd]    exclusive (ISO or epoch ms)
 * @param {Function|number} [o.now=Date.now]  clock for generated_at
 * @returns {object} EP-GATE-ART14-PACK-v1
 */
export declare function buildArt14EvidencePack(entries?: Array<Record<string, any>>, { organization, system, periodStart, periodEnd, now, }?: Art14Options): {
    '@version': string;
    notice: string;
    organization: string;
    system: string;
    period: {
        start: string;
        end: string;
    };
    generated_at: string;
    evidence: {
        head: null;
        entries_total: number;
        entries_in_window: number;
        excluded_outside_window: number;
        executions: number;
    };
    oversight_exercised: any[];
    interventions: {
        total: number;
        by_predicate: Record<string, number>;
        entries: Record<string, any>[];
    };
    replay_tamper: {
        replay_blocked: number;
        tamper_blocked: number;
        entries: Record<string, any>[];
    };
    uncontrolled_action_exceptions: {
        total: number;
        entries: Record<string, any>[];
    };
    coverage: {
        decisions_total: number;
        decisions_guarded: number;
        ratio: number | null;
    };
    integrity_warnings: Record<string, any>[];
};
/**
 * Render the pack as the human-readable Markdown view. Refuses any document
 * that is not a verbatim EP-GATE-ART14-PACK-v1 — a missing or edited honesty
 * notice must never render as an apparently-complete report.
 */
export declare function renderMarkdown(pack: any): string;
declare const _default: {
    ART14_PACK_VERSION: string;
    ART14_HONESTY_NOTICE: string;
    buildArt14EvidencePack: typeof buildArt14EvidencePack;
    renderMarkdown: typeof renderMarkdown;
    failingPredicate: typeof failingPredicate;
};
export default _default;
//# sourceMappingURL=art14.d.ts.map
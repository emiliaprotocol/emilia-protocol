// SPDX-License-Identifier: Apache-2.0
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
export const ART14_PACK_VERSION = 'EP-GATE-ART14-PACK-v1';
/**
 * Mandatory honesty header. Present verbatim in every pack and every rendered
 * view; a pack without it is not an EP-GATE-ART14-PACK-v1.
 */
export const ART14_HONESTY_NOTICE = 'This evidence pack SUPPORTS an EU AI Act Article 14 human-oversight assessment. '
    + 'It does not itself constitute, and must not be represented as, Article 14 compliance '
    + 'or a certification of compliance. Counts are derived from the gate\'s tamper-evident '
    + 'evidence log; the identity of principals is as pinned by the deployer, not '
    + 'independently verified by this report.';
// Gate refusal reason -> the named oversight predicate that failed. An unmapped
// reason is surfaced as `unmapped:<reason>` — visible, never genericized away.
const FAILING_PREDICATE_BY_REASON = {
    receipt_required: 'authorization_receipt_present',
    replay_refused: 'one_time_consumption',
    consumption_store_lacks_reserve: 'one_time_consumption',
    assurance_too_low: 'assurance_tier_sufficient',
    unknown_required_tier: 'assurance_tier_sufficient',
    execution_binding_failed: 'execution_binding_intact',
    evidence_log_failed: 'evidence_durably_recorded',
};
const RECEIPT_REJECTED_PREFIX = 'receipt_rejected:';
function oversightKey(principal, action, tier) {
    return JSON.stringify([principal, action, tier]);
}
export function failingPredicate(reason) {
    if (FAILING_PREDICATE_BY_REASON[reason])
        return FAILING_PREDICATE_BY_REASON[reason];
    if (reason.startsWith(RECEIPT_REJECTED_PREFIX)) {
        return `receipt_valid:${reason.slice(RECEIPT_REJECTED_PREFIX.length)}`;
    }
    return `unmapped:${reason}`;
}
const TIER_ORDER = { software: 0, class_a: 1, quorum: 2 };
function toMs(t) {
    if (t == null)
        return null;
    const ms = typeof t === 'number' ? t : Date.parse(t);
    return Number.isFinite(ms) ? ms : null;
}
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
export function buildArt14EvidencePack(entries = [], { organization, system, periodStart, periodEnd, now = Date.now, } = {}) {
    if (!Array.isArray(entries))
        throw new Error('art14: entries must be an array (evidence.all())');
    if (!organization || typeof organization !== 'string')
        throw new Error('art14: organization is required');
    if (!system || typeof system !== 'string')
        throw new Error('art14: system is required');
    const startMs = toMs(periodStart);
    const endMs = toMs(periodEnd);
    if (startMs == null || endMs == null) {
        throw new Error('art14: periodStart and periodEnd must be ISO timestamps or epoch ms');
    }
    if (endMs <= startMs)
        throw new Error('art14: empty or inverted period (periodEnd must be after periodStart)');
    const warnings = [];
    const oversight = new Map(); // principal\0action\0tier -> row
    const interventions = [];
    const replayBlocked = [];
    const tamperBlocked = [];
    const exceptions = [];
    let decisionsTotal = 0;
    let decisionsGuarded = 0;
    let executionsInWindow = 0;
    let inWindow = 0;
    let outsideWindow = 0;
    let head = null;
    entries.forEach((e, index) => {
        const ref = {
            index,
            seq: e && typeof e === 'object' && Number.isInteger(e.seq) ? e.seq : null,
            hash: e && typeof e === 'object' && typeof e.hash === 'string' ? e.hash : null,
        };
        if (!e || typeof e !== 'object' || Array.isArray(e)) {
            warnings.push({ ...ref, problem: 'not_an_object' });
            return;
        }
        // An entry whose timestamp cannot be parsed cannot be placed in ANY period;
        // it is warned, never silently assigned in or out of the window.
        const atMs = toMs(e.at);
        if (atMs == null) {
            warnings.push({ ...ref, problem: 'missing_or_unparseable_at' });
            return;
        }
        if (atMs < startMs || atMs >= endMs) {
            outsideWindow += 1;
            return;
        }
        if (e.kind !== 'decision' && e.kind !== 'execution') {
            warnings.push({ ...ref, problem: 'unknown_kind', kind: e.kind ?? null });
            return;
        }
        if (e.kind === 'execution') {
            inWindow += 1;
            head = ref.hash ?? head;
            executionsInWindow += 1;
            return;
        }
        // A decision record must carry a boolean verdict and a reason; anything
        // else is counted as an integrity warning, not folded into the tables.
        if (typeof e.allow !== 'boolean' || typeof e.reason !== 'string' || e.reason.length === 0) {
            warnings.push({ ...ref, problem: 'malformed_decision' });
            return;
        }
        inWindow += 1;
        head = ref.hash ?? head;
        decisionsTotal += 1;
        const principal = typeof e.subject === 'string' && e.subject ? e.subject : '(unattributed)';
        const action = typeof e.action === 'string' && e.action ? e.action : '(unspecified)';
        if (e.allow) {
            if (e.reason === 'not_guarded') {
                // Passed through OUTSIDE the manifest: no receipt, no human oversight —
                // an exception the assessor must see, not a covered decision.
                exceptions.push({ at: e.at, action, selector: e.selector ?? null, hash: ref.hash });
                return;
            }
            decisionsGuarded += 1;
            const tier = e.have_tier || e.required_tier || 'unknown';
            const key = oversightKey(principal, action, tier);
            const row = oversight.get(key)
                || { principal, action_type: action, assurance_tier: tier, count: 0 };
            row.count += 1;
            oversight.set(key, row);
            return;
        }
        decisionsGuarded += 1;
        const row = {
            at: e.at,
            action,
            principal,
            reason: e.reason,
            failing_predicate: failingPredicate(e.reason),
            receipt_id: e.receipt_id ?? null,
            hash: ref.hash,
        };
        interventions.push(row);
        if (e.reason === 'replay_refused')
            replayBlocked.push(row);
        if (e.reason.startsWith(RECEIPT_REJECTED_PREFIX) || e.reason === 'execution_binding_failed') {
            tamperBlocked.push(row);
        }
    });
    // Deterministic ordering: principal, then action, then tier strength.
    const oversightRows = [...oversight.values()].sort((a, b) => a.principal.localeCompare(b.principal)
        || a.action_type.localeCompare(b.action_type)
        || ((TIER_ORDER[a.assurance_tier] ?? 99) - (TIER_ORDER[b.assurance_tier] ?? 99))
        || a.assurance_tier.localeCompare(b.assurance_tier));
    const byPredicate = {};
    for (const i of interventions)
        byPredicate[i.failing_predicate] = (byPredicate[i.failing_predicate] || 0) + 1;
    const byPredicateSorted = {};
    for (const k of Object.keys(byPredicate).sort())
        byPredicateSorted[k] = byPredicate[k];
    return {
        '@version': ART14_PACK_VERSION,
        notice: ART14_HONESTY_NOTICE,
        organization,
        system,
        period: { start: new Date(startMs).toISOString(), end: new Date(endMs).toISOString() },
        generated_at: new Date(typeof now === 'function' ? now() : now).toISOString(),
        evidence: {
            head, // hash of the last in-window record — ties the pack to a chain state
            entries_total: entries.length,
            entries_in_window: inWindow,
            excluded_outside_window: outsideWindow,
            executions: executionsInWindow,
        },
        oversight_exercised: oversightRows,
        interventions: {
            total: interventions.length,
            by_predicate: byPredicateSorted,
            entries: interventions,
        },
        replay_tamper: {
            replay_blocked: replayBlocked.length,
            tamper_blocked: tamperBlocked.length,
            entries: [...replayBlocked, ...tamperBlocked.filter((t) => t.reason !== 'replay_refused')],
        },
        uncontrolled_action_exceptions: {
            total: exceptions.length,
            entries: exceptions,
        },
        coverage: {
            decisions_total: decisionsTotal,
            decisions_guarded: decisionsGuarded,
            // null (not 0, not 1) when the period holds no decisions: an empty period
            // proves nothing and must not read as either perfect or absent coverage.
            ratio: decisionsTotal > 0 ? decisionsGuarded / decisionsTotal : null,
        },
        integrity_warnings: warnings,
    };
}
/**
 * Table cells must not break the table; the source strings are log-derived.
 * Backslash is escaped FIRST: escaping only the pipe turns a log-derived
 * `a\|b` into `a\\|b`, where the `\\` renders as a literal backslash and
 * leaves the pipe live as a cell delimiter, letting an action or refusal
 * reason split its cell and shift every column after it.
 */
function md(v) {
    return String(v ?? '—')
        .replace(/\\/g, '\\\\')
        .replace(/\|/g, '\\|')
        .replace(/\r?\n/g, ' ');
}
/**
 * Render the pack as the human-readable Markdown view. Refuses any document
 * that is not a verbatim EP-GATE-ART14-PACK-v1 — a missing or edited honesty
 * notice must never render as an apparently-complete report.
 */
export function renderMarkdown(pack) {
    if (!pack || pack['@version'] !== ART14_PACK_VERSION) {
        throw new Error(`art14: renderMarkdown requires an ${ART14_PACK_VERSION} pack`);
    }
    if (pack.notice !== ART14_HONESTY_NOTICE) {
        throw new Error('art14: refusing to render a pack whose honesty notice was altered or removed');
    }
    const L = [];
    L.push('# Article 14 Human-Oversight Evidence Pack');
    L.push('');
    L.push(`> ${pack.notice}`);
    L.push('');
    L.push(`- **Format:** ${ART14_PACK_VERSION}`);
    L.push(`- **Organization:** ${md(pack.organization)}`);
    L.push(`- **System:** ${md(pack.system)}`);
    L.push(`- **Period:** ${pack.period.start} — ${pack.period.end} (end exclusive)`);
    L.push(`- **Generated:** ${pack.generated_at}`);
    L.push(`- **Evidence head:** ${md(pack.evidence.head)} (${pack.evidence.entries_in_window} record(s) in window, ${pack.evidence.excluded_outside_window} outside)`);
    L.push('');
    L.push('## Oversight exercised');
    if (pack.oversight_exercised.length === 0) {
        L.push('');
        L.push('No authorized guarded actions in this period.');
    }
    else {
        L.push('');
        L.push('| Principal | Action type | Assurance tier | Authorizations |');
        L.push('| --- | --- | --- | ---: |');
        for (const r of pack.oversight_exercised) {
            L.push(`| ${md(r.principal)} | ${md(r.action_type)} | ${md(r.assurance_tier)} | ${r.count} |`);
        }
    }
    L.push('');
    L.push('## Interventions (refusals)');
    if (pack.interventions.total === 0) {
        L.push('');
        L.push('No refusals in this period.');
    }
    else {
        L.push('');
        L.push('| At | Action | Principal | Failing predicate | Reason |');
        L.push('| --- | --- | --- | --- | --- |');
        for (const r of pack.interventions.entries) {
            L.push(`| ${md(r.at)} | ${md(r.action)} | ${md(r.principal)} | ${md(r.failing_predicate)} | ${md(r.reason)} |`);
        }
    }
    L.push('');
    L.push('## Replay / tamper attempts blocked');
    L.push('');
    L.push(`- Replay attempts blocked: **${pack.replay_tamper.replay_blocked}**`);
    L.push(`- Tamper attempts blocked: **${pack.replay_tamper.tamper_blocked}**`);
    L.push('');
    L.push('## Uncontrolled-action exceptions');
    if (pack.uncontrolled_action_exceptions.total === 0) {
        L.push('');
        L.push('None — every decision in this period was for a manifest-guarded action.');
    }
    else {
        L.push('');
        L.push(`${pack.uncontrolled_action_exceptions.total} action(s) passed through OUTSIDE the manifest (no receipt required, no oversight exercised):`);
        L.push('');
        L.push('| At | Action |');
        L.push('| --- | --- |');
        for (const r of pack.uncontrolled_action_exceptions.entries) {
            L.push(`| ${md(r.at)} | ${md(r.action)} |`);
        }
    }
    L.push('');
    L.push('## Coverage');
    L.push('');
    if (pack.coverage.ratio === null) {
        L.push('No decisions recorded in this period — coverage is indeterminate, not 100%.');
    }
    else {
        L.push(`${pack.coverage.decisions_guarded} of ${pack.coverage.decisions_total} decision(s) were manifest-guarded — coverage ratio **${pack.coverage.ratio.toFixed(4)}**.`);
    }
    L.push('');
    L.push('## Integrity warnings');
    if (pack.integrity_warnings.length === 0) {
        L.push('');
        L.push('None.');
    }
    else {
        L.push('');
        L.push(`${pack.integrity_warnings.length} log entr(ies) could not be classified and are EXCLUDED from the tables above:`);
        L.push('');
        L.push('| Index | Seq | Problem |');
        L.push('| ---: | ---: | --- |');
        for (const w of pack.integrity_warnings) {
            L.push(`| ${w.index} | ${md(w.seq)} | ${md(w.problem)} |`);
        }
    }
    L.push('');
    return L.join('\n');
}
export default { ART14_PACK_VERSION, ART14_HONESTY_NOTICE, buildArt14EvidencePack, renderMarkdown, failingPredicate };
//# sourceMappingURL=art14.js.map
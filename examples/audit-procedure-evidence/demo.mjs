// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Audit-procedure evidence composition demo.
 *
 * An AI agent performs one real assurance procedure end to end through the
 * repository's evidence machinery: a full-population cash tie-out of three
 * fixture general-ledger cash accounts against fixture bank statements. The
 * run produces five separable artifacts and keeps their claims separate:
 *
 *   AUTHORIZATION  a two-approver quorum receipt over the exact procedure
 *                  scope (EP-RECEIPT-v1, verified under pinned anchors)
 *   ADMISSION      the Gate's own decision to admit that exact procedure,
 *                  once, joined to the authorization by content identity
 *                  (CAID recomputed from the material the Gate observed)
 *   EXECUTION      the execution record of the tie-out, cryptographically
 *                  bound to the admitted decision
 *   SIGN-OFF       a second quorum ceremony dispositioning the exception the
 *                  procedure raised, admitted as its own consequential action
 *   WORKPAPER      a generated, deterministic markdown document mapping every
 *                  artifact to an audit documentation CONCEPT (informative
 *                  mapping only; see the claim boundary in README.md)
 *
 * The tie-out is fail-closed by construction: exactly one reconciling item
 * (a claimed in-transit transfer that appears in neither closing document)
 * cannot be resolved. Its status is INDETERMINATE, the procedure result is
 * EXCEPTIONS-NOTED, completion without a human disposition of the exception
 * is refused with a named reason, and an attempt to launder the item into
 * "resolved" by re-deriving it from the agent's own summary is refused by
 * the origin-label machinery. INDETERMINATE never authorizes anything and is
 * never auto-cleared; the human disposition records the exception, it does
 * not erase it.
 *
 * Determinism: all fixture data, timestamps, and identifiers are fixed. The
 * generated WORKPAPER.md is byte-stable across runs and machines. Receipt
 * signatures and Gate decision hashes are run-bound (fresh conformance keys
 * per process) and are therefore reported on stdout, never embedded in the
 * deterministic workpaper bytes.
 *
 * Status: worked example over fixture data. It is not an audit, it does not
 * produce audit evidence in any legal or professional sense, and it claims
 * no compliance with, satisfaction of, or endorsement by any audit standard.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGate, createEg1Harness, evaluateOriginLabelAssertions, hashCanonical, MemoryConsumptionStore, ORIGIN_LABELS_VERSION, } from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import { computeCaid, verifyCaid } from '../../caid/impl/js/caid.mjs';
export const PROFILE = 'EP-AUDIT-PROCEDURE-EVIDENCE-DEMO-v0.1';
const HERE = dirname(fileURLToPath(import.meta.url));
// Fixed clock for every minted artifact. No Date.now() reaches any output.
const FIXED_NOW_ISO = '2026-08-16T09:00:00.000Z';
const FIXED_NOW_MS = Date.parse(FIXED_NOW_ISO);
const GL = JSON.parse(readFileSync(resolve(HERE, 'fixtures/general-ledger.json'), 'utf8'));
const BANK = JSON.parse(readFileSync(resolve(HERE, 'fixtures/bank-statements.json'), 'utf8'));
const RECON = JSON.parse(readFileSync(resolve(HERE, 'fixtures/reconciling-items.json'), 'utf8'));
const CAID_DEFINITIONS = JSON.parse(readFileSync(resolve(HERE, 'fixtures/caid-definitions.json'), 'utf8')).types;
const CAID_SUITE = 'jcs-sha256';
// ---------------------------------------------------------------------------
// Deterministic money arithmetic (integer cents; fixtures carry 2-decimal
// amount strings; no floating point ever touches a balance).
// ---------------------------------------------------------------------------
function toCents(amount) {
    const m = /^(-?)([0-9]+)\.([0-9]{2})$/.exec(String(amount));
    if (!m)
        throw new Error(`fixture amount is not a 2-decimal string: ${amount}`);
    const sign = m[1] === '-' ? -1 : 1;
    return sign * (Number(m[2]) * 100 + Number(m[3]));
}
function centsToAmount(cents) {
    const sign = cents < 0 ? '-' : '';
    const abs = Math.abs(cents);
    const dollars = Math.floor(abs / 100);
    const rem = String(abs % 100).padStart(2, '0');
    return `${sign}${dollars}.${rem}`;
}
function sha256OfText(text) {
    return `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
}
function requireFound(value, what) {
    if (value === undefined || value === null)
        throw new Error(`missing: ${what}`);
    return value;
}
// ---------------------------------------------------------------------------
// The exact procedure action. The population digest pins the full population
// of reconciling items: dropping, adding, or editing an item changes the
// CAID and therefore breaks the authorization-to-admission join.
// ---------------------------------------------------------------------------
const POPULATION_DIGEST = `sha256:${hashCanonical(RECON.items)}`;
export const PROCEDURE_ACTION = Object.freeze({
    action_type: 'assurance.cash-tie-out.1',
    engagement_id: 'ENG-2026-114',
    entity: 'Meridian Robotics Inc. (fixture entity)',
    period_end: '2026-06-30',
    procedure_id: 'C-2.1',
    procedure: 'Full-population cash tie-out of all general-ledger cash accounts to bank statements at period end, resolving every reconciling item against the closing documents',
    accounts: Object.freeze(['OPER-001', 'PAYR-002', 'RESV-003']),
    population_digest: POPULATION_DIGEST,
});
const PROCEDURE_SELECTOR = Object.freeze({ protocol: 'assurance', tool: 'cash-tie-out' });
const PROCEDURE_PACK = Object.freeze([
    Object.freeze({
        id: 'assurance.cash-tie-out',
        label: 'Cash tie-out procedure',
        action_type: 'assurance.cash-tie-out.1',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: PROCEDURE_SELECTOR.protocol, tool: PROCEDURE_SELECTOR.tool },
        why: 'The results feed an assurance workpaper others rely on. Dual control pins the exact scope the agent may test.',
        execution_binding: {
            required_fields: [
                'action_type',
                'engagement_id',
                'entity',
                'period_end',
                'procedure_id',
                'procedure',
                'accounts',
                'population_digest',
            ],
        },
    }),
]);
const DISPOSITION_SELECTOR = Object.freeze({ protocol: 'assurance', tool: 'exception-disposition' });
const DISPOSITION_PACK_FIELDS = [
    'action_type',
    'engagement_id',
    'procedure_caid',
    'item_id',
    'finding',
    'disposition',
    'follow_up',
    'disposed_at',
];
const DISPOSITION_PACK = Object.freeze([
    Object.freeze({
        id: 'assurance.exception-disposition',
        label: 'Exception disposition',
        action_type: 'assurance.exception-disposition.1',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: DISPOSITION_SELECTOR.protocol, tool: DISPOSITION_SELECTOR.tool },
        why: 'Dispositioning an exception is a consequential act of judgment. It requires named humans, and it never rewrites the procedure result.',
        execution_binding: { required_fields: DISPOSITION_PACK_FIELDS },
    }),
]);
// ---------------------------------------------------------------------------
// The tie-out engine (lab code, deliberately small). Every mechanism claim
// in the output (verification, admission, one-time consumption, execution
// binding, origin-label refusal) comes from the repository implementation;
// the reconciliation arithmetic below is the worked procedure itself.
// ---------------------------------------------------------------------------
function glAccount(accountId) {
    return requireFound(GL.accounts.find((a) => a.account_id === accountId), `GL account ${accountId}`);
}
function bankStatement(accountId) {
    return requireFound(BANK.statements.find((s) => s.account_id === accountId), `bank statement ${accountId}`);
}
function matchLine(lines, ref, absCents) {
    if (!Array.isArray(lines))
        return null;
    const line = lines.find((l) => l.ref === ref && toCents(l.amount) === absCents);
    return line ?? null;
}
/**
 * Full-population resolution: every item is tested against the closing
 * documents; nothing is sampled and nothing is skipped. An item that cannot
 * be evidenced on both required legs is INDETERMINATE with named reasons,
 * never dropped and never assumed.
 */
function resolveItem(item) {
    const absCents = Math.abs(toCents(item.signed_amount));
    const evidence = [];
    const reasons = [];
    if (item.kind === 'deposit_in_transit' || item.kind === 'outstanding_check') {
        const ledger = matchLine(glAccount(item.account_id).entries, item.id, absCents);
        const cleared = matchLine(bankStatement(item.account_id).subsequent_lines, item.id, absCents);
        if (ledger)
            evidence.push(`gl:${item.account_id}:${item.id}`);
        else
            reasons.push(`no_ledger_entry:${item.account_id}:${item.id}`);
        if (cleared)
            evidence.push(`bank-subsequent:${item.account_id}:${item.id}`);
        else
            reasons.push(`no_subsequent_bank_line:${item.account_id}:${item.id}`);
    }
    else if (item.kind === 'bank_charge_not_recorded' || item.kind === 'interest_not_recorded') {
        const bankLine = matchLine(bankStatement(item.account_id).period_lines, item.id, absCents);
        if (bankLine)
            evidence.push(`bank-period:${item.account_id}:${item.id}`);
        else
            reasons.push(`no_period_bank_line:${item.account_id}:${item.id}`);
    }
    else if (item.kind === 'transfer_in_transit') {
        const sourceId = requireFound(item.source_account_id, `source account on ${item.id}`);
        const receiving = matchLine(bankStatement(item.account_id).subsequent_lines, item.id, absCents);
        const sourceLedger = matchLine(glAccount(sourceId).entries, item.id, absCents);
        const sourceBank = matchLine(bankStatement(sourceId).period_lines, item.id, absCents)
            ?? matchLine(bankStatement(sourceId).subsequent_lines, item.id, absCents);
        if (receiving)
            evidence.push(`bank-subsequent:${item.account_id}:${item.id}`);
        else
            reasons.push(`no_subsequent_bank_line:${item.account_id}:${item.id}`);
        if (sourceLedger || sourceBank)
            evidence.push(`source-document:${sourceId}:${item.id}`);
        else
            reasons.push(`no_counterpart_document:${sourceId}:${item.id}`);
    }
    else {
        reasons.push(`unknown_item_kind:${item.kind}`);
    }
    return {
        id: item.id,
        account_id: item.account_id,
        kind: item.kind,
        side: item.side,
        signed_amount: item.signed_amount,
        status: reasons.length === 0 ? 'RESOLVED' : 'INDETERMINATE',
        evidence,
        reasons,
    };
}
export function runTieOut() {
    const items = RECON.items.map(resolveItem);
    const accounts = PROCEDURE_ACTION.accounts.map((accountId) => {
        const gl = glAccount(accountId);
        const bank = bankStatement(accountId);
        const forAccount = items.filter((i) => i.account_id === accountId);
        const sum = (side, statusWanted) => forAccount
            .filter((i) => i.side === side && i.status === statusWanted)
            .reduce((total, i) => total + toCents(i.signed_amount), 0);
        const adjustedBank = toCents(bank.closing_balance) + sum('bank', 'RESOLVED');
        const adjustedGl = toCents(gl.gl_balance) + sum('ledger', 'RESOLVED');
        const residual = adjustedBank - adjustedGl;
        const unresolvedNet = sum('bank', 'INDETERMINATE') - sum('ledger', 'INDETERMINATE');
        return {
            account_id: accountId,
            name: gl.name,
            gl_balance: gl.gl_balance,
            bank_closing_balance: bank.closing_balance,
            adjusted_bank: centsToAmount(adjustedBank),
            adjusted_gl: centsToAmount(adjustedGl),
            residual: centsToAmount(residual),
            // The audit-relevant invariant: any residual is exactly the net of the
            // items the procedure could NOT resolve; nothing is unexplained twice
            // and nothing quietly plugs.
            residual_fully_attributed_to_unresolved_items: residual + unresolvedNet === 0,
            status: residual === 0 ? 'TIES' : 'EXCEPTION-OPEN',
        };
    });
    const exceptions = items.filter((i) => i.status === 'INDETERMINATE');
    return {
        items,
        accounts,
        exceptions,
        items_tested: items.length,
        items_resolved: items.filter((i) => i.status === 'RESOLVED').length,
        result: exceptions.length === 0 ? 'COMPLETE' : 'EXCEPTIONS-NOTED',
    };
}
// ---------------------------------------------------------------------------
// Origin labels over every evidence field the procedure consumed, using the
// closed EP-ORIGIN-LABELS-v1 vocabulary. Client-produced documents are
// counterparty-document; engagement configuration is operator-config;
// computed reconciliation values are derived with derived_from naming every
// contributing base class.
// ---------------------------------------------------------------------------
function throughOriginInput(tieout) {
    const assertions = [
        { path: '/engagement/accounts', label: 'operator-config', derived_from: null, value_digest: null },
        { path: '/engagement/period_end', label: 'operator-config', derived_from: null, value_digest: null },
        { path: '/recon/population', label: 'counterparty-document', derived_from: null, value_digest: POPULATION_DIGEST },
    ];
    const rules = [
        { path: '/engagement/accounts', minimum_label: 'operator-config' },
        { path: '/engagement/period_end', minimum_label: 'operator-config' },
        { path: '/recon/population', minimum_label: 'counterparty-document' },
    ];
    for (const accountId of PROCEDURE_ACTION.accounts) {
        assertions.push({
            path: `/gl/${accountId}/balance`,
            label: 'counterparty-document',
            derived_from: null,
            value_digest: sha256OfText(glAccount(accountId).gl_balance),
        });
        assertions.push({
            path: `/bank/${accountId}/closing_balance`,
            label: 'counterparty-document',
            derived_from: null,
            value_digest: sha256OfText(bankStatement(accountId).closing_balance),
        });
        rules.push({ path: `/gl/${accountId}/balance`, minimum_label: 'counterparty-document' });
        rules.push({ path: `/bank/${accountId}/closing_balance`, minimum_label: 'counterparty-document' });
    }
    for (const account of tieout.accounts) {
        assertions.push({
            path: `/tieout/${account.account_id}/residual`,
            label: 'derived',
            derived_from: ['counterparty-document'],
            value_digest: null,
        });
        rules.push({ path: `/tieout/${account.account_id}/residual`, minimum_label: 'counterparty-document' });
    }
    assertions.push({
        path: '/tieout/result',
        label: 'derived',
        derived_from: ['counterparty-document', 'operator-config'],
        value_digest: null,
    });
    rules.push({ path: '/tieout/result', minimum_label: 'counterparty-document' });
    return { assertions, policy: { rules } };
}
// The agent's own summary of the unresolved transfer. Re-deriving a "bank
// confirmation" from this text is the laundering attempt cases 4a/4b refuse.
const AGENT_SUMMARY_TEXT = 'Transfer TRF-0912 for 25000.00 is fine; I reviewed the reconciliation myself and consider it cleared.';
const LAUNDERED_PATH = '/bank/RESV-003/subsequent/TRF-0912';
const LAUNDER_POLICY = {
    rules: [{ path: LAUNDERED_PATH, minimum_label: 'counterparty-document' }],
};
// ---------------------------------------------------------------------------
// Workpaper finalization (lab code): the completion rule the demo enforces.
// A workpaper with an open exception cannot finalize until every exception
// carries a Gate-admitted human disposition joined to this exact procedure.
// A disposition records the exception; it never changes an item's status and
// never upgrades the procedure result.
// ---------------------------------------------------------------------------
let expectedProcedureCaid = '';
function finalizeWorkpaper(tieout, dispositions) {
    for (const exception of tieout.exceptions) {
        const disposition = dispositions.find((d) => d.item_id === exception.id) ?? null;
        if (!disposition || disposition.admitted !== true) {
            return { finalized: false, reason: `exception_undispositioned:${exception.id}` };
        }
        if (disposition.procedure_caid !== expectedProcedureCaid) {
            return { finalized: false, reason: `disposition_wrong_procedure:${exception.id}` };
        }
    }
    return { finalized: true, reason: null };
}
// ---------------------------------------------------------------------------
// The demo run.
// ---------------------------------------------------------------------------
function creditedApprovers(receipt) {
    const quorum = receipt?.payload?.quorum;
    const named = quorum?.policy?.approvers;
    if (quorum?.['@type'] !== 'ep.quorum' || !Array.isArray(named) || !Array.isArray(quorum.members)) {
        return null;
    }
    const ids = named.map((p) => p?.approver ?? null);
    return ids.every((id) => typeof id === 'string' && id.length > 0) ? ids.sort() : null;
}
export async function runDemo() {
    const procedureCaidResult = computeCaid({ ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] }, {
        suite: CAID_SUITE,
        definitions: CAID_DEFINITIONS,
    });
    if (!('caid' in procedureCaidResult) || typeof procedureCaidResult.caid !== 'string') {
        throw new Error(`procedure CAID refused: ${JSON.stringify(procedureCaidResult)}`);
    }
    const procedureCaid = procedureCaidResult.caid;
    const procedureCaidDigest = String(procedureCaidResult.digest ?? '');
    const actionHash = hashCanonical(PROCEDURE_ACTION);
    expectedProcedureCaid = procedureCaid;
    const DISPOSITION_ACTION = Object.freeze({
        action_type: 'assurance.exception-disposition.1',
        engagement_id: PROCEDURE_ACTION.engagement_id,
        procedure_caid: procedureCaid,
        item_id: 'TRF-0912',
        finding: 'Claimed in-transit transfer of 25000.00 into RESV-003 appears in neither closing document: no subsequent credit on the Coastal Trust statement and no counterpart entry or line for the operating account.',
        disposition: 'exception_noted',
        follow_up: 'Confirm the transfer instruction directly with both banks and reperform the tie-out for RESV-003 on receipt of the confirmations.',
        disposed_at: '2026-08-16T09:30:00Z',
    });
    const dispositionCaidResult = computeCaid({ ...DISPOSITION_ACTION }, {
        suite: CAID_SUITE,
        definitions: CAID_DEFINITIONS,
    });
    if (!('caid' in dispositionCaidResult) || typeof dispositionCaidResult.caid !== 'string') {
        throw new Error(`disposition CAID refused: ${JSON.stringify(dispositionCaidResult)}`);
    }
    const dispositionCaid = dispositionCaidResult.caid;
    const procedureHarness = createEg1Harness({
        action: { ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] },
        idPrefix: 'audit',
        now: () => FIXED_NOW_MS,
    });
    const signoffHarness = createEg1Harness({
        action: { ...DISPOSITION_ACTION },
        idPrefix: 'auditsig',
        now: () => FIXED_NOW_MS,
    });
    const procedureGate = createGate({
        manifest: manifestFromPack([...PROCEDURE_PACK]),
        trustedKeys: [procedureHarness.publicKey],
        approverKeys: procedureHarness.approverKeys,
        rpId: procedureHarness.rpId,
        allowedOrigins: procedureHarness.allowedOrigins,
        quorumPolicy: procedureHarness.quorumPolicy,
        store: new MemoryConsumptionStore(),
        allowEphemeralStore: true, // worked example; production requires durable shared state
        now: () => FIXED_NOW_MS, // fixed clock so the fixed-timestamp receipts stay in window
    });
    const signoffGate = createGate({
        manifest: manifestFromPack([...DISPOSITION_PACK]),
        trustedKeys: [signoffHarness.publicKey],
        approverKeys: signoffHarness.approverKeys,
        rpId: signoffHarness.rpId,
        allowedOrigins: signoffHarness.allowedOrigins,
        quorumPolicy: signoffHarness.quorumPolicy,
        store: new MemoryConsumptionStore(),
        allowEphemeralStore: true,
        now: () => FIXED_NOW_MS,
    });
    const cases = [];
    const dispositions = [];
    let tieout = null;
    let procedureExecutions = 0;
    let dispositionExecutions = 0;
    // 1. AUTHORIZATION -> ADMISSION -> EXECUTION for the exact procedure.
    //    Two named approvers authorize the exact scope; the receipt claim also
    //    names the procedure CAID. The Gate recomputes the action identity from
    //    the material IT observes; the CAID recomputed from that same observed
    //    material equals the authorized one, which is the join.
    {
        const receipt = procedureHarness.mint({
            outcome: 'allow_with_signoff',
            quorum: { threshold: 2 },
            extra: { caid: procedureCaid },
        });
        const outcome = await procedureGate.run({ selector: { ...PROCEDURE_SELECTOR }, receipt, observedAction: { ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] } }, async () => {
            procedureExecutions += 1;
            tieout = runTieOut();
            return { result: tieout.result, items_tested: tieout.items_tested };
        });
        if (!outcome.ok || tieout === null)
            throw new Error('through-case did not admit');
        // One approval is one admission: presenting the consumed receipt again
        // is refused by the boundary's own ledger and the effect does not rerun.
        const replay = await procedureGate.run({ selector: { ...PROCEDURE_SELECTOR }, receipt, observedAction: { ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] } }, async () => {
            procedureExecutions += 1;
            return { result: 'should-never-rerun' };
        });
        const admission = outcome.authorization;
        const observedHash = admission.evidence?.observed_action_hash ?? null;
        const caidRecheck = verifyCaid({ ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] }, procedureCaid, { definitions: CAID_DEFINITIONS });
        cases.push({
            id: 'procedure-authorized-admitted-executed',
            title: 'Partner quorum authorizes the exact scope; the Gate admits it once (a replay of the consumed receipt is refused); the tie-out runs and reports exceptions instead of completing silently',
            authorization: {
                verdict: 'proven',
                receipt_id: receipt.payload.receipt_id,
                approvers: creditedApprovers(receipt),
                names_caid: receipt.payload.claim.caid === procedureCaid,
            },
            admission: {
                verdict: 'admitted',
                reason: admission.reason ?? null,
                replay_refused: {
                    allow: replay.ok === true,
                    reason: replay.ok ? null : (replay.authorization?.reason ?? null),
                },
                caid_join: {
                    caid: procedureCaid,
                    observed_action_hash_matches_authorized_action: observedHash === actionHash,
                    caid_digest_matches_observed_action_hash: procedureCaidDigest === `sha256:${observedHash}`,
                    caid_recomputes_from_observed_action: caidRecheck.valid === true,
                },
            },
            execution: {
                verdict: 'executed',
                effect_ran: procedureExecutions === 1,
                bound_to_admitted_decision: typeof outcome.execution?.authorizes_decision === 'string'
                    && outcome.execution.authorizes_decision === outcome.packet?.summary?.decision_hash,
                procedure_result: tieout.result,
                items_tested: tieout.items_tested,
                items_resolved: tieout.items_resolved,
                exceptions: tieout.exceptions.map((e) => e.id),
            },
            boundary_reason: null,
        });
    }
    const settledTieout = requireFound(tieout, 'tie-out result');
    // 2. Origin labels over every evidence field the procedure consumed.
    {
        const evaluated = evaluateOriginLabelAssertions(throughOriginInput(settledTieout));
        cases.push({
            id: 'origin-labels-admitted',
            title: 'Every fixture field carries a closed-vocabulary origin label; the assertion set satisfies the policy floors',
            origin_labels: {
                verdict: evaluated.admitted === true ? 'admitted' : 'refused',
                reason: evaluated.reason ?? null,
                vocabulary: ORIGIN_LABELS_VERSION,
                label_count: Object.keys(evaluated.floors ?? {}).length,
                floors: evaluated.floors ?? null,
            },
            boundary_reason: evaluated.reason ?? null,
        });
    }
    // 3. Completion without human disposition is refused, and the agent cannot
    //    self-disposition: the sign-off boundary demands a ceremony.
    {
        const premature = finalizeWorkpaper(settledTieout, dispositions);
        const agentAttempt = await signoffGate.run({ selector: { ...DISPOSITION_SELECTOR }, receipt: null, observedAction: { ...DISPOSITION_ACTION } }, async () => {
            dispositionExecutions += 1;
            return { dispositioned: true };
        });
        cases.push({
            id: 'completion-without-disposition-refused',
            title: 'The workpaper will not finalize over an open exception, and a disposition without human evidence is refused by name',
            finalization: { verdict: 'refused', reason: premature.reason },
            agent_self_disposition: {
                verdict: agentAttempt.ok ? 'admitted' : 'refused',
                reason: agentAttempt.ok ? null : (agentAttempt.authorization?.reason ?? null),
                effect_ran: dispositionExecutions !== 0,
            },
            boundary_reason: premature.reason,
        });
    }
    // 4. The laundering attempt. The agent re-derives the missing bank
    //    confirmation from its own summary. 4a labels it honestly and fails
    //    the policy floor; 4b relabels it counterparty-document while the
    //    honest twin assertion still names the same value digest, and the
    //    cross-path consistency check refuses the upgrade.
    {
        const honest = evaluateOriginLabelAssertions({
            assertions: [
                {
                    path: LAUNDERED_PATH,
                    label: 'derived',
                    derived_from: ['model-generated'],
                    value_digest: sha256OfText(AGENT_SUMMARY_TEXT),
                },
            ],
            policy: LAUNDER_POLICY,
        });
        const laundered = evaluateOriginLabelAssertions({
            assertions: [
                {
                    path: '/agent/notes/TRF-0912-summary',
                    label: 'derived',
                    derived_from: ['model-generated'],
                    value_digest: sha256OfText(AGENT_SUMMARY_TEXT),
                },
                {
                    path: LAUNDERED_PATH,
                    label: 'counterparty-document',
                    derived_from: null,
                    value_digest: sha256OfText(AGENT_SUMMARY_TEXT),
                },
            ],
            policy: LAUNDER_POLICY,
        });
        cases.push({
            id: 'origin-label-laundering-refused',
            title: 'Re-deriving the unresolved item from the agent\'s own summary cannot mark it resolved: the honest label fails the floor, the relabel trips the value-consistency check',
            honest_derivation: { verdict: honest.admitted === true ? 'admitted' : 'refused', reason: honest.reason ?? null },
            laundered_relabel: { verdict: laundered.admitted === true ? 'admitted' : 'refused', reason: laundered.reason ?? null },
            item_status_after: requireFound(settledTieout.items.find((i) => i.id === 'TRF-0912'), 'TRF-0912').status,
            boundary_reason: laundered.reason ?? null,
        });
    }
    // 5. Scope substitution. The authorization is real; the observed procedure
    //    is not the authorized one. Consent to scope X is not consent to
    //    scope Y, and the CAID no longer recomputes.
    {
        const receipt = procedureHarness.mint({
            outcome: 'allow_with_signoff',
            quorum: { threshold: 2 },
            extra: { caid: procedureCaid },
        });
        const substituted = { ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts], period_end: '2026-07-31' };
        const before = procedureExecutions;
        const outcome = await procedureGate.run({ selector: { ...PROCEDURE_SELECTOR }, receipt, observedAction: substituted }, async () => {
            procedureExecutions += 1;
            return { result: 'should-never-run' };
        });
        const recheck = verifyCaid(substituted, procedureCaid, { definitions: CAID_DEFINITIONS });
        cases.push({
            id: 'scope-substitution-refused',
            title: 'The period end changed between authorization and execution; the exact-scope binding refuses and the CAID no longer recomputes',
            authorization: { verdict: 'proven_for_different_scope' },
            admission: {
                verdict: outcome.ok ? 'admitted' : 'refused',
                reason: outcome.ok ? null : (outcome.authorization?.reason ?? null),
            },
            execution: { verdict: 'not_entered', effect_ran: procedureExecutions !== before },
            caid_join: { caid_recomputes_from_observed_action: recheck.valid, reasons: recheck.reasons },
            boundary_reason: outcome.ok ? null : (outcome.authorization?.reason ?? null),
        });
    }
    // 6. The human sign-off ceremony dispositions the exception (a real
    //    two-approver quorum over the disposition action, admitted once by its
    //    own boundary), and only then does the workpaper finalize. The item
    //    stays INDETERMINATE and the result stays EXCEPTIONS-NOTED: the
    //    disposition records the exception, it does not clear it.
    {
        const receipt = signoffHarness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } });
        const outcome = await signoffGate.run({ selector: { ...DISPOSITION_SELECTOR }, receipt, observedAction: { ...DISPOSITION_ACTION } }, async () => {
            dispositionExecutions += 1;
            return { dispositioned: true };
        });
        if (!outcome.ok)
            throw new Error('sign-off ceremony did not admit');
        dispositions.push({
            item_id: DISPOSITION_ACTION.item_id,
            procedure_caid: DISPOSITION_ACTION.procedure_caid,
            disposition: DISPOSITION_ACTION.disposition,
            follow_up: DISPOSITION_ACTION.follow_up,
            disposed_at: DISPOSITION_ACTION.disposed_at,
            receipt_id: receipt.payload.receipt_id,
            approvers: creditedApprovers(receipt),
            admitted: true,
        });
        const finalized = finalizeWorkpaper(settledTieout, dispositions);
        cases.push({
            id: 'signoff-ceremony-dispositions-exception',
            title: 'Two named humans disposition the exception under a verifiable ceremony; the workpaper finalizes with the exception recorded, not erased',
            signoff: {
                verdict: 'proven',
                receipt_id: receipt.payload.receipt_id,
                approvers: creditedApprovers(receipt),
                disposition_caid: dispositionCaid,
                joined_to_procedure_caid: DISPOSITION_ACTION.procedure_caid === procedureCaid,
            },
            admission: { verdict: 'admitted', reason: null },
            execution: {
                verdict: 'executed',
                effect_ran: dispositionExecutions === 1,
                bound_to_admitted_decision: typeof outcome.execution?.authorizes_decision === 'string'
                    && outcome.execution.authorizes_decision === outcome.packet?.summary?.decision_hash,
            },
            finalization: { verdict: 'finalized', reason: finalized.reason },
            finalized: finalized.finalized,
            item_status_after: requireFound(settledTieout.items.find((i) => i.id === 'TRF-0912'), 'TRF-0912').status,
            procedure_result_after: settledTieout.result,
            boundary_reason: null,
        });
    }
    // Deterministic case report and digest: identical bytes on every
    // conforming run, on any machine. Run-bound material (signatures, decision
    // hashes, fresh public keys) never enters it.
    const deterministic = {
        '@profile': PROFILE,
        procedure: {
            action: { ...PROCEDURE_ACTION, accounts: [...PROCEDURE_ACTION.accounts] },
            action_hash: actionHash,
            caid: procedureCaid,
        },
        disposition: { action: { ...DISPOSITION_ACTION }, caid: dispositionCaid },
        cases: cases.map((c) => ({
            id: c.id,
            title: c.title,
            boundary_reason: c.boundary_reason ?? null,
        })),
        tieout: {
            result: settledTieout.result,
            items_tested: settledTieout.items_tested,
            items_resolved: settledTieout.items_resolved,
            exceptions: settledTieout.exceptions.map((e) => ({ id: e.id, reasons: e.reasons })),
            accounts: settledTieout.accounts,
        },
    };
    const resultsDigest = `sha256:${hashCanonical(deterministic)}`;
    const workpaper = renderWorkpaper({
        tieout: settledTieout,
        procedureCaid,
        dispositionCaid,
        actionHash,
        dispositions,
        resultsDigest,
        dispositionAction: DISPOSITION_ACTION,
    });
    let committedWorkpaper = null;
    try {
        committedWorkpaper = readFileSync(resolve(HERE, 'WORKPAPER.md'), 'utf8');
    }
    catch {
        committedWorkpaper = null;
    }
    return {
        cases,
        tieout: settledTieout,
        dispositions,
        deterministic,
        results_digest: resultsDigest,
        workpaper,
        workpaper_matches_committed: committedWorkpaper === null ? null : committedWorkpaper === workpaper,
        procedure: { action: PROCEDURE_ACTION, caid: procedureCaid, action_hash: actionHash },
        disposition_action: DISPOSITION_ACTION,
        total_procedure_executions: procedureExecutions,
        total_disposition_executions: dispositionExecutions,
    };
}
// ---------------------------------------------------------------------------
// The workpaper: deterministic bytes, committed beside this file and
// regenerated (and byte-compared) on every run.
// ---------------------------------------------------------------------------
function mdTableRow(cells) {
    return `| ${cells.join(' | ')} |`;
}
function renderWorkpaper({ tieout, procedureCaid, dispositionCaid, actionHash, dispositions, resultsDigest, dispositionAction }) {
    const a = PROCEDURE_ACTION;
    const disposition = dispositions[0] ?? null;
    const lines = [];
    const push = (line = '') => lines.push(line);
    push('<!-- Generated by examples/audit-procedure-evidence/demo.mts. Deterministic bytes: regenerate with `node examples/audit-procedure-evidence/demo.mjs` and the file must not change. -->');
    push('# Workpaper C-2.1: Cash tie-out at 2026-06-30 (fixture engagement)');
    push();
    push('Result: **EXCEPTIONS-NOTED**. 12 reconciling items tested (full population), 11 resolved, 1 indeterminate, dispositioned by human sign-off and carried as an open exception. This document is a demonstration workpaper over fixture data; see the claim boundary at the end.');
    push();
    push('## Procedure identity');
    push();
    push(mdTableRow(['Field', 'Value']));
    push(mdTableRow(['---', '---']));
    push(mdTableRow(['Engagement', a.engagement_id]));
    push(mdTableRow(['Entity', a.entity]));
    push(mdTableRow(['Period end', a.period_end]));
    push(mdTableRow(['Procedure', `${a.procedure_id}: ${a.procedure}`]));
    push(mdTableRow(['Accounts in scope', a.accounts.join(', ')]));
    push(mdTableRow(['Population digest', `\`${a.population_digest}\``]));
    push(mdTableRow(['Procedure CAID', `\`${procedureCaid}\``]));
    push(mdTableRow(['Authorized action hash', `\`sha256:${actionHash}\``]));
    push(mdTableRow(['Results digest', `\`${resultsDigest}\``]));
    push();
    push('## Tie-out by account');
    push();
    push(mdTableRow(['Account', 'GL balance', 'Bank closing', 'Adjusted bank', 'Adjusted GL', 'Residual', 'Status']));
    push(mdTableRow(['---', '---', '---', '---', '---', '---', '---']));
    for (const account of tieout.accounts) {
        push(mdTableRow([
            `${account.account_id} (${account.name})`,
            account.gl_balance,
            account.bank_closing_balance,
            account.adjusted_bank,
            account.adjusted_gl,
            account.residual,
            account.status,
        ]));
    }
    push();
    push('Every residual is fully attributed to named unresolved items; nothing is plugged.');
    push();
    push('## Items tested (full population)');
    push();
    push(mdTableRow(['Item', 'Account', 'Kind', 'Signed amount', 'Status', 'Evidence / reasons']));
    push(mdTableRow(['---', '---', '---', '---', '---', '---']));
    for (const item of tieout.items) {
        const detail = item.status === 'RESOLVED' ? item.evidence.join('; ') : item.reasons.join('; ');
        push(mdTableRow([item.id, item.account_id, item.kind, item.signed_amount, item.status, detail]));
    }
    push();
    push('## Exception and disposition');
    push();
    push(`- **${dispositionAction.item_id}** is INDETERMINATE: ${dispositionAction.finding}`);
    push('- An indeterminate item never authorizes anything and is never auto-cleared. The tie-out reported EXCEPTIONS-NOTED instead of completing, and finalization of this workpaper was refused (\`exception_undispositioned:TRF-0912\`) until a human ceremony dispositioned the exception.');
    if (disposition) {
        push(`- Disposition: \`${disposition.disposition}\` under sign-off receipt \`${disposition.receipt_id}\` (quorum of 2 fixture approvers: ${(disposition.approvers ?? []).join(', ')}), recorded ${disposition.disposed_at}. Follow-up: ${disposition.follow_up}`);
        push(`- The disposition is its own Gate-admitted action, \`${dispositionCaid}\`, joined to this exact procedure by \`procedure_caid\`. It records the exception; the item remains INDETERMINATE and the procedure result remains EXCEPTIONS-NOTED.`);
    }
    push();
    push('## Evidence-to-concept map');
    push();
    push('Each artifact the run produced is mapped to the audit documentation concept it evidences. The concepts are drawn informatively from audit documentation standards such as PCAOB AS 1215, ISA 230, and AICPA SAS No. 142; this table claims no compliance with, satisfaction of, or endorsement by any of them.');
    push();
    push(mdTableRow(['EMILIA artifact', 'Identity in this run', 'Documentation concept it evidences']));
    push(mdTableRow(['---', '---', '---']));
    push(mdTableRow([
        'Authorization receipt (EP-RECEIPT-v1, quorum threshold 2)',
        'receipt `audit_1`, naming the procedure CAID in its signed claim',
        'Who directed the procedure and the exact nature, timing, and extent they authorized',
    ]));
    push(mdTableRow([
        'CAID (canonical action identifier)',
        `\`${procedureCaid}\``,
        'Identification of the specific procedure performed, pinned to its full item population',
    ]));
    push(mdTableRow([
        'Gate admission record',
        'observed-action hash recomputed at the boundary, equal to the authorized action hash and to the CAID digest (run-bound decision hash on stdout)',
        'Evidence that the procedure performed is the one authorized, admitted once',
    ]));
    push(mdTableRow([
        'Execution evidence',
        'execution record bound to the admitted decision (run-bound hashes on stdout)',
        'That the procedure was performed, and its results',
    ]));
    push(mdTableRow([
        'Full-population item table',
        'the Items tested table above; population digest in the procedure identity',
        'Items tested and the extent of testing',
    ]));
    push(mdTableRow([
        'Origin-label evidence (EP-ORIGIN-LABELS-v1)',
        'per-field trust floors over ledger, statement, and derived values',
        'Source and reliability class of the information used as evidence',
    ]));
    push(mdTableRow([
        'INDETERMINATE verdict + EXCEPTIONS-NOTED result',
        'item TRF-0912; account RESV-003 residual -25000.00',
        'Results of the procedure and exceptions noted',
    ]));
    push(mdTableRow([
        'Exception disposition (Gate-admitted action)',
        `receipt \`auditsig_1\`, \`${dispositionCaid}\``,
        'How exceptions were resolved or carried, and by whom',
    ]));
    push(mdTableRow([
        'Sign-off ceremony (quorum evidence)',
        'two per-signer-verifiable approvals over the disposition action',
        'Reviewer identity and date of review (sign-off)',
    ]));
    push();
    push('## Claim boundary and residuals');
    push();
    push('- This is a demonstration of an evidence-chain shape over fixture data. It is not an audit, it does not produce audit evidence in any legal or professional sense, and no audit standard is complied with, satisfied, or implicated.');
    push('- The entity, balances, statements, approver identities, and timestamps are fixtures. The approver identities are conformance-harness identities standing in for an engagement partner and a second reviewer.');
    push('- The bank statement format is a toy. Real statements, cutoff bank statements, and confirmations have structure and provenance this demo does not model.');
    push('- The procedure tests a full population of 12 fixture items; no sampling theory is used or claimed.');
    push('- One procedure only. A real engagement composes many procedures, review layers, and materiality judgments that are out of scope here.');
    push('- Origin labels are producer claims checked for closed vocabulary, internal consistency, and policy floors at admission. A producer that lies consistently and never contradicts itself is not detectable by this mechanism; the laundering case is caught because the honest twin assertion names the same value digest.');
    push('- Receipt signatures, public keys, and Gate decision hashes are regenerated per run (fresh conformance keys) and therefore live on stdout, not in these deterministic bytes. Receipt ids and every timestamp are fixed.');
    push('- One-time admission is scoped to each boundary\'s own consumption ledger in this process.');
    push();
    return `${lines.join('\n')}\n`;
}
// ---------------------------------------------------------------------------
// CLI entry.
// ---------------------------------------------------------------------------
function printDemo(result) {
    const width = 78;
    console.log('='.repeat(width));
    console.log(`Audit-procedure evidence demo ${PROFILE}`);
    console.log('An agent performs a cash tie-out through authorization, admission,');
    console.log('execution evidence, human sign-off, and a generated workpaper.');
    console.log('='.repeat(width));
    console.log(`Procedure: ${PROCEDURE_ACTION.procedure_id} cash tie-out, ${PROCEDURE_ACTION.entity}, period end ${PROCEDURE_ACTION.period_end}`);
    console.log(`CAID: ${result.procedure.caid}`);
    console.log('-'.repeat(width));
    for (const [index, c] of result.cases.entries()) {
        console.log(`${index + 1}. ${c.id}`);
        console.log(`   ${c.title}`);
        if (c.authorization)
            console.log(`   authorization: ${c.authorization.verdict}`);
        if (c.origin_labels)
            console.log(`   origin labels: ${c.origin_labels.verdict} (${c.origin_labels.label_count} labeled paths)`);
        if (c.honest_derivation)
            console.log(`   honest derivation: ${c.honest_derivation.verdict} (${c.honest_derivation.reason})`);
        if (c.laundered_relabel)
            console.log(`   laundered relabel: ${c.laundered_relabel.verdict} (${c.laundered_relabel.reason})`);
        if (c.admission)
            console.log(`   admission: ${c.admission.verdict}${c.admission.reason ? ` (${c.admission.reason})` : ''}`);
        if (c.admission?.replay_refused)
            console.log(`   replay of consumed receipt: refused (${c.admission.replay_refused.reason})`);
        if (c.execution)
            console.log(`   execution: ${c.execution.verdict}`);
        if (c.signoff)
            console.log(`   sign-off: ${c.signoff.verdict} by ${(c.signoff.approvers ?? []).join(', ')}`);
        if (c.finalization)
            console.log(`   finalization: ${c.finalization.verdict}${c.finalization.reason ? ` (${c.finalization.reason})` : ''}`);
        if (c.agent_self_disposition)
            console.log(`   agent self-disposition: ${c.agent_self_disposition.verdict} (${c.agent_self_disposition.reason})`);
        if (c.item_status_after)
            console.log(`   TRF-0912 status after: ${c.item_status_after}`);
        if (c.boundary_reason)
            console.log(`   boundary refusal names: ${c.boundary_reason}`);
    }
    console.log('-'.repeat(width));
    console.log(`Tie-out: ${result.tieout.result}; ${result.tieout.items_resolved}/${result.tieout.items_tested} items resolved; exceptions: ${result.tieout.exceptions.map((e) => e.id).join(', ')}`);
    console.log(`Procedure effect ran ${result.total_procedure_executions} time(s); disposition effect ran ${result.total_disposition_executions} time(s).`);
    console.log(`results_digest: ${result.results_digest}`);
    console.log(`workpaper matches committed bytes: ${result.workpaper_matches_committed}`);
    console.log('The receipt proves approval. Admission, execution, and sign-off are');
    console.log('separate claims with separate evidence, and INDETERMINATE never clears itself.');
    console.log();
}
const isMain = process.argv[1]
    && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
    const result = await runDemo();
    writeFileSync(resolve(HERE, 'WORKPAPER.md'), result.workpaper);
    if (process.argv.includes('--json')) {
        console.log(JSON.stringify(result.deterministic, null, 2));
    }
    else {
        printDemo(result);
    }
    if (result.workpaper_matches_committed === false) {
        console.error('WORKPAPER.md differed from the generated bytes and has been rewritten; commit the regenerated file.');
        process.exitCode = 1;
    }
}

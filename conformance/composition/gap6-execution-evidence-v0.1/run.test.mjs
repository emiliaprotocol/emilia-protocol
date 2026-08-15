// SPDX-License-Identifier: Apache-2.0
// Generated from run.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { EXACT_ACTION, PROFILE, runProfile } from './run.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
describe('Gap 6 execution-evidence composition profile', () => {
    it('separates approval, admission, and execution and matches the committed reference digest', async () => {
        const result = await runProfile();
        const byId = Object.fromEntries(result.cases.map((c) => [c.id, c]));
        // The through-case: named humans, exact action recomputed at the
        // executor, one admission, execution bound to the admitted decision.
        const through = byId['through-exact-human-exact-action-once'];
        expect(through.claims.approval.verdict).toBe('proven');
        expect(through.claims.approval.approvers).toHaveLength(2);
        expect(through.caid_recomputed_at_executor).toBe(true);
        expect(through.claims.execution.effect_ran).toBe(true);
        expect(through.claims.execution.bound_to_admitted_decision).toBe(true);
        // Every refusal names the mechanism that refused, and never executes.
        for (const [id, reason] of [
            ['missing-human-evidence', 'receipt_required'],
            ['fabricated-approval-refused', 'assurance_too_low'],
            ['wrong-approver-refused', 'receipt_rejected:untrusted_or_invalid_signature'],
            ['action-substitution-refused', 'execution_binding_failed'],
            ['replay-refused', 'replay_refused'],
        ]) {
            expect(byId[id].claims.admission.verdict, id).toBe('refused');
            expect(byId[id].boundary_reason, id).toBe(reason);
            expect(byId[id].claims.execution.effect_ran, id).toBe(false);
        }
        // Missing evidence is indeterminate at the approval claim and fail-closed
        // at the boundary; the two are different statements and both are reported.
        expect(byId['missing-human-evidence'].claims.approval.verdict).toBe('indeterminate');
        // Replay: the artifact still verifies; verification is not admission.
        expect(byId['replay-refused'].claims.approval.verdict).toBe('proven');
        // Lost acknowledgement: entered, unknown, committed, and never retried.
        const lost = byId['lost-acknowledgement-indeterminate'];
        expect(lost.claims.execution.verdict).toBe('indeterminate');
        expect(lost.boundary_reason).toBe('effect_attempted_outcome_unknown');
        expect(lost.claims.execution.committed_not_released).toBe(true);
        expect(lost.claims.execution.bound_to_admitted_decision).toBe(true);
        expect(lost.claims.execution.blind_retry.allow).toBe(false);
        expect(lost.claims.execution.blind_retry.reason).toBe('replay_refused');
        // A forged result that binds nothing is not execution evidence.
        const forged = byId['false-execution-claim-rejected'];
        expect(forged.claims.execution.verdict).toBe('claim_not_credited');
        expect(forged.claims.execution.binding_matches).toBe(false);
        // The executor ran exactly four times across the whole profile: the
        // through-case, the unresolved entry, the pre-replay admission, and the
        // false-claim setup. Nothing else reached the effect.
        expect(result.total_executions).toBe(4);
        // Reproduction contract: the deterministic portion hashes to the
        // committed reference digest, on any machine, every run.
        const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
        expect(reference['@profile']).toBe(PROFILE);
        expect(reference.action).toEqual(EXACT_ACTION);
        expect(result.results_digest).toBe(reference.results_digest);
        // And the digest is stable across two in-process runs.
        const second = await runProfile();
        expect(second.results_digest).toBe(result.results_digest);
    });
});

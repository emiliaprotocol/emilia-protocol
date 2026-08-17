// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { PROCEDURE_ACTION, PROFILE, runDemo, runTieOut } from './demo.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

test('audit-procedure evidence demo: composition, refusals, and deterministic workpaper', async () => {
  const result = await runDemo();
  const byId = Object.fromEntries(result.cases.map((c) => [c.id, c]));

  // 1. Authorization, admission, and execution are separate claims that all
  //    hold on the through-case, joined by content identity (CAID).
  const through = byId['procedure-authorized-admitted-executed'];
  assert.equal(through.authorization.verdict, 'proven');
  assert.deepEqual(through.authorization.approvers, [
    'ep:approver:eg1:cfo',
    'ep:approver:eg1:security-officer',
  ]);
  assert.equal(through.authorization.names_caid, true);
  assert.equal(through.admission.verdict, 'admitted');
  assert.equal(through.admission.replay_refused.allow, false);
  assert.equal(through.admission.replay_refused.reason, 'replay_refused');
  assert.equal(through.admission.caid_join.observed_action_hash_matches_authorized_action, true);
  assert.equal(through.admission.caid_join.caid_digest_matches_observed_action_hash, true);
  assert.equal(through.admission.caid_join.caid_recomputes_from_observed_action, true);
  assert.equal(through.execution.verdict, 'executed');
  assert.equal(through.execution.effect_ran, true);
  assert.equal(through.execution.bound_to_admitted_decision, true);

  // The procedure never completes silently: full population tested, one
  // item INDETERMINATE, result EXCEPTIONS-NOTED.
  assert.equal(result.tieout.result, 'EXCEPTIONS-NOTED');
  assert.equal(result.tieout.items_tested, 12);
  assert.equal(result.tieout.items_resolved, 11);
  assert.deepEqual(result.tieout.exceptions.map((e) => e.id), ['TRF-0912']);
  const trf = result.tieout.items.find((i) => i.id === 'TRF-0912');
  assert.ok(trf);
  assert.equal(trf.status, 'INDETERMINATE');
  assert.deepEqual(trf.reasons, [
    'no_subsequent_bank_line:RESV-003:TRF-0912',
    'no_counterpart_document:OPER-001:TRF-0912',
  ]);

  // Arithmetic invariants: two accounts tie exactly, and the third account's
  // residual is fully attributed to the unresolved item, never plugged.
  for (const account of result.tieout.accounts) {
    assert.equal(account.residual_fully_attributed_to_unresolved_items, true, account.account_id);
  }
  const residuals = Object.fromEntries(result.tieout.accounts.map((a) => [a.account_id, a.residual]));
  assert.deepEqual(residuals, { 'OPER-001': '0.00', 'PAYR-002': '0.00', 'RESV-003': '-25000.00' });

  // 2. Origin labels over every consumed evidence field are admitted under
  //    the closed vocabulary and the relying-party policy floors.
  const labels = byId['origin-labels-admitted'];
  assert.equal(labels.origin_labels.verdict, 'admitted');
  assert.equal(labels.origin_labels.label_count, 13);
  assert.equal(labels.origin_labels.floors['/gl/OPER-001/balance'], 'counterparty-document');
  assert.equal(labels.origin_labels.floors['/engagement/accounts'], 'operator-config');
  assert.equal(labels.origin_labels.floors['/tieout/RESV-003/residual'], 'counterparty-document');

  // 3. Completion without a human disposition is refused with a named
  //    reason, and the agent cannot self-disposition past the ceremony.
  const premature = byId['completion-without-disposition-refused'];
  assert.equal(premature.finalization.verdict, 'refused');
  assert.equal(premature.finalization.reason, 'exception_undispositioned:TRF-0912');
  assert.equal(premature.agent_self_disposition.verdict, 'refused');
  assert.equal(premature.agent_self_disposition.reason, 'receipt_required');
  assert.equal(premature.agent_self_disposition.effect_ran, false);

  // 4. Origin-label laundering: an honest re-derivation from the agent's own
  //    summary fails the trust floor, and relabeling the same value digest as
  //    counterparty-document trips cross-path value consistency. The item
  //    stays INDETERMINATE either way.
  const laundering = byId['origin-label-laundering-refused'];
  assert.equal(laundering.honest_derivation.verdict, 'refused');
  assert.equal(
    laundering.honest_derivation.reason,
    'origin_trust_floor_violation:/bank/RESV-003/subsequent/TRF-0912',
  );
  assert.equal(laundering.laundered_relabel.verdict, 'refused');
  assert.equal(
    laundering.laundered_relabel.reason,
    'value_origin_conflict:/bank/RESV-003/subsequent/TRF-0912',
  );
  assert.equal(laundering.item_status_after, 'INDETERMINATE');

  // 5. Scope substitution is refused by the exact-action binding and the
  //    CAID no longer recomputes over the substituted material.
  const substitution = byId['scope-substitution-refused'];
  assert.equal(substitution.admission.verdict, 'refused');
  assert.equal(substitution.boundary_reason, 'execution_binding_failed');
  assert.equal(substitution.execution.effect_ran, false);
  assert.equal(substitution.caid_join.caid_recomputes_from_observed_action, false);
  assert.ok(substitution.caid_join.reasons.includes('digest_mismatch'));

  // 6. The sign-off ceremony dispositions the exception through its own
  //    admitted action, joined to the procedure CAID; only then does the
  //    workpaper finalize, and nothing is cleared retroactively.
  const signoff = byId['signoff-ceremony-dispositions-exception'];
  assert.equal(signoff.signoff.verdict, 'proven');
  assert.deepEqual(signoff.signoff.approvers, [
    'ep:approver:eg1:cfo',
    'ep:approver:eg1:security-officer',
  ]);
  assert.equal(signoff.signoff.joined_to_procedure_caid, true);
  assert.equal(signoff.execution.bound_to_admitted_decision, true);
  assert.equal(signoff.finalized, true);
  assert.equal(signoff.item_status_after, 'INDETERMINATE');
  assert.equal(signoff.procedure_result_after, 'EXCEPTIONS-NOTED');

  // Effects ran exactly once each across all six cases.
  assert.equal(result.total_procedure_executions, 1);
  assert.equal(result.total_disposition_executions, 1);

  // The workpaper is deterministic and matches the committed artifact byte
  // for byte, and its headline counts match the mechanism's own output.
  const committed = readFileSync(resolve(HERE, 'WORKPAPER.md'), 'utf8');
  assert.equal(result.workpaper, committed);
  assert.ok(result.workpaper.includes('12 reconciling items tested (full population), 11 resolved, 1 indeterminate'));
  assert.ok(result.workpaper.includes(result.procedure.caid));
  assert.ok(result.workpaper.includes(result.results_digest));
  assert.ok(result.workpaper.includes('claims no compliance with, satisfaction of, or endorsement by any of them'));
  assert.equal(result.deterministic['@profile'], PROFILE);
  assert.equal(result.deterministic.procedure.action.action_type, PROCEDURE_ACTION.action_type);

  // Deterministic across runs in the same process too.
  const second = await runDemo();
  assert.equal(second.results_digest, result.results_digest);
  assert.equal(second.workpaper, result.workpaper);

  // The tie-out engine alone is pure and stable.
  const tieout = runTieOut();
  assert.equal(tieout.result, 'EXCEPTIONS-NOTED');
  assert.equal(tieout.items_tested, 12);
});

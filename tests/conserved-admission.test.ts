// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import {
  EXACT_ACTION,
  LAB_VERSION,
  runConservedAdmissionLab,
} from '../examples/conserved-admission/demo.mjs';

describe('Conserved-Admission Handoff Lab (DMSC gap-analysis -04 §7.8)', () => {
  it('conserves exclusive admission across the handoff and refuses every 7.8 failure case by name', async () => {
    const result = await runConservedAdmissionLab();

    expect(result['@version']).toBe(LAB_VERSION);
    expect(result.action).toEqual(EXACT_ACTION);

    const byId = Object.fromEntries(result.cases.map((item) => [item.id, item]));

    // The gap, executable: without conserved transfer both gateways admit
    // the same single-use action and the effect runs twice.
    const naive = byId['copy-without-disposal-admits-twice'];
    expect(naive.verdict).toBe('double_admission');
    expect(naive.admissions).toBe(2);
    expect(naive.executions).toEqual({ a: 1, b: 1 });

    // The through-case: dispose-before-enable yields exactly one admission,
    // at B, under B's own anchors; A provably cannot admit afterwards.
    const through = byId['conserved-handoff-admits-once'];
    expect(through.verdict).toBe('admit_once');
    expect(through.admissions).toBe(1);
    expect(through.executions).toEqual({ a: 0, b: 1 });
    expect(through.a.reservation.allow).toBe(true);
    expect(through.a.after_disposal.allow).toBe(false);
    expect(through.a.after_disposal.reason).toBe('replay_refused');
    expect(through.b.allow).toBe(true);
    // Transfer and admission records correlate by shared action digest and
    // handoff id, never by one gateway ingesting the other's verdict.
    expect(through.records.joined_by.same_action_digest).toBe(true);
    expect(through.records.transfer.handoff_id).toBe(through.records.joined_by.handoff_id);
    expect(through.records.transfer.action_hash).toBe(result.action_hash);

    // Every refusal case names the check that refused, and admits nothing.
    for (const [id, reason] of [
      ['duplicate-delivery-refused', 'replay_refused'],
      ['revoked-during-handoff-refused', 'status_revoked'],
      ['material-action-change-refused', 'execution_binding_failed'],
      ['enablement-is-not-evidence', 'receipt_required'],
    ] as const) {
      expect(byId[id].verdict, id).toBe('refuse');
      expect(byId[id].admissions, id).toBe(0);
      expect(byId[id].executions, id).toEqual({ a: 0, b: 0 });
      expect(byId[id].reason, id).toBe(reason);
    }

    // Concurrent presentation at A and B during the handoff: at most one
    // admission regardless of interleaving, because A disposed first.
    const race = byId['concurrent-admission-at-most-once'];
    expect(race.verdict).toBe('admit_once');
    expect(race.admissions).toBe(1);
    expect(race.a.allow).toBe(false);
    expect(race.a.reason).toBe('replay_refused');
    expect(race.b.allow).toBe(true);
    expect(race.executions).toEqual({ a: 0, b: 1 });

    // Lost acknowledgement: nothing admits anywhere, the retry at A refuses,
    // and the handoff closes as unresolved rather than reopening.
    const lost = byId['lost-acknowledgement-closed'];
    expect(lost.verdict).toBe('closed_unresolved');
    expect(lost.admissions).toBe(0);
    expect(lost.executions).toEqual({ a: 0, b: 0 });
    expect(lost.a.allow).toBe(false);
    expect(lost.a.reason).toBe('replay_refused');
    expect(lost.records.reconciliation.outcome).toBe('unresolved_closed');
    expect(lost.records.reconciliation.handoff_id).toBe(lost.records.transfer.handoff_id);

    // Whole-lab execution accounting: the double-admission case contributes
    // one execution per gateway (the demonstrated failure); every conserved
    // case contributes at most one, at B.
    expect(result.executions.a).toBe(1);
    expect(result.executions.b).toBe(3);
  });
});

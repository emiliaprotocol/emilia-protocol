// SPDX-License-Identifier: Apache-2.0
// GET /api/pilot/sandbox/report — the automated observe-mode pilot report.
//
// The deliverable the GovGuard page promises: "log decisions, never block,
// generate the report that shows what would have been blocked." Authenticated
// by the pilot's own key; scoped to that entity's observed actions only. Reads
// the audit events the adapters already write (no separate store) and
// aggregates them into a procurement-ready summary.

import { NextResponse } from 'next/server';
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

// The decision an observe-mode event WOULD have produced in enforce mode.
function effectiveDecision(after) {
  // In observe mode the adapter records observed_decision (the would-be
  // outcome); in enforce/warn the decision itself is authoritative.
  if (after.enforcement_mode === 'observe') {
    return after.observed_decision || after.decision || 'allow';
  }
  return after.decision || 'allow';
}

export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);
    const actorId = authEntityId(auth);

    const supabase = getGuardedClient();
    const { data: events, error } = await supabase
      .from('audit_events')
      .select('after_state, created_at')
      .eq('event_type', 'guard.trust_receipt.created')
      .eq('actor_id', actorId)
      .order('created_at', { ascending: false })
      .limit(1000);

    if (error) {
      logger.error('[pilot/sandbox/report] load failed:', error);
      return epProblem(500, 'report_failed', 'Could not load the report');
    }

    const rows = events || [];
    const summary = {
      total_actions: rows.length,
      would_allow: 0,
      would_require_signoff: 0,
      would_deny: 0,
    };
    const byActionType = {};
    const samples = []; // the riskiest handful, with reasons + action hash

    for (const ev of rows) {
      const a = ev.after_state || {};
      const decision = effectiveDecision(a);
      const at = a.action_type || 'unknown';
      byActionType[at] = byActionType[at] || { total: 0, allow: 0, signoff: 0, deny: 0 };
      byActionType[at].total += 1;

      if (decision === 'deny') {
        summary.would_deny += 1; byActionType[at].deny += 1;
      } else if (decision === 'allow_with_signoff') {
        summary.would_require_signoff += 1; byActionType[at].signoff += 1;
      } else {
        summary.would_allow += 1; byActionType[at].allow += 1;
      }

      if ((decision === 'deny' || decision === 'allow_with_signoff') && samples.length < 20) {
        samples.push({
          action_type: at,
          target_resource_id: a.target_resource_id || null,
          would_have: decision,
          signoff_tier: a.signoff_tier || null,
          amount: a.amount ?? null,
          currency: a.currency ?? null,
          action_hash: a.action_hash || null,
          at: ev.created_at,
        });
      }
    }

    const gated = summary.would_require_signoff + summary.would_deny;
    const headline = summary.total_actions === 0
      ? 'No actions observed yet. Send a few through the gate in observe mode, then refresh.'
      : `Of ${summary.total_actions} observed action(s), ${gated} would have been stopped or held for a named human in enforce mode `
        + `(${summary.would_deny} denied, ${summary.would_require_signoff} held for signoff).`;

    return NextResponse.json({
      pilot_id: actorId,
      mode: 'observe',
      generated_at: new Date().toISOString(),
      headline,
      summary,
      by_action_type: byActionType,
      samples,
      next_step: gated > 0
        ? 'These are the actions that currently execute with no provable human owner. Turn on enforce mode for one action type to require — and prove — that approval.'
        : 'Send your real high-risk action traffic through the adapters in observe mode to populate this report.',
    });
  } catch (err) {
    logger.error('[pilot/sandbox/report] error:', err);
    return epProblem(500, 'internal_error', 'Report generation failed');
  }
}

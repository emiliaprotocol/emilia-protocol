// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — GET /api/identity/principal/[principalId]/delegation-judgment
//
// Returns a principal's delegation judgment score: a measure of how well this
// human chooses and oversees the agents they authorize.
//
// This is a new EP primitive that scores humans, not just machines.
// The question is no longer only "can I trust this agent?" but
// "can I trust the human who authorized it?"

import { NextResponse } from 'next/server';
import { getPrincipal } from '@/lib/ep-ix';
import { getDelegationJudgmentScore } from '@/lib/attribution';
import { EP_ERRORS } from '@/lib/errors';
import { getServiceClient } from '@/lib/supabase';

// Grade thresholds
function computeGrade(score) {
  if (score >= 0.85) return 'excellent';
  if (score >= 0.70) return 'good';
  if (score >= 0.50) return 'fair';
  return 'poor';
}

// Build a plain-English interpretation of the judgment score
function buildInterpretation(judgmentScore, grade, agentsAuthorized, activeAgents, goodOutcomeRate, totalSignals) {
  if (judgmentScore === null || totalSignals === 0) {
    return 'No delegation history yet — this principal has not authorized any agents with recorded outcomes.';
  }

  const pct = Math.round((goodOutcomeRate ?? 0) * 100);
  const signalNoun = totalSignals === 1 ? 'receipt' : 'receipts';

  if (grade === 'excellent') {
    return `Consistently authorizes high-confidence agents with excellent outcomes (${totalSignals} ${signalNoun}, ${pct}% positive).`;
  }

  if (grade === 'good') {
    return `Strong delegation track record — most authorized agents perform reliably (${totalSignals} ${signalNoun}, ${pct}% positive).`;
  }

  if (grade === 'fair') {
    const badAgents = agentsAuthorized - Math.round(agentsAuthorized * (goodOutcomeRate ?? 0));
    if (badAgents > 0) {
      return `Mixed delegation history — ${badAgents} of ${agentsAuthorized} authorized agents have poor behavioral records (${pct}% positive outcomes).`;
    }
    return `Mixed delegation history — ${pct}% of outcomes were positive across ${totalSignals} ${signalNoun}.`;
  }

  // poor
  return `Repeated poor agent choices — only ${pct}% positive outcomes across ${totalSignals} ${signalNoun}. Review authorized agents immediately.`;
}

/**
 * GET /api/identity/principal/[principalId]/delegation-judgment
 *
 * Returns the principal's delegation judgment score and breakdown.
 * No auth required — public, for trust evaluation purposes.
 */
export async function GET(request, { params }) {
  try {
    const { principalId } = await params;

    // Verify the principal exists
    const principalResult = await getPrincipal(principalId);
    if (principalResult.error) {
      return EP_ERRORS.NOT_FOUND('Principal');
    }

    const supabase = getServiceClient();

    // Fetch judgment score from attribution library
    const judgment = await getDelegationJudgmentScore(principalId, supabase);

    // Count delegations for this principal (all-time authorized agents)
    const { count: agentsAuthorized } = await supabase
      .from('delegations')
      .select('agent_entity_id', { count: 'exact', head: true })
      .eq('principal_id', principalId);

    // Count currently active delegations
    const { count: activeAgents } = await supabase
      .from('delegations')
      .select('agent_entity_id', { count: 'exact', head: true })
      .eq('principal_id', principalId)
      .eq('status', 'active')
      .gt('expires_at', new Date().toISOString());

    // Fetch authorized agent entity IDs to compute avgAgentConfidence
    const { data: delegationRows } = await supabase
      .from('delegations')
      .select('agent_entity_id')
      .eq('principal_id', principalId);

    let avgAgentConfidence = null;
    if (delegationRows && delegationRows.length > 0) {
      const agentEntityIds = [...new Set(delegationRows.map(d => d.agent_entity_id))];
      const { data: agentEntities } = await supabase
        .from('entities')
        .select('entity_id, emilia_score')
        .in('entity_id', agentEntityIds);

      if (agentEntities && agentEntities.length > 0) {
        // LEGACY: uses emilia_score (compat_score) as a proxy for agent confidence.
        // This is a display/summary heuristic, NOT a trust-critical decision gate.
        // Trust-critical delegation decisions should use policy evaluation. See §20.
        const scoreSum = agentEntities.reduce((sum, e) => sum + (e.emilia_score ?? 50), 0);
        // Normalize emilia_score (0-100) to 0.0-1.0
        avgAgentConfidence = Math.round((scoreSum / agentEntities.length / 100) * 1000) / 1000;
      }
    }

    // Fetch the last 10 delegation signals for this principal
    const { data: recentSignals } = await supabase
      .from('principal_delegation_signals')
      .select('agent_entity_id, receipt_id, outcome_positive, weight, created_at')
      .eq('principal_id', principalId)
      .order('created_at', { ascending: false })
      .limit(10);

    const judgmentScore = judgment.judgment_score;
    const goodOutcomeRate = judgment.good_outcome_rate;
    const totalSignals = judgment.total_signals;

    const grade = judgmentScore !== null ? computeGrade(judgmentScore) : 'poor';
    const interpretation = buildInterpretation(
      judgmentScore,
      grade,
      agentsAuthorized ?? 0,
      activeAgents ?? 0,
      goodOutcomeRate,
      totalSignals
    );

    return NextResponse.json({
      principalId,
      judgmentScore,
      grade,
      agentsAuthorized: agentsAuthorized ?? 0,
      activeAgents: activeAgents ?? 0,
      goodOutcomeRate,
      avgAgentConfidence,
      recentSignals: recentSignals ?? [],
      interpretation,
      _meta: {
        totalSignals,
        positiveSignals: judgment.positive_signals,
        negativeSignals: judgment.negative_signals,
        _protocol_version: 'EP/1.1-v2',
      },
    });
  } catch (err) {
    console.error('[delegation-judgment] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

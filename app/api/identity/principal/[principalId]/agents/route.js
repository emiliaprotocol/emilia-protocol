// SPDX-License-Identifier: Apache-2.0
// EMILIA Protocol — GET /api/identity/principal/[principalId]/agents
//
// Lists all agents authorized by this principal, drawn from the delegations
// table. Enriches each with the agent's trust profile and outcome summary
// derived from principal_delegation_signals.

import { NextResponse } from 'next/server';
import { getPrincipal } from '@/lib/ep-ix';
import { authenticateRequest } from '@/lib/supabase';
import { EP_ERRORS } from '@/lib/errors';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '../../../../../../lib/logger.js';

/**
 * GET /api/identity/principal/[principalId]/agents
 *
 * Lists all agents this principal has ever authorized, with their trust
 * profiles and per-agent outcome summaries.
 *
 * Auth required — delegation graph (scope, max_value_usd, outcome rates)
 * is sensitive. Only the principal themselves or operators may browse it.
 * Use GET /api/delegations/[id]/verify for public delegation spot-checks.
 */
export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const { principalId } = await params;

    // Only the principal themselves or operators may list their delegation history.
    if (auth.entity.entity_id !== principalId && !auth.entity.is_operator) {
      return EP_ERRORS.FORBIDDEN('You may only view delegation history for your own principal.');
    }

    // Verify the principal exists
    const principalResult = await getPrincipal(principalId);
    if (principalResult.error) {
      return EP_ERRORS.NOT_FOUND('Principal');
    }

    const supabase = getGuardedClient();

    // Fetch all delegations for this principal, most recent first
    const { data: delegations, error: delegationsError } = await supabase
      .from('delegations')
      .select('agent_entity_id, scope, status, max_value_usd, expires_at, created_at')
      .eq('principal_id', principalId)
      .order('created_at', { ascending: false });

    if (delegationsError) {
      logger.error('[principal/agents] delegations query error:', delegationsError.message);
      return EP_ERRORS.INTERNAL();
    }

    if (!delegations || delegations.length === 0) {
      return NextResponse.json({ principalId, agents: [] });
    }

    // Deduplicate agent IDs — a principal may authorize the same agent multiple times
    const uniqueAgentIds = [...new Set(delegations.map(d => d.agent_entity_id))];

    // Batch-fetch entity profiles for all authorized agents
    const { data: entities } = await supabase
      .from('entities')
      .select('entity_id, display_name, entity_type, emilia_score, status')
      .in('entity_id', uniqueAgentIds);

    const entityMap = {};
    if (entities) {
      for (const e of entities) {
        entityMap[e.entity_id] = e;
      }
    }

    // Fetch delegation signals to compute per-agent outcome summaries
    const { data: signals } = await supabase
      .from('principal_delegation_signals')
      .select('agent_entity_id, outcome_positive, weight')
      .eq('principal_id', principalId)
      .in('agent_entity_id', uniqueAgentIds);

    // Index signals by agent entity ID
    const signalsByAgent = {};
    if (signals) {
      for (const s of signals) {
        if (!signalsByAgent[s.agent_entity_id]) {
          signalsByAgent[s.agent_entity_id] = [];
        }
        signalsByAgent[s.agent_entity_id].push(s);
      }
    }

    // Build agent entries — one per unique agent, using the most recent delegation
    const agentMap = {};
    for (const d of delegations) {
      const id = d.agent_entity_id;
      if (!agentMap[id]) {
        agentMap[id] = d; // first = most recent (delegations are ordered desc)
      }
    }

    const agents = uniqueAgentIds.map(agentId => {
      const delegation = agentMap[agentId];
      const entity = entityMap[agentId];
      const agentSignals = signalsByAgent[agentId] || [];

      const totalOutcomes = agentSignals.length;
      const positiveOutcomes = agentSignals.filter(s => s.outcome_positive).length;
      const outcomeRate = totalOutcomes > 0
        ? Math.round((positiveOutcomes / totalOutcomes) * 1000) / 1000
        : null;

      return {
        entity_id: agentId,
        name: entity?.display_name ?? agentId,
        entity_type: entity?.entity_type ?? null,
        // Normalize emilia_score (0-100) to 0.0-1.0 confidence range
        confidence: entity?.emilia_score != null
          ? Math.round((entity.emilia_score / 100) * 1000) / 1000
          : null,
        entity_status: entity?.status ?? null,
        delegated_at: delegation.created_at,
        delegation_status: delegation.status,
        delegation_scope: delegation.scope,
        delegation_expires_at: delegation.expires_at,
        outcome_summary: {
          total_outcomes: totalOutcomes,
          positive_outcomes: positiveOutcomes,
          outcome_rate: outcomeRate,
        },
      };
    });

    return NextResponse.json({ principalId, agents });
  } catch (err) {
    logger.error('[principal/agents] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

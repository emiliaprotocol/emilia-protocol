import { NextResponse } from 'next/server';
import { getServiceClient, authenticateRequest } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/needs/[id]/claim
 *
 * Claim an open need. Trust is evaluated by policy if the need specifies one,
 * or by compatibility score threshold as legacy fallback.
 *
 * Auth: Bearer ep_live_...
 */
export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) {
      return epProblem(401, 'unauthorized', auth.error);
    }

    const { id } = await params;
    const supabase = getServiceClient();

    const { data: need, error: fetchError } = await supabase
      .from('needs')
      .select('*')
      .eq('need_id', id)
      .single();

    if (fetchError || !need) {
      return epProblem(404, 'need_not_found', 'Need not found');
    }

    if (need.status !== 'open') {
      return epProblem(409, 'need_not_open', `Need is ${need.status}, not open`);
    }

    if (need.from_entity_id === auth.entity.id) {
      return epProblem(403, 'self_claim', 'Cannot claim your own need');
    }

    // === TRUST GATE ===
    // If need specifies a trust_policy, evaluate against it (primary path).
    // Uses need.context for context-aware evaluation when available.
    // Otherwise fall back to legacy min_emilia_score threshold.
    if (need.trust_policy) {
      const needContext = need.context && typeof need.context === 'object' ? need.context : null;
      const evaluation = await canonicalEvaluate(auth.entity.id, {
        context: needContext,
        policy: need.trust_policy,
        includeDisputes: false,
        includeEstablishment: true,
      });

      if (evaluation.error) {
        return epProblem(evaluation.status || 404, 'trust_evaluation_failed', evaluation.error);
      }

      const result = evaluation.policyResult;
      // Internal engine still uses .pass; public API exposes this as decision via buildTrustDecision
      if (!result?.pass) {
        return epProblem(403, 'trust_policy_failed', `Trust evaluation failed for policy "${result?.policyName || 'custom'}".`, {
          context_used: evaluation.contextUsed,
          failures: result?.failures || [],
          warnings: result?.warnings || [],
          _hint: 'Build trust through verified receipts from established counterparties.',
        });
      }
    } else if (auth.entity.emilia_score < (need.min_emilia_score || 0)) {
      // LEGACY: raw score threshold fallback. This path exists only for backward
      // compatibility with needs that predate trust_policy adoption. New needs SHOULD
      // always specify a trust_policy. See PROTOCOL-STANDARD.md §20.
      return epProblem(403, 'score_too_low', `Compatibility score (${auth.entity.emilia_score}) below minimum (${need.min_emilia_score}). Build trust through verified receipts.`, {
        _hint: 'For richer trust evaluation, use POST /api/trust/evaluate with a policy.',
        _legacy: true,
      });
    }

    // Check expiry
    if (need.expires_at && new Date(need.expires_at) < new Date()) {
      await supabase
        .from('needs')
        .update({ status: 'expired' })
        .eq('id', need.id);
      return epProblem(410, 'need_expired', 'Need has expired');
    }

    // Atomic claim — only succeeds if status is still 'open'
    const { data: claimed, error: claimError } = await supabase
      .from('needs')
      .update({
        status: 'claimed',
        claimed_by: auth.entity.id,
        claimed_at: new Date().toISOString(),
      })
      .eq('id', need.id)
      .eq('status', 'open') // optimistic lock
      .select()
      .single();

    if (claimError || !claimed) {
      return epProblem(409, 'need_already_claimed', 'Need was already claimed by another entity');
    }

    return NextResponse.json({
      need: {
        need_id: claimed.need_id,
        capability_needed: claimed.capability_needed,
        context: claimed.context,
        input_data: claimed.input_data,
        budget_cents: claimed.budget_cents,
        deadline_ms: claimed.deadline_ms,
        status: claimed.status,
        claimed_at: claimed.claimed_at,
      },
      message: 'Need claimed successfully. Complete it by posting to /api/needs/{id}/complete',
    });
  } catch (err) {
    console.error('Need claim error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

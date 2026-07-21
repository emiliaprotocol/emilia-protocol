import { NextResponse, type NextRequest } from 'next/server';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { getGuardedClient } from '@/lib/write-guard';
import { authenticateRequest } from '@/lib/supabase';
import { isDemoEntity } from '@/lib/demo-entities';
import { logger } from '../../../../lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';

const MAX_EVALUATE_BYTES = 64 * 1024;
const MAX_UNAUTH_DEMO_BYTES = 4096;

let canonicalEvaluate: any, buildTrustDecision: any, passToDecision: any;
try {
  ({ canonicalEvaluate } = await import('@/lib/canonical-evaluator'));
  ({ buildTrustDecision, passToDecision } = await import('@/lib/trust-decision'));
} catch { /* optional deps — federation operators may not have full schema */ }

/**
 * POST /api/trust/evaluate
 *
 * Evaluate an entity against a trust policy with optional context.
 * Full operators route through the canonical evaluator.
 * Federation operators with minimal schema use a simple score-based decision.
 *
 * Body: { entity_id, policy, context }
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const authHeader = request.headers.get('authorization');
    let auth: any = null;

    if (authHeader) {
      auth = await authenticateRequest(request);
      if (auth.error) return EP_ERRORS.UNAUTHORIZED();
    }

    // readLimitedJson's return shape isn't a native TS annotation yet; cast to
    // its documented ok/error union rather than the loosely-inferred one.
    const parsed = (await readLimitedJson(
      request,
      auth ? MAX_EVALUATE_BYTES : MAX_UNAUTH_DEMO_BYTES,
    )) as
      | { ok: true; value: any }
      | { ok: false; status: number; code: string; detail: string };
    if (!parsed.ok) {
      if (!auth) return EP_ERRORS.UNAUTHORIZED();
      return epProblem(parsed.status, parsed.code, parsed.detail);
    }
    const body = parsed.value;

    // Public demo carve-out: only the synthetic demo entity is evaluable
    // without auth. Unauthenticated requests get a tiny bounded parse solely so
    // the demo can keep working; real entities and malformed anonymous probes do
    // not trigger DB-backed evaluation.
    if (!body.entity_id) {
      return auth ? EP_ERRORS.BAD_REQUEST('entity_id is required') : EP_ERRORS.UNAUTHORIZED();
    }
    if (!auth && !isDemoEntity(body.entity_id)) {
      return EP_ERRORS.UNAUTHORIZED();
    }

    // Try full canonical evaluation first
    if (canonicalEvaluate && buildTrustDecision) {
      try {
        const result = await canonicalEvaluate(body.entity_id, {
          context: body.context || null,
          policy: body.policy || 'standard',
          includeDisputes: false,
          includeEstablishment: true,
        });

        if (!result.error) {
          const pr = result.policyResult;
          const pass = pr?.pass ?? null;

          return NextResponse.json(buildTrustDecision({
            decision: pass === null ? 'review' : passToDecision(pass),
            entityId: result.entity_id,
            policyUsed: pr?.policyName || 'standard',
            confidence: result.confidence,
            reasons: pass === false ? ['policy_not_satisfied'] : [],
            warnings: pr?.warnings?.length ? ['review_recommended'] : [],
            contextUsed: result.contextUsed,
            profileSummary: null,
            extensions: { _protocol_version: 'EP/1.1-v2' },
          }));
        }
      } catch { /* fall through to simple evaluation */ }
    }

    // Simple evaluation fallback — works with minimal federation schema
    const supabase = getGuardedClient();
    const { data: entity, error } = await supabase
      .from('entities')
      .select('entity_id, display_name, emilia_score, total_receipts')
      .eq('entity_id', body.entity_id)
      .single();

    if (error || !entity) {
      return EP_ERRORS.NOT_FOUND('Entity');
    }

    const score = entity.emilia_score / 100;
    const depth = entity.total_receipts || 0;
    let decision: string;
    if (depth === 0) decision = 'review';
    // Fail conservative: the fallback path does not have v2 quality-gated
    // evidence, concentration caps, dispute dampening, or software checks. It
    // can guide manual review, but it must never produce an allow decision.
    else if (score >= 0.3) decision = 'review';
    else decision = 'deny';

    return NextResponse.json({
      decision,
      entity_id: entity.entity_id,
      policy_used: body.policy || 'standard',
      confidence: depth === 0 ? 'none' : depth < 5 ? 'low' : depth < 20 ? 'medium' : 'high',
      reasons: decision === 'deny' ? ['policy_not_satisfied'] : [],
      protocol_version: 'EP-CORE-v1.0',
      degraded: true,
      warnings: ['canonical_evaluator_unavailable', ...(depth < 5 ? ['review_recommended'] : [])],
    });
  } catch (err) {
    logger.error('Trust evaluate error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

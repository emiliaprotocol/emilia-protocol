import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { filterByVisibility } from '@/lib/procedural-justice';
import { logger } from '../../../lib/logger.js';

/**
 * GET /api/audit?target_id=...&target_type=...&limit=50
 *
 * Query the append-only audit trail. Operator-level access only.
 * Every trust-changing action is recorded with before/after state.
 *
 * Dual-control actions (entity.suspend, entity.unsuspend, dispute.override,
 * evidence.redact, redaction.manage) are logged with both operator IDs in
 * the audit record's after_state — first_operator_id and second_operator_id —
 * so that the two-person authorization chain is fully auditable.
 */
export async function GET(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    // Enforce operator-level authorization: caller must have audit.view permission.
    // Only check verified permissions from the authenticated API key record.
    // NOTE: x-ep-role header check was removed — it allowed unauthenticated
    // role escalation (HIGH-02 pentest finding).
    const permissions = auth.permissions || [];
    const hasAuditPermission = permissions.includes('audit.view');

    if (!hasAuditPermission) {
      return epProblem(403, 'insufficient_permissions', 'Audit access requires operator role with audit.view permission');
    }

    const url = new URL(request.url);
    const targetId = url.searchParams.get('target_id');
    const targetType = url.searchParams.get('target_type');
    const actorId = url.searchParams.get('actor_id');
    const eventType = url.searchParams.get('event_type');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
    const offset = parseInt(url.searchParams.get('offset') || '0');

    const supabase = getGuardedClient();
    let query = supabase
      .from('audit_events')
      .select('*')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (targetId) query = query.eq('target_id', targetId);
    if (targetType) query = query.eq('target_type', targetType);
    if (actorId) query = query.eq('actor_id', actorId);
    if (eventType) query = query.eq('event_type', eventType);

    const { data, error } = await query;

    if (error) return epProblem(500, 'audit_query_failed', error.message);

    return NextResponse.json({
      events: data || [],
      count: (data || []).length,
      offset,
      limit,
    });
  } catch (err) {
    logger.error('Audit query error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

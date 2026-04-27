// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — GET /api/v1/trust-receipts/[receiptId]/evidence
//
// Returns the full evidence packet for a receipt — assembled from the
// append-only audit_events log. Per MD §7.2, the packet includes:
// receipt id, organization, actor, auth source, action type, before/after
// hashes, policy id+hash, decision, risk flags, signoff requirement,
// approver identity, signoff timestamp, consume timestamp, replay attempts,
// immutable event timeline.
//
// Returns JSON by default. PDF export deferred to a follow-up (the JSON
// shape is the canonical evidence; PDF is a rendering of it).

import { NextResponse } from 'next/server';
import { authenticateRequest, getServiceClient } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';

export async function GET(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const { receiptId } = await params;
    const supabase = getServiceClient();

    const { data: events, error } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, actor_type, action, before_state, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (error) {
      logger.error('[guard] evidence fetch failed:', error);
      return epProblem(500, 'internal_error', 'Failed to load evidence');
    }
    if (!events || events.length === 0) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) {
      return epProblem(500, 'corrupted_receipt', 'Receipt missing creation event');
    }
    const base = created.after_state;

    const signoffEvents = events.filter((e) => e.event_type.startsWith('guard.signoff.'));
    const consumed = events.find((e) => e.event_type === 'guard.trust_receipt.consumed');
    const approved = events.find((e) => e.event_type === 'guard.signoff.approved');
    const rejected = events.find((e) => e.event_type === 'guard.signoff.rejected');
    const replays = events.filter((e) => e.event_type === 'guard.trust_receipt.replay_attempt');

    return NextResponse.json({
      receipt_id: receiptId,
      organization_id: base.organization_id,
      actor: {
        id: created.actor_id,
        type: created.actor_type,
        auth_source: 'authenticated_session',
      },
      action: {
        type: base.action_type,
        action_hash: base.action_hash,
        before_state_hash: base.before_state_hash,
        after_state_hash: base.after_state_hash,
      },
      policy: {
        id: base.policy_id,
        hash: base.policy_hash,
        decision: base.decision,
        enforcement_mode: base.enforcement_mode,
      },
      signoff: {
        required: base.signoff_required,
        approver_id: approved?.actor_id || null,
        approved_at: approved?.created_at || null,
        rejected_at: rejected?.created_at || null,
        events: signoffEvents.map((e) => ({
          event_type: e.event_type,
          actor_id: e.actor_id,
          at: e.created_at,
        })),
      },
      consume: {
        consumed_at: consumed?.after_state?.consumed_at || null,
        consumed_by_system: consumed?.after_state?.consumed_by_system || null,
        execution_reference_id: consumed?.after_state?.execution_reference_id || null,
      },
      replay_attempts: replays.length,
      timeline: events.map((e) => ({
        timestamp: e.created_at,
        event: e.event_type,
        actor_id: e.actor_id,
        action: e.action,
      })),
      issued_at: created.created_at,
      expires_at: base.expires_at,
      // Evidence packet is plaintext JSON for now. PDF export is a rendering
      // concern — the JSON above IS the canonical evidence and is itself
      // tamper-evident via the underlying audit_events immutability triggers.
      format: 'application/json',
      schema_version: 'ep-guard-evidence-v1',
    });
  } catch (err) {
    logger.error('[guard] GET evidence error:', err);
    return epProblem(500, 'internal_error', 'Evidence fetch failed');
  }
}

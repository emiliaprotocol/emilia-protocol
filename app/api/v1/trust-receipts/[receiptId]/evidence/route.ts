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

import { NextRequest, NextResponse } from 'next/server';
import { authenticateGuardRequest, isCloudGuardPrincipal } from '@/lib/guard-auth.js';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { signEvidenceReceipt } from '@/lib/guard-evidence-receipt.js';
import { findBoundSignoffDecision } from '@/lib/guard-signoff-binding.js';
import { buildPortableSignoffDecision } from '@/lib/signoff/decision-evidence.js';
import { canReadReceipt } from '@/lib/tenant-binding';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ receiptId: string }> }
): Promise<NextResponse> {
  try {
    const auth = await authenticateGuardRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);

    const { receiptId } = await params;
    const supabase = getGuardedClient();

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
    if (isCloudGuardPrincipal(auth)) {
      const permissions = Array.isArray(auth.permissions) ? auth.permissions : [];
      const mayReadApproval = permissions.includes('admin')
        || permissions.includes('approval_request');
      if (!mayReadApproval
          || base.action_type !== 'large_payment_release'
          || created.actor_id !== authEntityId(auth)) {
        return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
      }
    }

    // Tenant scoping (IDOR): the evidence packet exposes approver identity,
    // amounts, policy, and the full timeline — scope it to the receipt's org
    // (or, transitionally, its creator). Mismatch => 404.
    if (!canReadReceipt(auth, { organizationId: base.organization_id, creatorActorId: created.actor_id })) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    const signoffEvents = events.filter((e) => e.event_type.startsWith('guard.signoff.'));
    const consumed = events.find((e) => e.event_type === 'guard.trust_receipt.consumed');
    const approved = findBoundSignoffDecision(events, created, 'guard.signoff.approved');
    const rejected = findBoundSignoffDecision(events, created, 'guard.signoff.rejected');
    const replays = events.filter((e) => e.event_type === 'guard.trust_receipt.replay_attempt');
    // A healthy timeline has exactly one terminal decision for a signoff. If a
    // corrupt/imported timeline carries both outcomes, do not choose one.
    const terminalDecisions = [approved, rejected].filter(Boolean);
    const decisionEvidence = terminalDecisions.length === 1
      ? buildPortableSignoffDecision(terminalDecisions[0])
      : null;

    // ── Signed, offline-verifiable receipt (EP-RECEIPT-v1) ───────────────
    // When the receipt has reached a terminal positive state (approved /
    // consumed) AND carries the canonical action it must sign over, mint a
    // signed { document, public_key } pair — the SAME shape the public demo
    // endpoint serves, consumable by @emilia-protocol/verify's verifyReceipt()
    // / examples/grok_guard.py with NO trust in this server. signEvidenceReceipt
    // returns null for any receipt it cannot honestly sign (pending, denied,
    // rejected, expired, or missing signed material); in that case we keep
    // returning the existing unsigned ep-guard-evidence-v1 packet below and
    // fabricate nothing.
    let signed: ReturnType<typeof signEvidenceReceipt> = null;
    try {
      signed = signEvidenceReceipt({
        receiptId,
        base,
        approved: approved || null,
        rejected: rejected || null,
        consumed: consumed || null,
        issuedAt: created.created_at,
      });
    } catch (e) {
      // Never let signing failure break evidence retrieval — degrade to the
      // unsigned packet. Log so SIEM sees a key/material problem.
      logger.warn('[guard] evidence signing failed:', e?.message);
      signed = null;
    }

    return NextResponse.json({
      // When present, these two fields let a relying party verify the receipt
      // OFFLINE — Ed25519 over the canonical EP-RECEIPT-v1 payload — without
      // trusting this endpoint. Absent (null) when the receipt is not yet in a
      // signable state; the rest of the packet remains the tamper-evident
      // audit-log view it has always been.
      document: signed?.document ?? null,
      public_key: signed?.public_key ?? null,
      signed: Boolean(signed),
      verify_with: '@emilia-protocol/verify',
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
        approver_id: (approved || rejected)?.actor_id || null,
        recorded_decision: approved ? 'approved' : (rejected ? 'denied' : null),
        // `decision` is populated only when the terminal outcome is itself
        // present in portable, device-signed evidence. Callers that only need
        // the operator's audit view can inspect recorded_decision explicitly.
        decision: decisionEvidence?.decision || null,
        approved_at: approved?.created_at || null,
        rejected_at: rejected?.created_at || null,
        decision_evidence_signed: Boolean(decisionEvidence),
        // Class-A approvals and denials use the same portable EP-SIGNOFF-v1
        // shape. Verify `decision_evidence.signoff` with an independently
        // pinned approver key; a key carried by the presenter is not authority.
        decision_evidence: decisionEvidence,
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

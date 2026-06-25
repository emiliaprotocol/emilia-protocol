// SPDX-License-Identifier: Apache-2.0
// EP GovGuard + FinGuard — POST /api/v1/trust-receipts/[receiptId]/consume
//
// One-time consume of a trust receipt. Per MD §6.3 and §12.2 invariants:
//   - receipt must exist
//   - receipt must not already be consumed
//   - receipt must not be expired
//   - action_hash at consume MUST match action_hash at issuance
//   - if signoff_required, signoff status must be 'approved'
//
// Idempotency / atomicity is provided by inserting the consume audit event
// inside a single transaction that also checks the prior consume sentinel.

import { NextResponse } from 'next/server';
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { quorumGate } from '@/lib/signoff/quorum-session.js';
import { decisionsToMembers } from '@/lib/signoff/attestation-members.js';
import { getRpConfig } from '@/lib/webauthn.js';
import { boundSignoffDecisionEvents, findBoundSignoffDecision } from '@/lib/guard-signoff-binding.js';
import { resolveGuardAuthority } from '@/lib/guard-authority.js';
import { canReadReceipt } from '@/lib/tenant-binding.js';

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;

export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const { receiptId } = await params;
    if (!RECEIPT_ID_PATTERN.test(receiptId || '')) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }

    const body = await request.json().catch(() => ({}));

    if (!body.action_hash) {
      return epProblem(400, 'missing_action_hash', 'action_hash is required');
    }
    if (!body.executing_system) {
      return epProblem(400, 'missing_executing_system', 'executing_system is required');
    }

    const supabase = getGuardedClient();

    // ── Load full timeline (source of truth) ──────────────────────────────
    const { data: events, error: eventsErr } = await supabase
      .from('audit_events')
      .select('event_type, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (eventsErr) {
      logger.error('[guard] consume: load events failed:', eventsErr);
      return epProblem(500, 'internal_error', 'Failed to load receipt');
    }
    if (!events || events.length === 0) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) {
      return epProblem(500, 'corrupted_receipt', 'Receipt missing creation event');
    }
    const base = created.after_state;

    // Tenant scoping (IDOR): consume is a mutation and must be at least as
    // tightly scoped as read/evidence. An org-bound caller may consume only
    // its own org's receipt; an unbound transitional caller may consume only
    // its own created receipt. Mismatch => 404 to avoid receipt enumeration.
    if (!canReadReceipt(auth, { organizationId: base.organization_id, creatorActorId: created.actor_id })) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    // ── Invariant checks (per MD §12.2) ──────────────────────────────────
    const alreadyConsumed = events.some((e) => e.event_type === 'guard.trust_receipt.consumed');
    if (alreadyConsumed) {
      return epProblem(409, 'receipt_already_consumed', 'Receipt has already been consumed');
    }

    if (new Date(base.expires_at) < new Date()) {
      return epProblem(410, 'receipt_expired', 'Receipt has expired');
    }

    if (base.action_hash !== body.action_hash) {
      return epProblem(
        409,
        'action_hash_mismatch',
        'action_hash at consume does not match action_hash at issuance',
      );
    }

    let authorityFacts = null;

    // A quorum policy always implies a signoff is required, even if the policy
    // decision didn't set signoff_required.
    if (base.signoff_required || base.quorum_policy) {
      const rejected = findBoundSignoffDecision(events, created, 'guard.signoff.rejected');
      if (rejected) {
        return epProblem(403, 'signoff_rejected', 'Receipt signoff was rejected');
      }

      if (base.quorum_policy) {
        // ── Multi-party (EP-QUORUM-v1): require a SATISFIED quorum ──────────
        // Re-verify ALL approvals through the same fail-closed predicate the
        // cross-language conformance suite covers (distinct humans, roles,
        // order, window, action-binding, signatures). The approve route already
        // recorded each assertion; we reconstitute members and gate on them.
        const approvedDecisions = boundSignoffDecisionEvents(events, created, 'guard.signoff.approved')
          .map((e) => e.after_state)
          .filter(Boolean);
        const credentialIds = approvedDecisions
          .map((d) => d.webauthn && d.webauthn.credential_id)
          .filter(Boolean);
        let credsByCredentialId = {};
        if (credentialIds.length > 0) {
          const { data: creds, error: credErr } = await supabase
            .from('approver_credentials')
            .select('credential_id, public_key_spki')
            .in('credential_id', credentialIds);
          if (credErr) {
            logger.error('[guard] consume: credential load failed:', credErr);
            return epProblem(500, 'internal_error', 'Failed to load approver credentials');
          }
          credsByCredentialId = Object.fromEntries(
            (creds || []).map((c) => [c.credential_id, c]),
          );
        }
        const members = decisionsToMembers(base.quorum_policy, approvedDecisions, credsByCredentialId);
        const { rpID } = getRpConfig();
        const gate = quorumGate(base.quorum_policy, base.action_hash, members, { rpId: rpID });
        if (!gate.satisfied) {
          const failed = Object.entries(gate.checks || {})
            .filter(([, v]) => v === false)
            .map(([k]) => k);
          return epProblem(
            403,
            'quorum_not_satisfied',
            `Receipt requires a satisfied multi-party quorum before consume${failed.length ? ` (failing: ${failed.join(', ')})` : ''}`,
          );
        }
      } else {
        const approved = findBoundSignoffDecision(events, created, 'guard.signoff.approved');
        if (!approved) {
          return epProblem(403, 'signoff_required', 'Receipt requires signoff before consume');
        }
        const keyClass = approved.after_state?.key_class || 'C';
        if (base.required_assurance === 'A' && keyClass !== 'A') {
          return epProblem(
            403,
            'insufficient_assurance',
            'Receipt requires a Class-A WebAuthn/passkey signoff before consume',
          );
        }
        // #5 Authority: credentials prove control; the registry proves permission.
        // The approver must hold a valid authority (in-org, in-role, in-window,
        // not revoked, sufficient assurance). Fail closed when no authority is
        // registered too: a credential proves control, not permission.
        const approverId = approved.after_state?.approver_id || approved.actor_id || null;
        const authority = await resolveGuardAuthority(supabase, {
          organizationId: base.organization_id,
          approverId,
          role: approved.after_state?.role,
          requiredAssurance: base.required_assurance || undefined,
          at: new Date().toISOString(),
        });
        if (!authority.authorized) {
          return epProblem(403, 'authority_invalid', `Approver authority check failed: ${authority.reason}`);
        }
        authorityFacts = {
          authority_id: authority.authority_id || null,
          assurance_class: authority.assurance_class || null,
          authority_check: authority.reason,
        };
      }
    }

    // ── Record consume event (append-only) ───────────────────────────────
    const consumedAt = new Date().toISOString();
    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: 'guard.trust_receipt.consumed',
      actor_id: authEntityId(auth),
      actor_type: 'system',
      target_type: 'trust_receipt',
      target_id: receiptId,
      action: 'consume',
      before_state: { receipt_status: 'pending_consume' },
      after_state: {
        receipt_status: 'consumed',
        consumed_at: consumedAt,
        consumed_by_system: body.executing_system,
        execution_reference_id: body.execution_reference_id || null,
        action_hash: body.action_hash,
        authority: authorityFacts,
      },
    });

    if (insertErr) {
      // Postgres unique_violation (SQLSTATE 23505) on the
      // guard_receipt_consume_once partial unique index means another
      // request raced this one and won. Return 409 (the receipt has
      // already been consumed) instead of 500.
      if (insertErr.code === '23505') {
        return epProblem(409, 'receipt_already_consumed', 'Receipt has already been consumed');
      }
      logger.error('[guard] consume: audit insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to record consume');
    }

    return NextResponse.json({
      receipt_id: receiptId,
      status: 'consumed',
      consumed_at: consumedAt,
      consumed_by_system: body.executing_system,
      execution_reference_id: body.execution_reference_id || null,
    });
  } catch (err) {
    logger.error('[guard] POST consume error:', err);
    return epProblem(500, 'internal_error', 'Consume failed');
  }
}

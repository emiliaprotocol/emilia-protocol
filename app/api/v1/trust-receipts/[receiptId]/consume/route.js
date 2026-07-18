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
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { quorumGate } from '@/lib/signoff/quorum-session.js';
import { decisionsToMembers } from '@/lib/signoff/attestation-members.js';
import { getRpConfig } from '@/lib/webauthn.js';
import { boundSignoffDecisionEvents, findBoundSignoffDecision } from '@/lib/guard-signoff-binding.js';
import { deriveSignoffUserVerification } from '@/lib/guard-signoff-uv.js';
import { resolveGuardAuthority } from '@/lib/guard-authority.js';
import { isTierQuorumEnforced } from '@/lib/env';
import { countDistinctValidApprovers, requiredApprovalsForTier } from '@/lib/guard-tier.js';
import { canReadReceipt } from '@/lib/tenant-binding.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { resolveOrgQuorumTemplate, evaluateQuorumAgainstTemplate } from '@/lib/guard-quorum-template.js';

const RECEIPT_ID_PATTERN = /^tr_[a-f0-9]{32}$/;
const MAX_TRUST_RECEIPT_CONSUME_BYTES = 32 * 1024;

export async function POST(request, { params }) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const { receiptId } = await params;
    if (!RECEIPT_ID_PATTERN.test(receiptId || '')) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }

    const parsed = await readLimitedJson(request, MAX_TRUST_RECEIPT_CONSUME_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

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
        // ── Defense in depth: the STORED quorum_policy must still meet the org
        // template at consume. Creation already gates this, but re-checking here
        // catches a template tightened after issuance or a policy that reached
        // the timeline by a path other than the create route (e.g. a direct DB
        // write). A real store fault fails closed; a not-yet-migrated table is
        // surfaced as template:null and does not block a legitimately-issued
        // receipt (matching the create path's un-migrated behavior).
        const tpl = await resolveOrgQuorumTemplate(supabase, {
          organizationId: base.organization_id,
          actionType: base.action_type,
        });
        if (tpl.error) {
          return epProblem(
            503,
            'quorum_template_unavailable',
            'Could not verify the receipt quorum against the organization policy template; failing closed.',
          );
        }
        if (tpl.template) {
          const cmp = evaluateQuorumAgainstTemplate(base.quorum_policy, tpl.template);
          if (!cmp.ok) {
            return epProblem(
              403,
              'quorum_policy_below_template',
              `Receipt quorum_policy is weaker than the organization template (${cmp.violations.join(', ')})`,
            );
          }
        }

        // ── Multi-party (EP-QUORUM-v1): require a SATISFIED quorum ──────────
        // Re-verify ALL approvals through the same fail-closed predicate the
        // cross-language conformance suite covers (distinct humans, roles,
        // order, window, action-binding, signatures). The approve route already
        // recorded each assertion; we reconstitute members and gate on them.
        // Separation of duties: the initiator can never fill a quorum seat — the
        // same rule the single-signoff branch enforces. The approve routes already
        // reject self-approval at write time; dropping it here too keeps the
        // consume gate fail-closed even if an initiator approval ever reached the
        // timeline (e.g. a direct DB write): it leaves the quorum unsatisfied
        // rather than silently counting toward it.
        const quorumInitiatorId = created.actor_id || null;
        const approvedDecisions = boundSignoffDecisionEvents(events, created, 'guard.signoff.approved')
          .map((e) => e.after_state)
          .filter(Boolean)
          .filter((d) => {
            const approver = d.approver_id || (d.context && d.context.approver) || null;
            return approver !== quorumInitiatorId;
          });
        const credentialIds = approvedDecisions
          .map((d) => d.webauthn && d.webauthn.credential_id)
          .filter(Boolean);
        let credsByCredentialId = {};
        if (credentialIds.length > 0) {
          const { data: creds, error: credErr } = await supabase
            .from('approver_credentials')
            .select('credential_id, public_key_spki')
            .eq('organization_id', base.organization_id)
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
        const { rpID, origin } = getRpConfig();
        const gate = quorumGate(base.quorum_policy, base.action_hash, members, {
          rpId: rpID,
          allowedOrigins: [origin],
        });
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

        // ── Real WebAuthn user-verification (UV) signal ────────────────────
        // key_class:'A' is a LABEL written by the approve-webauthn route. The
        // security property is the UV flag actually set in the authenticator
        // data the approver's device signed. Do not admit a Class-A receipt on
        // the label alone: re-derive the REAL signal from the stored assertion
        // with the same offline EP primitive the quorum gate uses
        // (verifyWebAuthnSignoff → user_verified from the auth-data flags byte),
        // and fail closed if the assertion is missing, does not bind this
        // action, does not verify against the approver's enrolled key, or does
        // not assert user verification. This is where the genuine WebAuthn UV
        // flag — which lives at signoff time, not at the bearer-authenticated
        // mint — is threaded into the decision that consumes it.
        if (base.required_assurance === 'A') {
          const credentialId = approved.after_state?.webauthn?.credential_id || null;
          let approverPublicKeySpki = null;
          if (credentialId) {
            const { data: credRows, error: credErr } = await supabase
              .from('approver_credentials')
              .select('credential_id, public_key_spki')
              .eq('organization_id', base.organization_id)
              .eq('credential_id', credentialId)
              .is('revoked_at', null)
              .limit(1);
            if (credErr) {
              logger.error('[guard] consume: approver credential load failed:', credErr);
              return epProblem(500, 'internal_error', 'Failed to load approver credential for signoff verification');
            }
            approverPublicKeySpki = (credRows || [])[0]?.public_key_spki || null;
          }
          const { rpID, origin } = getRpConfig();
          const uv = deriveSignoffUserVerification({
            decision: approved.after_state,
            approverPublicKeySpki,
            expectedActionHash: base.action_hash,
            rpId: rpID,
            allowedOrigins: [origin],
          });
          if (!uv.verified) {
            return epProblem(
              403,
              'insufficient_assurance',
              `Class-A signoff does not carry a verified WebAuthn user-verification signal (${uv.reason})`,
            );
          }
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
          // Real WebAuthn UV signal re-derived above (only set for Class-A).
          user_verification: base.required_assurance === 'A' ? 'verified' : null,
        };

        // Assurance-tier escalation (flag-gated, default off): a 'dual' value tier
        // (e.g. payment >= $1M) requires TWO distinct, individually-authorized
        // Class-A approvers — the single approval above is necessary but not
        // sufficient for high-value actions. Reuses the same per-approver
        // authority/revocation check. See ASSURANCE-TIER-ENFORCEMENT.md.
        if (isTierQuorumEnforced() && base.signoff_tier === 'dual') {
          const initiatorId = created.actor_id || null;
          const approvals = boundSignoffDecisionEvents(events, created, 'guard.signoff.approved')
            .map((e) => e.after_state)
            .filter(Boolean);
          const distinct = await countDistinctValidApprovers(approvals, {
            initiatorId,
            requiredAssurance: base.required_assurance || null,
            resolveAuthority: (a) => resolveGuardAuthority(supabase, {
              organizationId: base.organization_id,
              approverId: a.approver_id || null,
              role: a.role,
              requiredAssurance: base.required_assurance || undefined,
              at: new Date().toISOString(),
            }),
          });
          const need = requiredApprovalsForTier('dual');
          if (distinct < need) {
            return epProblem(
              403,
              'dual_authorization_required',
              `This value tier requires dual authorization: ${distinct} of ${need} distinct valid Class-A approvals present`,
            );
          }
          authorityFacts = { ...authorityFacts, tier: 'dual', distinct_approvers: distinct };
        }
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

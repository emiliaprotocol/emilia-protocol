// SPDX-License-Identifier: Apache-2.0
// EP enforcement adapter — POST /api/v1/trust-receipts/[receiptId]/execution
//
// #6 The adapter contract has two halves:
//   1. Blocked-until-consume (the consume gate already refuses to record a
//      consume without a valid, bound, authorized signoff — reject-BEFORE-mutation).
//   2. Emit an execution attestation AFTER the mutation, bound to the consumed
//      receipt: proof that the action which actually ran is the action that was
//      authorized. This endpoint is half 2.
//
// It refuses to attest an execution for a receipt that was never consumed
// (you cannot have legitimately executed an unauthorized action), and it REFUSES
// -- while recording EXECUTION DRIFT as evidence rather than hiding it -- when
// executed_action_hash != the approved action_hash, or when a required
// execution-binding contract does not hold. The receipt proves what was
// authorized, the attestation proves what executed, and a drift is a refusal
// with a named reason plus a durable `guard.trust_receipt.execution_drift`
// event, never a 201 'executed' record carrying binding_status 'drift'.

import { NextRequest, NextResponse } from 'next/server';
import { authenticateGuardRequest, isCloudGuardPrincipal } from '@/lib/guard-auth.js';
import { authEntityId } from '@/lib/auth-projections.js';
import { canMutateReceipt } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { buildExecutionIntegrity } from '@/lib/execution/integrity.js';
import { verifyExecutionBindingContract } from '@/lib/execution/binding-contract';
import { readLimitedJson } from '@/lib/http/body-limit';

const MAX_EXECUTION_ATTESTATION_BYTES = 256 * 1024;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ receiptId: string }> }
): Promise<NextResponse> {
  try {
    const auth = await authenticateGuardRequest(request);
    if (auth.error) return epProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);

    const { receiptId } = await params;
    if (!/^tr_[a-f0-9]{32}$/.test(receiptId || '')) {
      return epProblem(400, 'invalid_receipt_id', 'receipt_id must match tr_<32-hex>');
    }
    const parsed = await readLimitedJson(request, MAX_EXECUTION_ATTESTATION_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) {
      const failure = parsed as { ok: false; status: number; code: string; detail: string };
      return epProblem(failure.status, failure.code, failure.detail);
    }
    const body = (parsed as { ok: true; value: any }).value;

    if (!body.executed_action || typeof body.executed_action !== 'object' || Array.isArray(body.executed_action)) {
      return epProblem(400, 'missing_executed_action', 'executed_action (the canonical action that ran) is required');
    }
    if (!body.executing_system) {
      return epProblem(400, 'missing_executing_system', 'executing_system is required');
    }

    const supabase = getGuardedClient();

    const { data: events, error: eventsErr } = await supabase
      .from('audit_events')
      .select('event_type, actor_id, after_state, created_at')
      .eq('target_type', 'trust_receipt')
      .eq('target_id', receiptId)
      .order('created_at', { ascending: true });

    if (eventsErr) {
      logger.error('[guard] execution: load events failed:', eventsErr);
      return epProblem(500, 'internal_error', 'Failed to load receipt');
    }
    if (!events || events.length === 0) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }

    const created = events.find((e) => e.event_type === 'guard.trust_receipt.created');
    if (!created) return epProblem(500, 'corrupted_receipt', 'Receipt missing creation event');
    if (isCloudGuardPrincipal(auth)) {
      const permissions = Array.isArray(auth.permissions) ? auth.permissions : [];
      if (!permissions.includes('admin') && !permissions.includes('receipt.execute')) {
        return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
      }
    }
    if (!canMutateReceipt(auth, {
      organizationId: created.after_state?.organization_id,
      creatorActorId: created.actor_id,
    }, 'receipt.execute')) {
      return epProblem(404, 'receipt_not_found', `Trust receipt ${receiptId} not found`);
    }
    if (created.after_state?.enforcement_mode === 'observe') {
      return epProblem(
        409,
        'observe_receipt_not_authority',
        'Observe-mode receipts are telemetry and cannot support an execution attestation',
      );
    }

    // Half 1 of the contract: you cannot attest execution of an action that was
    // never authorized + consumed. Reject-before-mutation is enforced at consume;
    // here we require that consume already happened.
    const consumed = events.find((e) => e.event_type === 'guard.trust_receipt.consumed');
    if (!consumed) {
      return epProblem(409, 'receipt_not_consumed', 'Receipt must be consumed before an execution can be attested');
    }
    if (events.some((e) => e.event_type === 'guard.trust_receipt.executed' || e.event_type === 'guard.trust_receipt.execution_drift')) {
      return epProblem(409, 'execution_already_attested', 'An execution attestation already exists for this receipt');
    }

    // Half 2: bind what executed to what was approved. binding_status is 'match'
    // when the executed action canonicalizes to the approved action_hash, else 'drift'.
    const approvedActionHash = created.after_state.action_hash;
    // buildExecutionIntegrity (lib/execution/integrity.ts) conditionally sets
    // execution_id/executed_at on its returned object via property assignment
    // rather than the object literal, so TS's inferred return type omits them
    // even though they are set whenever executionId/executedAt are supplied
    // (as they always are here). Widen the annotation to match reality.
    const attestation: ReturnType<typeof buildExecutionIntegrity> & {
      execution_id?: any;
      executed_at?: any;
    } = buildExecutionIntegrity({
      approvedActionHash,
      executedAction: body.executed_action,
      executionId: body.execution_id,
      executedAt: body.executed_at || new Date().toISOString(),
    });
    const executionBinding = created.after_state.execution_binding || null;
    if (executionBinding?.required === true
      && (!body.observed_action || typeof body.observed_action !== 'object' || Array.isArray(body.observed_action))) {
      return epProblem(
        400,
        'missing_observed_action',
        'observed_action is required when the receipt carries a required execution binding',
      );
    }
    const bindingCheck = verifyExecutionBindingContract({
      contract: executionBinding,
      observedAction: body.observed_action || body.executed_action,
      executedAction: body.executed_action,
    });

    // A hash mismatch is NEVER a successful execution record. Gating this on
    // `executionBinding?.required === true` meant a receipt with no binding
    // contract -- the common case -- had its drift written as
    // `guard.trust_receipt.executed` with binding_status 'drift' and answered
    // 201 with only a logger.warn: the audit trail then read "executed" for an
    // action that is not the action the receipt authorized, and the
    // `execution_drift_refused` conformance check this project publishes in
    // public/.well-known/agent-action-control.json was not what the route did.
    // Refuse on either failure, regardless of the required flag: a re-derived
    // hash mismatch (binding_status 'drift') or a failed high-risk
    // observed-field contract. Both record the drift as evidence first.
    const driftRefused = attestation.binding_status !== 'match' || !bindingCheck.ok;
    if (driftRefused) {
      const driftCode = attestation.binding_status !== 'match'
        ? 'execution_action_drift'
        : 'execution_binding_mismatch';
      const driftDetail = attestation.binding_status !== 'match'
        ? 'The executed action does not hash to the action the receipt authorized'
        : 'Observed high-risk execution fields do not match the authorized receipt';
      const { error: driftErr } = await supabase.from('audit_events').insert({
        event_type: 'guard.trust_receipt.execution_drift',
        actor_id: authEntityId(auth),
        actor_type: 'system',
        target_type: 'trust_receipt',
        target_id: receiptId,
        action: 'reject_execution',
        before_state: { receipt_status: 'consumed' },
        after_state: {
          receipt_status: 'execution_drift',
          executing_system: body.executing_system,
          execution_id: attestation.execution_id || null,
          executed_at: attestation.executed_at || null,
          executed_action_hash: attestation.executed_action_hash,
          binding_status: attestation.binding_status,
          execution_binding_check: bindingCheck,
          execution_integrity: attestation,
        },
      });
      if (driftErr) {
        logger.error('[guard] execution: drift audit insert failed:', driftErr);
        return epProblem(500, 'internal_error', 'Failed to record execution drift');
      }
      logger.warn(`[guard] execution: DRIFT refused on receipt ${receiptId} (${driftCode})`);
      return epProblem(
        409,
        driftCode,
        driftDetail,
        {
          binding_status: attestation.binding_status,
          execution_binding_check: bindingCheck,
          executed_action_hash: attestation.executed_action_hash,
          approved_action_hash: approvedActionHash,
        },
      );
    }

    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: 'guard.trust_receipt.executed',
      actor_id: authEntityId(auth),
      actor_type: 'system',
      target_type: 'trust_receipt',
      target_id: receiptId,
      action: 'execute',
      before_state: { receipt_status: 'consumed' },
      after_state: {
        receipt_status: 'executed',
        executing_system: body.executing_system,
        execution_id: attestation.execution_id || null,
        executed_at: attestation.executed_at || null,
        executed_action_hash: attestation.executed_action_hash,
        binding_status: attestation.binding_status,
        execution_binding_check: bindingCheck,
        execution_integrity: attestation,
      },
    });
    if (insertErr) {
      if (insertErr.code === '23505') {
        return epProblem(409, 'execution_already_attested', 'An execution attestation already exists for this receipt');
      }
      logger.error('[guard] execution: audit insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to record execution attestation');
    }

    return NextResponse.json({
      receipt_id: receiptId,
      status: 'executed',
      binding_status: attestation.binding_status,
      executed_action_hash: attestation.executed_action_hash,
      approved_action_hash: approvedActionHash,
      execution_binding_check: bindingCheck,
      execution_integrity: attestation,
    }, { status: 201 });
  } catch (err) {
    logger.error('[guard] POST execution error:', err);
    return epProblem(500, 'internal_error', 'Execution attestation failed');
  }
}

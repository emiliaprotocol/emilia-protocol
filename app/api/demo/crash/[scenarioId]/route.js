/**
 * GET /api/demo/crash/[scenarioId]
 * @license Apache-2.0
 *
 * Public, unauthenticated, CORS-open endpoint behind the /demo crash test.
 * For each "Agent That Tried To" scenario it:
 *   1. builds the canonical action + action_hash,
 *   2. computes the verdict — for ENFORCED scenarios via the REAL production
 *      policy engine (evaluateGuardPolicy, lib/guard-policies.js); for
 *      ILLUSTRATIVE scenarios via the scenario's labeled illustrative verdict,
 *   3. signs an EP-RECEIPT-v1 document with the demo Ed25519 key (verifiable
 *      against the published demo public key),
 *   4. returns the pre-execution BLOCK (RFC-7807 403 the consume gate emits)
 *      and the post-signoff COMMITTED record.
 *
 * No production keys, no production data — demo only.
 */

import { NextResponse } from 'next/server';
import { evaluateGuardPolicy, hashCanonicalAction } from '@/lib/guard-policies';
import { signDemoPayload, getDemoPublicKeyBase64url } from '@/lib/demo-receipt';
import { getCrashScenario, buildCanonicalAction } from '@/lib/crash-scenarios';

export const dynamic = 'force-dynamic';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

export async function GET(_request, { params }) {
  const { scenarioId } = await params;
  const s = getCrashScenario(scenarioId);
  if (!s) {
    return NextResponse.json({ error: 'unknown_scenario' }, { status: 404, headers: CORS });
  }

  const action = buildCanonicalAction(s);
  const actionHash = hashCanonicalAction(action);

  // ── The verdict: real engine for enforced verbs, labeled illustration otherwise ──
  const verdict =
    s.mode === 'enforced'
      ? evaluateGuardPolicy({
          organizationId: 'demo_org',
          actorId: 'autonomous_ai_agent',
          actorRole: 'autonomous_agent',
          actionType: s.actionType,
          targetChangedFields: s.changedFields,
          amount: typeof s.amount === 'number' ? s.amount : undefined,
          riskFlags: s.riskFlags,
          authStrength: 'service_account',
        })
      : s.illustrativeVerdict;

  const blocked = Boolean(verdict.signoffRequired) || verdict.decision === 'deny';

  // ── Signed EP-RECEIPT-v1 over the action + verdict ──
  const payload = {
    receipt_id: `tr_crash_${s.id}`,
    issuer: 'ep_demo_guard_v1',
    subject: 'agent:autonomous_ai_agent',
    claim: {
      action_type: s.actionType,
      outcome: verdict.decision,
      context: {
        scenario: s.id,
        mode: s.mode,
        changed_fields: s.changedFields,
        amount_usd: typeof s.amount === 'number' ? s.amount : null,
        risk_signals: s.riskFlags,
        reasons: verdict.reasons,
        action_hash: actionHash,
      },
    },
    created_at: s.requestedAt,
    protocol_version: 'EP-CORE-v1.0',
  };
  const signature = signDemoPayload(payload);
  const receipt = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      signer: payload.issuer,
      value: signature,
      key_source: 'inline-demo-only',
    },
    metadata: { _demo_only: true, mode: s.mode },
  };

  // ── The pre-execution block the consume gate returns (RFC-7807) ──
  const blockedResponse = blocked
    ? {
        type: 'https://emiliaprotocol.ai/errors/signoff_required',
        title: 'Signoff Required',
        status: 403,
        detail:
          'This action requires accountable human signoff before it can be consumed. The agent cannot self-authorize.',
        action_hash: actionHash,
        decision: verdict.decision,
        reasons: verdict.reasons,
      }
    : null;

  // ── The COMMITTED record, after two independent humans approve ──
  const committed = blocked
    ? {
        threshold: 'two_party_independent_approval',
        approvers: [
          { id: 'human:controller_j_park', role: 'Controller', approved_at: bump(s.requestedAt, 18 * 60) },
          { id: 'human:cfo_delegate_k_chen', role: 'CFO Delegate', approved_at: bump(s.requestedAt, 34 * 60) },
        ],
        self_approval_rejected: {
          by: 'autonomous_ai_agent',
          error: 'self_approval_forbidden',
          note: 'Separation of duties: the actor cannot approve its own action.',
        },
        consumed_at: bump(s.requestedAt, 34 * 60 + 6),
        execution_reference_id: `exec_${actionHash.slice(0, 12)}`,
      }
    : null;

  return NextResponse.json(
    {
      scenario: {
        id: s.id,
        mode: s.mode,
        actor: s.actor,
        title: s.title,
        agentTask: s.agentTask,
        injection: s.injection,
        riskyAction: s.riskyAction,
        costLabel: s.costLabel,
        costUsd: s.costUsd,
        gateCitation: s.gateCitation,
      },
      action_hash: actionHash,
      decision: verdict.decision,
      signoff_required: blocked,
      reasons: verdict.reasons,
      blocked_response: blockedResponse,
      committed,
      receipt,
      public_key: getDemoPublicKeyBase64url(),
    },
    { headers: CORS },
  );
}

function bump(iso, seconds) {
  return new Date(new Date(iso).getTime() + seconds * 1000).toISOString();
}

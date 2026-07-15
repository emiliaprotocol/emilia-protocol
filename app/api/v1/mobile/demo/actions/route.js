// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { createDemoAction } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const MAX_BODY_BYTES = 16 * 1024;
const MEMBERS = new Set(['approver_id', 'scenario']);

function scenario(name, actionReference) {
  const common = { action_id: actionReference, requested_by: 'ep:agent:operations-copilot' };
  if (name === 'grid') {
    const earliestStart = new Date(Date.now() + 15 * 60_000).toISOString();
    return {
      action: {
        '@type': 'grid.datacenter.curtailment',
        ...common,
        facility_id: 'us-west-dc-17',
        requested_reduction_mw: 18,
        duration_minutes: 90,
        earliest_start: earliestStart,
        grid_event: 'CAISO-stage-2-heat',
      },
      presentation: {
        title: 'Reduce load by 18 MW',
        summary: 'An autonomous grid coordinator is requesting a bounded data-center curtailment during a heat emergency.',
        risk: 'critical infrastructure',
        material_fields: {
          facility: 'US West Data Center 17',
          reduction: '18 MW',
          duration: '90 minutes',
          earliest_start: new Intl.DateTimeFormat('en-US', {
            hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
          }).format(new Date(earliestStart)),
          grid_event: 'CAISO Stage 2 heat event',
        },
        consequence: 'Approval permits one exact curtailment command. It does not authorize later or larger reductions.',
      },
      policy: { policy_id: 'emilia.demo.grid.v1', max_reduction_mw: 20, human_approval: 'class_a' },
    };
  }
  if (name === 'healthcare') {
    return {
      action: {
        '@type': 'pharmacy.coverage.override',
        ...common,
        case_id: 'rx-case-7F41',
        medication_class: 'specialty-biologic',
        coverage_days: 30,
        plan_cost_minor: 1845000,
        currency: 'USD',
      },
      presentation: {
        title: 'Approve coverage override',
        summary: 'A payer agent recommends a 30-day specialty-medication override after automated review.',
        risk: 'patient access and financial',
        material_fields: {
          case: 'RX-7F41',
          therapy: 'Specialty biologic',
          coverage: '30 days',
          plan_exposure: '$18,450.00',
          basis: 'Documented continuity-of-care exception',
        },
        consequence: 'Approval authorizes only this pseudonymous case and coverage window.',
      },
      policy: { policy_id: 'emilia.demo.payer.v1', max_coverage_days: 30, human_approval: 'class_a' },
    };
  }
  return {
    action: {
      '@type': 'treasury.disbursement.release',
      ...common,
      amount_minor: 25000000,
      currency: 'USD',
      beneficiary_id: 'vendor:grid-restoration-42',
      destination_fingerprint: 'US••••1842',
      purpose: 'Emergency grid-restoration equipment',
    },
    presentation: {
      title: 'Release $250,000',
      summary: 'An autonomous treasury agent is ready to release an emergency vendor payment.',
      risk: 'high-value financial',
      material_fields: {
        amount: '$250,000.00',
        beneficiary: 'Grid Restoration Services',
        destination: 'Account ending 1842',
        purpose: 'Emergency grid-restoration equipment',
        requested_by: 'Operations Copilot',
      },
      consequence: 'Approval permits one exact release. Any change to amount, beneficiary, or destination requires a new ceremony.',
    },
    policy: { policy_id: 'emilia.demo.treasury.v1', max_amount_minor: 50000000, human_approval: 'class_a' },
  };
}

export async function POST(request) {
  try {
    if (process.env.MOBILE_DEMO_ENABLED !== 'true') {
      return mobileProblem(404, 'mobile_demo_disabled', 'Mobile demo action injection is disabled');
    }
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Mobile demo requests require application/json');
    }
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(auth, 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const limited = await checkRateLimit(authEntityId(auth), 'protocol_write');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile demo actions');
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))) {
      return mobileProblem(400, 'invalid_demo_action', 'Demo action request has unknown or malformed members');
    }
    const approverId = parsed.value.approver_id;
    const scenarioName = parsed.value.scenario || 'treasury';
    if (!APPROVER_ID_PATTERN.test(approverId || '') || !['treasury', 'grid', 'healthcare'].includes(scenarioName)) {
      return mobileProblem(400, 'invalid_demo_action', 'approver_id or scenario is invalid');
    }
    const actionReference = `mobact_${crypto.randomBytes(16).toString('hex')}`;
    const selected = scenario(scenarioName, actionReference);
    const expiresAt = new Date(Date.now() + 4 * 60 * 60_000).toISOString();
    await createDemoAction(getGuardedClient(), {
      action_reference: actionReference,
      entity_ref: authEntityId(auth),
      approver_id: approverId,
      initiator_id: 'ep:agent:operations-copilot',
      action: selected.action,
      presentation: selected.presentation,
      policy: selected.policy,
      policy_id: selected.policy.policy_id,
      expires_at: expiresAt,
    });
    return mobileJson({
      action_reference: actionReference,
      scenario: scenarioName,
      expires_at: expiresAt,
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] demo action creation failed', error);
    return mobileProblem(503, 'mobile_demo_unavailable', 'Mobile demo action service unavailable');
  }
}

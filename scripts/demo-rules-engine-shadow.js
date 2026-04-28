#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Local proof of the rules-engine v0 shadow signal.
//
// Mirrors the input-shaping logic in app/api/v1/trust-receipts/route.js
// (the EP_RULES_ENGINE_V0=enabled branch), feeds three synthetic
// scenarios into lib/rules-engine.js, and prints the audit_event
// payload that would be inserted in production.
//
// Run:
//   node scripts/demo-rules-engine-shadow.js
//
// Use this to:
//   1. Verify the wiring without needing a bearer token
//   2. Show a buyer what the shadow signal looks like
//   3. Compare against the live SQL query result once
//      EP_RULES_ENGINE_V0=enabled and real receipts have been created

import { evaluateAction, DECISIONS } from '../lib/rules-engine.js';

// ─── Three scenarios that exercise different §4 rule paths ────────────────

const SCENARIOS = [
  {
    name: 'Benign vendor payment ($500, business hours, established vendor)',
    body: {
      organization_id: 'org_demo_treasury',
      action_type: 'vendor_payment',
      target_resource_id: 'vendor:VEND-1234',
      amount: 500,
      business_hours: true,
      destination_age_days: 365,
    },
  },
  {
    name: 'Vendor bank-account change — the live /r/example scenario',
    body: {
      organization_id: 'org_demo_treasury',
      action_type: 'vendor_bank_account_change',
      target_resource_id: 'vendor:VEND-9821',
      amount: 248_750,
      business_hours: false,           // 22:14 UTC — after-hours
      destination_age_days: 0,         // brand-new destination
      prior_changes_target_30d: 0,
      risk_flags: [],
    },
  },
  {
    name: 'High-risk caseworker override at $75K with prior denials',
    body: {
      organization_id: 'org_state_dhs',
      action_type: 'caseworker_override',
      target_resource_id: 'case:CASE-77812',
      amount: 75_000,
      business_hours: false,
      destination_age_days: 5,
      velocity_same_actor_24h: 6,
      prior_denials_actor_30d: 2,
      prior_changes_target_30d: 3,
    },
  },
];

const ENFORCEMENT_MODES = { OBSERVE: 'observe', WARN: 'warn', ENFORCE: 'enforce' };

// Mirrors the adapter inside app/api/v1/trust-receipts/route.js
function buildRulesEngineInput({ body, actor_id, mode }) {
  return {
    tenant_id: body.organization_id,
    environment: mode === ENFORCEMENT_MODES.ENFORCE ? 'enforce' : 'shadow',
    workflow: body.action_type,
    actor: {
      actor_id,
      role: body.actor_role || 'unknown',
      department: body.actor_department,
      assurance_level: 'high',
      mfa_verified: true,
    },
    action: {
      action_id: `tr_${'demo'.repeat(8)}`,
      action_type: body.action_type,
      amount_usd: typeof body.amount === 'number' ? body.amount : undefined,
    },
    authority: {
      authority_id: 'shadow_default_authority',
      scope: [body.action_type],
      max_amount_usd: Number.MAX_SAFE_INTEGER,
      revoked: false,
    },
    context: {
      business_hours: typeof body.business_hours === 'boolean' ? body.business_hours : true,
      velocity_same_actor_24h: body.velocity_same_actor_24h,
      prior_denials_actor_30d: body.prior_denials_actor_30d,
      prior_changes_target_30d: body.prior_changes_target_30d,
      destination_age_days: body.destination_age_days,
      watchlist_hit: (body.risk_flags || []).includes('watchlist_hit'),
    },
  };
}

// ─── Run ──────────────────────────────────────────────────────────────────

console.log('═'.repeat(76));
console.log('Rules-Engine v0 Shadow Signal — Local Proof');
console.log('═'.repeat(76));
console.log();
console.log('Each scenario below shows the audit_event payload that');
console.log('app/api/v1/trust-receipts/route.js will insert in production');
console.log('when EP_RULES_ENGINE_V0=enabled.');
console.log();

const actor_id = 'ap_demo_actor_alice';
const mode = ENFORCEMENT_MODES.ENFORCE;

for (const scenario of SCENARIOS) {
  console.log('─'.repeat(76));
  console.log(scenario.name);
  console.log('─'.repeat(76));

  const input = buildRulesEngineInput({ body: scenario.body, actor_id, mode });
  const result = evaluateAction(input);

  // This is the literal after_state shape inserted by the route handler:
  const auditEvent = {
    event_type: 'rules-engine.v0.shadow',
    actor_id,
    actor_type: 'system',
    target_type: 'trust_receipt',
    target_id: input.action.action_id,
    action: 'shadow_evaluate',
    before_state: null,
    after_state: {
      rules_engine_decision: result.decision,
      rules_engine_reason_codes: result.reason_codes,
      rules_engine_required_approvals: result.required_approvals,
      rules_engine_required_signoff: result.required_signoff,
      rules_engine_risk_score: result.risk_score,
      // (live decision filled in by the route from evaluateGuardPolicy)
      guard_policy_decision: '<filled-in-by-route-from-evaluateGuardPolicy>',
      guard_policy_signoff_required: '<filled-in-by-route>',
      feature_flag: 'EP_RULES_ENGINE_V0',
      evaluator_version: '0',
    },
  };

  console.log(JSON.stringify(auditEvent, null, 2));
  console.log();
  console.log(`  → decision: ${result.decision}`);
  console.log(`  → required approvals: ${result.required_approvals}`);
  console.log(`  → risk score: ${result.risk_score}`);
  if (result.required_signoff) {
    console.log(`  → signoff required: ${result.required_signoff.reason_code}`);
  }
  console.log();
}

console.log('═'.repeat(76));
console.log('Once a real receipt is created against the live API in prod,');
console.log('this is the shape you will see in:');
console.log();
console.log('  SELECT * FROM audit_events');
console.log("  WHERE event_type = 'rules-engine.v0.shadow'");
console.log('  ORDER BY created_at DESC LIMIT 5;');
console.log();
console.log(`Decisions you can expect: ${Object.values(DECISIONS).join(', ')}`);
console.log('═'.repeat(76));

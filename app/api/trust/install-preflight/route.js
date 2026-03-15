import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';

/**
 * POST /api/trust/install-preflight
 *
 * EP-SX: "Should I install this plugin/app/package/extension/MCP server?"
 * Routes through the canonical evaluator — same trust brain as profile and evaluate.
 *
 * Body: { entity_id, policy, context }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id) {
      return EP_ERRORS.BAD_REQUEST('entity_id is required');
    }

    const result = await canonicalEvaluate(body.entity_id, {
      context: body.context || null,
      policy: body.policy || 'standard',
      includeSoftwareChecks: true,
      includeDisputes: false,
      includeEstablishment: true,
    });

    if (result.error) {
      return EP_ERRORS.NOT_FOUND('Entity');
    }

    const pr = result.policyResult;
    const swChecks = pr?.softwareChecks || { passed: [], failed: [] };

    // Decision logic
    let decision;
    if (pr?.pass && (pr?.softwarePass !== false)) {
      decision = 'allow';
    } else if (!pr?.pass && swChecks.failed.length > 0) {
      decision = 'deny';
    } else {
      decision = 'review';
    }

    return NextResponse.json({
      entity_id: result.entity_id,
      entity_type: result.entity_type,
      display_name: result.display_name,
      decision,
      policy_used: pr?.policyName || 'standard',
      context_used: result.contextUsed,

      trust_pass: pr?.trustPass ?? false,
      score: result.score,
      confidence: result.confidence,
      effective_evidence: result.effectiveEvidence,
      trust_failures: pr?.failures || [],
      trust_warnings: pr?.warnings || [],

      software_checks: {
        passed: swChecks.passed || [],
        failed: swChecks.failed || [],
      },
      software_meta: {
        publisher_verified: result.softwareMeta?.publisher_verified || false,
        provenance_verified: result.softwareMeta?.provenance_verified || false,
        permission_class: result.softwareMeta?.permission_class || null,
        install_scope: result.softwareMeta?.install_scope || null,
        registry_listed: result.softwareMeta?.registry_listed || false,
      },

      reasons: [
        ...(swChecks.passed || []).map(r => `✓ ${r}`),
        ...(swChecks.failed || []).map(r => `✗ ${r}`),
        ...(pr?.pass ? ['✓ trust_policy_passed'] : (pr?.failures || []).map(f => `✗ ${f}`)),
      ],

      _protocol_version: 'EP/1.1-v2',
    });
  } catch (err) {
    console.error('Install preflight error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

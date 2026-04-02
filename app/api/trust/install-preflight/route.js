import { NextResponse } from 'next/server';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { EP_ERRORS } from '@/lib/errors';
import { buildTrustDecision } from '@/lib/trust-decision';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/trust/install-preflight (experimental — pre-action enforcement)
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

    const reasons = [
      ...(swChecks.passed || []).map(r => `\u2713 ${r}`),
      ...(swChecks.failed || []).map(r => `\u2717 ${r}`),
      ...(pr?.pass ? ['\u2713 trust_policy_passed'] : (pr?.failures || []).map(f => `\u2717 ${f}`)),
    ];

    return NextResponse.json(buildTrustDecision({
      decision,
      entityId: result.entity_id,
      policyUsed: pr?.policyName || 'standard',
      confidence: result.confidence,
      reasons,
      warnings: pr?.warnings || [],
      contextUsed: result.contextUsed,
      profileSummary: {
        confidence: result.confidence,
        evidence_level: result.effectiveEvidence,
        dispute_rate: result.profile?.behavioral?.dispute_rate ?? 0,
      },
      extensions: {
        entity_type: result.entity_type,
        display_name: result.display_name,
        decision: pr?.trustPass ? 'allow' : 'deny',
        trust_pass: pr?.trustPass ?? false, // DEPRECATED: derived from decision for backward compat
        score: result.score,
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
        _protocol_version: 'EP/1.1-v2',
      },
    }));
  } catch (err) {
    logger.error('Pre-action enforcement error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

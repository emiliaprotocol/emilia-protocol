import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { computeTrustProfile, evaluateTrustPolicy, TRUST_POLICIES } from '@/lib/scoring-v2';

/**
 * POST /api/trust/install-preflight
 * 
 * EP-SX: "Should I install this plugin/app/package/extension/MCP server?"
 * 
 * Combines trust profile evaluation with software-specific checks:
 *   - Publisher verification
 *   - Permission risk assessment
 *   - Provenance verification
 *   - Incident/dispute history
 *   - Policy evaluation in context
 * 
 * Returns: allow / review / deny with specific reasons.
 * 
 * Body: {
 *   entity_id: "github_app:acme/code-helper",
 *   policy: "github_private_repo_safe_v1",    // or built-in: strict/standard/permissive/discovery
 *   context: {
 *     host: "github",
 *     install_scope: "selected_repos",
 *     permission_class: "read_only",
 *     data_sensitivity: "private_code"
 *   }
 * }
 */

// Software-specific policy templates
const SOFTWARE_POLICIES = {
  github_private_repo_safe_v1: {
    min_score: 70,
    min_confidence: 'provisional',
    max_dispute_rate: 3,
    software_requirements: {
      publisher_verified: true,
      max_permission_class: 'read_only',
      install_scope: 'selected_repos',
      max_active_disputes: 0,
      min_provenance_score: 80,
      reject_severe_anomaly: true,
    },
  },
  npm_buildtime_safe_v1: {
    min_score: 60,
    min_confidence: 'provisional',
    software_requirements: {
      trusted_publishing: true,
      provenance_verified: true,
      max_active_disputes: 0,
      max_recent_incidents: 0,
      min_runtime_score: 75,
    },
  },
  browser_extension_safe_v1: {
    min_score: 65,
    min_confidence: 'provisional',
    software_requirements: {
      listing_review_passed: true,
      max_permission_class: 'limited_content_read',
      max_site_scope: 'declared_sites_only',
      max_active_disputes: 0,
      reject_severe_anomaly: true,
    },
  },
  mcp_server_safe_v1: {
    min_score: 60,
    min_confidence: 'provisional',
    software_requirements: {
      registry_listed: true,
      server_card_present: true,
      publisher_verified: true,
      max_permission_class: 'bounded_external_access',
      max_active_disputes: 0,
      min_provenance_score: 70,
    },
  },
};

// Permission risk hierarchy (higher = more dangerous)
const PERMISSION_RISK = {
  'no_access': 0,
  'metadata_read': 1,
  'read_only': 2,
  'limited_content_read': 3,
  'read_write': 4,
  'code_execution': 5,
  'admin': 6,
  'bounded_external_access': 3,
};

export async function POST(request) {
  try {
    const body = await request.json();

    if (!body.entity_id) {
      return NextResponse.json({ error: 'entity_id is required' }, { status: 400 });
    }

    const supabase = getServiceClient();

    // Look up entity
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.entity_id);
    const { data: entity } = await supabase
      .from('entities')
      .select('*')
      .eq(isUuid ? 'id' : 'entity_id', body.entity_id)
      .single();

    if (!entity || entity.status !== 'active') {
      return NextResponse.json({ error: 'Entity not found' }, { status: 404 });
    }

    // Resolve policy
    let policy;
    const policyName = body.policy || 'standard';
    if (typeof policyName === 'string') {
      policy = SOFTWARE_POLICIES[policyName] || TRUST_POLICIES[policyName];
      if (!policy) {
        return NextResponse.json({
          error: `Unknown policy: ${policyName}. Available: ${[...Object.keys(SOFTWARE_POLICIES), ...Object.keys(TRUST_POLICIES)].join(', ')}`,
        }, { status: 400 });
      }
    } else if (typeof policyName === 'object') {
      policy = policyName;
    } else {
      policy = TRUST_POLICIES.standard;
    }

    // Get receipts — context-aware
    const requestContext = body.context || null;
    let receiptQuery = supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entity.id)
      .order('created_at', { ascending: false })
      .limit(200);

    if (requestContext) {
      receiptQuery = receiptQuery.contains('context', requestContext);
    }

    const { data: contextReceipts } = await receiptQuery;
    let receipts = contextReceipts || [];
    let contextUsed = requestContext || 'global';

    if (requestContext && receipts.length < 3) {
      const { data: globalReceipts } = await supabase
        .from('receipts')
        .select('*')
        .eq('entity_id', entity.id)
        .order('created_at', { ascending: false })
        .limit(200);
      receipts = globalReceipts || [];
      contextUsed = 'global_fallback';
    }

    // Compute trust profile
    const profile = computeTrustProfile(receipts, entity);

    // Standard trust evaluation
    const trustResult = evaluateTrustPolicy(profile, policy);

    // Software-specific checks
    const softwareReasons = [];
    const softwareWarnings = [];
    const softwareMeta = entity.software_meta || {};
    const softwareReqs = policy.software_requirements || {};

    // Publisher verification
    if (softwareReqs.publisher_verified && !softwareMeta.publisher_verified) {
      softwareReasons.push('publisher_not_verified');
    } else if (softwareMeta.publisher_verified) {
      softwareReasons.push('+publisher_verified');
    }

    // Provenance
    if (softwareReqs.provenance_verified && !softwareMeta.provenance_verified) {
      softwareReasons.push('provenance_not_verified');
    } else if (softwareMeta.provenance_verified) {
      softwareReasons.push('+provenance_verified');
    }

    if (softwareReqs.trusted_publishing && !softwareMeta.trusted_publishing) {
      softwareReasons.push('trusted_publishing_not_verified');
    }

    // Permission class check
    if (softwareReqs.max_permission_class && softwareMeta.permission_class) {
      const maxRisk = PERMISSION_RISK[softwareReqs.max_permission_class] ?? 99;
      const actualRisk = PERMISSION_RISK[softwareMeta.permission_class] ?? 99;
      if (actualRisk > maxRisk) {
        softwareReasons.push(`permission_class_too_high: ${softwareMeta.permission_class} exceeds max ${softwareReqs.max_permission_class}`);
      } else {
        softwareReasons.push(`+permission_class_acceptable: ${softwareMeta.permission_class}`);
      }
    }

    // Install scope
    if (softwareReqs.install_scope && softwareMeta.install_scope) {
      if (softwareReqs.install_scope === 'selected_repos' && softwareMeta.install_scope === 'all_repos') {
        softwareReasons.push('install_scope_too_broad: all_repos when selected_repos required');
      }
    }

    // Registry / server card
    if (softwareReqs.registry_listed && !softwareMeta.registry_listed) {
      softwareReasons.push('not_registry_listed');
    }
    if (softwareReqs.server_card_present && !softwareMeta.server_card_present) {
      softwareReasons.push('no_server_card');
    }
    if (softwareReqs.listing_review_passed && !softwareMeta.listing_review_passed) {
      softwareReasons.push('listing_review_not_passed');
    }

    // Active disputes
    if (softwareReqs.max_active_disputes !== undefined) {
      const { count } = await supabase
        .from('disputes')
        .select('id', { count: 'exact', head: true })
        .eq('entity_id', entity.id)
        .in('status', ['open', 'under_review']);
      if ((count || 0) > softwareReqs.max_active_disputes) {
        softwareReasons.push(`active_disputes: ${count} exceeds max ${softwareReqs.max_active_disputes}`);
      }
    }

    // Anomaly
    if (softwareReqs.reject_severe_anomaly && profile.anomaly?.alert === 'severe') {
      softwareReasons.push('severe_anomaly_detected');
    }

    // Determine decision
    const softwareFailures = softwareReasons.filter(r => !r.startsWith('+'));
    const softwarePasses = softwareReasons.filter(r => r.startsWith('+')).map(r => r.slice(1));
    const trustPasses = trustResult.pass;
    const softwarePasses_all = softwareFailures.length === 0;

    let decision;
    if (trustPasses && softwarePasses_all) {
      decision = 'allow';
    } else if (!trustPasses && softwareFailures.length > 0) {
      decision = 'deny';
    } else {
      decision = 'review';
    }

    return NextResponse.json({
      entity_id: entity.entity_id,
      entity_type: entity.entity_type,
      display_name: entity.display_name,
      decision,
      policy_used: typeof body.policy === 'string' ? body.policy : 'custom',
      context_used: contextUsed,

      // Trust evaluation
      trust_pass: trustPasses,
      score: profile.score,
      confidence: profile.confidence,
      effective_evidence: profile.effectiveEvidence,
      trust_failures: trustResult.failures,
      trust_warnings: trustResult.warnings,

      // Software-specific evaluation
      software_checks: {
        passed: softwarePasses,
        failed: softwareFailures,
      },
      software_meta: {
        publisher_verified: softwareMeta.publisher_verified || false,
        provenance_verified: softwareMeta.provenance_verified || false,
        permission_class: softwareMeta.permission_class || null,
        install_scope: softwareMeta.install_scope || null,
        registry_listed: softwareMeta.registry_listed || false,
      },

      // Combined reasons
      reasons: [
        ...softwarePasses.map(r => `✓ ${r}`),
        ...softwareFailures.map(r => `✗ ${r}`),
        ...(trustPasses ? ['✓ trust_policy_passed'] : trustResult.failures.map(f => `✗ ${f}`)),
      ],
    });
  } catch (err) {
    console.error('Install preflight error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

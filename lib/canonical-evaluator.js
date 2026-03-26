/**
 * EP Canonical Trust Evaluator
 * 
 * ONE function that every trust-consuming surface calls.
 * No route-specific trust logic. No drift.
 * 
 * Inputs: entity, context, policy, options
 * Outputs: trust profile, confidence, anomaly, policy result, explanation
 * 
 * Used by:
 *   - GET /api/trust/profile/:entityId
 *   - POST /api/trust/evaluate
 *   - POST /api/trust/install-preflight
 *   - POST /api/needs/[id]/claim
 *   - POST /api/needs/broadcast (suggestions)
 *   - GET /api/entities/search (confidence enrichment)
 *   - GET /api/leaderboard (confidence enrichment)
 *   - GET /api/feed (confidence filtering)
 *   - GET /api/score/:entityId
 *   - MCP tools
 * 
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { computeTrustProfile, evaluateTrustPolicy, TRUST_POLICIES } from '@/lib/scoring-v2';
import { TrustEvaluationError } from '@/lib/errors';

// Software-specific policy templates (same as pre-action enforcement)
const SOFTWARE_POLICIES = {
  github_private_repo_safe_v1: TRUST_POLICIES.github_private_repo_safe_v1,
  npm_buildtime_safe_v1: TRUST_POLICIES.npm_buildtime_safe_v1,
  browser_extension_safe_v1: TRUST_POLICIES.browser_extension_safe_v1,
  mcp_server_safe_v1: TRUST_POLICIES.mcp_server_safe_v1,
};

const PERMISSION_RISK = {
  'no_access': 0, 'metadata_read': 1, 'read_only': 2,
  'limited_content_read': 3, 'read_write': 4, 'code_execution': 5,
  'admin': 6, 'bounded_external_access': 3,
};

/**
 * Resolve an entity from slug or UUID.
 */
export async function resolveEntity(entityIdOrSlug) {
  const supabase = getServiceClient();
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityIdOrSlug);
  const { data: entity } = await supabase
    .from('entities')
    .select('*')
    .eq(isUuid ? 'id' : 'entity_id', entityIdOrSlug)
    .single();
  return entity?.status === 'active' ? entity : null;
}

/**
 * Fetch receipts for an entity, optionally filtered by context.
 * Falls back to global if context-specific data is too sparse.
 */
export async function fetchReceipts(entityDbId, context = null, limit = 200) {
  const supabase = getServiceClient();
  
  let query = supabase
    .from('receipts')
    .select('*')
    .eq('entity_id', entityDbId)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (context && typeof context === 'object') {
    query = query.contains('context', context);
  }

  const { data: contextReceipts } = await query;
  let receipts = contextReceipts || [];
  let contextUsed = context || 'global';

  // Fall back to global if context-specific data is too sparse
  if (context && receipts.length < 3) {
    const { data: globalReceipts } = await supabase
      .from('receipts')
      .select('*')
      .eq('entity_id', entityDbId)
      .order('created_at', { ascending: false })
      .limit(limit);
    receipts = globalReceipts || [];
    contextUsed = 'global_fallback';
  }

  return { receipts, contextUsed };
}

/**
 * Fetch canonical establishment from DB function.
 */
export async function fetchEstablishment(entityDbId) {
  const supabase = getServiceClient();
  // Trust-bearing: establishment status directly affects trust decisions
  // (policy gating, confidence levels). Returning a false default when
  // the DB is down would make established entities look unestablished.
  const { data: estData, error: estError } = await supabase.rpc('is_entity_established', { p_entity_id: entityDbId });
  if (estError) {
    throw new TrustEvaluationError(
      `Establishment lookup failed: ${estError.message}`,
      { code: 'ESTABLISHMENT_LOOKUP_FAILED', cause: estError }
    );
  }
  if (estData && estData[0]) return estData[0];
  return { established: false, unique_submitters: 0, effective_evidence: 0, total_receipts: 0 };
}

/**
 * Fetch dispute summary for an entity.
 */
export async function fetchDisputeSummary(entityDbId) {
  const supabase = getServiceClient();
  
  const { count: total } = await supabase
    .from('disputes')
    .select('id', { count: 'exact', head: true })
    .eq('entity_id', entityDbId);

  const { count: active } = await supabase
    .from('disputes')
    .select('id', { count: 'exact', head: true })
    .eq('entity_id', entityDbId)
    .in('status', ['open', 'under_review']);

  const { count: reversed } = await supabase
    .from('disputes')
    .select('id', { count: 'exact', head: true })
    .eq('entity_id', entityDbId)
    .eq('status', 'reversed');

  const { data: recent } = await supabase
    .from('disputes')
    .select('dispute_id, status, reason')
    .eq('entity_id', entityDbId)
    .order('created_at', { ascending: false })
    .limit(5);

  return {
    total: total || 0,
    active: active || 0,
    reversed: reversed || 0,
    recent: (recent || []).map(d => ({
      dispute_id: d.dispute_id,
      status: d.status,
      reason: d.reason,
    })),
  };
}

/**
 * Resolve a policy by name or pass through a custom object.
 */
export function resolvePolicy(policyInput) {
  if (!policyInput) return TRUST_POLICIES.standard;
  if (typeof policyInput === 'string') {
    const found = TRUST_POLICIES[policyInput] || SOFTWARE_POLICIES[policyInput];
    if (found) return { resolved: found, name: policyInput };
    // Try JSON parse — guard size to prevent DoS via deeply nested payloads
    if (policyInput.length <= 4096) {
      try {
        const parsed = JSON.parse(policyInput);
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return { resolved: parsed, name: 'custom' };
        }
      } catch {}
    }
    return { resolved: TRUST_POLICIES.standard, name: 'standard' };
  }
  if (typeof policyInput === 'object') {
    return { resolved: policyInput, name: 'custom' };
  }
  return { resolved: TRUST_POLICIES.standard, name: 'standard' };
}

/**
 * Evaluate software-specific checks against entity metadata and policy.
 */
export function evaluateSoftwareChecks(entity, policy) {
  const softwareMeta = entity.software_meta || {};
  const reqs = policy.software_requirements;
  if (!reqs) return { passed: [], failed: [] };

  const reasons = [];

  if (reqs.publisher_verified && !softwareMeta.publisher_verified) {
    reasons.push('publisher_not_verified');
  } else if (softwareMeta.publisher_verified) {
    reasons.push('+publisher_verified');
  }

  if (reqs.provenance_verified && !softwareMeta.provenance_verified) {
    reasons.push('provenance_not_verified');
  } else if (softwareMeta.provenance_verified) {
    reasons.push('+provenance_verified');
  }

  if (reqs.trusted_publishing && !softwareMeta.trusted_publishing) {
    reasons.push('trusted_publishing_not_verified');
  }

  if (reqs.max_permission_class && softwareMeta.permission_class) {
    const maxRisk = PERMISSION_RISK[reqs.max_permission_class] ?? 99;
    const actualRisk = PERMISSION_RISK[softwareMeta.permission_class] ?? 99;
    if (actualRisk > maxRisk) {
      reasons.push(`permission_class_too_high: ${softwareMeta.permission_class} exceeds max ${reqs.max_permission_class}`);
    } else {
      reasons.push(`+permission_class_acceptable: ${softwareMeta.permission_class}`);
    }
  }

  if (reqs.install_scope && softwareMeta.install_scope) {
    if (reqs.install_scope === 'selected_repos' && softwareMeta.install_scope === 'all_repos') {
      reasons.push('install_scope_too_broad');
    }
  }

  if (reqs.registry_listed && !softwareMeta.registry_listed) reasons.push('not_registry_listed');
  if (reqs.server_card_present && !softwareMeta.server_card_present) reasons.push('no_server_card');
  if (reqs.listing_review_passed && !softwareMeta.listing_review_passed) reasons.push('listing_review_not_passed');

  return {
    passed: reasons.filter(r => r.startsWith('+')).map(r => r.slice(1)),
    failed: reasons.filter(r => !r.startsWith('+')),
  };
}

/**
 * THE CANONICAL EVALUATOR
 * 
 * Every trust-consuming surface should call this.
 * Same entity + same context + same policy = same result. Always.
 * 
 * @param {string} entityIdOrSlug - Entity identifier
 * @param {object} options
 * @param {object} options.context - Context key for filtering
 * @param {string|object} options.policy - Policy name or custom object
 * @param {boolean} options.includeDisputes - Include dispute summary (default true)
 * @param {boolean} options.includeSoftwareChecks - Run EP-SX checks (default: auto-detect)
 * @param {boolean} options.includeEstablishment - Include historical establishment (default true)
 * @returns {object} Canonical trust evaluation result
 */
export async function canonicalEvaluate(entityIdOrSlug, options = {}) {
  const {
    context = null,
    policy: policyInput = null,
    includeDisputes = true,
    includeSoftwareChecks = null, // null = auto-detect from entity_type
    includeEstablishment = true,
  } = options;

  // Resolve entity
  const entity = await resolveEntity(entityIdOrSlug);
  if (!entity) {
    return { error: 'Entity not found', status: 404 };
  }

  // === MATERIALIZATION FAST PATH ===
  // If the entity has a fresh trust snapshot (< 5 min) and no context filtering
  // is needed, use the cached snapshot instead of recomputing from receipts.
  // Context-specific requests always recompute (snapshot is global).
  const SNAPSHOT_TTL_MS = 5 * 60 * 1000; // 5 minutes
  const hasContext = context && typeof context === 'object' && Object.keys(context).length > 0;
  const hasFreshSnapshot = entity.trust_snapshot
    && entity.trust_materialized_at
    && (Date.now() - new Date(entity.trust_materialized_at).getTime()) < SNAPSHOT_TTL_MS;

  let profile;
  let contextUsed;

  if (hasFreshSnapshot && !hasContext) {
    // Use materialized snapshot — no receipt fetch or recompute needed
    profile = entity.trust_snapshot;
    contextUsed = 'global_materialized';
  } else {
    // Full recompute from receipts (context-aware with fallback)
    const fetched = await fetchReceipts(entity.id, context);

    // Fetch active disputes so their receipts receive dampened weight (0.3x).
    // Statuses that constitute "active dispute": open, under_review, adjudicating.
    const supabase = getServiceClient();
    const { data: activeDisputes } = await supabase
      .from('disputes')
      .select('receipt_id')
      .eq('entity_id', entity.id)
      .in('status', ['open', 'under_review', 'adjudicating']);
    const disputedReceiptIds = new Set((activeDisputes || []).map(d => d.receipt_id));

    profile = computeTrustProfile(fetched.receipts, entity, disputedReceiptIds);
    contextUsed = fetched.contextUsed;
  }

  // Resolve and evaluate policy
  let policyResult = null;
  let policyName = null;
  if (policyInput) {
    const { resolved, name } = resolvePolicy(policyInput);
    policyName = name;
    policyResult = evaluateTrustPolicy(profile, resolved);

    // Software-specific checks (if policy has software_requirements)
    const isSoftwareEntity = [
      'github_app', 'github_action', 'mcp_server', 'npm_package',
      'chrome_extension', 'shopify_app', 'marketplace_plugin', 'agent_tool',
    ].includes(entity.entity_type);

    const doSoftwareChecks = includeSoftwareChecks !== null
      ? includeSoftwareChecks
      : (isSoftwareEntity && resolved.software_requirements);

    if (doSoftwareChecks && resolved.software_requirements) {
      const swChecks = evaluateSoftwareChecks(entity, resolved);

      // Check active disputes against policy
      if (resolved.software_requirements.max_active_disputes !== undefined) {
        const supabase = getServiceClient();
        const { count } = await supabase
          .from('disputes')
          .select('id', { count: 'exact', head: true })
          .eq('entity_id', entity.id)
          .in('status', ['open', 'under_review']);
        if ((count || 0) > resolved.software_requirements.max_active_disputes) {
          swChecks.failed.push(`active_disputes: ${count} exceeds max ${resolved.software_requirements.max_active_disputes}`);
        }
      }

      // Check anomaly
      if (resolved.software_requirements.reject_severe_anomaly && profile.anomaly?.alert === 'severe') {
        swChecks.failed.push('severe_anomaly_detected');
      }

      policyResult.softwareChecks = swChecks;
      policyResult.softwarePass = swChecks.failed.length === 0;
    }
  }

  // Historical establishment
  let establishment = null;
  if (includeEstablishment) {
    establishment = await fetchEstablishment(entity.id);
  }

  // Disputes
  let disputes = null;
  if (includeDisputes) {
    disputes = await fetchDisputeSummary(entity.id);
  }

  // EP-IX: Identity continuity (if principal is linked)
  let continuity = null;
  if (entity.principal_id) {
    try {
      const supabase = getServiceClient();
      
      // Get principal
      const { data: principal } = await supabase
        .from('principals')
        .select('principal_id, principal_type, display_name, status')
        .eq('id', entity.principal_id)
        .single();

      // Get lineage
      const { data: asSuccessor } = await supabase
        .from('continuity_claims')
        .select('old_entity_id, reason, status, transfer_policy')
        .eq('new_entity_id', entity.entity_id)
        .in('status', ['approved_full', 'approved_partial']);

      const { data: asPredecessor } = await supabase
        .from('continuity_claims')
        .select('new_entity_id, reason, status, transfer_policy')
        .eq('old_entity_id', entity.entity_id)
        .in('status', ['approved_full', 'approved_partial']);

      // Check for whitewashing risk: recent rejected claims or laundering flags
      const { count: rejectedClaims } = await supabase
        .from('continuity_claims')
        .select('id', { count: 'exact', head: true })
        .eq('new_entity_id', entity.entity_id)
        .in('status', ['rejected', 'frozen_pending_dispute']);

      // Inherited dispute burden from predecessors
      let inheritedDisputes = 0;
      if (asSuccessor && asSuccessor.length > 0) {
        for (const pred of asSuccessor) {
          const { count } = await supabase
            .from('disputes')
            .select('id', { count: 'exact', head: true })
            .eq('entity_id', pred.old_entity_id)
            .in('status', ['open', 'under_review']);
          inheritedDisputes += (count || 0);
        }
      }

      continuity = {
        principal: principal ? {
          principal_id: principal.principal_id,
          principal_type: principal.principal_type,
          display_name: principal.display_name,
        } : null,
        status: asSuccessor?.length > 0 ? asSuccessor[0].status : 'original',
        mode: asSuccessor?.length > 0 ? 'successor' : (asPredecessor?.length > 0 ? 'predecessor' : 'standalone'),
        lineage_depth: (asSuccessor?.length || 0) + (asPredecessor?.length || 0),
        inherits_historical_establishment: asSuccessor?.some(c => c.transfer_policy === 'full') || false,
        inherits_unresolved_disputes: inheritedDisputes > 0,
        inherited_dispute_count: inheritedDisputes,
        whitewashing_risk: (rejectedClaims || 0) > 0,
        predecessors: (asSuccessor || []).map(c => ({ from: c.old_entity_id, reason: c.reason, transfer: c.transfer_policy })),
        successors: (asPredecessor || []).map(c => ({ to: c.new_entity_id, reason: c.reason, transfer: c.transfer_policy })),
      };
    } catch (e) {
      const isMissingTable = e.message?.includes('does not exist') || e.message?.includes('relation');
      if (isMissingTable) {
        // Non-truth-bearing: safe to degrade — EP-IX tables not yet deployed.
        // Continuity data is additive; its absence does not corrupt trust state.
        continuity = {
          _unavailable: true,
          reason: 'ep_ix_tables_not_deployed',
        };
      } else {
        // Trust-bearing: EP-IX lookup failed for a non-schema reason.
        // Continuity includes whitewashing detection and inherited disputes —
        // silently skipping this could hide trust manipulation.
        throw new TrustEvaluationError(
          `EP-IX continuity lookup failed: ${e.message}`,
          { code: 'CONTINUITY_LOOKUP_FAILED', cause: e }
        );
      }
    }
  }

  return {
    // Entity identity
    entity_id: entity.entity_id,
    display_name: entity.display_name,
    entity_type: entity.entity_type,
    category: entity.category,

    // Trust profile (THE canonical truth)
    profile: profile.profile,
    score: profile.score,
    confidence: profile.confidence,
    effectiveEvidence: profile.effectiveEvidence,
    qualityGatedEvidence: profile.qualityGatedEvidence,
    uniqueSubmitters: profile.uniqueSubmitters,
    receiptCount: profile.receiptCount,
    anomaly: profile.anomaly,
    dispute_dampened_count: profile.dispute_dampened_count ?? 0,

    // Context
    contextUsed,

    // Historical establishment
    establishment,

    // Disputes
    disputes,

    // EP-IX: Identity continuity
    continuity,

    // Policy evaluation (if requested)
    policyResult: policyResult ? {
      pass: policyResult.pass && (policyResult.softwarePass !== false),
      policyName,
      trustPass: policyResult.pass,
      softwarePass: policyResult.softwarePass ?? null,
      failures: policyResult.failures,
      warnings: policyResult.warnings,
      softwareChecks: policyResult.softwareChecks ?? null,
    } : null,

    // Software metadata
    softwareMeta: entity.software_meta || null,

    // Raw entity (for routes that need additional fields)
    _entity: entity,
    _protocol_version: 'EP/1.1-v2',
  };
}

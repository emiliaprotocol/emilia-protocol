/**
 * EMILIA Protocol — Domain-Specific Trust Scoring
 *
 * Trust is not a scalar. An agent excellent at financial transactions
 * may be unreliable at creative tasks. Domain scoring computes per-domain
 * behavioral confidence using the context.task_type field on receipts.
 *
 * Domain taxonomy:
 *   financial       — monetary transactions, payments, billing
 *   code_execution  — running code, deployments, infrastructure changes
 *   communication   — sending messages, emails, notifications on behalf of users
 *   delegation      — acting under delegated authority
 *   infrastructure  — managing systems, cloud resources, files
 *   content_creation — generating content, writing, editing
 *   data_access     — reading/writing data stores, databases, APIs
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import { logger } from './logger.js';

const KNOWN_DOMAINS = [
  'financial',
  'code_execution',
  'communication',
  'delegation',
  'infrastructure',
  'content_creation',
  'data_access',
];

const BEHAVIOR_WEIGHTS = {
  completed:         1.0,
  retried_same:      0.7,
  retried_different: 0.6,
  abandoned:         0.1,
  disputed:          0.0,
};

/**
 * Compute domain-specific trust scores for an entity.
 *
 * @param {string} entityId
 * @param {string[]|null} domains - Specific domains to compute. If null, computes all.
 * @returns {Promise<Object>} { entity_id, domains: { [domain]: { confidence, evidence_count, completion_rate, dispute_rate } } }
 */
export async function getDomainScores(entityId, domains = null) {
  const supabase = getServiceClient();

  const targetDomains = domains?.length ? domains : KNOWN_DOMAINS;

  // Fetch receipts with context for this entity
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

  const { data: receipts, error } = await supabase
    .from('receipts')
    .select('id, agent_behavior, graph_weight, provenance_tier, context, created_at')
    .eq('entity_id', entityId)
    .gte('created_at', ninetyDaysAgo)
    .not('agent_behavior', 'is', null);

  if (error) {
    logger.error('[domain-scoring] fetch error:', error.message);
    return { entity_id: entityId, domains: {} };
  }

  const allReceipts = receipts || [];

  // Group receipts by domain (from context.task_type)
  const byDomain = {};
  for (const domain of targetDomains) {
    byDomain[domain] = [];
  }

  for (const receipt of allReceipts) {
    const taskType = receipt.context?.task_type;
    if (taskType && byDomain[taskType] !== undefined) {
      byDomain[taskType].push(receipt);
    }
  }

  // Compute scores per domain
  const result = {};
  for (const domain of targetDomains) {
    const domainReceipts = byDomain[domain];
    if (!domainReceipts.length) continue;

    const total = domainReceipts.length;
    const behaviors = domainReceipts.map(r => r.agent_behavior);

    const completions = behaviors.filter(b => b === 'completed').length;
    const disputes = behaviors.filter(b => b === 'disputed').length;

    // Effective evidence for this domain
    const PROVENANCE_WEIGHTS = { unilateral: 0.6, bilateral: 1.0, verified: 1.3, anchored: 1.5 };
    let effectiveEvidence = 0;
    for (const r of domainReceipts) {
      const pw = PROVENANCE_WEIGHTS[r.provenance_tier] || 0.6;
      const bw = BEHAVIOR_WEIGHTS[r.agent_behavior] ?? 0.5;
      effectiveEvidence += (r.graph_weight || 1.0) * pw * bw;
    }

    // Confidence thresholds (same as global scoring)
    let confidence = 'pending';
    if (effectiveEvidence >= 100) confidence = 'established';
    else if (effectiveEvidence >= 40)  confidence = 'high';
    else if (effectiveEvidence >= 15)  confidence = 'moderate';
    else if (effectiveEvidence >= 5)   confidence = 'low';

    result[domain] = {
      confidence,
      evidence_count: total,
      effective_evidence: Math.round(effectiveEvidence * 100) / 100,
      completion_rate: Math.round((completions / total) * 100),
      dispute_rate: Math.round((disputes / total) * 100),
    };
  }

  return { entity_id: entityId, domains: result };
}

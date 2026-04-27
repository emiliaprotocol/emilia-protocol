/**
 * EMILIA Protocol — Sybil Resistance Layer
 *
 * Three layers of defense against fake entities and synthetic transactions:
 * 1. Registration friction (rate limiting, validation)
 * 2. Receipt graph analysis (closed loops, thin graphs, velocity)
 * 3. Protocol design (no self-scoring, rolling window, dampening)
 *
 * @license Apache-2.0
 */
import { logger } from './logger.js';

// =============================================================================
// REGISTRATION RATE LIMITING
// =============================================================================

const REGISTRATION_LIMITS = {
  maxEntitiesPerKeyPerDay: 5,
  maxEntitiesPerKeyTotal: 50,
};

/**
 * Check if an entity owner has exceeded registration limits.
 * @param {Object} supabase - Supabase service client
 * @param {string} ownerId - The owner_id to check
 * @returns {{ allowed: boolean, reason?: string }}
 */
export async function checkRegistrationLimits(supabase, ownerId) {
  // Count entities created by this owner in the last 24 hours
  const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const { count: dailyCount } = await supabase
    .from('entities')
    .select('id', { count: 'exact', head: true })
    .eq('owner_id', ownerId)
    .gte('created_at', dayAgo);

  if (dailyCount >= REGISTRATION_LIMITS.maxEntitiesPerKeyPerDay) {
    return {
      allowed: false,
      reason: `Rate limit: max ${REGISTRATION_LIMITS.maxEntitiesPerKeyPerDay} entities per day per owner`,
    };
  }

  // Count total entities for this owner
  const { count: totalCount } = await supabase
    .from('entities')
    .select('id', { count: 'exact', head: true })
    .eq('owner_id', ownerId);

  if (totalCount >= REGISTRATION_LIMITS.maxEntitiesPerKeyTotal) {
    return {
      allowed: false,
      reason: `Limit: max ${REGISTRATION_LIMITS.maxEntitiesPerKeyTotal} entities per owner`,
    };
  }

  return { allowed: true };
}

// =============================================================================
// RECEIPT GRAPH ANALYSIS
// =============================================================================

/**
 * Detect closed-loop scoring (A scores B, B scores A).
 * @param {Object} supabase
 * @param {string} entityId - Entity being scored
 * @param {string} submittedBy - Entity submitting the receipt
 * @returns {{ flagged: boolean, reason?: string }}
 */
export async function detectClosedLoop(supabase, entityId, submittedBy) {
  // Check if the entity being scored has also scored the submitter
  const { data: reverseReceipts } = await supabase
    .from('receipts')
    .select('id')
    .eq('entity_id', submittedBy)
    .eq('submitted_by', entityId)
    .limit(1);

  if (reverseReceipts && reverseReceipts.length > 0) {
    return {
      flagged: true,
      reason: 'closed_loop',
      detail: `Bidirectional scoring detected: ${entityId} and ${submittedBy} score each other`,
    };
  }

  return { flagged: false };
}

/**
 * Check receipt submission velocity for anomalies.
 * @param {Object} supabase
 * @param {string} submittedBy - UUID of submitting entity
 * @returns {{ flagged: boolean, reason?: string }}
 */
export async function detectVelocitySpike(supabase, submittedBy) {
  // Count receipts submitted in the last hour
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

  const { count: hourlyCount } = await supabase
    .from('receipts')
    .select('id', { count: 'exact', head: true })
    .eq('submitted_by', submittedBy)
    .gte('created_at', hourAgo);

  // More than 100 receipts per hour is suspicious
  if (hourlyCount >= 100) {
    return {
      flagged: true,
      reason: 'velocity_spike',
      detail: `${hourlyCount} receipts submitted in the last hour`,
    };
  }

  return { flagged: false };
}

/**
 * Analyze the receipt graph for an entity to detect thin-graph patterns.
 * An entity should have receipts from multiple unique submitters to be credible.
 *
 * @param {Object} supabase
 * @param {string} entityId - UUID of entity to analyze
 * @returns {{ uniqueSubmitters: number, thinGraph: boolean, flags: string[] }}
 */
export async function analyzeReceiptGraph(supabase, entityId) {
  const flags = [];

  // Count unique submitters
  const { data: submitters } = await supabase
    .from('receipts')
    .select('submitted_by')
    .eq('entity_id', entityId);

  const uniqueSubmitters = new Set((submitters || []).map(r => r.submitted_by)).size;
  const totalReceipts = (submitters || []).length;

  // Thin graph: many receipts but few unique submitters
  if (totalReceipts >= 5 && uniqueSubmitters < 3) {
    flags.push('thin_graph');
  }

  // Single source: all receipts from one entity
  if (totalReceipts >= 3 && uniqueSubmitters === 1) {
    flags.push('single_source');
  }

  // Check for cluster patterns: does this entity only interact with a small group?
  if (uniqueSubmitters >= 2 && uniqueSubmitters <= 3 && totalReceipts >= 20) {
    // Check if these submitters also mostly score each other
    const submitterIds = [...new Set((submitters || []).map(r => r.submitted_by))];

    /* c8 ignore next -- submitterIds.length is always > 0 when uniqueSubmitters >= 2 */
    if (submitterIds.length > 0) {
      const { count: intraGroupReceipts } = await supabase
        .from('receipts')
        .select('id', { count: 'exact', head: true })
        .in('entity_id', submitterIds)
        .in('submitted_by', [entityId, ...submitterIds]);

      // If most receipts among this group are between each other, flag it
      if (intraGroupReceipts > totalReceipts * 0.8) {
        flags.push('cluster_detected');
      }
    }
  }

  return {
    uniqueSubmitters,
    thinGraph: flags.includes('thin_graph') || flags.includes('single_source'),
    flags,
  };
}

/**
 * Split an array into chunks of at most `size` elements.
 * @param {Array} arr
 * @param {number} size
 * @returns {Array[]}
 */
function chunk(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

/**
 * Retroactively apply graph weight penalties to existing receipts.
 * When fraud is detected between an entity/submitter pair, their historical
 * receipts must also carry the penalty — otherwise the protocol allows trust
 * built before detection to persist at full weight.
 *
 * Principle: never increase existing weight retroactively. Only reduce.
 *
 * @returns {{ updated: number, failed: number, partial_failure?: boolean, failed_ids?: string[] }}
 */
async function retroactivelyApplyGraphWeight(supabase, entityId, submittedBy, newWeight) {
  let updated = 0;
  let failed = 0;
  const failedIds = [];

  try {
    // Fetch existing receipts between this pair
    const { data: existing } = await supabase
      .from('receipts')
      .select('id, graph_weight')
      .eq('entity_id', entityId)
      .eq('submitted_by', submittedBy)
      .gt('graph_weight', newWeight); // Only update those with higher weight

    if (!existing || existing.length === 0) return { updated: 0, failed: 0 };

    const ids = existing.map(r => r.id);

    for (const batch of chunk(ids, 50)) {
      try {
        const { error } = await supabase
          .from('receipts')
          .update({ graph_weight: newWeight })
          .in('id', batch);
        if (error) throw error;
        updated += batch.length;
      } catch (e) {
        failed += batch.length;
        for (const id of batch) failedIds.push(id);
        logger.error('Retroactive weight update chunk failed:', e.message, { entityId, submittedBy, newWeight, batchSize: batch.length });
      }
    }
  } catch (e) {
    logger.error('Retroactive graph weight fetch failed:', e.message);
    return { updated: 0, failed: -1 }; // -1 = fetch error
  }

  // Audit trail — record every retroactive adjustment in fraud_flags
  if (updated > 0 || failed > 0) {
    try {
      await supabase.from('fraud_flags').insert({
        entity_id: entityId,
        submitted_by: submittedBy,
        flags: ['retroactive_weight_adjustment'],
        detail: JSON.stringify({
          new_weight: newWeight,
          receipts_updated: updated,
          receipts_failed: failed,
          timestamp: new Date().toISOString(),
        }),
        blocked: false,
      });
    } catch (e) {
      // Audit failure is non-fatal — but the partial-failure record is the
      // operator's only signal that retroactive weight bumps had a hole.
      // Silently dropping it makes the failure impossible to investigate
      // post-hoc. Log so SIEM picks it up.
      logger.warn('[sybil] fraud_flags audit insert failed (retroactive partial):', e?.message);
    }
  }

  if (failed > 0) {
    return { updated, failed, partial_failure: true, failed_ids: failedIds };
  }

  return { updated, failed };
}

/**
 * Run all fraud checks before accepting a receipt.
 * Returns { allowed: true } or { allowed: false, flags: [...] }.
 *
 * @param {Object} supabase
 * @param {string} entityId - Entity being scored (UUID)
 * @param {string} submittedBy - Entity submitting (UUID)
 */
export async function runReceiptFraudChecks(supabase, entityId, submittedBy) {
  const flags = [];

  // Check closed loop
  const loop = await detectClosedLoop(supabase, entityId, submittedBy);
  if (loop.flagged) flags.push(loop);

  // Check velocity
  const velocity = await detectVelocitySpike(supabase, submittedBy);
  if (velocity.flagged) flags.push(velocity);

  // FIX #5: Actually run graph analysis (was diagnostic-only before)
  const graph = await analyzeReceiptGraph(supabase, entityId);
  if (graph.thinGraph) {
    flags.push({ flagged: true, reason: 'thin_graph', detail: `Only ${graph.uniqueSubmitters} unique submitters` });
  }
  if (graph.flags.includes('cluster_detected')) {
    flags.push({ flagged: true, reason: 'cluster_detected', detail: 'Suspicious cluster pattern detected' });
  }

  // Velocity spikes and cluster detection block the receipt
  const blocked = flags.some(f => f.reason === 'velocity_spike' || f.reason === 'cluster_detected');

  // Compute graph credibility weight
  let graphWeight = 1.0;
  // Closed loop: A scores B AND B scores A — reduce weight
  if (loop.flagged) graphWeight *= 0.4;
  // Thin graph: few unique submitters
  if (graph.thinGraph) graphWeight = Math.min(graphWeight, 0.5);
  // Single source: all receipts from one submitter
  if (graph.flags.includes('single_source')) graphWeight = Math.min(graphWeight, 0.3);
  // Cluster: coordinated fake activity
  if (graph.flags.includes('cluster_detected')) graphWeight = Math.min(graphWeight, 0.1);

  if (flags.length > 0) {
    try {
      await supabase.from('fraud_flags').insert({
        entity_id: entityId,
        submitted_by: submittedBy,
        flags: flags.map(f => f.reason),
        detail: JSON.stringify(flags),
        blocked,
      });
    } catch (e) {
      logger.error('Failed to log fraud flag:', e);
    }
  }

  // Retroactively apply graph weight to all existing receipts between this pair.
  // Historical receipts from fraud pairs must reflect the new weight.
  // Only reduce — never increase retroactively.
  if (graphWeight < 1.0) {
    const retroResult = await retroactivelyApplyGraphWeight(supabase, entityId, submittedBy, graphWeight);
    if (retroResult.partial_failure) {
      logger.error('Partial retroactive weight failure — operator action required:', {
        entityId,
        submittedBy,
        newWeight: graphWeight,
        failedIds: retroResult.failed_ids,
      });
      try {
        await supabase.from('fraud_flags').insert({
          entity_id: entityId,
          submitted_by: submittedBy,
          flags: ['retroactive_weight_partial_failure'],
          detail: JSON.stringify({
            new_weight: graphWeight,
            failed_ids: retroResult.failed_ids,
            timestamp: new Date().toISOString(),
          }),
          blocked: false,
        });
      } catch (e) {
        // Same rationale as above — partial-failure audit is the only
        // operator signal that retroactive weight bumps were incomplete.
        logger.warn('[sybil] fraud_flags audit insert failed (cluster partial):', e?.message);
      }
    }
  }

  return {
    allowed: !blocked,
    flags: flags.map(f => f.reason),
    graphWeight,
    detail: blocked ? 'Receipt blocked due to suspicious activity' : null,
  };
}

/**
 * DEPRECATED: Use is_entity_established() SQL function or compute from effective evidence.
 * This function uses raw receipt count, not effective evidence.
 * Kept for backward compat but should be replaced by callers.
 */
export function isEstablished(receiptCount, uniqueSubmitters) {
  return receiptCount >= 5 && uniqueSubmitters >= 3;
}

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

  return {
    uniqueSubmitters,
    thinGraph: flags.includes('thin_graph') || flags.includes('single_source'),
    flags,
  };
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

  // Compute graph credibility weight (0.5 for thin graphs, 1.0 for healthy graphs)
  let graphWeight = 1.0;
  if (graph.thinGraph) graphWeight = 0.5;
  if (graph.flags.includes('single_source')) graphWeight = 0.3;
  if (graph.flags.includes('cluster_detected')) graphWeight = 0.1;

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
      console.error('Failed to log fraud flag:', e);
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

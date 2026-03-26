/**
 * EP Attribution Chain
 *
 * Computes how receipt outcomes propagate up a delegation chain.
 *
 * The protocol axiom: when an agent acts under delegation, the outcome is not
 * theirs alone. The human who authorized the agent made a judgment call. That
 * judgment — did they choose a well-behaved agent? — belongs in the ledger too.
 *
 * Primary attribution:   agent entity (full weight, 1.0)
 * Secondary attribution: principal (weak signal, 0.15 — delegation authority)
 *
 * The weak signal is deliberately weak. A single delegation gone wrong should
 * not destroy a principal's trust profile. But a pattern of authorizing
 * misbehaving agents should be legible to the system.
 *
 * Receipt chain: "Human A authorized Agent B to use Tool C. Outcome: X."
 *   - Attaches to Agent B's behavioral record at full weight
 *   - Creates a 0.15-weight signal on Human A's delegation authority
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';

/** Weight applied to the principal's delegation authority signal. */
const PRINCIPAL_DELEGATION_WEIGHT = 0.15;

/**
 * Build an attribution chain from a receipt.
 *
 * Reads receipt.delegation_id (if present) and receipt.context.principal_id
 * (if present) to determine whether a principal should receive a secondary
 * attribution signal.
 *
 * @param {Object} receipt - The receipt object as submitted or returned from DB
 * @param {string} receipt.entity_id - The agent entity's slug or UUID
 * @param {string} [receipt.delegation_id] - Optional delegation ID
 * @param {Object} [receipt.context] - Optional context object
 * @param {string} [receipt.context.principal_id] - Optional principal identifier
 * @returns {Array<{ role: string, entity_id: string, weight: number }>}
 */
export function buildAttributionChain(receipt) {
  const chain = [
    {
      role: 'agent',
      entity_id: receipt.entity_id,
      weight: 1.0,
    },
  ];

  // Only extend the chain if a delegation was declared and a principal is
  // identifiable. We require both: a bare context.principal_id with no
  // delegation_id is not sufficient to create accountability — anyone could
  // claim they acted on behalf of someone. The delegation record is the proof.
  const principalId =
    receipt.context?.principal_id || null;

  const hasDelegation = !!(receipt.delegation_id);

  if (hasDelegation && principalId) {
    chain.push({
      role: 'principal',
      entity_id: principalId,
      weight: PRINCIPAL_DELEGATION_WEIGHT,
      delegation_id: receipt.delegation_id,
    });
  }

  return chain;
}

/**
 * Determine whether a receipt outcome is positive.
 *
 * Positive: completed tasks, high-composite receipts (≥ 70), good behavior.
 * Negative: abandoned, disputed, low-composite receipts (< 50).
 * Neutral receipts return true (erring toward positive for judgment purposes).
 *
 * @param {Object} receipt
 * @returns {boolean}
 */
function isPositiveOutcome(receipt) {
  // Explicit behavioral outcome takes precedence
  if (receipt.agent_behavior) {
    const positive = ['completed'];
    const negative = ['abandoned', 'disputed'];
    if (positive.includes(receipt.agent_behavior)) return true;
    if (negative.includes(receipt.agent_behavior)) return false;
    // retried_same, retried_different: treat as neutral-positive
    return true;
  }

  // Fall back to composite score
  if (receipt.composite_score != null) {
    return receipt.composite_score >= 70;
  }

  // No behavioral signal and no composite — treat as neutral-positive
  return true;
}

/**
 * Apply the attribution chain after a receipt has been written.
 *
 * For the agent entry: the receipt write is already handled by the main
 * submission flow — we do not re-write it here.
 *
 * For the principal entry: if present, we write a synthetic delegation_judgment
 * signal to the principal_delegation_signals table. This is NOT a full receipt.
 * It is a lightweight accountability row that feeds getDelegationJudgmentScore.
 *
 * This function is designed to be called fire-and-forget (non-blocking).
 * Errors are caught and logged; they must never surface to the caller.
 *
 * @param {Object} receipt - The receipt object returned from the DB insert
 * @param {Array}  attributionChain - From buildAttributionChain()
 * @param {import('@supabase/supabase-js').SupabaseClient} [supabase] - Optional; created if omitted
 * @returns {Promise<{ agent_attributed: boolean, principal_attributed: boolean, signals_written: number }>}
 */
export async function applyAttributionChain(receipt, attributionChain, supabase) {
  const db = supabase || getServiceClient();
  const result = { agent_attributed: true, principal_attributed: false, signals_written: 0 };

  for (const entry of attributionChain) {
    if (entry.role === 'agent') {
      // Agent attribution is handled by the main receipt write path.
      // We mark it as attributed here for the return value only.
      result.agent_attributed = true;
      result.signals_written += 1;
      continue;
    }

    if (entry.role === 'principal') {
      try {
        const outcomePositive = isPositiveOutcome(receipt);

        const { error } = await db
          .from('principal_delegation_signals')
          .insert({
            principal_id: entry.entity_id,
            agent_entity_id: receipt.entity_id,
            receipt_id: receipt.receipt_id,
            outcome_positive: outcomePositive,
            weight: entry.weight,
          });

        if (error) {
          // Graceful degradation: if the table does not yet exist (pre-migration),
          // log a warning but do not throw. Attribution is best-effort.
          const isMissingTable =
            error.code === '42P01' ||
            error.message?.includes('does not exist') ||
            error.message?.includes('relation');

          if (isMissingTable) {
            console.warn(
              '[EP Attribution] principal_delegation_signals table not yet created — ' +
              'run migration 026_attribution_chain.sql to enable principal attribution.'
            );
          } else {
            console.error('[EP Attribution] Failed to write delegation signal:', error.message);
          }
        } else {
          result.principal_attributed = true;
          result.signals_written += 1;
        }
      } catch (err) {
        // Never propagate — attribution is a background concern
        console.error('[EP Attribution] Unexpected error writing principal signal:', err.message);
      }
    }
  }

  return result;
}

/**
 * Compute a principal's delegation authority score.
 *
 * Answers: "Does this principal consistently authorize well-behaved agents?"
 *
 * Score formula:
 *   - Base: fraction of delegations that produced positive outcomes
 *   - Weighted by the signal weight (currently always 0.15, but future-proofed)
 *   - Agents with zero delegations: score null (no judgment yet)
 *
 * @param {string} principalId - Principal entity ID or human identifier
 * @param {import('@supabase/supabase-js').SupabaseClient} [supabase]
 * @returns {Promise<{
 *   judgment_score: number|null,
 *   agents_authorized: number,
 *   good_outcome_rate: number|null,
 *   total_signals: number,
 *   positive_signals: number,
 *   negative_signals: number,
 * }>}
 */
export async function getDelegationJudgmentScore(principalId, supabase) {
  const db = supabase || getServiceClient();

  try {
    const { data: signals, error } = await db
      .from('principal_delegation_signals')
      .select('agent_entity_id, outcome_positive, weight')
      .eq('principal_id', principalId);

    if (error) {
      const isMissingTable =
        error.code === '42P01' ||
        error.message?.includes('does not exist') ||
        error.message?.includes('relation');

      if (isMissingTable) {
        console.warn('[EP Attribution] principal_delegation_signals table not yet created.');
      }

      return {
        judgment_score: null,
        agents_authorized: 0,
        good_outcome_rate: null,
        total_signals: 0,
        positive_signals: 0,
        negative_signals: 0,
      };
    }

    if (!signals || signals.length === 0) {
      return {
        judgment_score: null,
        agents_authorized: 0,
        good_outcome_rate: null,
        total_signals: 0,
        positive_signals: 0,
        negative_signals: 0,
      };
    }

    const totalSignals = signals.length;
    const positiveSignals = signals.filter(s => s.outcome_positive).length;
    const negativeSignals = totalSignals - positiveSignals;
    const goodOutcomeRate = totalSignals > 0 ? positiveSignals / totalSignals : null;

    // Unique agents authorized by this principal
    const agentsAuthorized = new Set(signals.map(s => s.agent_entity_id)).size;

    // Weighted judgment score: weight each outcome by the declared signal weight.
    // This future-proofs for heterogeneous weights (e.g. high-value delegations
    // weighted more heavily than low-value ones).
    const weightedPositive = signals
      .filter(s => s.outcome_positive)
      .reduce((sum, s) => sum + (s.weight ?? PRINCIPAL_DELEGATION_WEIGHT), 0);

    const weightedTotal = signals
      .reduce((sum, s) => sum + (s.weight ?? PRINCIPAL_DELEGATION_WEIGHT), 0);

    const judgmentScore = weightedTotal > 0
      ? Math.round((weightedPositive / weightedTotal) * 100) / 100
      : null;

    return {
      judgment_score: judgmentScore,
      agents_authorized: agentsAuthorized,
      good_outcome_rate: goodOutcomeRate != null
        ? Math.round(goodOutcomeRate * 1000) / 1000
        : null,
      total_signals: totalSignals,
      positive_signals: positiveSignals,
      negative_signals: negativeSignals,
    };
  } catch (err) {
    console.error('[EP Attribution] getDelegationJudgmentScore failed:', err.message);
    return {
      judgment_score: null,
      agents_authorized: 0,
      good_outcome_rate: null,
      total_signals: 0,
      positive_signals: 0,
      negative_signals: 0,
    };
  }
}

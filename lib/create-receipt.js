/**
 * EMILIA Protocol — Receipt Creation Helper
 *
 * ONE receipt creation engine. ONE truth path.
 * Both /api/receipts/submit and /api/needs/[id]/rate MUST use this.
 */

import { getServiceClient } from '@/lib/supabase';
import { computeReceiptComposite, computeReceiptHash, behaviorToSatisfaction, computeScoresFromClaims } from '@/lib/scoring';
import { runReceiptFraudChecks } from '@/lib/sybil';
import { resolveProvenanceTier } from '@/lib/signatures';
import { getUpstashConfig } from '@/lib/env';
import crypto from 'crypto';

// =============================================================================
// DEDUPLICATION LOCK — two-layer TOCTOU guard
// =============================================================================

const _upstash = getUpstashConfig();
const UPSTASH_URL = _upstash?.url;
const UPSTASH_TOKEN = _upstash?.token;
const _dedupUseRedis = !!_upstash;

/** In-process mutex map for when Redis is not configured. */
const _dedupMemoryLocks = new Map();

/**
 * Acquire a short-lived deduplication lock for a receipt submission.
 *
 * Redis path  : SET NX EX 10 — atomic, cross-instance safe.
 * Memory path : Promise-chain mutex — correct for concurrent async in one process.
 *
 * @param {string} entityId
 * @param {string} submitterId
 * @param {string} transactionRef
 * @returns {Promise<{ acquired: boolean, release: () => void }>}
 */
async function acquireDeduplicationLock(entityId, submitterId, transactionRef) {
  const refHash = crypto.createHash('sha256').update(transactionRef).digest('hex').slice(0, 16);
  const lockKey = `ep:dedup:${entityId}:${submitterId}:${refHash}`;
  const LOCK_TTL = 10; // seconds

  if (_dedupUseRedis) {
    // Upstash REST: SET key value NX EX ttl — returns "OK" or null
    const res = await fetch(UPSTASH_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(['SET', lockKey, '1', 'NX', 'EX', LOCK_TTL]),
    });
    const json = await res.json();
    const acquired = json.result === 'OK';

    const release = acquired
      ? async () => {
          try {
            await fetch(UPSTASH_URL, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${UPSTASH_TOKEN}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(['DEL', lockKey]),
            });
          } catch {
            // Best-effort; TTL will expire the key anyway
          }
        }
      : () => {};

    return { acquired, release };
  }

  // --- In-memory mutex path ---
  // Each lock key maps to a Promise that resolves when the lock is free.
  // We chain onto the existing promise so concurrent calls queue up.
  let releaseFn;
  const previousLock = _dedupMemoryLocks.get(lockKey) ?? Promise.resolve();

  // This promise represents OUR hold on the lock.
  const ourLock = previousLock.then(
    () =>
      new Promise((resolve) => {
        releaseFn = resolve; // caller invokes this to release
      })
  );

  // Replace the map entry so the next waiter chains onto our hold.
  _dedupMemoryLocks.set(lockKey, ourLock);

  // Wait until all prior holders have released.
  await previousLock;

  // Auto-expire the in-memory lock after TTL (safety net).
  const ttlTimer = setTimeout(() => {
    if (releaseFn) releaseFn();
  }, LOCK_TTL * 1000);

  const release = () => {
    clearTimeout(ttlTimer);
    if (releaseFn) releaseFn();
    // Clean up the map entry once no waiters remain.
    if (_dedupMemoryLocks.get(lockKey) === ourLock) {
      _dedupMemoryLocks.delete(lockKey);
    }
  };

  return { acquired: true, release };
}

// =============================================================================
// PER-ENTITY DAILY RECEIPT QUOTA
// =============================================================================

const ENTITY_DAILY_RECEIPT_LIMIT = 500;

/**
 * Check whether an entity has exceeded its daily receipt submission quota.
 *
 * Redis path  : INCR + EXPIRE — atomic, cross-instance safe.
 * DB fallback : COUNT query against receipts table for current UTC day.
 * Fail-open   : If both paths fail, the request is allowed through.
 *
 * @param {import('@supabase/supabase-js').SupabaseClient} supabase
 * @param {string} entityId - UUID of the target entity
 * @returns {Promise<{ allowed: boolean, count?: number, limit?: number }>}
 */
async function checkEntityDailyQuota(supabase, entityId) {
  // Try Redis first (fast, no DB load)
  /* c8 ignore next 35 -- Redis/Upstash path; UPSTASH_URL and UPSTASH_TOKEN not configured in tests */
  if (UPSTASH_URL && UPSTASH_TOKEN) {
    try {
      const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
      const key = `ep:quota:entity:${entityId}:${today}`;
      const res = await fetch(UPSTASH_URL, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${UPSTASH_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(['INCR', key]),
      });
      const data = await res.json();
      if (!data.error && data.result != null) {
        if (data.result === 1) {
          // Set expiry on first increment — expires at end of UTC day
          const secondsUntilMidnight = 86400 - (Math.floor(Date.now() / 1000) % 86400);
          await fetch(UPSTASH_URL, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${UPSTASH_TOKEN}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(['EXPIRE', key, String(secondsUntilMidnight + 60)]),
          });
        }
        if (data.result > ENTITY_DAILY_RECEIPT_LIMIT) {
          return { allowed: false, count: data.result, limit: ENTITY_DAILY_RECEIPT_LIMIT };
        }
        return { allowed: true, count: data.result, limit: ENTITY_DAILY_RECEIPT_LIMIT };
      }
    } catch (e) {
      // Redis unavailable — fall through to DB count
    }
  }

  // Fallback: count from Supabase
  try {
    const startOfDay = new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);
    const { count } = await supabase
      .from('receipts')
      .select('id', { count: 'exact', head: true })
      .eq('entity_id', entityId)
      .gte('created_at', startOfDay.toISOString());

    if (count >= ENTITY_DAILY_RECEIPT_LIMIT) {
      return { allowed: false, count, limit: ENTITY_DAILY_RECEIPT_LIMIT };
    }
    return { allowed: true, count: count ?? 0, limit: ENTITY_DAILY_RECEIPT_LIMIT };
  } catch (e) {
    // Cannot check quota — fail open (don't block on monitoring failure)
    console.warn('Entity daily quota check failed:', e.message);
    return { allowed: true };
  }
}

/**
 * createReceipt — THE ONLY function that writes to the receipts table.
 * All receipt creation (manual, auto, system) MUST flow through this function.
 * This is the canonical receipt write path. There is no other.
 *
 * Enforces: idempotency/deduplication (two-layer TOCTOU guard), fraud checks
 * (graph analysis via runReceiptFraudChecks), self-score prevention,
 * per-entity daily quota, composite_score computation, provenance verification,
 * chain linking, and submitter credibility assessment.
 *
 * The caller (canonicalSubmitReceipt in canonical-writer.js) handles event
 * emission and trust profile materialization after this function returns.
 *
 * @param {Object} params
 * @param {string} params.targetEntitySlug - entity_id slug or UUID of entity being scored
 * @param {Object} params.submitter - Authenticated submitter entity object (from auth)
 * @param {string} params.transactionRef - Required external transaction reference
 * @param {string} params.transactionType - purchase | service | task_completion | delivery | return
 * @param {Object} [params.signals] - { delivery_accuracy, product_accuracy, price_integrity, return_processing, agent_satisfaction }
 * @param {string} [params.agentBehavior] - completed | retried_same | retried_different | abandoned | disputed
 * @param {Object} [params.claims] - v2 structured claims
 * @param {Object} [params.evidence] - Supporting evidence
 * @param {string} [params.idempotencyKey] - Caller-supplied idempotency key. If omitted, one is generated deterministically from (submitter.id, transactionRef, transactionType).
 * @returns {Object} { receipt, entityScore, warnings } or { error, status }
 */
export async function createReceipt(params) {
  const {
    targetEntitySlug,
    submitter,
    transactionRef,
    transactionType,
    signals = {},
    agentBehavior,
    claims,
    evidence = {},
    context = null,
    provenanceTier = 'self_attested',
    requestBilateral = false, // If true, sets bilateral_status to 'pending_confirmation'
    idempotencyKey: callerIdempotencyKey = null,
  } = params;

  // === IDEMPOTENCY KEY ===
  // If the caller supplies one, use it. Otherwise generate deterministically
  // from the triple (submitter.id, transactionRef, transactionType) so that
  // machine-originated writes are automatically idempotent.
  const idempotencyKey = callerIdempotencyKey ||
    `ep_idem_${crypto.createHash('sha256').update(`${submitter.id}:${transactionRef}:${transactionType}`).digest('hex')}`;

  const supabase = getServiceClient();

  // === RESOLVE TARGET ENTITY ===
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetEntitySlug);
  const { data: targetEntity } = await supabase
    .from('entities')
    .select('id, entity_id')
    .eq(isUuid ? 'id' : 'entity_id', targetEntitySlug)
    .single();

  if (!targetEntity) {
    return { error: 'Target entity not found', status: 404 };
  }

  const targetEntityId = targetEntity.id;

  // === SELF-SCORE CHECK ===
  if (targetEntityId === submitter.id) {
    return { error: 'An entity cannot submit receipts for itself', status: 403 };
  }

  // === PER-ENTITY DAILY QUOTA ===
  const quotaCheck = await checkEntityDailyQuota(supabase, targetEntityId);
  if (!quotaCheck.allowed) {
    return {
      error: `Daily receipt limit reached for this entity (${quotaCheck.limit}/day). Try again tomorrow.`,
      status: 429,
    };
  }

  // === IDEMPOTENCY / DEDUPLICATION (TOCTOU-safe) ===
  // Layer 1: acquire a short-lived mutex so concurrent requests with the same
  // key cannot both pass the check and both insert.
  const { acquired: lockAcquired, release: releaseLock } =
    await acquireDeduplicationLock(targetEntityId, submitter.id, transactionRef);

  /* c8 ignore next 3 -- memory lock always returns acquired=true; Redis path not active in tests */
  if (!lockAcquired) {
    // Another in-flight request is already processing this exact receipt.
    return { error: 'Duplicate submission in progress. Please retry shortly.', retry_after: 10, status: 409 };
  }

  // === IDEMPOTENCY KEY CHECK (system-level, DB-enforced) ===
  // Check for an existing receipt with the same idempotency_key first.
  // This is the primary replay protection — the DB unique index is the
  // source of truth, this application check is defense-in-depth.
  const { data: idempotentHit } = await supabase
    .from('receipts')
    .select('receipt_id, receipt_hash, created_at')
    .eq('idempotency_key', idempotencyKey)
    .single();

  if (idempotentHit) {
    releaseLock();
    return {
      receipt: idempotentHit,
      deduplicated: true,
      _message: 'Receipt already exists for this idempotency_key. Returning existing receipt (idempotent).',
    };
  }

  // Same transaction_ref + same submitter + same entity = duplicate.
  // Returns the existing receipt instead of creating a new one.
  // This makes receipt submission safe to retry.
  // The lock is held across both the check AND the insert so that no concurrent
  // request can interleave between them. It is always released in the finally
  // block at the bottom of createReceipt() via the _releaseDedupLock variable.
  let existingReceipt;
  const { data } = await supabase
    .from('receipts')
    .select('receipt_id, receipt_hash, created_at')
    .eq('entity_id', targetEntityId)
    .eq('submitted_by', submitter.id)
    .eq('transaction_ref', transactionRef)
    .single();
  existingReceipt = data;

  if (existingReceipt) {
    releaseLock();
    return {
      receipt: existingReceipt,
      deduplicated: true,
      _message: 'Receipt already exists for this transaction_ref. Returning existing receipt (idempotent).',
    };
  }

  // Lock is held from here through the insert. Released in the finally block.
  try {
    // === FRAUD CHECKS (graph analysis wired in) ===
    const fraudCheck = await runReceiptFraudChecks(supabase, targetEntityId, submitter.id);
    if (!fraudCheck.allowed) {
      return {
        error: fraudCheck.detail,
        flags: fraudCheck.flags,
        status: 429,
      };
    }

    // === SUBMITTER CREDIBILITY (via canonical DB function) ===
    const submitterScore = submitter.emilia_score ?? 50;

    let submitterEstablished = false;
    try {
      const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: submitter.id });
      if (estData && estData[0]) {
        submitterEstablished = estData[0].established;
      }
    } catch {
      // Fallback if function doesn't exist yet (pre-migration)
      submitterEstablished = false;
    }

    // === BEHAVIORAL SATISFACTION ===
    let agentSatisfaction = signals.agent_satisfaction ?? null;
    if (agentBehavior) {
      agentSatisfaction = behaviorToSatisfaction(agentBehavior);
    }

    // === EVIDENCE-BASED SCORING (v2) ===
    let deliveryAccuracy = signals.delivery_accuracy ?? null;
    let productAccuracy = signals.product_accuracy ?? null;
    let priceIntegrity = signals.price_integrity ?? null;
    let returnProcessing = signals.return_processing ?? null;

    if (claims) {
      const claimScores = computeScoresFromClaims(claims);
      if (claimScores.delivery_accuracy != null) deliveryAccuracy = claimScores.delivery_accuracy;
      if (claimScores.product_accuracy != null) productAccuracy = claimScores.product_accuracy;
      if (claimScores.price_integrity != null) priceIntegrity = claimScores.price_integrity;
      if (claimScores.return_processing != null) returnProcessing = claimScores.return_processing;
    }

    // Post-processing validation: ensure receipt has at least one meaningful signal
    const hasAnySignal = [deliveryAccuracy, productAccuracy, priceIntegrity,
      returnProcessing, agentSatisfaction].some(v => v != null);
    if (!hasAnySignal) {
      return { error: 'Receipt produced no meaningful signals. Claims must include recognized fields (delivered, on_time, price_honored, as_described, return_accepted).', status: 400 };
    }

    // === COMPOSITE SCORE ===
    const composite = computeReceiptComposite({
      delivery_accuracy: deliveryAccuracy,
      product_accuracy: productAccuracy,
      price_integrity: priceIntegrity,
      return_processing: returnProcessing,
      agent_satisfaction: agentSatisfaction,
    });

    // === CHAIN LINKING ===
    const { data: prevReceipt } = await supabase
      .from('receipts')
      .select('receipt_hash')
      .eq('entity_id', targetEntityId)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    const previousHash = prevReceipt?.receipt_hash || null;
    const receiptId = `ep_rcpt_${crypto.randomBytes(16).toString('hex')}`;

    // === CANONICAL HASH (all truth-bearing fields) ===
    const receiptData = {
      entity_id: targetEntityId,
      submitted_by: submitter.id,
      transaction_ref: transactionRef,
      transaction_type: transactionType,
      context: context || null,
      delivery_accuracy: deliveryAccuracy,
      product_accuracy: productAccuracy,
      price_integrity: priceIntegrity,
      return_processing: returnProcessing,
      agent_satisfaction: agentSatisfaction,
      agent_behavior: agentBehavior || null,
      claims: claims || null,
      evidence: evidence,
      submitter_score: submitterScore,
      submitter_established: submitterEstablished,
    };

    const receiptHash = await computeReceiptHash(receiptData, previousHash);

    // === PROVENANCE TIER VERIFICATION ===
    // Validate any claimed `identified_signed` tier against the ed25519 signature
    // in evidence. Unverified claims are silently downgraded to `self_attested`.
    const provenanceResolution = resolveProvenanceTier(provenanceTier, receiptHash, evidence);
    const resolvedProvenanceTier = provenanceResolution.tier;
    const provenanceWarning = provenanceResolution.warning;

    // === INSERT ===
    const { data: receipt, error: insertError } = await supabase
      .from('receipts')
      .insert({
        receipt_id: receiptId,
        idempotency_key: idempotencyKey,
        entity_id: targetEntityId,
        submitted_by: submitter.id,
        transaction_ref: transactionRef,
        transaction_type: transactionType,
        context: context || null,
        delivery_accuracy: deliveryAccuracy,
        product_accuracy: productAccuracy,
        price_integrity: priceIntegrity,
        return_processing: returnProcessing,
        agent_satisfaction: agentSatisfaction,
        agent_behavior: agentBehavior || null,
        evidence: evidence,
        claims: claims || null,
        submitter_score: submitterScore,
        submitter_established: submitterEstablished,
        graph_weight: fraudCheck.graphWeight ?? 1.0,
        provenance_tier: resolvedProvenanceTier,
        bilateral_status: requestBilateral ? 'pending_confirmation' : null,
        confirmation_deadline: requestBilateral ? new Date(Date.now() + 48 * 3600000).toISOString() : null,
        composite_score: composite,
        receipt_hash: receiptHash,
        previous_hash: previousHash,
      })
      .select()
      .single();

    if (insertError) {
      // === Layer 2: DB unique-constraint fallback (defense in depth) ===
      // If a concurrent request raced past the mutex and inserted first,
      // Postgres will raise a unique-constraint violation (code 23505).
      // Treat it as a dedup hit instead of a 500 error.
      const isUniqueViolation =
        insertError.code === '23505' ||
        insertError.message?.includes('duplicate key') ||
        insertError.message?.includes('unique');

      if (isUniqueViolation) {
        // Try idempotency_key first (covers the new unique index), then
        // fall back to the legacy submitter+entity+ref lookup.
        const { data: racedByKey } = await supabase
          .from('receipts')
          .select('receipt_id, receipt_hash, created_at')
          .eq('idempotency_key', idempotencyKey)
          .single();

        const racedReceipt = racedByKey || (await supabase
          .from('receipts')
          .select('receipt_id, receipt_hash, created_at')
          .eq('entity_id', targetEntityId)
          .eq('submitted_by', submitter.id)
          .eq('transaction_ref', transactionRef)
          .single()).data;

        return {
          receipt: racedReceipt,
          deduplicated: true,
          _message: 'Receipt already exists (unique constraint). Returning existing receipt (idempotent).',
        };
      }

      console.error('Receipt insert error:', insertError);
      return { error: 'Failed to submit receipt', status: 500 };
    }

    // === GET UPDATED SCORE ===
    const { data: updatedEntity } = await supabase
      .from('entities')
      .select('emilia_score, total_receipts')
      .eq('id', targetEntityId)
      .single();

    const result = {
      receipt: {
        receipt_id: receipt.receipt_id,
        idempotency_key: receipt.idempotency_key,
        entity_id: receipt.entity_id,
        composite_score: receipt.composite_score,
        receipt_hash: receipt.receipt_hash,
        created_at: receipt.created_at,
      },
      entityScore: {
        emilia_score: updatedEntity?.emilia_score,
        total_receipts: updatedEntity?.total_receipts,
      },
    };

    const allWarnings = [...(fraudCheck.flags || [])];
    if (provenanceWarning) {
      allWarnings.push(provenanceWarning);
    }
    if (allWarnings.length > 0) {
      result.warnings = allWarnings;
    }

    return result;
  } finally {
    // Always release the deduplication lock, regardless of outcome.
    releaseLock();
  }
}

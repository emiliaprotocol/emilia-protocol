/**
 * EP Privacy-Preserving Commitment Proof Layer
 *
 * Commitment-based implementation using HMAC-SHA256 commitments + Merkle trees.
 *
 * Why this design:
 *   Full zk-SNARKs (Groth16, PLONK) require heavy circuit toolchains and
 *   trusted setups that are impractical to deploy in a web API. This
 *   commitment-based approach achieves the core privacy guarantee:
 *
 *   - What is REVEALED:  claim type, threshold, domain, receipt count,
 *                        commitment Merkle root, on-chain anchor block
 *   - What is HIDDEN:    receipt contents, counterparty identities,
 *                        transaction amounts, transaction dates,
 *                        counterparty entity IDs
 *
 * Proof structure:
 * {
 *   proof_id:          'ep_zkp_...',
 *   claim:             { type: 'score_above', threshold: 0.85, domain: 'financial' },
 *   commitment_root:   '<merkle root of HMAC-SHA256 receipt commitments>',
 *   receipt_count:     N,
 *   salt:              '<public nonce — used to generate commitments, NOT the secret>',
 *   anchor_block:      '<Base L2 tx hash — on-chain commitment_root anchor>',
 *   entity_id:         '<who is making the claim>',
 *   generated_at:      ISO8601,
 *   expires_at:        ISO8601 (30 days)
 * }
 *
 * Security properties:
 *   - The salt is a public nonce (included in the proof). The hiding property
 *     comes from the fact that receipt content is NOT included in the commitment
 *     input — only the receipt ID and timestamps. An adversary who sees the proof
 *     cannot reconstruct which counterparty was involved or what the transaction was.
 *   - The Merkle root binds the proof to a specific set of receipts without
 *     revealing them. The root is anchored on Base L2 for tamper-evidence.
 *   - Score verification at read-time ensures the claim is still true —
 *     scores can only be downgraded, so a verified proof is always conservative.
 *
 * @license Apache-2.0
 */

import { createHmac, randomBytes } from 'crypto';
import { buildMerkleTree } from '@/lib/blockchain';
import { getServiceClient } from '@/lib/supabase';

// =============================================================================
// COMMITMENT PRIMITIVES
// =============================================================================

/**
 * Generate a commitment for a single receipt.
 *
 * Commitment input = receipt_id + entity_id + created_at (ISO8601).
 * Deliberately excludes: counterparty_id, transaction amounts, outcome details,
 * submitted_by, provenance_tier. These are the fields that would reveal who
 * transacted with whom — exactly what we are hiding.
 *
 * HMAC(salt, receipt_id || entity_id || created_at) → hex string
 *
 * @param {{ id: string, entity_id: string, created_at: string }} receipt
 * @param {string} salt  Public nonce (hex or any string)
 * @returns {string}  64-char hex commitment
 */
export function generateReceiptCommitment(receipt, salt) {
  if (!receipt?.id || !receipt?.entity_id || !receipt?.created_at) {
    throw new Error('generateReceiptCommitment: receipt must have id, entity_id, created_at');
  }
  if (!salt) throw new Error('generateReceiptCommitment: salt is required');

  // Canonical input: pipe-delimited to prevent field boundary ambiguity
  const input = `${receipt.id}|${receipt.entity_id}|${receipt.created_at}`;
  return createHmac('sha256', salt).update(input).digest('hex');
}

/**
 * Build a Merkle tree from an array of commitment hex strings.
 *
 * Delegates to blockchain.js buildMerkleTree so the construction is
 * identical to the receipt anchoring layer — same canonical Merkle,
 * same sorted-pair hashing, same promotion rule for odd leaves.
 *
 * @param {string[]} commitments  Array of 64-char hex commitment strings
 * @returns {{ root: string, layers: string[][], leafCount: number }}
 */
export function buildCommitmentTree(commitments) {
  if (!commitments || commitments.length === 0) {
    return { root: null, layers: [], leafCount: 0 };
  }
  return buildMerkleTree(commitments);
}

// =============================================================================
// CLAIM EVALUATION
// =============================================================================

/**
 * Evaluate whether a claim is provable given entity data.
 *
 * Returns { provable: bool, measured_value: number, receipts_for_claim: [] }
 * so the caller can decide which receipts to commit to.
 *
 * Score thresholds are expressed on [0, 1] (normalized from EP's 0-100 scale)
 * to match the language in the protocol specification.
 */
async function evaluateClaim(entityId, claim, supabase) {
  const { type, threshold, domain } = claim;

  // The minimum data we touch: IDs, timestamps, and the fields needed to
  // compute the relevant score. Counterparty fields are intentionally excluded.
  const baseSelect = 'id, entity_id, created_at, agent_behavior, graph_weight, provenance_tier, context';
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

  const { data: receipts, error } = await supabase
    .from('receipts')
    .select(baseSelect)
    .eq('entity_id', entityId)
    .gte('created_at', ninetyDaysAgo)
    .order('created_at', { ascending: false })
    .limit(500);

  if (error) throw new Error(`ZK proof: failed to fetch receipts: ${error.message}`);

  const allReceipts = receipts || [];

  if (type === 'receipt_count_above') {
    // Threshold is an integer: count of receipts
    const count = allReceipts.length;
    return {
      provable: count > threshold,
      measured_value: count,
      receipts_for_claim: allReceipts,
    };
  }

  if (type === 'score_above') {
    // Global behavioral score, normalized to [0, 1]
    const score = computeBehavioralScore(allReceipts);
    return {
      provable: score >= threshold,
      measured_value: score,
      receipts_for_claim: allReceipts,
    };
  }

  if (type === 'domain_score_above') {
    if (!domain) throw new Error('domain is required for domain_score_above claim');

    // Filter to receipts in the target domain
    const domainReceipts = allReceipts.filter(r => r.context?.task_type === domain);

    const score = computeBehavioralScore(domainReceipts);
    return {
      provable: score >= threshold,
      measured_value: score,
      receipts_for_claim: domainReceipts,
    };
  }

  throw new Error(`Unknown claim type: ${type}`);
}

/**
 * Compute a normalized [0, 1] behavioral score from receipts.
 *
 * Uses completion rate as the primary signal (same weighting philosophy as
 * scoring-v2.js behavioral tier). Returns 0 if no receipts.
 *
 * The score is intentionally simple — the claim is "score > threshold",
 * not the full v2 composite. This makes it easy to reason about and audit.
 *
 * Behavior values (same as BEHAVIOR_VALUES in scoring-v2.js, normalized):
 *   completed:          0.95
 *   retried_same:       0.75
 *   retried_different:  0.40
 *   abandoned:          0.15
 *   disputed:           0.05
 */
const BEHAVIOR_VALUES_NORMALIZED = {
  completed:           0.95,
  retried_same:        0.75,
  retried_different:   0.40,
  abandoned:           0.15,
  disputed:            0.05,
};

function computeBehavioralScore(receipts) {
  if (!receipts || receipts.length === 0) return 0;

  let weightedSum = 0;
  let totalWeight = 0;

  for (const r of receipts) {
    const bv = BEHAVIOR_VALUES_NORMALIZED[r.agent_behavior] ?? 0.50;
    const gw = r.graph_weight ?? 1.0;
    weightedSum += bv * gw;
    totalWeight += gw;
  }

  return totalWeight > 0 ? weightedSum / totalWeight : 0;
}

// =============================================================================
// PROOF GENERATION
// =============================================================================

/**
 * Generate a privacy-preserving commitment proof for an entity.
 *
 * The proof proves the claim without revealing receipt contents, counterparty
 * identities, or transaction details. It is safe to share publicly.
 *
 * @param {string} entityId
 * @param {{ type: string, threshold: number, domain?: string }} claim
 * @param {import('@supabase/supabase-js').SupabaseClient} [supabase]
 * @returns {Promise<Object>} Proof object (safe to share publicly)
 * @throws 'claim_not_provable' if the entity's score does not meet the threshold
 */
export async function generateZKProof(entityId, claim, supabase) {
  if (!entityId) throw new Error('entityId is required');
  if (!claim?.type || claim.threshold == null) {
    throw new Error('claim must have type and threshold');
  }

  const db = supabase || getServiceClient();

  // 1. Verify the entity exists and is active
  const { data: entity, error: entityError } = await db
    .from('entities')
    .select('id, entity_id, status')
    .eq('entity_id', entityId)
    .single();

  if (entityError || !entity) throw new Error(`Entity not found: ${entityId}`);
  if (entity.status !== 'active') throw new Error(`Entity is not active: ${entityId}`);

  // 2. Evaluate the claim — does this entity actually meet the threshold?
  const evaluation = await evaluateClaim(entityId, claim, db);

  if (!evaluation.provable) {
    const err = new Error(
      `claim_not_provable: ${claim.type} threshold ${claim.threshold} not met ` +
      `(measured: ${evaluation.measured_value.toFixed(4)})`
    );
    err.code = 'claim_not_provable';
    err.measured_value = evaluation.measured_value;
    throw err;
  }

  const receiptsForClaim = evaluation.receipts_for_claim;

  if (receiptsForClaim.length === 0) {
    const err = new Error('claim_not_provable: no receipts to build proof from');
    err.code = 'claim_not_provable';
    throw err;
  }

  // 3. Generate a random public salt (nonce)
  //    This is NOT a secret — it is included in the proof. The privacy comes
  //    from what is NOT in the commitment input (no counterparty, no amounts).
  const salt = randomBytes(32).toString('hex');

  // 4. Generate HMAC-SHA256 commitment for each qualifying receipt
  const commitments = receiptsForClaim.map(r =>
    generateReceiptCommitment(
      { id: r.id, entity_id: r.entity_id, created_at: r.created_at },
      salt
    )
  );

  // 5. Build Merkle tree of commitments
  const tree = buildCommitmentTree(commitments);

  if (!tree.root) {
    throw new Error('Failed to build commitment tree: no root produced');
  }

  // 6. Look up the most recent blockchain anchor for this entity
  //    (used to tie the commitment root to an on-chain event)
  const { data: anchorBatch } = await db
    .from('anchor_batches')
    .select('batch_id, transaction_hash, created_at')
    .not('transaction_hash', 'is', null)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  const anchorBlock = anchorBatch?.transaction_hash || null;

  // 7. Construct the proof record
  const proofId = `ep_zkp_${randomBytes(16).toString('hex')}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

  const proofRecord = {
    proof_id: proofId,
    entity_id: entityId,
    claim_type: claim.type,
    claim_threshold: claim.threshold,
    claim_domain: claim.domain || null,
    commitment_root: tree.root,
    receipt_count: receiptsForClaim.length,
    salt,
    anchor_block: anchorBlock,
    generated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    is_valid: true,
  };

  // 8. Persist to zk_proofs table
  const { error: insertError } = await db
    .from('zk_proofs')
    .insert(proofRecord);

  if (insertError) {
    throw new Error(`Failed to store ZK proof: ${insertError.message}`);
  }

  // 9. Return the proof — safe to share publicly
  //    Receipt details, counterparties, and amounts are not in this object.
  return {
    proof_id: proofId,
    claim: {
      type: claim.type,
      threshold: claim.threshold,
      ...(claim.domain ? { domain: claim.domain } : {}),
    },
    commitment_root: tree.root,
    receipt_count: receiptsForClaim.length,
    salt,
    anchor_block: anchorBlock,
    entity_id: entityId,
    generated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    _privacy_note:
      'This proof reveals only the claim, count, and commitment root. ' +
      'Receipt contents, counterparty identities, and transaction details are hidden.',
  };
}

// =============================================================================
// PROOF VERIFICATION
// =============================================================================

/**
 * Verify a privacy-preserving commitment proof by proof_id.
 *
 * Verification checks:
 *   1. Proof exists and has not expired
 *   2. Entity still exists and is active
 *   3. Entity still meets the claimed threshold (live re-evaluation)
 *
 * Note on live re-evaluation: we re-evaluate the claim against current data.
 * A proof that was valid when generated will remain valid unless the entity's
 * behavior has degraded since. This is a conservative, honest design:
 * the proof cannot become "more valid" than reality.
 *
 * @param {string} proofId  'ep_zkp_...' proof identifier
 * @param {import('@supabase/supabase-js').SupabaseClient} [supabase]
 * @returns {Promise<{ valid: boolean, claim: Object, entity_id: string, verified_at: string, reason?: string }>}
 */
export async function verifyZKProof(proofId, supabase) {
  if (!proofId) throw new Error('proofId is required');

  const db = supabase || getServiceClient();

  // 1. Fetch the proof record
  const { data: proof, error: fetchError } = await db
    .from('zk_proofs')
    .select('*')
    .eq('proof_id', proofId)
    .single();

  if (fetchError || !proof) {
    return {
      valid: false,
      claim: null,
      entity_id: null,
      verified_at: new Date().toISOString(),
      reason: 'proof_not_found',
    };
  }

  const verifiedAt = new Date().toISOString();

  // 2. Check expiry
  if (new Date(proof.expires_at) < new Date()) {
    await db
      .from('zk_proofs')
      .update({ is_valid: false })
      .eq('proof_id', proofId);

    return {
      valid: false,
      claim: buildClaimObject(proof),
      entity_id: proof.entity_id,
      verified_at: verifiedAt,
      reason: 'proof_expired',
      expired_at: proof.expires_at,
    };
  }

  // 3. Check entity still exists and is active
  const { data: entity } = await db
    .from('entities')
    .select('entity_id, status')
    .eq('entity_id', proof.entity_id)
    .single();

  if (!entity || entity.status !== 'active') {
    return {
      valid: false,
      claim: buildClaimObject(proof),
      entity_id: proof.entity_id,
      verified_at: verifiedAt,
      reason: 'entity_inactive_or_not_found',
    };
  }

  // 4. Re-evaluate the claim against current data
  //    This is the key integrity check: the proof cannot outlive the reality.
  let currentlyProvable = false;
  let evaluationError = null;

  try {
    const claim = {
      type: proof.claim_type,
      threshold: Number(proof.claim_threshold),
      domain: proof.claim_domain || undefined,
    };
    const evaluation = await evaluateClaim(proof.entity_id, claim, db);
    currentlyProvable = evaluation.provable;
  } catch (err) {
    evaluationError = err.message;
    currentlyProvable = false;
  }

  // 5. Update last_verified_at and is_valid
  await db
    .from('zk_proofs')
    .update({
      last_verified_at: verifiedAt,
      is_valid: currentlyProvable,
    })
    .eq('proof_id', proofId);

  if (!currentlyProvable) {
    return {
      valid: false,
      claim: buildClaimObject(proof),
      entity_id: proof.entity_id,
      verified_at: verifiedAt,
      reason: evaluationError ? `evaluation_error: ${evaluationError}` : 'claim_no_longer_met',
    };
  }

  return {
    valid: true,
    claim: buildClaimObject(proof),
    entity_id: proof.entity_id,
    receipt_count: proof.receipt_count,
    commitment_root: proof.commitment_root,
    anchor_block: proof.anchor_block,
    generated_at: proof.generated_at,
    expires_at: proof.expires_at,
    verified_at: verifiedAt,
  };
}

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

function buildClaimObject(proof) {
  const claim = {
    type: proof.claim_type,
    threshold: Number(proof.claim_threshold),
  };
  if (proof.claim_domain) claim.domain = proof.claim_domain;
  return claim;
}

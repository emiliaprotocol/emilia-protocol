import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { verifyMerkleProof } from '@/lib/blockchain';
import { computeReceiptHash } from '@/lib/scoring';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

/**
 * GET /api/verify/[receiptId]
 *
 * Verify a receipt's cryptographic integrity and blockchain anchor.
 * No authentication required — verification is public by design.
 *
 * Returns:
 *   - Receipt data and hash
 *   - Merkle proof (if anchored)
 *   - On-chain verification status
 *   - Links to block explorer
 */
export async function GET(request, { params }) {
  try {
    const { receiptId } = await params;
    const supabase = getGuardedClient();

    // Look up the receipt
    const { data: receipt, error } = await supabase
      .from('receipts')
      .select(`
        receipt_id, entity_id, submitted_by,
        transaction_ref, transaction_type,
        delivery_accuracy, product_accuracy,
        price_integrity, return_processing,
        agent_satisfaction, agent_behavior,
        composite_score, evidence,
        receipt_hash, previous_hash,
        anchor_batch_id, merkle_proof, merkle_leaf_index,
        created_at
      `)
      .eq('receipt_id', receiptId)
      .single();

    if (error || !receipt) {
      return epProblem(404, 'receipt_not_found', 'Receipt not found');
    }

    // Recompute hash to verify integrity
    const recomputedHash = await computeReceiptHash({
      entity_id: receipt.entity_id,
      submitted_by: receipt.submitted_by,
      transaction_ref: receipt.transaction_ref,
      transaction_type: receipt.transaction_type,
      delivery_accuracy: receipt.delivery_accuracy,
      product_accuracy: receipt.product_accuracy,
      price_integrity: receipt.price_integrity,
      return_processing: receipt.return_processing,
      agent_satisfaction: receipt.agent_satisfaction,
      evidence: receipt.evidence,
    }, receipt.previous_hash);

    const hashValid = recomputedHash === receipt.receipt_hash;

    // Build response
    const response = {
      receipt_id: receipt.receipt_id,
      receipt_hash: receipt.receipt_hash,
      hash_valid: hashValid,
      recomputed_hash: recomputedHash,
      created_at: receipt.created_at,

      // Receipt data (for independent verification)
      data: {
        entity_id: receipt.entity_id,
        submitted_by: receipt.submitted_by,
        transaction_ref: receipt.transaction_ref,
        transaction_type: receipt.transaction_type,
        delivery_accuracy: receipt.delivery_accuracy,
        product_accuracy: receipt.product_accuracy,
        price_integrity: receipt.price_integrity,
        return_processing: receipt.return_processing,
        agent_satisfaction: receipt.agent_satisfaction,
        agent_behavior: receipt.agent_behavior,
        composite_score: receipt.composite_score,
      },

      // Chain integrity
      chain: {
        previous_hash: receipt.previous_hash,
        chain_intact: hashValid,
      },

      // Blockchain anchor (if present)
      anchor: null,
    };

    // Add anchor verification if this receipt has been anchored
    if (receipt.anchor_batch_id && receipt.merkle_proof) {
      const { data: batch } = await supabase
        .from('anchor_batches')
        .select('batch_id, merkle_root, transaction_hash, chain_id, block_number, explorer_url, created_at')
        .eq('batch_id', receipt.anchor_batch_id)
        .single();

      if (batch) {
        const proofValid = verifyMerkleProof(
          receipt.receipt_hash,
          receipt.merkle_proof,
          batch.merkle_root
        );

        response.anchor = {
          batch_id: batch.batch_id,
          merkle_root: batch.merkle_root,
          merkle_proof: receipt.merkle_proof,
          leaf_index: receipt.merkle_leaf_index,
          proof_valid: proofValid,
          transaction_hash: batch.transaction_hash,
          chain_id: batch.chain_id,
          block_number: batch.block_number,
          explorer_url: batch.explorer_url,
          anchored_at: batch.created_at,
        };
      }
    }

    return NextResponse.json(response);
  } catch (err) {
    logger.error('Verify error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

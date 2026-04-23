/**
 * EP Privacy-Preserving Commitment Proof API
 *
 * POST /api/trust/zk-proof
 *   Generate a commitment trust proof for an entity.
 *   Auth: Bearer ep_live_... for the entity making the claim.
 *   Body: { entity_id, claim: { type, threshold, domain? } }
 *   Returns: proof object — safe to share publicly (no PII, no receipt details).
 *
 * GET /api/trust/zk-proof?proof_id=ep_zkp_...
 *   Verify a commitment trust proof by proof_id. Public endpoint — no auth required.
 *   Returns: { valid, claim, entity_id, verified_at, receipt_count }
 *   Does NOT return commitment details, salt, or anything that could help
 *   reconstruct the underlying receipt set.
 *
 * Privacy invariants enforced at this layer:
 *   - POST: entity can only generate proofs for themselves (key → entity binding).
 *   - GET: verifier receives only the claim verdict and public metadata.
 *          Commitment root and salt are omitted from verification responses
 *          so the verifier learns nothing about the receipt set.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { generateCommitmentProof, verifyCommitmentProof } from '@/lib/zk-proofs';
import { authenticateRequest } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { EP_ERRORS } from '@/lib/errors';
import { siemEvent } from '@/lib/siem';
import { logger } from '../../../../lib/logger.js';

const VALID_CLAIM_TYPES = ['score_above', 'receipt_count_above', 'domain_score_above'];
const VALID_DOMAINS = [
  'financial', 'code_execution', 'communication', 'delegation',
  'infrastructure', 'content_creation', 'data_access',
];

// =============================================================================
// POST — generate a commitment proof
// =============================================================================

export async function POST(request) {
  try {
    // 1. Authenticate — entity must hold a valid API key
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const body = await request.json().catch(() => ({}));
    const { entity_id, claim } = body;

    // 2. Validate inputs
    if (!entity_id) {
      return EP_ERRORS.BAD_REQUEST('entity_id is required');
    }
    if (!claim || typeof claim !== 'object') {
      return EP_ERRORS.BAD_REQUEST('claim is required (object with type, threshold)');
    }
    if (!claim.type || !VALID_CLAIM_TYPES.includes(claim.type)) {
      return EP_ERRORS.BAD_REQUEST(
        `claim.type must be one of: ${VALID_CLAIM_TYPES.join(', ')}`
      );
    }
    if (claim.threshold == null || typeof claim.threshold !== 'number') {
      return EP_ERRORS.BAD_REQUEST('claim.threshold must be a number');
    }
    if (claim.type === 'domain_score_above') {
      if (!claim.domain || !VALID_DOMAINS.includes(claim.domain)) {
        return EP_ERRORS.BAD_REQUEST(
          `claim.domain is required for domain_score_above. Valid: ${VALID_DOMAINS.join(', ')}`
        );
      }
    }
    if (claim.type !== 'receipt_count_above') {
      if (claim.threshold < 0 || claim.threshold > 1) {
        return EP_ERRORS.BAD_REQUEST('claim.threshold must be between 0.0 and 1.0 for score claims');
      }
    } else {
      if (!Number.isInteger(claim.threshold) || claim.threshold < 1) {
        return EP_ERRORS.BAD_REQUEST('claim.threshold must be a positive integer for receipt_count_above');
      }
    }

    // 3. Authorization: an entity can only generate proofs for their own entity_id.
    //    This prevents entity A from generating proofs on behalf of entity B.
    if (auth.entity.entity_id !== entity_id) {
      return EP_ERRORS.FORBIDDEN(
        'You can only generate commitment proofs for your own entity. ' +
        `Key belongs to: ${auth.entity.entity_id}`
      );
    }

    // 4. Generate the proof
    const supabase = getGuardedClient();
    let proof;
    try {
      proof = await generateCommitmentProof(entity_id, claim, supabase);
    } catch (err) {
      if (err.code === 'claim_not_provable') {
        return NextResponse.json(
          {
            error: 'Claim is not provable: your current trust data does not meet the specified threshold.',
            code: 'CLAIM_NOT_PROVABLE',
            status: 422,
            details: {
              claim,
              measured_value: err.measured_value ?? null,
              _help: 'Accumulate more receipts or lower the threshold to generate a valid proof.',
            },
          },
          { status: 422 }
        );
      }
      throw err; // re-throw unexpected errors
    }

    // 5. SIEM: commitment proof generation is a medium-severity security event
    siemEvent('COMMITMENT_PROOF_GENERATED', {
      proof_id: proof.proof_id,
      entity_id: proof.entity_id,
      claim_type: proof.claim?.type,
    });

    // 6. Return proof — safe to share publicly
    return NextResponse.json(
      {
        proof_id: proof.proof_id,
        claim: proof.claim,
        commitment_root: proof.commitment_root,
        receipt_count: proof.receipt_count,
        salt: proof.salt,
        anchor_block: proof.anchor_block,
        entity_id: proof.entity_id,
        generated_at: proof.generated_at,
        expires_at: proof.expires_at,
        _privacy_note: proof._privacy_note,
        _usage: 'Share proof_id with verifiers. They call GET /api/trust/zk-proof?proof_id=... to verify.',
      },
      { status: 201 }
    );
  } catch (err) {
    logger.error('[zk-proof POST] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

// =============================================================================
// GET — verify a commitment proof (public)
// =============================================================================

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const proofId = searchParams.get('proof_id');

    if (!proofId) {
      return EP_ERRORS.BAD_REQUEST('proof_id query parameter is required');
    }

    if (!proofId.startsWith('ep_zkp_')) {
      return EP_ERRORS.BAD_REQUEST('proof_id must start with ep_zkp_');
    }

    const supabase = getGuardedClient();
    const result = await verifyCommitmentProof(proofId, supabase);

    if (result.reason === 'proof_not_found') {
      return EP_ERRORS.NOT_FOUND('Commitment proof');
    }

    // Return only the verification verdict — deliberately omit commitment_root
    // and salt from GET responses so the verifier learns nothing about the
    // underlying receipt set beyond what the claim explicitly states.
    const response = {
      proof_id: proofId,
      valid: result.valid,
      claim: result.claim,
      entity_id: result.entity_id,
      verified_at: result.verified_at,
    };

    if (result.valid) {
      // Minimal public metadata: count (reveals depth of evidence) and expiry
      response.receipt_count = result.receipt_count;
      response.expires_at = result.expires_at;
      response.anchor_block = result.anchor_block;
      response._note =
        'Proof is valid. The entity has proven the stated claim without revealing ' +
        'receipt contents, counterparty identities, or transaction details.';
    } else {
      response.reason = result.reason;
      if (result.expired_at) response.expired_at = result.expired_at;
      response._note =
        result.reason === 'proof_expired'
          ? 'Proof has expired. Ask the entity to generate a fresh proof.'
          : result.reason === 'claim_no_longer_met'
          ? 'The entity\'s current trust data no longer meets the claimed threshold.'
          : 'Proof could not be verified.';
    }

    return NextResponse.json(response);
  } catch (err) {
    logger.error('[zk-proof GET] error:', err);
    return EP_ERRORS.INTERNAL();
  }
}

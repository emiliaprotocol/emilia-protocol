/**
 * GET /api/commit/keys — Public signing key discovery (JWKS-style)
 *
 * Returns the current Ed25519 public key(s) used to sign EP Commits.
 * No authentication required — this is a trust root discovery endpoint.
 *
 * Consumers SHOULD cache this response and re-fetch periodically (e.g., every
 * hour or on signature verification failure) to pick up key rotations.
 *
 * @license Apache-2.0
 */

import { NextResponse } from 'next/server';
import { _internals } from '@/lib/commit';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

export async function GET(): Promise<NextResponse> {
  try {
    // Trigger keypair initialization (populates trusted key registry)
    _internals.getPublicKeyBase64();

    // Return all trusted keys from the registry (supports key rotation)
    const trustedKeys = _internals.getAllTrustedKeys();

    return NextResponse.json({
      keys: trustedKeys.map(({ kid, publicKeyBase64 }) => ({
        kid,
        algorithm: 'Ed25519',
        public_key_base64: publicKeyBase64,
        status: 'active',
      })),
      rotation_policy: {
        rotation_interval_days: 90,
        overlap_period_days: 14,
        revocation_mechanism:
          'Key removed from active set; old signatures remain verifiable via archived keys',
      },
    });
  } catch (err) {
    logger.error('[commit-keys] Failed to retrieve signing keys:', err);
    return epProblem(500, 'commit_keys_unavailable', 'Commit signing keys are temporarily unavailable');
  }
}

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

export async function GET() {
  try {
    // ensureKeypair is not directly exported, but signPayload calls it internally.
    // We use _internals.signPayload to trigger keypair initialization, then read the
    // public key from a dummy sign operation — however, that's wasteful.
    // Instead, we call getPublicKeyInfo() which we added to _internals.
    const publicKeyBase64 = _internals.getPublicKeyBase64();

    return NextResponse.json({
      keys: [
        {
          kid: 'ep-signing-key-1',
          algorithm: 'Ed25519',
          public_key_base64: publicKeyBase64,
          status: 'active',
          created_at: '2025-01-01T00:00:00Z',
        },
      ],
      rotation_policy: {
        rotation_interval_days: 90,
        overlap_period_days: 14,
        revocation_mechanism:
          'Key removed from active set; old signatures remain verifiable via archived keys',
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: 'Failed to retrieve signing keys', detail: err.message },
      { status: 500 }
    );
  }
}

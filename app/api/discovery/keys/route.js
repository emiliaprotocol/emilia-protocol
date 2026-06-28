import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { getEvidenceSigningKeypair } from '@/lib/guard-evidence-receipt';
import { getCommitSigningConfig } from '@/lib/env';

/**
 * GET /api/discovery/keys
 *
 * Serves the /.well-known/ep-keys.json discovery document — the operator's
 * published verification keys. This is one of the three federation surfaces
 * PIP-006 requires every conformant operator to publish; it is what
 * `@emilia-protocol/verify`'s federation client consumes to verify a receipt
 * issued by this operator without contacting it.
 *
 * Rewritten from /.well-known/ep-keys.json via next.config.js.
 *
 * Document shape (PIP-006 §"Federation contract" + §"Security considerations"):
 *   - operator_signing_keys: the operator's commit signing key(s) (key_class C,
 *                      ep-signing-key-1) that sign /evidence EP-RECEIPT-v1
 *                      documents. Published so a verifier following a receipt's
 *                      discovery link can pin the signer out-of-band. PUBLIC SPKI
 *                      only — never the seed; omitted when no real key is
 *                      configured so an ephemeral dev key is never advertised.
 *   - keys:            currently-valid federation signing keys, by entity_id
 *   - historical_keys: retired keys, by entity_id, so receipts signed before a
 *                      rotation remain verifiable (key-rotation safety)
 *   - cache_ttl_seconds: how long a relying party MAY cache this document
 *   - verify_url_template: the verifier-of-record / revocation surface
 *
 * @public — no authentication required. Key discovery is a protocol property.
 */

const OPERATOR_ID = 'ep_operator_emilia_primary';
const BASE = 'https://www.emiliaprotocol.ai';
// Receipts are short-lived; a 5-minute cache bounds key-rotation propagation
// while keeping the surface cheap to consume.
const CACHE_TTL_SECONDS = 300;

export async function GET() {
  // The operator commit signing key (key_class C, ep-signing-key-1) signs the
  // /evidence EP-RECEIPT-v1 documents. Publish its PUBLIC half here so a verifier
  // that follows a receipt's discovery link can pin the signer out-of-band. Only
  // the public SPKI is ever exposed — the seed (EP_COMMIT_SIGNING_KEY) never
  // leaves getEvidenceSigningKeypair(). Omitted when no real key is configured
  // (dev/test) so we never advertise an ephemeral key.
  const operator_signing_keys = {};
  try {
    if (getCommitSigningConfig().signingKey) {
      const kp = getEvidenceSigningKeypair();
      if (kp?.publicKeySpkiB64u) {
        operator_signing_keys['ep-signing-key-1'] = {
          public_key: kp.publicKeySpkiB64u,
          algorithm: 'Ed25519',
          key_class: 'C',
          key_id: 'ep-signing-key-1',
        };
      }
    }
  } catch {
    // Misconfigured key -> advertise nothing rather than 500.
  }

  const base = {
    version: '1.1',
    operator_id: OPERATOR_ID,
    protocol_version: 'EP-CORE-v1.0',
    cache_ttl_seconds: CACHE_TTL_SECONDS,
    // Where a relying party confirms a receipt is well-formed, signed by a key
    // advertised here, and not revoked (PIP-006 §"Federation contract" item 3).
    verify_url_template: `${BASE}/api/verify/{receipt_id}`,
    operator_signing_keys,
  };

  try {
    const supabase = getGuardedClient();

    // Current signing keys.
    const { data: entities, error } = await supabase
      .from('entities')
      .select('entity_id, public_key')
      .limit(1000);

    const keys = {};
    if (entities && !error) {
      for (const e of entities) {
        if (e.public_key) {
          keys[e.entity_id] = {
            public_key: e.public_key,
            algorithm: 'Ed25519',
          };
        }
      }
    }

    // Retired signing keys (rotation safety). Read from the real history table
    // (migration 094). Tolerant of the table not existing on older deployments:
    // an unavailable history surface degrades to no historical keys, never a 500.
    const historical_keys = {};
    try {
      const { data: retired } = await supabase
        .from('entity_signing_key_history')
        .select('entity_id, public_key, algorithm')
        .order('retired_at', { ascending: false })
        .limit(1000);
      if (Array.isArray(retired)) {
        for (const r of retired) {
          if (!r.public_key) continue;
          (historical_keys[r.entity_id] ||= []).push({
            public_key: r.public_key,
            algorithm: r.algorithm || 'Ed25519',
          });
        }
      }
    } catch {
      // History table absent — no rotations advertised. Not an error.
    }

    return NextResponse.json(
      { ...base, keys, historical_keys },
      {
        headers: {
          'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}`,
          'Content-Type': 'application/json',
        },
      },
    );
  } catch {
    return NextResponse.json({ ...base, keys: {}, historical_keys: {} });
  }
}

import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';

/**
 * GET /api/discovery/keys
 *
 * Serves the /.well-known/ep-keys.json discovery document.
 * Returns all entity public keys for cross-operator receipt verification.
 *
 * Rewritten from /.well-known/ep-keys.json via next.config.js.
 *
 * @public — no authentication required. Key discovery is a protocol property.
 */
export async function GET() {
  try {
    const supabase = getGuardedClient();

    // Fetch all entities, filter for those with public keys client-side
    // (avoids PostgREST filter compatibility issues across Postgres versions)
    const { data: entities, error } = await supabase
      .from('entities')
      .select('entity_id, display_name, public_key, created_at')
      .limit(1000);

    const keys = {};
    if (entities && !error) {
      for (const e of entities) {
        if (e.public_key) {
          keys[e.entity_id] = {
            public_key: e.public_key,
            algorithm: 'Ed25519',
            created_at: e.created_at,
          };
        }
      }
    }

    return NextResponse.json({
      version: '1.0',
      operator_id: 'ep_operator_emilia_primary',
      keys,
    }, {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Content-Type': 'application/json',
      },
    });
  } catch (err) {
    return NextResponse.json({
      version: '1.0',
      operator_id: 'ep_operator_emilia_primary',
      keys: {},
    });
  }
}

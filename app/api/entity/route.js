import crypto from 'crypto';
import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
// API key generated inline — no dependency on lib/supabase internals
import { epProblem } from '@/lib/errors';

/**
 * POST /api/entity
 *
 * Protocol-standard entity registration endpoint.
 * Accepts minimal input (just a name), auto-generates entity_id and Ed25519 keys.
 *
 * This is the conformance-standard route. The internal /api/entities/register
 * endpoint accepts richer input for production use.
 *
 * Body: { name: "My Entity" }
 * Returns: { entity_id, name, public_key, api_key }
 *
 * @public — no authentication required for entity creation.
 */
export async function POST(request) {
  try {
    const body = await request.json();
    const name = (body.name || '').slice(0, 200).trim();

    if (!name) {
      return epProblem(400, 'missing_name', 'name is required');
    }

    // Generate entity ID and owner ID
    const suffix = crypto.randomBytes(12).toString('hex');
    const entityId = `ep_entity_${suffix}`;
    const ownerId = `ep_owner_${crypto.randomBytes(16).toString('hex')}`;

    // Generate Ed25519 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });

    const publicKeyB64 = Buffer.from(publicKey).toString('base64url');
    const privateKeyB64 = Buffer.from(privateKey).toString('base64url');

    // Generate API key inline
    const apiKey = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');

    const supabase = getGuardedClient();

    // Insert entity
    const { error: entityError } = await supabase
      .from('entities')
      .insert({
        entity_id: entityId,
        owner_id: ownerId,
        display_name: name,
        entity_type: 'agent',
        description: `Entity: ${name}`,
        api_key_hash: keyHash,
        public_key: publicKeyB64,
        private_key_encrypted: privateKeyB64,
      });

    if (entityError) {
      console.error('[entity/route] Registration failed:', entityError);
      return epProblem(500, 'registration_failed', entityError.message || JSON.stringify(entityError));
    }

    return NextResponse.json({
      entity_id: entityId,
      name,
      public_key: publicKeyB64,
      api_key: apiKey,
    }, { status: 201 });
  } catch (err) {
    console.error('[entity/route] Unhandled error:', err);
    return epProblem(500, 'internal_error', err.message || 'Entity registration failed');
  }
}

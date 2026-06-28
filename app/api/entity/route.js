import crypto from 'crypto';
import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { logger } from '@/lib/logger.js';
import { seal } from '@/lib/crypto/secret-box';
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

    // Insert entity (capture the UUID id — api_keys references it, not the
    // string entity_id).
    const { data: insertedEntity, error: entityError } = await supabase
      .from('entities')
      .insert({
        entity_id: entityId,
        organization_id: entityId,
        owner_id: ownerId,
        display_name: name,
        entity_type: 'agent',
        description: `Entity: ${name}`,
        api_key_hash: keyHash,
        public_key: publicKeyB64,
        private_key_encrypted: seal(privateKeyB64),
      })
      .select('id')
      .single();

    if (entityError || !insertedEntity) {
      logger.error('[entity/route] Registration failed:', entityError);
      return epProblem(500, 'registration_failed', entityError?.message || JSON.stringify(entityError));
    }

    // Register the key in api_keys so it authenticates protocol-standard routes
    // (POST /api/receipt et al). resolve_authenticated_actor reads api_keys, not
    // entities.api_key_hash — without this row the caller cannot use the key it
    // was just issued. Mirrors POST /api/entities/register.
    const { error: keyError } = await supabase.from('api_keys').insert({
      entity_id: insertedEntity.id,
      key_hash: keyHash,
      key_prefix: apiKey.slice(0, 16),
      label: 'Default key',
    });
    if (keyError) {
      logger.error('[entity/route] api_keys insert failed:', keyError);
      return epProblem(500, 'registration_failed', 'Entity created but key registration failed');
    }

    return NextResponse.json({
      entity_id: entityId,
      name,
      public_key: publicKeyB64,
      api_key: apiKey,
    }, { status: 201 });
  } catch (err) {
    logger.error('[entity/route] Unhandled error:', err);
    return epProblem(500, 'internal_error', err.message || 'Entity registration failed');
  }
}

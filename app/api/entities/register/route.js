import crypto from 'crypto';
import { NextResponse } from 'next/server';
import { generateApiKey } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { computeReceiptComposite } from '@/lib/scoring';
import { epProblem } from '@/lib/errors';
import { generateEmbedding } from '@/lib/providers/embeddings';
import { logger } from '../../../../lib/logger.js';

/**
 * POST /api/entities/register
 *
 * Register a new entity on the EMILIA Protocol.
 * Returns an API key and an owner_id that the entity uses for all future interactions.
 *
 * Body: {
 *   entity_id: "rex-booking-v2",
 *   display_name: "Rex — Inbound AI Receptionist",
 *   entity_type: "agent" | "merchant" | "service_provider",
 *   description: "Handles inbound SMS booking for service businesses",
 *   capabilities: ["inbound_booking", "sms_reply"],
 *   category: "salon",                    // optional, for merchants
 *   pricing_model: "per_task",            // optional
 *   pricing_amount_cents: 25,             // optional
 *   a2a_endpoint: "https://...",          // optional
 *   ucp_profile_url: "https://...",       // optional
 *   input_schema: { ... },               // optional JSON Schema
 *   output_schema: { ... },              // optional JSON Schema
 * }
 *
 * Returns: { entity, api_key, owner_id }
 *   api_key is returned ONCE at registration. Store it securely.
 *   owner_id is the registrant's portable identity handle. Store it securely.
 *   Use POST /api/identity/bind to establish durable principal binding
 *   (e.g. linking to a GitHub account or org) for long-lived ownership.
 */
export async function POST(request) {
  try {
    const body = await request.json();
    const supabase = getGuardedClient();

    // Validate required fields
    const required = ['entity_id', 'display_name', 'entity_type', 'description'];
    for (const field of required) {
      if (!body[field]) {
        return epProblem(400, 'missing_field', `Missing required field: ${field}`);
      }
    }

    const VALID_ENTITY_TYPES = [
      // Commerce entities
      'agent', 'merchant', 'service_provider',
      // Software entities (EP-SX)
      'github_app', 'github_action', 'mcp_server', 'npm_package',
      'chrome_extension', 'shopify_app', 'marketplace_plugin', 'agent_tool',
    ];

    // Block reserved entity IDs to prevent privilege escalation
    const RESERVED_ENTITY_IDS = ['system', 'admin', 'operator', 'root', 'superuser', 'service'];
    if (RESERVED_ENTITY_IDS.includes(body.entity_id?.toLowerCase())) {
      return epProblem(400, 'reserved_entity_id', 'This entity ID is reserved and cannot be used');
    }

    if (!VALID_ENTITY_TYPES.includes(body.entity_type)) {
      return epProblem(400, 'invalid_entity_type', `entity_type must be one of: ${VALID_ENTITY_TYPES.join(', ')}`);
    }

    if (typeof body.display_name === 'string' && body.display_name.length > 200) {
      return epProblem(400, 'display_name_too_long', 'display_name must not exceed 200 characters');
    }

    // Check for duplicate entity_id
    const { data: existing } = await supabase
      .from('entities')
      .select('id')
      .eq('entity_id', body.entity_id)
      .single();

    if (existing) {
      return epProblem(400, 'registration_failed', 'Unable to complete registration');
    }

    // Rate limiting handled by middleware on all /api/* routes

    // Generate embedding from description + capabilities (optional — skipped if no provider configured)
    const embeddingText = [
      body.display_name,
      body.description,
      ...(body.capabilities || []),
      body.category,
    ].filter(Boolean).join('. ');

    const embedding = await generateEmbedding(embeddingText);

    // Generate API key
    const { key: apiKey, hash: apiKeyHash, prefix } = generateApiKey();

    // Generate a random, portable owner_id for this registrant.
    // Previous implementation derived owner_id from a hashed client IP, which
    // was not durable (IP changes), not portable (different networks), and
    // misleading under NAT / shared infrastructure.
    // Durable ownership should be established via POST /api/identity/bind.
    const ownerId = `ep_owner_${crypto.randomUUID()}`;

    // Insert entity
    const { data: entity, error: insertError } = await supabase
      .from('entities')
      .insert({
        entity_id: body.entity_id,
        owner_id: ownerId,
        display_name: body.display_name,
        entity_type: body.entity_type,
        description: body.description,
        website_url: body.website_url || null,
        capabilities: body.capabilities || [],
        input_schema: body.input_schema || null,
        output_schema: body.output_schema || null,
        category: body.category || null,
        software_meta: body.software_meta || null,
        service_area: body.service_area || null,
        pricing_model: body.pricing_model || null,
        pricing_amount_cents: body.pricing_amount_cents || 0,
        capability_embedding: embedding,
        api_key_hash: apiKeyHash,
        a2a_endpoint: body.a2a_endpoint || null,
        ucp_profile_url: body.ucp_profile_url || null,
      })
      .select()
      .single();

    if (insertError) {
      logger.error('Entity insert error:', insertError);
      return epProblem(500, 'registration_failed', 'Failed to register entity');
    }

    // Create API key record
    await supabase.from('api_keys').insert({
      entity_id: entity.id,
      key_hash: apiKeyHash,
      key_prefix: prefix,
      label: 'Default key',
    });

    return NextResponse.json({
      entity: {
        id: entity.id,
        entity_id: entity.entity_id,
        display_name: entity.display_name,
        entity_type: entity.entity_type,
        compat_score: entity.emilia_score,
        confidence: 'pending',
        status: entity.status,
        created_at: entity.created_at,
      },
      api_key: apiKey,
      owner_id: ownerId,
      message: 'Store this API key and owner_id securely. They will not be shown again. Use POST /api/identity/bind to establish durable principal binding.',
      _note: 'Query /api/trust/profile/:entityId for full trust profile. compat_score is for sorting only.',
    }, { status: 201 });
  } catch (err) {
    logger.error('Registration error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

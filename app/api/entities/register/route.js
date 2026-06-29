import crypto from 'crypto';
import { NextResponse } from 'next/server';
import { generateApiKey } from '@/lib/supabase';
import { getGuardedClient } from '@/lib/write-guard';
import { computeReceiptComposite } from '@/lib/scoring';
import { epProblem } from '@/lib/errors';
import { generateEmbedding } from '@/lib/providers/embeddings';
import { logger } from '../../../../lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';

const MAX_REGISTER_BYTES = 64 * 1024;
const ENTITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$/;
const MAX_DESCRIPTION_CHARS = 2000;
const MAX_CAPABILITIES = 50;
const MAX_CAPABILITY_CHARS = 100;

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
    const parsed = await readLimitedJson(request, MAX_REGISTER_BYTES);
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    const supabase = getGuardedClient();

    // Validate required fields
    const required = ['entity_id', 'display_name', 'entity_type', 'description'];
    for (const field of required) {
      if (typeof body[field] !== 'string' || !body[field].trim()) {
        return epProblem(400, 'missing_field', `Missing required field: ${field}`);
      }
    }

    const entityId = String(body.entity_id).normalize('NFKC').trim();
    const displayName = String(body.display_name).trim();
    const description = String(body.description).trim();

    const VALID_ENTITY_TYPES = [
      // Commerce entities
      'agent', 'merchant', 'service_provider',
      // Software entities (EP-SX)
      'github_app', 'github_action', 'mcp_server', 'npm_package',
      'chrome_extension', 'shopify_app', 'marketplace_plugin', 'agent_tool',
    ];

    // Block reserved entity IDs to prevent privilege escalation. Normalize first
    // (NFKC + strip whitespace/zero-width + lowercase) so case, spacing, and
    // unicode-compatibility variants ("SYSTEM", "s y s t e m", full-width) can't
    // slip a reserved name past the check. (Defense-in-depth: reserved names
    // grant no privilege by themselves; this just removes the foot-gun.)
    const RESERVED_ENTITY_IDS = ['system', 'admin', 'operator', 'root', 'superuser', 'service'];
    const normalizedEntityId = entityId
      .normalize('NFKC')
      .replace(/[\s​‌‍﻿]/g, '')
      .toLowerCase();
    if (RESERVED_ENTITY_IDS.includes(normalizedEntityId)) {
      return epProblem(400, 'reserved_entity_id', 'This entity ID is reserved and cannot be used');
    }

    if (!ENTITY_ID_PATTERN.test(entityId)) {
      return epProblem(400, 'invalid_entity_id', 'entity_id must be 3-128 chars of [A-Za-z0-9_.:-] and start with an alphanumeric');
    }

    if (!VALID_ENTITY_TYPES.includes(body.entity_type)) {
      return epProblem(400, 'invalid_entity_type', `entity_type must be one of: ${VALID_ENTITY_TYPES.join(', ')}`);
    }

    if (displayName.length > 200) {
      return epProblem(400, 'display_name_too_long', 'display_name must not exceed 200 characters');
    }
    if (description.length > MAX_DESCRIPTION_CHARS) {
      return epProblem(400, 'description_too_long', `description must not exceed ${MAX_DESCRIPTION_CHARS} characters`);
    }

    const capabilities = sanitizeStringArray(body.capabilities, MAX_CAPABILITIES, MAX_CAPABILITY_CHARS);
    if (body.capabilities !== undefined && capabilities.error) {
      return epProblem(400, 'invalid_capabilities', capabilities.error);
    }

    // Check for duplicate entity_id
    const { data: existing } = await supabase
      .from('entities')
      .select('id')
      .eq('entity_id', entityId)
      .single();

    if (existing) {
      return epProblem(400, 'registration_failed', 'Unable to complete registration');
    }

    // Rate limiting handled by middleware on all /api/* routes

    // Generate embedding from description + capabilities (optional — skipped if no provider configured)
    const embeddingText = [
      displayName,
      description,
      ...capabilities.values,
      typeof body.category === 'string' ? body.category.slice(0, 100) : null,
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
        entity_id: entityId,
        // One organization per key/entity. v1 writes derive organization scope
        // from the authenticated entity; body.organization_id is only a
        // cross-check. A public registration path that omits this reopens the
        // tenant-binding hole for every key born here.
        organization_id: entityId,
        owner_id: ownerId,
        display_name: displayName,
        entity_type: body.entity_type,
        description,
        website_url: body.website_url || null,
        capabilities: capabilities.values,
        input_schema: body.input_schema || null,
        output_schema: body.output_schema || null,
        category: typeof body.category === 'string' ? body.category.slice(0, 100) : null,
        software_meta: body.software_meta || null,
        service_area: body.service_area || null,
        pricing_model: body.pricing_model || null,
        pricing_amount_cents: body.pricing_amount_cents || 0,
        capability_embedding: embedding,
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
        confidence: 'pending',
        status: entity.status,
        created_at: entity.created_at,
      },
      api_key: apiKey,
      owner_id: ownerId,
      message: 'Store this API key and owner_id securely. They will not be shown again. Use POST /api/identity/bind to establish durable principal binding.',
      _note: 'Query /api/trust/profile/:entityId for the full trust profile (confidence + verifiable evidence). New entities start at confidence: pending.',
    }, { status: 201 });
  } catch (err) {
    logger.error('Registration error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

function sanitizeStringArray(value, maxItems, maxChars) {
  if (value === undefined || value === null) return { values: [] };
  if (!Array.isArray(value)) return { error: 'capabilities must be an array of strings' };
  if (value.length > maxItems) return { error: `capabilities must contain at most ${maxItems} items` };
  const values = [];
  for (const item of value) {
    if (typeof item !== 'string') return { error: 'capabilities must contain only strings' };
    const s = item.trim();
    if (!s) continue;
    if (s.length > maxChars) return { error: `capability entries must be ${maxChars} characters or fewer` };
    values.push(s);
  }
  return { values };
}

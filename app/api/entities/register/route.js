import { NextResponse } from 'next/server';
import { getServiceClient, generateApiKey } from '@/lib/supabase';
import { computeReceiptComposite } from '@/lib/scoring';
import { checkRegistrationLimits } from '@/lib/sybil';

/**
 * POST /api/entities/register
 * 
 * Register a new entity on the EMILIA Protocol.
 * Returns an API key that the entity uses for all future interactions.
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
 * Returns: { entity, api_key }
 *   api_key is returned ONCE at registration. Store it securely.
 */
export async function POST(request) {
  try {
    const body = await request.json();
    const supabase = getServiceClient();

    // Validate required fields
    const required = ['entity_id', 'display_name', 'entity_type', 'description'];
    for (const field of required) {
      if (!body[field]) {
        return NextResponse.json({ error: `Missing required field: ${field}` }, { status: 400 });
      }
    }

    if (!['agent', 'merchant', 'service_provider'].includes(body.entity_type)) {
      return NextResponse.json({ error: 'entity_type must be: agent, merchant, or service_provider' }, { status: 400 });
    }

    // Check for duplicate entity_id
    const { data: existing } = await supabase
      .from('entities')
      .select('id')
      .eq('entity_id', body.entity_id)
      .single();

    if (existing) {
      return NextResponse.json({ error: `entity_id "${body.entity_id}" is already registered` }, { status: 409 });
    }

    // === SYBIL RESISTANCE: Rate limit registrations ===
    const ownerId = body.owner_id || body.entity_id;
    const regCheck = await checkRegistrationLimits(supabase, ownerId);
    if (!regCheck.allowed) {
      return NextResponse.json({ error: regCheck.reason }, { status: 429 });
    }

    // Generate embedding from description + capabilities
    let embedding = null;
    if (process.env.OPENAI_API_KEY) {
      const embeddingText = [
        body.display_name,
        body.description,
        ...(body.capabilities || []),
        body.category,
      ].filter(Boolean).join('. ');

      const embRes = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'text-embedding-3-small',
          input: embeddingText,
        }),
      });

      if (embRes.ok) {
        const embData = await embRes.json();
        embedding = embData.data[0].embedding;
      }
    }

    // Generate API key
    const { key: apiKey, hash: apiKeyHash, prefix } = generateApiKey();

    // Insert entity
    const { data: entity, error: insertError } = await supabase
      .from('entities')
      .insert({
        entity_id: body.entity_id,
        owner_id: body.owner_id || body.entity_id,
        display_name: body.display_name,
        entity_type: body.entity_type,
        description: body.description,
        website_url: body.website_url || null,
        capabilities: body.capabilities || [],
        input_schema: body.input_schema || null,
        output_schema: body.output_schema || null,
        category: body.category || null,
        service_area: body.service_area || null,
        pricing_model: body.pricing_model || null,
        pricing_amount_cents: body.pricing_amount_cents || 0,
        capability_embedding: embedding,
        a2a_endpoint: body.a2a_endpoint || null,
        ucp_profile_url: body.ucp_profile_url || null,
        api_key_hash: apiKeyHash,
      })
      .select()
      .single();

    if (insertError) {
      console.error('Entity insert error:', insertError);
      return NextResponse.json({ error: 'Failed to register entity' }, { status: 500 });
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
        emilia_score: entity.emilia_score,
        status: entity.status,
        created_at: entity.created_at,
      },
      api_key: apiKey,
      message: 'Store this API key securely. It will not be shown again.',
    }, { status: 201 });
  } catch (err) {
    console.error('Registration error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

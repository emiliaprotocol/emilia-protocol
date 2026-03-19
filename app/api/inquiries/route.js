// SPDX-License-Identifier: Apache-2.0
// POST /api/inquiries — stores partner and investor inquiries

import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { epProblem } from '@/lib/errors';

const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
  : null;

export async function POST(request) {
  try {
    const body = await request.json();
    const { type, name, email, ...rest } = body;

    if (!type || !name || !email) {
      return epProblem(400, 'missing_fields', 'name, email, and type are required');
    }

    if (!['partner', 'investor'].includes(type)) {
      return epProblem(400, 'invalid_type', 'type must be partner or investor');
    }

    const record = {
      inquiry_type: type,
      name,
      email,
      organization: rest.org || rest.firm || null,
      title: rest.title || null,
      website: rest.website || null,
      message: rest.problem || rest.whyEmilia || null,
      metadata_json: JSON.stringify({
        ...(type === 'partner' ? {
          partner_type: rest.partnerType || null,
          trust_surface: rest.trustSurface || null,
          timeline: rest.timeline || null,
        } : {
          why_emilia: rest.whyEmilia || null,
          help_offer: rest.helpOffer || null,
        }),
        notes: rest.notes || null,
      }),
      created_at: new Date().toISOString(),
    };

    // Store in Supabase if available
    if (supabase) {
      const table = type === 'partner' ? 'partner_inquiries' : 'investor_inquiries';
      const { error: dbError } = await supabase.from(table).insert(record);
      if (dbError) {
        console.error(`[inquiries] Supabase insert error (${table}):`, dbError.message);
        // Non-fatal — still return success so the user sees confirmation
      }
    } else {
      // Log to console when no DB is configured
      console.log(`[inquiries] No Supabase configured. ${type} inquiry from ${name} <${email}>:`, JSON.stringify(record, null, 2));
    }

    // TODO: Send notification email via SendGrid/Resend when configured
    // await sendNotificationEmail({ to: 'team@emiliaprotocol.ai', subject: `New ${type} inquiry: ${name}`, body: record });

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error('[inquiries] Error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

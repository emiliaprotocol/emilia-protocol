// SPDX-License-Identifier: Apache-2.0
// POST /api/inquiries — stores partner and investor inquiries

import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../lib/logger.js';

// ---------------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------------

/** Simple email format regex — intentionally permissive (RFC 5321 § 4.1.2). */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Basic URL format validation. */
const URL_RE = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;

/** Strip HTML tags to prevent stored XSS. */
function stripHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/<[^>]*>/g, '');
}

/** Trim, strip HTML, and return null for empty strings. */
function sanitizeText(val) {
  if (val == null) return null;
  const cleaned = stripHtml(String(val).trim());
  return cleaned || null;
}

/** Validate a URL string if present; return null if invalid. */
function sanitizeUrl(val) {
  if (val == null) return null;
  const trimmed = String(val).trim();
  if (!trimmed) return null;
  return URL_RE.test(trimmed) ? trimmed : null;
}

function getSupabase() {
  try {
    return getGuardedClient();
  } catch {
    return null;
  }
}

export async function POST(request) {
  try {
    const body = await request.json();

    // Honeypot field — bots that auto-fill hidden fields will populate this.
    // Legitimate users will never see or fill this field.
    if (body.website_url) {
      // Silently accept to avoid tipping off bots, but do nothing.
      return NextResponse.json({ ok: true });
    }

    const type = typeof body.type === 'string' ? body.type.trim().slice(0, 20) : '';
    const name = sanitizeText(body.name)?.slice(0, 200) ?? null;
    const rawEmail = typeof body.email === 'string' ? body.email.trim().toLowerCase().slice(0, 254) : '';
    const rest = body;

    if (!type || !name || !rawEmail) {
      return epProblem(400, 'missing_fields', 'name, email, and type are required');
    }

    // Validate email format
    if (!EMAIL_RE.test(rawEmail)) {
      return epProblem(400, 'invalid_email', 'Valid email address required');
    }

    if (!['partner', 'investor'].includes(type)) {
      return epProblem(400, 'invalid_type', 'type must be partner or investor');
    }

    // Sanitize and cap all free-text and URL fields
    const organization = sanitizeText(rest.org || rest.firm)?.slice(0, 200) ?? null;
    const title = sanitizeText(rest.title)?.slice(0, 200) ?? null;
    const website = sanitizeUrl(rest.website)?.slice(0, 500) ?? null;
    const message = sanitizeText(rest.problem || rest.whyEmilia)?.slice(0, 5000) ?? null;

    const record = {
      inquiry_type: type,
      name,
      email: rawEmail,
      organization,
      title,
      website,
      message,
      metadata_json: JSON.stringify({
        ...(type === 'partner' ? {
          partner_type: sanitizeText(rest.partnerType),
          trust_surface: sanitizeText(rest.trustSurface),
          timeline: sanitizeText(rest.timeline),
        } : {
          why_emilia: sanitizeText(rest.whyEmilia),
          help_offer: sanitizeText(rest.helpOffer),
        }),
        notes: sanitizeText(rest.notes),
      }),
      created_at: new Date().toISOString(),
    };

    // Store in Supabase if available
    const supabase = getSupabase();
    if (supabase) {
      const table = type === 'partner' ? 'partner_inquiries' : 'investor_inquiries';
      const { error: dbError } = await supabase.from(table).insert(record);
      if (dbError) {
        logger.error(`[inquiries] Supabase insert error (${table}):`, dbError.message);
        // Backup: log the full submission as structured JSON so it can be replayed
        logger.error(`[inquiries] BACKUP_RECORD::${JSON.stringify({ table, record, error: dbError.message, ts: new Date().toISOString() })}`);
        return epProblem(503, 'inquiry_storage_failed', 'Failed to store inquiry. Please try again shortly.', {
          retry: true,
        });
      }
    } else {
      // Log to console when no DB is configured
      logger.info(`[inquiries] No Supabase configured. ${type} inquiry from ${name} <${rawEmail}>:`, JSON.stringify(record, null, 2));
    }

    // TODO: Send notification email via SendGrid/Resend when configured
    // await sendNotificationEmail({ to: 'team@emiliaprotocol.ai', subject: `New ${type} inquiry: ${name}`, body: record });

    return NextResponse.json({ ok: true });
  } catch (err) {
    logger.error('[inquiries] Error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

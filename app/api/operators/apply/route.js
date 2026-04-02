import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../lib/logger.js';

// ---------------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------------

/** Simple email format regex — intentionally permissive (RFC 5321 § 4.1.2). */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

/**
 * POST /api/operators/apply
 *
 * Operator application submission. Stores application in operator_applications table.
 * No auth required — public application process.
 *
 * Body: { name, email, background, motivation }
 * Returns: { id, email, created_at }
 */
export async function POST(request) {
  try {
    const body = await request.json();

    // Honeypot field — bots that auto-fill hidden fields will populate this.
    // Legitimate users will never see or fill this field.
    if (body.website_url) {
      // Silently accept to avoid tipping off bots, but do nothing.
      return NextResponse.json({ id: null, email: '', created_at: new Date().toISOString() }, { status: 201 });
    }

    const name = sanitizeText(body.name);
    const rawEmail = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const background = sanitizeText(body.background);
    const motivation = sanitizeText(body.motivation);

    // Validate email format
    if (!rawEmail || !EMAIL_RE.test(rawEmail)) {
      return epProblem(400, 'invalid_email', 'Valid email required');
    }
    if (!name) {
      return epProblem(400, 'missing_name', 'Name required');
    }

    const normalizedEmail = rawEmail;

    const supabase = getGuardedClient();

    // Check for duplicate application
    const { data: existing, error: lookupError } = await supabase
      .from('operator_applications')
      .select('id')
      .eq('email', normalizedEmail)
      .maybeSingle();

    if (lookupError) {
      // Table may not exist yet — fall back gracefully
      if (lookupError.code === '42P01') {
        logger.warn('operator_applications table missing — run migration 022');
        return NextResponse.json({ id: null, email: normalizedEmail, fallback: true }, { status: 201 });
      }
      logger.error('Operator application lookup error:', lookupError);
      return epProblem(500, 'lookup_failed', 'Could not check for existing application');
    }

    if (existing) {
      return NextResponse.json({ id: existing.id, email: normalizedEmail, already_applied: true });
    }

    const { data: entry, error } = await supabase
      .from('operator_applications')
      .insert({
        name,
        email: normalizedEmail,
        background: background || null,
        motivation: motivation || null,
        status: 'pending',
      })
      .select()
      .single();

    if (error) {
      // Unique constraint violation — race condition duplicate
      if (error.code === '23505') {
        const { data: dup } = await supabase
          .from('operator_applications')
          .select('id')
          .eq('email', normalizedEmail)
          .maybeSingle();
        return NextResponse.json({ id: dup?.id ?? null, email: normalizedEmail, already_applied: true });
      }
      // Table may not exist yet — fall back gracefully
      if (error.code === '42P01') {
        logger.warn('operator_applications table missing — run migration 022');
        return NextResponse.json({ id: null, email: normalizedEmail, fallback: true }, { status: 201 });
      }
      logger.error('Operator application insert error:', error);
      return epProblem(500, 'application_failed', 'Application failed');
    }

    return NextResponse.json({
      id: entry.id,
      email: entry.email,
      created_at: entry.created_at,
    }, { status: 201 });
  } catch (err) {
    logger.error('Operator apply error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

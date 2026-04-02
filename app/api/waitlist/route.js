import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../lib/logger.js';

/**
 * POST /api/waitlist
 *
 * Landing page waitlist registration. Stores email and assigns next entity number.
 * No auth required — this is the public signup form.
 *
 * Body: { email: "user@example.com" }
 * Returns: { id, email, created_at }
 */
export async function POST(request) {
  try {
    const body = await request.json();
    const email = body.email?.trim();

    if (!email || !email.includes('@')) {
      return epProblem(400, 'invalid_email', 'Valid email required');
    }

    const supabase = getGuardedClient();

    // Check if already registered
    const { data: existing } = await supabase
      .from('waitlist')
      .select('id')
      .eq('email', email)
      .single();

    if (existing) {
      return NextResponse.json({ id: existing.id, email, already_registered: true });
    }

    // Get next entity number
    const { data: lastEntity } = await supabase
      .from('entities')
      .select('id')
      .order('id', { ascending: false })
      .limit(1)
      .single();

    const { data: lastWaitlist } = await supabase
      .from('waitlist')
      .select('claimed_number')
      .order('claimed_number', { ascending: false })
      .limit(1)
      .single();

    const lastEntityId = lastEntity?.id || 2;
    const lastClaimedNumber = lastWaitlist?.claimed_number || lastEntityId;
    const nextNumber = Math.max(lastEntityId, lastClaimedNumber) + 1;

    // Insert waitlist entry
    const { data: entry, error } = await supabase
      .from('waitlist')
      .insert({ email, claimed_number: nextNumber })
      .select()
      .single();

    if (error) {
      // If waitlist table doesn't exist yet, fall back gracefully
      if (error.code === '42P01') {
        return NextResponse.json({ id: lastEntityId + 1, email, fallback: true });
      }
      logger.error('Waitlist insert error:', error);
      return epProblem(500, 'registration_failed', 'Registration failed');
    }

    return NextResponse.json({
      id: entry.claimed_number,
      email: entry.email,
      created_at: entry.created_at,
    }, { status: 201 });
  } catch (err) {
    logger.error('Waitlist error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

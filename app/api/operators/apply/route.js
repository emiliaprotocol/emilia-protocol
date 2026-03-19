import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';
import { epProblem } from '@/lib/errors';

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
    const { name, email, background, motivation } = body;

    if (!email || !email.includes('@')) {
      return epProblem(400, 'invalid_email', 'Valid email required');
    }
    if (!name?.trim()) {
      return epProblem(400, 'missing_name', 'Name required');
    }

    const supabase = getServiceClient();

    // Check for duplicate application
    const { data: existing } = await supabase
      .from('operator_applications')
      .select('id')
      .eq('email', email.trim().toLowerCase())
      .single();

    if (existing) {
      return NextResponse.json({ id: existing.id, email, already_applied: true });
    }

    const { data: entry, error } = await supabase
      .from('operator_applications')
      .insert({
        name: name.trim(),
        email: email.trim().toLowerCase(),
        background: background?.trim() || null,
        motivation: motivation?.trim() || null,
        status: 'pending',
      })
      .select()
      .single();

    if (error) {
      // Table may not exist yet — fall back gracefully
      if (error.code === '42P01') {
        console.warn('operator_applications table missing — run migration 022');
        return NextResponse.json({ id: null, email, fallback: true }, { status: 201 });
      }
      console.error('Operator application insert error:', error);
      return epProblem(500, 'application_failed', 'Application failed');
    }

    return NextResponse.json({
      id: entry.id,
      email: entry.email,
      created_at: entry.created_at,
    }, { status: 201 });
  } catch (err) {
    console.error('Operator apply error:', err);
    return epProblem(500, 'internal_error', 'Internal server error');
  }
}

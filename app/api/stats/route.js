import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/stats
 *
 * Public stats for the landing page: entity count, next available number.
 * No auth required.
 */
export async function GET() {
  try {
    const supabase = getServiceClient();

    const { data, error } = await supabase
      .from('entities')
      .select('id')
      .order('id', { ascending: false })
      .limit(1)
      .single();

    const lastId = data?.id || 2;
    const nextId = lastId + 1;

    // Total active entities
    const { count } = await supabase
      .from('entities')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'active');

    return NextResponse.json({
      total_entities: count || 2,
      next_available: nextId,
    });
  } catch (err) {
    return NextResponse.json({ total_entities: 2, next_available: 3 });
  }
}

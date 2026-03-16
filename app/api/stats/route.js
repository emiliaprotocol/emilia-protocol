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

    // Total active entities
    const { count } = await supabase
      .from('entities')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'active');

    const total = count || 2;

    return NextResponse.json({
      total_entities: total,
      next_available: total + 1,
      trust_surfaces: 10,
      automated_checks: 147,
      trust_policies: 8,
      mcp_tools: 15,
    });
  } catch (err) {
    return NextResponse.json({ total_entities: 2, next_available: 3, trust_surfaces: 10, automated_checks: 147, trust_policies: 8, mcp_tools: 15 });
  }
}

import { NextResponse } from 'next/server';
import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/cron/expire
 * 
 * Scheduled job that enforces time-based protocol rules:
 * 
 * 1. Bilateral confirmations: expire after 48 hours
 *    pending_confirmation → expired
 * 
 * 2. Dispute response deadlines: escalate after 7 days
 *    open (past deadline, no response) → under_review
 * 
 * Without this, deadlines are checked only at request time,
 * meaning stale bilateral requests and overdue disputes sit
 * in limbo forever if nobody queries them.
 * 
 * Call via Vercel Cron (vercel.json) or external scheduler.
 * Requires CRON_SECRET for authentication.
 */
export async function GET(request) {
  // Authenticate cron
  const authHeader = request.headers.get('authorization');
  const cronSecret = process.env.CRON_SECRET;

  if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = getServiceClient();
  const now = new Date().toISOString();
  const results = { bilateral_expired: 0, disputes_escalated: 0, errors: [] };

  // 1. Expire stale bilateral confirmations (48h window)
  try {
    const { data: stale } = await supabase
      .from('receipts')
      .select('receipt_id')
      .eq('bilateral_status', 'pending_confirmation')
      .lt('confirmation_deadline', now);

    if (stale && stale.length > 0) {
      const ids = stale.map(r => r.receipt_id);
      await supabase
        .from('receipts')
        .update({ bilateral_status: 'expired' })
        .in('receipt_id', ids);
      results.bilateral_expired = ids.length;
    }
  } catch (err) {
    results.errors.push({ step: 'bilateral_expire', error: err.message });
  }

  // 2. Escalate overdue disputes (7-day response window)
  try {
    const { data: overdue } = await supabase
      .from('disputes')
      .select('dispute_id')
      .eq('status', 'open')
      .lt('response_deadline', now)
      .is('responded_at', null);

    if (overdue && overdue.length > 0) {
      const ids = overdue.map(d => d.dispute_id);
      await supabase
        .from('disputes')
        .update({ status: 'under_review', updated_at: now })
        .in('dispute_id', ids);
      results.disputes_escalated = ids.length;
    }
  } catch (err) {
    results.errors.push({ step: 'dispute_escalate', error: err.message });
  }

  return NextResponse.json({
    status: results.errors.length === 0 ? 'ok' : 'partial',
    timestamp: now,
    ...results,
  });
}

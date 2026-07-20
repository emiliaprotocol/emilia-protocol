/**
 * AI Trust Desk — expiry monitor.
 *
 * @license Apache-2.0
 *
 * Scans published trust pages and, when one crosses into "expiring" (30 days
 * out) or "stale" (past expiry), emails the customer a refresh notice exactly
 * once per status transition. Idempotent: a `monitor.last_notified_status`
 * marker on the page prevents re-notifying on every cron tick.
 *
 * The trust page already self-reports current/expiring/stale at render time
 * (customers.js:trustPageStatus); this just adds the proactive nudge.
 */

import { listPublishedSlugs, getPublishedPage, getPageMonitor, setPageMonitor } from './page-store.js';
import { notifyInternal } from './notify.js';
import { logger } from '../logger.js';

const RESEND_URL = 'https://api.resend.com/emails';
const FROM = process.env.TRUST_DESK_FROM_EMAIL || 'AI Trust Desk <trust@emiliaprotocol.ai>';

/**
 * Run one monitoring pass.
 * @returns {Promise<{scanned:number, current:number, expiring:number, stale:number, notified:string[]}>}
 */
export async function runMonitor() {
  const slugs = await listPublishedSlugs();
  /** @type {{scanned:number, current:number, expiring:number, stale:number, notified:string[]}} */
  const result = { scanned: 0, current: 0, expiring: 0, stale: 0, notified: [] };

  for (const slug of slugs) {
    const page = await getPublishedPage(slug);
    if (!page) continue;
    result.scanned++;

    const status = page.status;
    if (status === 'current' || status === 'unknown') {
      result.current++;
      continue;
    }
    result[/** @type {'expiring'|'stale'} */ (status)]++; // expiring | stale

    // Idempotency: only notify on a *new* status.
    const marker = await getPageMonitor(slug);
    if (marker.last_notified_status === status) continue;

    const customer = /** @type {{contact?: {email?: string}, company?: string}} */ (page.customer);
    const email = customer.contact?.email;
    const ok = await sendRefreshEmail({
      email,
      company: customer.company,
      slug,
      status: /** @type {'expiring'|'stale'} */ (status),
    });
    await setPageMonitor(slug, { last_notified_status: status, at: new Date().toISOString() });
    if (ok) result.notified.push(`${slug}:${status}`);
  }

  if (result.expiring + result.stale > 0) {
    await notifyInternal(
      `:hourglass_flowing_sand: Trust Desk monitor — ${result.expiring} expiring, ${result.stale} stale, ${result.notified.length} notified`,
    );
  }
  logger.info('trust-desk monitor: pass complete', result);
  return result;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * @param {{email: string|undefined, company: string|undefined, slug: string, status: 'expiring'|'stale'}} params
 */
async function sendRefreshEmail({ email, company, slug, status }) {
  if (!email) return false;
  const apiKey = process.env.RESEND_API_KEY;
  const subject =
    status === 'stale'
      ? 'Your AI Trust Page has expired — refresh recommended'
      : 'Your AI Trust Page expires soon';
  const body =
    `Hi ${company || 'there'},\n\n` +
    (status === 'stale'
      ? 'Your published AI Trust Page is past its review date. Buyers may see a "stale" banner. '
      : 'Your AI Trust Page is within 30 days of its review date. ') +
    `Refresh it in minutes by re-submitting your latest questionnaire, or reply to update specific claims.\n\n` +
    `Page: https://www.emiliaprotocol.ai/trust-desk/c/${slug}\n\n— AI Trust Desk`;

  if (!apiKey) {
    logger.info('trust-desk monitor (email suppressed — no RESEND_API_KEY)', { email, status });
    return false;
  }
  try {
    const res = await fetch(RESEND_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ from: FROM, to: email, subject, text: body }),
    });
    return res.ok;
  } catch (err) {
    logger.warn('trust-desk monitor: refresh email failed', { slug, error: err.message });
    return false;
  }
}

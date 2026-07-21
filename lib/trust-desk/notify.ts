/**
 * AI Trust Desk — notifications (graceful, provider-optional).
 *
 * @license Apache-2.0
 *
 * Customer email via Resend (RESEND_API_KEY); internal pings via Slack webhook
 * (TRUST_DESK_SLACK_WEBHOOK). When a provider isn't configured the notification
 * is logged and recorded on the engagement instead of failing — the pipeline's
 * job is to publish, not to be blocked on email delivery.
 */

import { logger } from '../logger.js';

const RESEND_URL = 'https://api.resend.com/emails';
const FROM = process.env.TRUST_DESK_FROM_EMAIL || 'AI Trust Desk <trust@emiliaprotocol.ai>';

/**
 * Notify the customer their trust page is live.
 */
export async function notifyPublished({
  engagement,
  slug,
  trustUrl,
}: {
  engagement: any;
  slug: string;
  trustUrl: string;
}): Promise<{ channel: string; delivered: boolean; detail?: string }> {
  const to = engagement?.intake?.contact_email || engagement?.contact_email;
  const subject = 'Your AI Trust Page is live';
  const body =
    `Your AI Trust Desk packet is published and live at:\n\n${trustUrl}\n\n` +
    `Forward this URL to your buyer's security team. Every claim is signed, ` +
    `timestamped, and independently verifiable. The page stays current — we'll ` +
    `flag it for refresh before it expires.\n\n— AI Trust Desk`;

  await slackPing(`:white_check_mark: Published trust page *${slug}* → ${trustUrl}`);
  return sendEmail({ to, subject, body });
}

/**
 * Notify the customer their packet escalated to a human reviewer.
 */
export async function notifyEscalated({
  engagement,
  reason,
  etaHours = 4,
}: {
  engagement: any;
  reason: string;
  etaHours?: number;
}): Promise<{ channel: string; delivered: boolean; detail?: string }> {
  const to = engagement?.intake?.contact_email || engagement?.contact_email;
  const subject = 'Your AI Trust packet is in review';
  const body =
    `Thanks — your questionnaire is in. A named reviewer is finishing the parts ` +
    `our automated pipeline flagged for human attention. Expected delivery: within ` +
    `${etaHours} business hours.\n\n— AI Trust Desk`;

  await slackPing(
    `:warning: Escalated *${engagement?.engagement_id}* (${reason}) — reviewer SLA ${etaHours}h`,
  );
  return sendEmail({ to, subject, body });
}

/** Internal-only ping (no customer email). */
export async function notifyInternal(message: string): Promise<{ channel: string; delivered: boolean; detail?: string }> {
  return slackPing(message);
}

// ── Providers ───────────────────────────────────────────────────────────────

async function sendEmail({
  to,
  subject,
  body,
}: {
  to?: string;
  subject: string;
  body: string;
}): Promise<{ channel: string; delivered: boolean; detail?: string }> {
  if (!to) {
    return { channel: 'email', delivered: false, detail: 'no recipient' };
  }
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    logger.info('trust-desk notify (email suppressed — no RESEND_API_KEY)', { to, subject });
    return { channel: 'email', delivered: false, detail: 'no_provider' };
  }
  try {
    const res = await fetch(RESEND_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ from: FROM, to, subject, text: body }),
    });
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 200);
      logger.warn('trust-desk notify: resend failed', { status: res.status, detail });
      return { channel: 'email', delivered: false, detail: `resend ${res.status}` };
    }
    return { channel: 'email', delivered: true };
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    logger.warn('trust-desk notify: email threw', { error: errMessage });
    return { channel: 'email', delivered: false, detail: errMessage };
  }
}

async function slackPing(text: string): Promise<{ channel: string; delivered: boolean; detail?: string }> {
  const url = process.env.TRUST_DESK_SLACK_WEBHOOK;
  if (!url) {
    logger.info('trust-desk notify (slack suppressed — no webhook)', { text });
    return { channel: 'slack', delivered: false, detail: 'no_provider' };
  }
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    return { channel: 'slack', delivered: res.ok };
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    logger.warn('trust-desk notify: slack threw', { error: errMessage });
    return { channel: 'slack', delivered: false, detail: errMessage };
  }
}

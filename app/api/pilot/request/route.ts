// SPDX-License-Identifier: Apache-2.0
// POST /api/pilot/request — pilot-request intake (public lead form).
//
// Replaces the bare mailto: CTA on /govguard and /finguard, which is a dead
// button on machines with no configured mail handler (most government
// workstations). Flow: validate → record an audit event (best-effort) →
// notify team@ via Resend → auto-acknowledge the requester with the matching
// vertical's compliance PDF. The request succeeds if EITHER the internal
// notification or the durable record lands — a lead is never silently lost;
// if both fail the caller gets a 503 with the mailto fallback.

import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { MANAGED_PILOT } from '@/lib/commercial-offer';

const RESEND_URL = 'https://api.resend.com/emails';
// Same verified Resend sender domain the Trust Desk uses.
const FROM = process.env.PILOT_FROM_EMAIL || 'EMILIA Protocol <trust@emiliaprotocol.ai>';
const TEAM = 'team@emiliaprotocol.ai';
const MAX_PILOT_REQUEST_BYTES = 16 * 1024;

const WORKFLOWS: Record<string, { label: string; pdf: string | null }> = {
  wire_release: { label: 'Wire / payment release', pdf: 'emilia-eu-ai-act-financial-services.pdf' },
  beneficiary_change: { label: 'Vendor / beneficiary bank-detail change', pdf: 'emilia-eu-ai-act-financial-services.pdf' },
  benefit_account_change: { label: 'Benefit payment-destination change', pdf: 'emilia-eu-ai-act-government.pdf' },
  caseworker_override: { label: 'Caseworker / examiner override', pdf: 'emilia-eu-ai-act-government.pdf' },
  clinical_action: { label: 'Clinical / administrative healthcare action', pdf: 'emilia-eu-ai-act-healthcare.pdf' },
  other: { label: 'Another irreversible agent action', pdf: null },
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function clean(v: unknown, max: number): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

async function sendEmail({ to, subject, body }: { to: string; subject: string; body: string }): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    logger.info('pilot request: email suppressed (no RESEND_API_KEY)', { to, subject });
    return false;
  }
  try {
    const res = await fetch(RESEND_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ from: FROM, to, subject, text: body }),
    });
    if (!res.ok) {
      logger.warn('pilot request: resend failed', { status: res.status, to });
      return false;
    }
    return true;
  } catch (err) {
    logger.warn('pilot request: resend error', { error: String(err), to });
    return false;
  }
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const parsed = await readLimitedJson(request, MAX_PILOT_REQUEST_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;

    // Honeypot: real users never fill the hidden "website" field. Bots do.
    // Return success so the bot learns nothing.
    if (typeof body.website === 'string' && body.website.length > 0) {
      return NextResponse.json({ ok: true });
    }

    const name = clean(body.name, 120);
    const org = clean(body.org, 160);
    const email = clean(body.email, 160);
    const message = clean(body.message, 2000);
    const workflowKey = WORKFLOWS[body.workflow] ? body.workflow : 'other';
    const workflow = WORKFLOWS[workflowKey];

    if (!name || !org) return epProblem(400, 'missing_fields', 'Name and organization are required');
    if (!EMAIL_RE.test(email)) return epProblem(400, 'invalid_email', 'A valid work email is required');

    // 1. Durable record — best-effort; the audit chain is the house pattern
    //    but a storage hiccup must not lose a lead that email can still carry.
    let stored = false;
    try {
      const supabase = getGuardedClient();
      const { error } = await supabase.from('audit_events').insert({
        event_type: 'pilot.request.received',
        actor_id: email,
        // audit_events CHECK constraint allows entity|principal|operator|system|human.
        actor_type: 'human',
        target_type: 'pilot_request',
        target_id: org.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 64) || 'unknown',
        action: 'request_pilot',
        before_state: null,
        after_state: { name, org, email, workflow: workflowKey, message },
      });
      stored = !error;
      if (error) logger.warn('pilot request: audit insert failed', { error: error.message });
    } catch (err) {
      logger.warn('pilot request: audit insert threw', { error: String(err) });
    }

    // 2. Internal notification — this is the lead reaching a human.
    const notified = await sendEmail({
      to: TEAM,
      subject: `PILOT REQUEST: ${org} — ${workflow.label}`,
      body:
        `New pilot request from ${name} (${email})\n` +
        `Organization: ${org}\n` +
        `Workflow: ${workflow.label}\n\n` +
        `${message || '(no message)'}\n\n` +
        `Recorded in audit_events: ${stored ? 'yes' : 'NO — email is the only copy'}`,
    });

    if (!notified && !stored) {
      return epProblem(503, 'intake_unavailable',
        `We could not record your request right now — please email ${TEAM} directly.`);
    }

    // 3. Auto-acknowledgment with the matching compliance mapping. Non-fatal.
    const pdfLine = workflow.pdf
      ? `For your compliance file, the sector mapping we discussed on the site:\nhttps://www.emiliaprotocol.ai/compliance/${workflow.pdf}\n\n`
      : '';
    await sendEmail({
      to: email,
      subject: 'EMILIA pilot request received — what happens next',
      body:
        `Hi ${name.split(' ')[0]},\n\n` +
        `Got your pilot request for: ${workflow.label}.\n\n` +
        `What happens next: I reply personally within one business day with a ` +
        `15-minute scheduling link and the one-page ${MANAGED_PILOT.durationLabel}, ` +
        `${MANAGED_PILOT.priceLabel} pilot scope (${MANAGED_PILOT.workflowLabel}; ` +
        `synthetic first, then a governed read-only export).\n\n` +
        `Meanwhile, three things you can verify without trusting us:\n` +
        `- Be the approver yourself (20 seconds): https://www.emiliaprotocol.ai/try\n` +
        `- Verify a receipt offline: https://www.emiliaprotocol.ai/verify\n` +
        pdfLine +
        `— Iman Schrock, Founder, EMILIA Protocol\n` +
        `team@emiliaprotocol.ai · emiliaprotocol.ai`,
    });

    return NextResponse.json({ ok: true, stored, notified });
  } catch (err) {
    logger.error('pilot request error:', err);
    return epProblem(500, 'internal_error', `Request failed — please email ${TEAM} directly.`);
  }
}

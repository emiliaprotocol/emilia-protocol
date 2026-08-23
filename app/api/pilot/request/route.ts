// SPDX-License-Identifier: Apache-2.0
// POST /api/pilot/request — pilot-request intake (public lead form).
//
// Replaces the bare mailto: CTA on /govguard and /finguard, which is a dead
// button on machines with no configured mail handler (most government
// workstations). Flow: validate → record an audit event (best-effort) →
// notify team@ via Resend. The request succeeds if EITHER the internal
// notification or the durable record lands — a lead is never silently lost;
// if both fail the caller gets a 503 with the mailto fallback.

import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { loadPublicArenaRefusal } from '@/lib/arena/service';
import { loadPublicAgentAdoptionBond } from '@/lib/agent-adoption/service';
import { loadPublicAgentRecord } from '@/lib/agent-record/service';
import { PROTECTED_WORKFLOW_PILOT } from '@/lib/commercial-offer';

const RESEND_URL = 'https://api.resend.com/emails';
// Same verified Resend sender domain the Trust Desk uses.
const FROM = process.env.PILOT_FROM_EMAIL || 'EMILIA Protocol <trust@emiliaprotocol.ai>';
const TEAM = 'team@emiliaprotocol.ai';
const MAX_PILOT_REQUEST_BYTES = 16 * 1024;

const WORKFLOWS: Record<string, { label: string }> = {
  beneficiary_change: { label: 'Vendor / beneficiary bank-detail change' },
  wire_release: { label: 'Wire / payment release' },
  payer_adverse_determination: { label: 'Payer adverse medical-necessity determination' },
  benefit_account_change: { label: 'Benefit payment-destination change' },
  caseworker_override: { label: 'Caseworker / examiner override' },
  clinical_action: { label: 'Clinical / administrative healthcare action' },
  other: { label: 'Another irreversible agent action' },
};

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const ARENA_SHARE_ID = /^arena_share_[0-9a-f]{40}$/;
const AGENT_SHARE_ID = /^agent_share_[0-9a-f]{40}$/;
const AGENT_RECORD_ID = /^agent_record_[0-9a-f]{40}$/;
const UNSUPPORTED_EVIDENCE_FIELDS = Object.freeze([
  'artifact',
  'artifact_url',
  'claimed_evidence',
  'evidence',
  'proof',
  'receipt',
]);

type IntakeOffer = {
  id: string;
  name: string;
  priceLabel: string;
  durationLabel: string;
  workflowLabel: string;
  firstProfileLabel: string;
  safetyRuleLabel: string;
  eligibilityLabel: string;
  rolloutLabel: string;
};

const PILOT_OFFER: IntakeOffer = PROTECTED_WORKFLOW_PILOT;

type ValidatedPublicArtifact = Readonly<{
  id: string;
  kind: 'arena_refusal' | 'operating_bond' | 'agent_record_observation';
  label: 'Arena refusal record' | 'Operating Bond' | 'Agent Record observation';
}>;

function clean(v: unknown, max: number): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

async function validatePublicArtifact(id: string): Promise<ValidatedPublicArtifact | null> {
  if (ARENA_SHARE_ID.test(id)) {
    const record = await loadPublicArenaRefusal(id);
    if (!record || record.share_id !== id || record.verification.integrity_verified !== true) return null;
    return Object.freeze({ id, kind: 'arena_refusal', label: 'Arena refusal record' });
  }
  if (AGENT_SHARE_ID.test(id)) {
    const record = await loadPublicAgentAdoptionBond({ shareId: id });
    if (!record || record.share_id !== id || record.revoked !== false) return null;
    return Object.freeze({ id, kind: 'operating_bond', label: 'Operating Bond' });
  }
  if (AGENT_RECORD_ID.test(id)) {
    const record = await loadPublicAgentRecord({ recordId: id });
    if (!record
        || record.record_id !== id
        || record.verification.integrity_verified !== true
        || record.verification.currently_public !== true) return null;
    return Object.freeze({
      id,
      kind: 'agent_record_observation',
      label: 'Agent Record observation',
    });
  }
  return null;
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

    if (UNSUPPORTED_EVIDENCE_FIELDS.some((field) => Object.hasOwn(body, field))) {
      return epProblem(400, 'unsupported_evidence_claim',
        'Attach an active public Arena or Agent Adoption record identifier instead of claimed evidence');
    }

    const name = clean(body.name, 120);
    const org = clean(body.org, 160);
    const email = clean(body.email, 160);
    const message = clean(body.message, 2000);
    const requestedOfferId = clean(body.offer_id, 100);
    const offer = !requestedOfferId || requestedOfferId === PILOT_OFFER.id ? PILOT_OFFER : null;
    const artifactId = clean(body.artifact_id, 80);
    const workflowKey = WORKFLOWS[body.workflow] ? body.workflow : 'other';
    const workflow = WORKFLOWS[workflowKey];

    if (!name || !org) return epProblem(400, 'missing_fields', 'Name and organization are required');
    if (!EMAIL_RE.test(email)) return epProblem(400, 'invalid_email', 'A valid work email is required');
    if (!offer) return epProblem(400, 'invalid_offer', 'The requested offer is not available');
    let publicArtifact: ValidatedPublicArtifact | null = null;
    if (artifactId) {
      if (!ARENA_SHARE_ID.test(artifactId)
          && !AGENT_SHARE_ID.test(artifactId)
          && !AGENT_RECORD_ID.test(artifactId)) {
        return epProblem(400, 'invalid_artifact_id',
          'Public record ID must be an active Arena, Operating Bond, or Agent Record identifier');
      }
      try {
        publicArtifact = await validatePublicArtifact(artifactId);
      } catch {
        return epProblem(503, 'artifact_validation_unavailable',
          'The public record could not be validated right now; try again later');
      }
      if (!publicArtifact) {
        return epProblem(400, 'invalid_artifact_id',
          'The public record is unknown, inactive, or did not pass its public validation profile');
      }
    }

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
        after_state: {
          name,
          org,
          email,
          workflow: workflowKey,
          buyer_context_unverified: message,
          offer_id: offer.id,
          public_artifact: publicArtifact,
        },
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
        `Offer: ${offer.name} (${offer.id})\n` +
        `Fixed scope: ${offer.durationLabel}; ${offer.priceLabel}; ${offer.workflowLabel}\n` +
        `First profile: ${offer.firstProfileLabel}\n` +
        `Safety rule: ${offer.safetyRuleLabel}\n` +
        `${offer.eligibilityLabel}.\n` +
        `Validated public record: ${publicArtifact ? `${publicArtifact.id} (${publicArtifact.label})` : '(none attached)'}\n\n` +
        `Buyer context (unverified): ${message || '(none)'}\n\n` +
        `Recorded in audit_events: ${stored ? 'yes' : 'NO — email is the only copy'}`,
    });

    if (!notified && !stored) {
      return epProblem(503, 'intake_unavailable',
        `We could not record your request right now — please email ${TEAM} directly.`);
    }

    // Do not send mail to caller-supplied addresses. Public intake only records
    // the request and notifies the internal team; that keeps this endpoint from
    // becoming an outbound-email relay for address validation or harassment.
    return NextResponse.json({ ok: true, stored, notified });
  } catch (err) {
    logger.error('pilot request error:', err);
    return epProblem(500, 'internal_error', `Request failed — please email ${TEAM} directly.`);
  }
}

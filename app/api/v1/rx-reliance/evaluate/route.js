// SPDX-License-Identifier: Apache-2.0
// EP Rx Reliance API — evaluate a pharmacy reliance packet.
//
// POST /api/v1/rx-reliance/evaluate
//   body: { challenge, packet, opts?, now?, appeal_bundle? }
//   -> { verdict, rely, determination, reasons, checks, appeal_bundle? }
//
// The hosted, concierge-grade surface over EP-NCPDP-RX-RELIANCE-PROFILE-v1
// (lib/ncpdp/rx-reliance.js). A relying party (payer / PBM / pharmacy / hub /
// auditor) posts its own pinned EP-RX-EVIDENCE-CHALLENGE-v1 and an
// EP-RX-RELIANCE-PACKET-v1 and gets back ONE closed rx verdict. Pure and
// fail-closed: the reliance kernel introduces no new crypto and this route adds
// no state. NO PHI: consent and clinical legs are signed digests, never records.
// The relying party supplies its own pinned keys in `opts` (approverKeys,
// logPublicKey, rpId, revokerKeys); EMILIA is never in the trust path.
import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/supabase';
import { EP_ERRORS, epProblem } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';
import { evaluateRxReliance, buildRxAppealBundle, RX_VERDICTS } from '@/lib/ncpdp/rx-reliance.js';

const MAX_BODY_BYTES = 256 * 1024;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readEpJson(request, MAX_BODY_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.value || {};

    if (!body.challenge || typeof body.challenge !== 'object') return EP_ERRORS.BAD_REQUEST('challenge (EP-RX-EVIDENCE-CHALLENGE-v1) is required');
    if (!body.packet || typeof body.packet !== 'object') return EP_ERRORS.BAD_REQUEST('packet (EP-RX-RELIANCE-PACKET-v1) is required');
    const opts = (body.opts && typeof body.opts === 'object') ? body.opts : {};

    const result = evaluateRxReliance({ challenge: body.challenge, packet: body.packet, now: body.now }, opts);
    // Defensive: the kernel only ever returns a member of the closed set; if that
    // contract were ever violated, refuse rather than pass an unknown verdict.
    if (!RX_VERDICTS.includes(result.verdict)) return epProblem(500, 'invalid_verdict', 'reliance kernel returned an unrecognized verdict');

    const response = {
      verdict: result.verdict,
      rely: result.rely,
      determination: result.determination,
      reasons: result.reasons,
      checks: result.checks,
    };
    if (body.appeal_bundle === true) {
      response.appeal_bundle = buildRxAppealBundle({ challenge: body.challenge, packet: body.packet, result, now: body.now ?? null });
    }
    return NextResponse.json(response);
  } catch (err) {
    logger.error('rx-reliance evaluate error:', err?.message);
    return EP_ERRORS.INTERNAL();
  }
}

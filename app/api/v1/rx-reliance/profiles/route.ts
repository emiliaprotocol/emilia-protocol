// SPDX-License-Identifier: Apache-2.0
// EP Rx Reliance API — pin a relying-party reliance profile.
//
// POST /api/v1/rx-reliance/profiles
//   body: { profile }   (an EP-RELIANCE-PROFILE-v1)
//   -> { valid, issues?, profile_hash, profile }
//
// The profile-pin surface. A payer/PBM submits its own reliance rule (the
// assurance floor, the accepted registry/issuer keys, the accepted policy
// hashes, the required evidence) and gets back a content-addressed
// `profile_hash`. Pharmacies and prescribers then know exactly what evidence is
// required before submission, and every party pins the SAME rule by hash.
// Validation only; EMILIA authors no bar and stores nothing here. NO PHI.
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { authenticateRequest } from '@/lib/supabase';
import { EP_ERRORS } from '@/lib/errors';
import { readEpJson } from '@/lib/http/route-body';
import { logger } from '@/lib/logger.js';
import { canonicalize } from '@/packages/verify/index.js';
import { validateRelianceProfile } from '@/packages/verify/reliance.js';

const MAX_BODY_BYTES = 64 * 1024;

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return EP_ERRORS.UNAUTHORIZED();

    const parsed = await readEpJson(request, MAX_BODY_BYTES, undefined);
    if (!parsed.ok) return (parsed as { ok: false; response: NextResponse }).response;
    const profile = parsed.value?.profile;
    if (!profile || typeof profile !== 'object') return EP_ERRORS.BAD_REQUEST('profile (EP-RELIANCE-PROFILE-v1) is required');

    const v = validateRelianceProfile(profile);
    const profile_hash = `sha256:${crypto.createHash('sha256').update(canonicalize(profile), 'utf8').digest('hex')}`;
    return NextResponse.json({ valid: v.ok, ...(v.ok ? {} : { issues: v.issues }), profile_hash, profile });
  } catch (err) {
    logger.error('rx-reliance profiles error:', err?.message);
    return EP_ERRORS.INTERNAL();
  }
}

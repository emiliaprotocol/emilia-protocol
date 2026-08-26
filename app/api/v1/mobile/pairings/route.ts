// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { getMobileConfig } from '@/lib/mobile/config.js';
import {
  createPairing,
  listMobilePairingIdentityCredentials,
  mobilePairingIdentityChallenge,
} from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { hasApproverEnrollmentPermission } from '@/lib/approver-enrollment-auth.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding.js';
import { resolveEnrollmentBasis } from '@/lib/scim/directory-anchor.js';

const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const MAX_BODY_BYTES = 16 * 1024;
const MEMBERS: Set<string> = new Set(['approver_id']);

function pairingCode(): string {
  const raw = Array.from(
    { length: 12 },
    () => ALPHABET[crypto.randomInt(ALPHABET.length)],
  ).join('');
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Pairing requests require application/json');
    }
    const limited = await checkRateLimit(getClientIP(request), 'mobile_pairing');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile pairing requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    if (!hasApproverEnrollmentPermission(auth)) {
      return mobileProblem(403, 'insufficient_permission', 'Mobile approver pairing requires approver.enroll or admin permission');
    }
    // lib/http/body-limit's readLimitedJson return type doesn't yet cover the
    // invalidValue option this call relies on; cast at this exact access
    // point to the shape it actually returns rather than fighting that
    // module's own (incomplete) inference.
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} } as any) as
      | { ok: true; value: any }
      | { ok: false; status: number; code: string; detail: string };
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))) {
      return mobileProblem(400, 'invalid_pairing_request', 'Pairing request has unknown or malformed members');
    }
    const approverId = parsed.value.approver_id;
    if (!APPROVER_ID_PATTERN.test(approverId || '')) {
      return mobileProblem(400, 'invalid_approver_id', 'approver_id must be 3-128 chars of [A-Za-z0-9:_.@-]');
    }
    const org = resolveAuthorizedOrg(auth as any, undefined, { requireBound: true });
    if (org.error || !org.organizationId) {
      return mobileProblem(org.error?.status || 403, org.error?.code || 'entity_not_org_bound', org.error?.detail || 'Authenticated entity is not bound to an organization');
    }
    const supabase = getGuardedClient();
    const enrollment = await resolveEnrollmentBasis(supabase, org.organizationId, approverId);
    if (enrollment.error) {
      return mobileProblem(enrollment.error.status, enrollment.error.code, enrollment.error.detail);
    }
    // Mobile enrollment adds a second device for an already directory-owned
    // identity. Operator-attested pilot names are intentionally insufficient:
    // otherwise an administrator could mint a code in somebody else's name.
    if (enrollment.basis !== 'directory' || !enrollment.directoryUserId) {
      return mobileProblem(403, 'directory_identity_required', 'Mobile pairing requires an active directory-backed approver identity');
    }
    const identityCredentials = await listMobilePairingIdentityCredentials(supabase, {
      organizationId: org.organizationId,
      approverId: enrollment.storedApproverId,
      directoryUserId: enrollment.directoryUserId,
    });
    if (identityCredentials.length === 0) {
      return mobileProblem(403, 'identity_credential_required', 'The directory approver must enroll a Class-A credential before adding a mobile device');
    }
    const config = getMobileConfig();
    const now = Date.now();
    const code = pairingCode();
    const allowedApps = {
      ios: [config.iosBundleId],
      android: config.androidConfigured && process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON
        ? [config.androidPackageName]
        : [],
    };
    await createPairing(supabase, {
      code,
      entityRef: authEntityId(auth as any),
      organizationId: org.organizationId,
      approverId: enrollment.storedApproverId,
      directoryUserId: enrollment.directoryUserId,
      profileId: config.profileId,
      allowedApps,
      expiresAt: new Date(now + config.pairingTtlMs).toISOString(),
      sessionExpiresAt: new Date(now + config.sessionTtlMs).toISOString(),
    });
    return mobileJson({
      pairing_code: code,
      identity_challenge: mobilePairingIdentityChallenge(code),
      identity_challenge_profile: 'EP-MOBILE-PAIRING-IDENTITY-v1',
      identity_allow_credentials: identityCredentials,
      profile_id: config.profileId,
      expires_at: new Date(now + config.pairingTtlMs).toISOString(),
      enabled_platforms: [
        'ios',
        ...(allowedApps.android.length ? ['android'] : []),
      ],
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] pairing creation failed', error);
    return mobileProblem(503, 'mobile_pairing_unavailable', 'Mobile pairing service unavailable');
  }
}

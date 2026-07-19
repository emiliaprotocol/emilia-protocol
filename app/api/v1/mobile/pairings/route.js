// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { APPROVER_ID_PATTERN } from '@/lib/webauthn.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { getMobileConfig } from '@/lib/mobile/config.js';
import { createPairing } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const MAX_BODY_BYTES = 16 * 1024;
const MEMBERS = new Set(['approver_id']);

function pairingCode() {
  const raw = Array.from(
    { length: 12 },
    () => ALPHABET[crypto.randomInt(ALPHABET.length)],
  ).join('');
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
}

export async function POST(request) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Pairing requests require application/json');
    }
    const limited = await checkRateLimit(getClientIP(request), 'mobile_pairing');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile pairing requests');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(auth, 'write'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'A write-capable organization key is required');
    }
    const parsed = await readLimitedJson(request, MAX_BODY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    if (!parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)
        || !Object.keys(parsed.value).every((key) => MEMBERS.has(key))) {
      return mobileProblem(400, 'invalid_pairing_request', 'Pairing request has unknown or malformed members');
    }
    const approverId = parsed.value.approver_id;
    if (!APPROVER_ID_PATTERN.test(approverId || '')) {
      return mobileProblem(400, 'invalid_approver_id', 'approver_id must be 3-128 chars of [A-Za-z0-9:_.@-]');
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
    await createPairing(getGuardedClient(), {
      code,
      entityRef: authEntityId(auth),
      approverId,
      profileId: config.profileId,
      allowedApps,
      expiresAt: new Date(now + config.pairingTtlMs).toISOString(),
      sessionExpiresAt: new Date(now + config.sessionTtlMs).toISOString(),
    });
    return mobileJson({
      pairing_code: code,
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

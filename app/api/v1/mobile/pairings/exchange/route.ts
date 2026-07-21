// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { exchangePairing } from '@/lib/mobile/store.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

const CODE = /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/;
const APP_ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const MAX_BODY_BYTES = 8 * 1024;
const MEMBERS: Set<string> = new Set(['pairing_code', 'platform', 'app_id']);

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Pairing exchanges require application/json');
    }
    const limited = await checkRateLimit(getClientIP(request), 'mobile_pairing');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many mobile pairing attempts');
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
      return mobileProblem(400, 'invalid_pairing', 'Pairing exchange has unknown or malformed members');
    }
    const code = typeof parsed.value.pairing_code === 'string'
      ? parsed.value.pairing_code.trim().toUpperCase()
      : '';
    const platform = parsed.value.platform;
    const appId = parsed.value.app_id;
    if (!CODE.test(code) || !['ios', 'android'].includes(platform) || !APP_ID.test(appId || '')) {
      return mobileProblem(400, 'invalid_pairing', 'Pairing code, platform, or app identity is malformed');
    }
    const token = `ep_mobile_${crypto.randomBytes(32).toString('base64url')}`;
    const result = await exchangePairing(getGuardedClient(), { code, token, platform, appId });
    if (result.ok !== true) return mobileProblem(401, 'pairing_refused', 'Pairing code is invalid, expired, consumed, or not valid for this app');
    return mobileJson({
      access_token: token,
      token_type: 'Bearer',
      expires_at: result.expires_at,
      approver_id: result.approver_id,
      profile_id: result.profile_id,
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] pairing exchange failed', error);
    return mobileProblem(503, 'mobile_pairing_unavailable', 'Mobile pairing service unavailable');
  }
}

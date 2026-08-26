// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { getGuardedClient } from '@/lib/write-guard.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import {
  exchangePairingVerified,
  loadMobilePairingIdentityContext,
  mobilePairingIdentityChallenge,
} from '@/lib/mobile/store.js';
import { getRpConfig } from '@/lib/webauthn.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';

const CODE = /^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/;
const APP_ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const MAX_BODY_BYTES = 128 * 1024;
const MEMBERS: Set<string> = new Set(['pairing_code', 'platform', 'app_id', 'identity_assertion']);
const SUPPORTED_TRANSPORTS = new Set<AuthenticatorTransportFuture>([
  'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb',
]);

function supportedTransports(value: string[] | null | undefined): AuthenticatorTransportFuture[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const result = value.filter((item): item is AuthenticatorTransportFuture =>
    SUPPORTED_TRANSPORTS.has(item as AuthenticatorTransportFuture));
  return result.length > 0 ? result : undefined;
}

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
    const assertion = parsed.value.identity_assertion;
    if (!CODE.test(code) || !['ios', 'android'].includes(platform) || !APP_ID.test(appId || '')
        || !assertion || typeof assertion !== 'object' || Array.isArray(assertion)
        || typeof assertion.id !== 'string' || !assertion.id) {
      return mobileProblem(400, 'invalid_pairing', 'Pairing code, platform, app identity, and identity assertion are required');
    }
    const supabase = getGuardedClient();
    const identity = await loadMobilePairingIdentityContext(supabase, {
      code,
      credentialId: assertion.id,
    });
    if (!identity) {
      return mobileProblem(403, 'pairing_identity_refused', 'Pairing identity is not an active directory-backed approver credential');
    }
    const { rpID, origin } = getRpConfig();
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: mobilePairingIdentityChallenge(code),
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: identity.credential.credential_id,
          publicKey: Buffer.from(identity.credential.public_key_cose, 'base64url'),
          counter: identity.credential.sign_count,
          transports: supportedTransports(identity.credential.transports),
        },
        requireUserVerification: true,
      });
    } catch {
      return mobileProblem(400, 'pairing_identity_invalid', 'Pairing identity assertion did not verify');
    }
    if (!verification.verified) {
      return mobileProblem(400, 'pairing_identity_invalid', 'Pairing identity assertion did not verify');
    }
    const token = `ep_mobile_${crypto.randomBytes(32).toString('base64url')}`;
    const identityProofDigest = `sha256:${crypto.createHash('sha256')
      .update(JSON.stringify(assertion), 'utf8')
      .digest('hex')}`;
    const result = await exchangePairingVerified(supabase, {
      code,
      token,
      platform,
      appId,
      credentialId: identity.credential.credential_id,
      approverId: identity.approverId,
      newSignCount: Number(verification.authenticationInfo.newCounter) || 0,
      identityProofDigest,
    });
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

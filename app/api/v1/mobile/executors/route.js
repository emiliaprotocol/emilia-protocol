// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { authenticateRequest, authEntityId } from '@/lib/supabase.js';
import { getGuardedClient } from '@/lib/write-guard.js';
import { registerMobileExecutorKey } from '@/lib/mobile/store.js';
import { mobileExecutorKeyId } from '@/lib/mobile/action-continuity.js';
import { readLimitedJson } from '@/lib/http/body-limit.js';
import { mobileJson, mobileProblem } from '@/lib/mobile/response.js';
import { logger } from '@/lib/logger.js';
import { checkRateLimit, getClientIP } from '@/lib/rate-limit.js';
import { requirePermission } from '@/lib/cloud/authorize.js';

const MEMBERS = new Set(['executor_id', 'key_id', 'public_key']);

export async function POST(request) {
  try {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return mobileProblem(415, 'invalid_content_type', 'Executor registration requires application/json');
    }
    const limited = await checkRateLimit(`ip:${getClientIP(request)}`, 'mobile_runtime_ip');
    if (!limited.allowed) return mobileProblem(429, 'rate_limited', 'Too many executor registrations');
    const auth = await authenticateRequest(request);
    if (auth.error) return mobileProblem(auth.status || 401, auth.code || 'unauthorized', auth.error);
    try { requirePermission(/** @type {any} */ (auth), 'admin'); } catch {
      return mobileProblem(403, 'insufficient_permission', 'An organization admin key is required');
    }
    const parsed = await readLimitedJson(request, 16 * 1024, { invalidValue: null });
    if (!parsed.ok) return mobileProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || !Object.keys(body).every((key) => MEMBERS.has(key))
        || typeof body.executor_id !== 'string' || body.executor_id.length < 3
        || typeof body.public_key !== 'string' || typeof body.key_id !== 'string') {
      return mobileProblem(400, 'invalid_executor_key', 'Executor key registration is malformed');
    }
    try {
      const key = crypto.createPublicKey({
        key: Buffer.from(body.public_key, 'base64url'),
        type: 'spki',
        format: 'der',
      });
      if (key.asymmetricKeyType !== 'ed25519' || mobileExecutorKeyId(body.public_key) !== body.key_id) {
        return mobileProblem(400, 'invalid_executor_key', 'Executor key ID or algorithm is invalid');
      }
    } catch {
      return mobileProblem(400, 'invalid_executor_key', 'Executor public key is invalid');
    }
    const registered = await registerMobileExecutorKey(getGuardedClient(), {
      entityRef: authEntityId(auth),
      executorId: body.executor_id,
      keyId: body.key_id,
      publicKey: body.public_key,
    });
    if (!registered) return mobileProblem(409, 'executor_key_refused', 'Executor key registration was refused');
    return mobileJson({
      registered: true,
      executor_id: body.executor_id,
      key_id: body.key_id,
    }, { status: 201, headers: { 'cache-control': 'no-store' } });
  } catch (error) {
    logger.error('[mobile] executor registration failed', error);
    return mobileProblem(503, 'mobile_executor_registration_unavailable', 'Executor registration unavailable');
  }
}

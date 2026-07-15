// SPDX-License-Identifier: Apache-2.0
import { strictJsonGate } from './strict-json.js';

const JSON_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-type': 'application/json; charset=utf-8',
});
const ENROLLMENT_ISSUE_MEMBERS = new Set(['approver_id', 'platform', 'app_id']);
const PRESENTATION_MEMBERS = new Set(['challenge', 'response']);

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exactMembers(value, members) {
  return record(value) && Object.keys(value).every((key) => members.has(key));
}

function safeJsonNumbers(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(safeJsonNumbers);
  if (record(value)) return Object.values(value).every(safeJsonNumbers);
  return true;
}

function reply(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function refused(status, verdict, reason) {
  return reply({ ok: false, valid: false, verdict, reason }, status);
}

function protocolStatus(result) {
  if (result?.verdict === 'refuse_malformed') return 400;
  if (result?.verdict === 'refuse_unauthorized') return 403;
  if (['refuse_store_unavailable', 'refuse_audit_unavailable'].includes(result?.verdict)) return 503;
  return 200;
}

async function parseBody(request, maxBodyBytes) {
  const type = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (type !== 'application/json') return { ok: false, reason: 'content type must be application/json' };
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxBodyBytes) {
      return { ok: false, reason: 'request body exceeds the configured limit' };
    }
  }
  let raw;
  try {
    const reader = request.body?.getReader();
    if (!reader) return { ok: false, reason: 'request body is required' };
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBodyBytes) {
        await reader.cancel();
        return { ok: false, reason: 'request body exceeds the configured limit' };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, reason: 'request body could not be read' };
  }
  const strict = strictJsonGate(raw);
  if (!strict.ok) return { ok: false, reason: strict.reason };
  const value = JSON.parse(raw);
  if (!record(value)) return { ok: false, reason: 'request body must be a JSON object' };
  if (!safeJsonNumbers(value)) return { ok: false, reason: 'JSON numbers must be safe integers' };
  return { ok: true, value };
}

/**
 * Fetch-compatible transport for the native reference applications.
 * Authentication is provided by the deployment and never inferred from JSON.
 */
export function createMobileHttpHandler({
  controller,
  enrollmentService,
  authenticate,
  resolveEnrollmentIdentity,
  enrollmentConfig,
  maxBodyBytes = 1_048_576,
} = {}) {
  if (typeof controller?.issue !== 'function' || typeof controller?.verify !== 'function') {
    throw new TypeError('controller must be a government mobile controller');
  }
  if (typeof enrollmentService?.issue !== 'function' || typeof enrollmentService?.complete !== 'function') {
    throw new TypeError('enrollmentService must be an EMILIA mobile enrollment service');
  }
  if (typeof authenticate !== 'function') throw new TypeError('authenticate must return the agency principal');
  if (typeof resolveEnrollmentIdentity !== 'function') {
    throw new TypeError('resolveEnrollmentIdentity must read the agency identity directory');
  }
  if (!record(enrollmentConfig) || typeof enrollmentConfig.rpId !== 'string'
      || typeof enrollmentConfig.origin !== 'string' || !enrollmentConfig.origin.startsWith('https://')) {
    throw new TypeError('enrollmentConfig must pin rpId and HTTPS origin');
  }
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 2_097_152) {
    throw new TypeError('maxBodyBytes must be an integer from 1024 to 2097152');
  }

  return async function handleMobileRequest(request) {
    let url;
    try {
      url = new URL(request?.url);
    } catch {
      return refused(400, 'refuse_malformed', 'request URL is malformed');
    }
    const routes = new Set([
      '/v1/mobile/challenges',
      '/v1/mobile/ceremonies',
      '/v1/mobile/enrollments/challenges',
      '/v1/mobile/enrollments',
    ]);
    if (!routes.has(url.pathname)) return refused(404, 'refuse_malformed', 'mobile endpoint not found');
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ ok: false, valid: false, verdict: 'refuse_malformed', reason: 'method not allowed' }), {
        status: 405,
        headers: { ...JSON_HEADERS, allow: 'POST' },
      });
    }
    if (url.protocol !== 'https:') return refused(400, 'refuse_malformed', 'HTTPS is required');

    let caller;
    try {
      caller = await authenticate(request);
    } catch {
      caller = null;
    }
    if (caller === null || caller === undefined || caller === false) {
      return refused(401, 'refuse_unauthorized', 'authentication required');
    }

    const parsed = await parseBody(request, maxBodyBytes);
    if (!parsed.ok) return refused(400, 'refuse_malformed', parsed.reason);
    const body = parsed.value;

    try {
      let result;
      if (url.pathname === '/v1/mobile/challenges') {
        result = await controller.issue(body, caller);
      } else if (url.pathname === '/v1/mobile/ceremonies') {
        if (!exactMembers(body, PRESENTATION_MEMBERS)) {
          return refused(400, 'refuse_malformed', 'ceremony body has unknown members');
        }
        result = await controller.verify(body, caller);
      } else if (url.pathname === '/v1/mobile/enrollments/challenges') {
        if (!exactMembers(body, ENROLLMENT_ISSUE_MEMBERS)
            || typeof body.approver_id !== 'string'
            || !['ios', 'android'].includes(body.platform)
            || typeof body.app_id !== 'string') {
          return refused(400, 'refuse_malformed', 'enrollment request is malformed');
        }
        const identity = await resolveEnrollmentIdentity({ caller, approver_id: body.approver_id });
        if (!record(identity) || typeof identity.userName !== 'string' || !identity.userName
            || typeof identity.displayName !== 'string' || !identity.displayName) {
          return refused(403, 'refuse_unauthorized', 'approver identity could not be resolved');
        }
        result = await enrollmentService.issue({
          approverId: body.approver_id,
          platform: body.platform,
          appId: body.app_id,
          rpId: enrollmentConfig.rpId,
          origin: enrollmentConfig.origin,
          userName: identity.userName,
          displayName: identity.displayName,
          caller,
        });
      } else {
        if (!exactMembers(body, PRESENTATION_MEMBERS)) {
          return refused(400, 'refuse_malformed', 'enrollment completion has unknown members');
        }
        result = await enrollmentService.complete({ ...body, caller });
      }
      return reply(result, protocolStatus(result));
    } catch {
      return refused(503, 'refuse_store_unavailable', 'mobile authorization service unavailable');
    }
  };
}

export default { createMobileHttpHandler };

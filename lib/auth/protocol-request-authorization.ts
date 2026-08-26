// SPDX-License-Identifier: Apache-2.0
// Central authorization floor for API-key-authenticated protocol requests.

import { isObserveScoped, isServerMarkedObserveScope } from './observe-scope.js';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Public pilot credentials may reach only these shared runGuardPrecheck-backed
 * adapter routes. Keep this an exact list: route-family wildcards make newly
 * added consequence endpoints writable before they have been reviewed.
 */
export const OBSERVE_PRECHECK_PATHS = Object.freeze([
  '/api/v1/adapters/fin/beneficiary-creation/precheck',
  '/api/v1/adapters/fin/payment-release/precheck',
  '/api/v1/adapters/fin/vendor-bank-change/precheck',
  '/api/v1/adapters/gov/benefit-address-change/precheck',
  '/api/v1/adapters/gov/benefit-bank-change/precheck',
  '/api/v1/adapters/gov/caseworker-override/precheck',
  '/api/v1/adapters/gov/disbursement-release/precheck',
  '/api/v1/adapters/gov/eligibility-override/precheck',
  '/api/v1/adapters/gov/grant-disbursement/precheck',
  '/api/v1/adapters/gov/provider-enrollment-change/precheck',
  '/api/v1/adapters/gov/vendor-payment-destination-change/precheck',
]);

const OBSERVE_PRECHECK_PATH_SET = new Set(OBSERVE_PRECHECK_PATHS);
const OBSERVE_REPORT_PATH = '/api/pilot/sandbox/report';

const NAMED_POST_CAPABILITIES = new Map<string, string>([
  ['/api/keys/rotate', 'keys.rotate'],
  ['/api/sso/connections', 'sso.manage'],
  ['/api/scim/v2/provisioning-token', 'scim.manage'],
  ['/api/v1/approvers/webauthn/register-options', 'approver.enroll'],
  ['/api/v1/approvers/webauthn/register-verify', 'approver.enroll'],
  ['/api/identity/continuity/resolve', 'dispute.review'],
]);

const READ_ONLY_POST_PATHS = new Set([
  '/api/trust/evaluate',
  '/api/trust/install-preflight',
  '/api/v1/rx-reliance/evaluate',
  '/api/v1/rx-reliance/profiles',
]);

const RECEIPT_CONSUME_PATH = /^\/api\/v1\/trust-receipts\/[^/]+\/consume$/;
const RECEIPT_EXECUTION_PATH = /^\/api\/v1\/trust-receipts\/[^/]+\/execution$/;

export interface ProtocolAuthLike {
  entity?: unknown;
  permissions?: unknown;
}

export interface ProtocolRequestLike {
  method?: string;
  url?: string;
  nextUrl?: { pathname?: string };
}

export type ProtocolRequestAuthorization =
  | { allowed: true }
  | {
    allowed: false;
    error: string;
    code: 'insufficient_permissions';
    status: 403;
  };

function requestPath(request: ProtocolRequestLike): string | null {
  if (typeof request?.nextUrl?.pathname === 'string' && request.nextUrl.pathname.startsWith('/')) {
    return request.nextUrl.pathname;
  }
  if (typeof request?.url !== 'string' || request.url.length === 0) return null;
  try {
    return new URL(request.url, 'https://www.emiliaprotocol.ai').pathname;
  } catch {
    return null;
  }
}

function permissionSet(auth: ProtocolAuthLike): Set<string> {
  return new Set(
    Array.isArray(auth?.permissions)
      ? auth.permissions.filter((permission): permission is string => typeof permission === 'string')
      : [],
  );
}

function namedPostCapability(path: string | null): string | null {
  if (!path) return null;
  const exact = NAMED_POST_CAPABILITIES.get(path);
  if (exact) return exact;
  if (RECEIPT_CONSUME_PATH.test(path)) return 'receipt.consume';
  if (RECEIPT_EXECUTION_PATH.test(path)) return 'receipt.execute';
  return null;
}

function denied(required: string): ProtocolRequestAuthorization {
  return {
    allowed: false,
    error: `Insufficient permissions: ${required} required`,
    code: 'insufficient_permissions',
    status: 403,
  };
}

/**
 * Apply the permission floor after API-key authentication succeeds.
 *
 * GET/HEAD/OPTIONS behavior is deliberately unchanged. Mutations require
 * write/admin unless an exact route names a narrower capability. Observe-mode
 * pilot identities are a separate, deny-by-default class: stale write/admin
 * bits can never widen them beyond the exact precheck list.
 */
export function authorizeProtocolRequest(
  auth: ProtocolAuthLike,
  request: ProtocolRequestLike,
): ProtocolRequestAuthorization {
  const method = typeof request?.method === 'string' ? request.method.toUpperCase() : '';
  const path = requestPath(request);
  const permissions = permissionSet(auth);

  // A self-serve pilot key is a narrow product capability, not a general
  // authenticated-directory credential. Evaluate this class before the normal
  // read-method pass-through so anonymously minted keys cannot enumerate feed,
  // entity, policy, leaderboard, statistics, or other authenticated reads.
  if (isObserveScoped(auth)) {
    const positiveGrant = isServerMarkedObserveScope(auth) && permissions.has('observe');
    const maySubmitObservation = positiveGrant
      && method === 'POST'
      && path !== null
      && OBSERVE_PRECHECK_PATH_SET.has(path);
    const mayReadOwnReport = positiveGrant
      && method === 'GET'
      && path === OBSERVE_REPORT_PATH;
    return maySubmitObservation || mayReadOwnReport
      ? { allowed: true }
      : denied('observe on an approved pilot precheck route or read the pilot sandbox report');
  }

  if (!MUTATING_METHODS.has(method)) return { allowed: true };

  if (method === 'POST') {
    const namedCapability = namedPostCapability(path);
    if (namedCapability) {
      // Receipt routes retain the established creator flow for ordinary
      // write-capable keys. Their route-level actor/tenant guard then requires
      // creator ownership or the exact peer capability. Other named control
      // planes do not have that ownership fallback.
      const receiptMutation = namedCapability === 'receipt.consume'
        || namedCapability === 'receipt.execute';
      const creatorCompatibleReceiptMutation = receiptMutation && permissions.has('write');
      return permissions.has(namedCapability) || permissions.has('admin')
        || creatorCompatibleReceiptMutation
        ? { allowed: true }
        : denied(receiptMutation
          ? `${namedCapability}, write, or admin`
          : `${namedCapability} or admin`);
    }

    if (path !== null && READ_ONLY_POST_PATHS.has(path)) {
      return permissions.has('read') || permissions.has('write') || permissions.has('admin')
        ? { allowed: true }
        : denied('read, write, or admin');
    }
  }

  return permissions.has('write') || permissions.has('admin')
    ? { allowed: true }
    : denied('write or admin');
}

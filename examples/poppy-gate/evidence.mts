// SPDX-License-Identifier: Apache-2.0
// Optional, company-pinned exact-operation approval evidence. This is a local
// reference profile over native EP receipts, not a new Poppy wire standard.
import { verifyTrustReceipt } from '../../packages/verify/dist/index.js';
import { verifyAuthorizationChain } from '../../packages/verify/dist/evidence-chain.js';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type ObjectValue = Record<string, any>;
export type PoppyApprovalResult = {
  satisfied: boolean; reasons: string[]; action_digest: string | null;
};

const own = (value: ObjectValue, name: string): boolean => Object.hasOwn(value, name);
const OP_KEYS = new Set(['operation_id', 'revision', 'state', 'summary', 'terms',
  'expires_at', 'user_approval_required', 'url', 'confirmation', 'result']);
const OWNER_KEYS = new Set(['clientId', 'userId', 'sessionId', 'accountId']);
const STATES = new Set(['proposed', 'in_progress', 'succeeded', 'failed', 'cancelled', 'expired']);

function record(value: any): value is ObjectValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

// Parsed JSON is the intended input. Accessors, exotic prototypes, sparse
// arrays, non-finite numbers and unbounded terms are rejected before hashing.
function copyJson(value: unknown, maxBytes = 65536, maxDepth = 16): Json {
  let nodes = 0;
  const seen = new Set<object>();
  function visit(current: any, depth: number): Json {
    if (++nodes > 10000 || depth > maxDepth) throw new TypeError('bounded_json_required');
    if (current === null || typeof current === 'boolean') return current;
    if (typeof current === 'number' && Number.isFinite(current)) return current;
    if (typeof current === 'string' && Buffer.byteLength(current, 'utf8') <= maxBytes) return current;
    if ((!record(current) && !Array.isArray(current)) || seen.has(current)) throw new TypeError('bounded_json_required');
    seen.add(current);
    const descriptors = Object.getOwnPropertyDescriptors(current);
    const keys = Reflect.ownKeys(current);
    if (keys.some(key => typeof key !== 'string')) throw new TypeError('bounded_json_required');
    for (const key of keys as string[]) {
      if (Array.isArray(current) && key === 'length') continue;
      const descriptor = descriptors[key];
      if (!descriptor?.enumerable || !own(descriptor, 'value')) throw new TypeError('bounded_json_required');
    }
    let result: Json;
    if (Array.isArray(current)) {
      if (keys.length !== current.length + 1 || current.length > 4000) throw new TypeError('bounded_json_required');
      result = current.map((_: any, index: number) => visit(descriptors[String(index)].value, depth + 1));
    } else {
      result = Object.create(null);
      for (const key of keys as string[]) {
        if (Buffer.byteLength(key, 'utf8') > 256) throw new TypeError('bounded_json_required');
        (result as ObjectValue)[key] = visit(descriptors[key].value, depth + 1);
      }
    }
    seen.delete(current);
    return result;
  }
  const result = visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(result), 'utf8') > maxBytes) throw new TypeError('bounded_json_required');
  return result;
}

function closed(value: any, keys: Set<string>): boolean {
  return record(value) && Object.keys(value).every(key => keys.has(key));
}

function text(value: any, max = 512): boolean {
  return typeof value === 'string' && value.length > 0 && value.trim() === value
    && Buffer.byteLength(value, 'utf8') <= max;
}

function instant(value: any): number {
  if (typeof value !== 'string') return NaN;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, zoneHour, zoneMinute] = match;
  const date = new Date(0);
  date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  date.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (date.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`
      || (zoneHour !== undefined && (Number(zoneHour) > 23 || Number(zoneMinute) > 59))) return NaN;
  return Date.parse(value);
}

function httpsUrl(value: any, issuer = false): boolean {
  if (!text(value, 2048)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.hash
      && (!issuer || !url.search);
  } catch { return false; }
}

/**
 * Construct the exact action from the company's immutable operation and a
 * trusted, already authenticated session context. Account-owned operations
 * deliberately omit the changing session ID; signed-out operations bind it.
 * The host must establish DPoP/token/account validity before calling this.
 * Dynamic state, confirmation and result are not approval terms.
 */
export function buildPoppyAction(operation: unknown, owner: unknown, companyIssuer: string): ObjectValue {
  const op = copyJson(operation) as ObjectValue;
  const principal = copyJson(owner) as ObjectValue;
  if (!httpsUrl(companyIssuer, true) || !closed(op, OP_KEYS) || !closed(principal, OWNER_KEYS)
      || !text(op.operation_id) || !Number.isSafeInteger(op.revision) || op.revision < 1
      || !STATES.has(op.state) || !text(op.summary, 8192)
      || !Number.isFinite(instant(op.expires_at))
      || (own(op, 'user_approval_required') && typeof op.user_approval_required !== 'boolean')
      || (own(op, 'terms') && !record(op.terms))
      || (own(op, 'url') && !httpsUrl(op.url))
      || !text(principal.clientId, 2048) || !text(principal.userId)
      || !text(principal.sessionId) || (principal.accountId !== null && !text(principal.accountId))
      || (own(op, 'confirmation') && op.confirmation !== null && !record(op.confirmation))
      || (own(op, 'result') && op.result !== null && !record(op.result))) {
    throw new TypeError('invalid_poppy_action_context');
  }
  const identity: ObjectValue = { client_id: principal.clientId, user_id: principal.userId };
  if (principal.accountId === null) identity.session_id = principal.sessionId;
  else identity.account_id = principal.accountId;
  const material: ObjectValue = { operation_id: op.operation_id, revision: op.revision,
    summary: op.summary, expires_at: op.expires_at,
    user_approval_required: op.user_approval_required ?? false };
  if (own(op, 'terms')) material.terms = op.terms;
  if (own(op, 'url')) material.url = op.url;
  return { ep_version: '1.0', action_type: 'poppy.operation.confirm',
    policy_id: 'poppy:operation-confirm@v1', initiator: principal.clientId,
    company_issuer: companyIssuer, owner: identity, operation: material };
}

function sameOwnerScope(left: ObjectValue, right: ObjectValue): boolean {
  return left.clientId === right.clientId && left.userId === right.userId
    && left.accountId === right.accountId
    && (left.accountId !== null || left.sessionId === right.sessionId);
}

function validOwnerScope(scope: any): boolean {
  return closed(scope, OWNER_KEYS) && text(scope.clientId, 2048) && text(scope.userId)
    && text(scope.sessionId) && (scope.accountId === null || text(scope.accountId));
}

/**
 * Trust, the owner/profile association and clock are fixed by the company at construction, never drawn
 * from a request or evidence envelope. This optional stronger profile requires
 * fresh Class-A evidence. Native Poppy standing-permission validation remains
 * the host's responsibility; this helper neither invents nor validates it.
 * SATISFIED is not AUTHORIZED, provider entry, external effect, or replay state.
 */
export function createPoppyApprovalVerifier({ companyIssuer, ownerScope, epReceiptProfile, now = Date.now }: {
  companyIssuer?: string; ownerScope?: unknown; epReceiptProfile?: unknown; now?: () => number | Date;
} = {}): { verify: (request?: unknown) => PoppyApprovalResult } {
  let profile: ObjectValue | null = null;
  let scope: ObjectValue | null = null;
  try { profile = copyJson(epReceiptProfile, 262144, 24) as ObjectValue; } catch { /* refusal below */ }
  try { scope = copyJson(ownerScope) as ObjectValue; } catch { /* refusal below */ }
  const configured = typeof companyIssuer === 'string' && httpsUrl(companyIssuer, true)
    && record(profile) && validOwnerScope(scope) && typeof now === 'function';
  const refuse = (reason: string): PoppyApprovalResult => ({ satisfied: false, reasons: [reason], action_digest: null });
  return {
    verify(request: unknown = {}): PoppyApprovalResult {
      if (!configured) return refuse('approval_profile_not_configured');
      try {
        if (!record(request)) return refuse('invalid_approval_request');
        const input = copyJson(request, 262144, 24) as ObjectValue;
        if (!closed(input, new Set(['operation', 'owner', 'evidence', 'approved_by']))) return refuse('invalid_approval_request');
        if (input.approved_by !== 'user') return refuse('fresh_user_evidence_required');
        const action = buildPoppyAction(input.operation, input.owner, companyIssuer!);
        if (!sameOwnerScope(input.owner, scope!)) return refuse('approval_owner_outside_pinned_scope');
        const clock = now();
        const at = clock instanceof Date ? clock.getTime() : clock;
        if (!Number.isFinite(at)) return refuse('invalid_company_clock');
        if (at >= instant(input.operation.expires_at)) return refuse('operation_expired');
        const verificationTime = new Date(at).toISOString();
        if (!record(input.evidence) || !Array.isArray(input.evidence.components)
            || input.evidence.components.length !== 1 || input.evidence.components[0]?.type !== 'ep-receipt') {
          return refuse('exactly_one_native_approval_receipt_required');
        }
        const chain = verifyAuthorizationChain(input.evidence, {
          requirement: 'ep-receipt', expectedAction: action,
          policiesByType: { 'ep-receipt': profile }, verificationTime,
        });
        if (chain.satisfied !== true || chain.expected_action_bound !== true) return refuse('approval_evidence_not_satisfied');
        // The AEC native leg enforces pinned Class-A identity, policy, origins,
        // directory freshness and action matching. Also use native current-time
        // receipt verification so future signoff/consumption cannot hide behind
        // the historical authenticity mode used by that AEC leg.
        const current = verifyTrustReceipt(input.evidence.components[0].evidence, {
          approverKeys: profile!.approver_keys, logPublicKey: profile!.log_public_key,
          rpId: profile!.rp_id, allowedOrigins: profile!.allowed_origins,
          expectedPolicyHash: profile!.expected_policy_hash,
          verificationMode: 'current', now: verificationTime,
        });
        if (current.valid !== true) return refuse('approval_receipt_not_current');
        return { satisfied: true, reasons: [], action_digest: `sha256:${chain.action_digest}` };
      } catch { return refuse('invalid_approval_input'); }
    },
  };
}

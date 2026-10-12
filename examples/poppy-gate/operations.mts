// SPDX-License-Identifier: Apache-2.0
/**
 * Reference Poppy Operations v1 adapter, not an OAuth issuer or full Poppy
 * implementation. The host must verify a resource-bound DPoP Session Token and
 * trusted client metadata in authenticateRequest. Only trusted host code may
 * propose/revise/reconcile; expose handle, not these setters, to the agent.
 *
 * Production requires a shared durable implementation of the store contract.
 * An advertised contract is an integration requirement, not deployment proof.
 * There is deliberately no lease takeover/re-execution of in_progress work.
 */
import { createHash, randomUUID } from 'node:crypto';
import { canonicalizeStrictJson, strictJsonGate } from '../../packages/verify/dist/strict-json.js';

export const POPPY_OPERATIONS_STORE_CONTRACT = 'POPPY-OPERATIONS-STORE-v1';
export const POPPY_APPROVAL_EXTENSION = 'emiliaprotocol.ai/approval-evidence';
type Json = any;
export type PoppyState = 'proposed' | 'in_progress' | 'succeeded' | 'failed' | 'cancelled' | 'expired';
export interface PoppyOperation {
  operation_id: string; revision: number; state: PoppyState; summary: string;
  terms?: Record<string, Json>; expires_at: string; user_approval_required?: boolean; url?: string;
  confirmation: null | { revision: number; approved_by: 'user' | 'standing_permission'; confirmed_at: string };
  result: null | { summary: string; data?: Json };
}
export interface PoppyPrincipal {
  clientId: string; userId: string; sessionId: string; accountId: string | null;
  scopes: string[]; dpop: { verified: true; jkt: string };
  extensions: Record<string, { version: string }>;
}
type Owner = Pick<PoppyPrincipal, 'clientId' | 'userId' | 'sessionId' | 'accountId'>;
export interface PoppyStoredRecord {
  companyIssuer: string; operation: PoppyOperation; owner: Owner; ownerFence: string;
  actionKey: string; observedAction: Json; action_digest: string; version: number;
}
export interface PoppyOperationStore {
  contract: typeof POPPY_OPERATIONS_STORE_CONTRACT; ephemeral?: boolean;
  durable: boolean; atomic: boolean; ownershipFenced: boolean;
  get(companyIssuer: string, operation_id: string): Promise<PoppyStoredRecord | null>;
  /** Atomic insert AND uniqueness of (companyIssuer, actionKey) for nonfinal work. */
  insert(record: PoppyStoredRecord): Promise<{ created: boolean; record: PoppyStoredRecord }>;
  /** Atomic CAS fenced by version, stable ownerFence, namespace and operation ID. */
  cas(companyIssuer: string, operation_id: string, version: number, ownerFence: string, next: PoppyStoredRecord): Promise<boolean>;
}
interface Options {
  companyIssuer: string; endpoint: string; authenticateRequest: (request: Json) => Promise<PoppyPrincipal | null>;
  store: PoppyOperationStore; gate: { run: (args: any, effect: any) => Promise<any> };
  selector: Record<string, Json>; requiredScopes: string[];
  resolveAction: (operation: PoppyOperation, owner: Owner) => Json | Promise<Json>;
  executeAction: (input: { operation: PoppyOperation; owner: Owner; observedAction: Json; actionKey: string; authorization: Json }) => Promise<Json>;
  resolveGateReceipt?: (input: { operation: PoppyOperation; owner: Owner; observedAction: Json; approval: Json }) => Json | Promise<Json>;
  verifyApprovalEvidence?: (input: { operation: PoppyOperation; owner: Owner; evidence: Json; approved_by: string }) => Json | Promise<Json>;
  requireApprovalEvidence?: boolean; now?: () => number; allowEphemeralStore?: boolean;
  confirmResponseWaitMs?: number;
  verifyProviderOutcome?: (input: { operation: PoppyOperation; owner: Owner; ownerFence: string; observedAction: Json; action_digest: string; evidence: Json }) => Json | Promise<Json>;
}
const ID = /^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,128}$/;
const final = (state: PoppyState) => ['succeeded', 'failed', 'cancelled', 'expired'].includes(state);
const object = (value: Json) => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value: Json) => typeof value === 'string' && value.length > 0 && value.length <= 4096 && value === value.trim();
function copy<T>(value: T): T { return JSON.parse(canonicalizeStrictJson(value)); }
function frozen<T>(value: T): T {
  const cloned = copy(value);
  function freeze(v: Json): void { if (object(v) || Array.isArray(v)) { Object.values(v).forEach(freeze); Object.freeze(v); } }
  freeze(cloned); return cloned;
}
export function poppyActionDigest(action: Json): string {
  return `sha256:${createHash('sha256').update(canonicalizeStrictJson(action), 'utf8').digest('hex')}`;
}
function ownerFence(owner: Owner): string {
  return poppyActionDigest(owner.accountId === null
    ? { clientId: owner.clientId, userId: owner.userId, sessionId: owner.sessionId, accountId: null }
    : { clientId: owner.clientId, userId: owner.userId, accountId: owner.accountId });
}
function owns(record: PoppyStoredRecord, principal: Owner): boolean {
  return record.owner.clientId === principal.clientId && record.owner.userId === principal.userId
    && (record.owner.accountId === null ? record.owner.sessionId === principal.sessionId : record.owner.accountId === principal.accountId);
}
class PoppyError extends Error {
  status: number; code: string; extra: Json;
  constructor(status: number, code: string, extra: Json = {}) { super(code); this.status = status; this.code = code; this.extra = extra; }
}
function timestamp(value: Json): boolean {
  if (typeof value !== 'string') return false;
  const fields = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!fields) return false;
  const [year, month, day, hour, minute, second] = fields.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] && hour <= 23 && minute <= 59 && second <= 59
    && (fields[7] === undefined || (Number(fields[8]) <= 23 && Number(fields[9]) <= 59)) && Number.isFinite(Date.parse(value));
}

/** A process-local test fixture. It proves neither durability nor deployment. */
export function createMemoryPoppyOperationStore(): PoppyOperationStore {
  const records = new Map<string, PoppyStoredRecord>();
  const active = new Map<string, string>();
  const key = (issuer: string, id: string) => canonicalizeStrictJson([issuer, id]);
  const actionKey = (record: PoppyStoredRecord) => key(record.companyIssuer, record.actionKey);
  return {
    contract: POPPY_OPERATIONS_STORE_CONTRACT, ephemeral: true, durable: false, atomic: true, ownershipFenced: true,
    async get(issuer, id) { const record = records.get(key(issuer, id)); return record ? copy(record) : null; },
    async insert(input) {
      const record = copy(input); const id = key(record.companyIssuer, record.operation.operation_id);
      const activeId = active.get(actionKey(record));
      const existing = records.get(activeId ?? id);
      if (existing) return { created: false, record: copy(existing) };
      records.set(id, record); active.set(actionKey(record), id);
      return { created: true, record: copy(record) };
    },
    async cas(issuer, id, version, fence, input) {
      const k = key(issuer, id); const current = records.get(k); const next = copy(input);
      if (!current || current.version !== version || current.ownerFence !== fence || final(current.operation.state)
        || next.version !== version + 1 || next.ownerFence !== fence || next.companyIssuer !== issuer
        || next.operation.operation_id !== id || next.actionKey !== current.actionKey) return false;
      if (current.operation.state === 'in_progress' && (next.operation.revision !== current.operation.revision
        || next.action_digest !== current.action_digest || next.operation.state === 'proposed')) return false;
      records.set(k, next);
      if (final(next.operation.state)) { if (active.get(actionKey(next)) === k) active.delete(actionKey(next)); }
      return true;
    },
  };
}

export function createPoppyOperationsAdapter(options: Options) {
  const { companyIssuer, store, requireApprovalEvidence = false, allowEphemeralStore = false } = options;
  const endpoint = new URL(options.endpoint);
  const issuer = new URL(companyIssuer);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
    || !nonempty(companyIssuer) || issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash) {
    throw new TypeError('Poppy adapter requires a pinned HTTPS company issuer and operations endpoint');
  }
  if (store?.contract !== POPPY_OPERATIONS_STORE_CONTRACT || typeof store.get !== 'function'
    || typeof store.insert !== 'function' || typeof store.cas !== 'function') throw new TypeError('Poppy atomic owner-fenced store contract required');
  if (store.ephemeral === true && !allowEphemeralStore) throw new TypeError('Ephemeral Poppy store is test-only; durable shared state is required');
  if (!allowEphemeralStore && (store.durable !== true || store.atomic !== true || store.ownershipFenced !== true)) {
    throw new TypeError('Durable atomic ownership-fenced store declarations required; declarations alone are not deployment proof');
  }
  if (typeof options.authenticateRequest !== 'function' || typeof options.resolveAction !== 'function'
    || typeof options.executeAction !== 'function' || typeof options.gate?.run !== 'function') throw new TypeError('Poppy pinned authentication, Gate and provider callbacks required');
  if (!Array.isArray(options.requiredScopes) || options.requiredScopes.length === 0 || !options.requiredScopes.every(nonempty)) throw new TypeError('Poppy configured action scopes required');
  if (requireApprovalEvidence && typeof options.verifyApprovalEvidence !== 'function') throw new TypeError('Stronger approval profile requires a pinned verifier');
  const confirmResponseWaitMs = options.confirmResponseWaitMs ?? 2500;
  if (!Number.isSafeInteger(confirmResponseWaitMs) || confirmResponseWaitMs < 0 || confirmResponseWaitMs > 5000) throw new TypeError('Poppy response wait must be bounded to at most 5000ms');
  // Capture every integration dependency; retained mutable options cannot swap
  // trust roots, execution handlers or atomic store methods after startup.
  const authenticateRequest = options.authenticateRequest;
  const resolveAction = options.resolveAction;
  const executeAction = options.executeAction;
  const resolveGateReceipt = options.resolveGateReceipt ?? (() => null);
  const verifyApprovalEvidence = options.verifyApprovalEvidence;
  const verifyProviderOutcome = options.verifyProviderOutcome;
  const runGate = options.gate.run.bind(options.gate);
  const get = store.get.bind(store), insert = store.insert.bind(store), cas = store.cas.bind(store);
  const clock = options.now ?? Date.now;
  if (typeof clock !== 'function') throw new TypeError('Poppy clock must be a function');
  const instant = clock();
  if (!Number.isSafeInteger(instant) || instant < 0 || instant > 8.64e15) throw new TypeError('Poppy clock must provide a valid finite millisecond instant');
  function now(): number {
    const at = clock();
    if (!Number.isSafeInteger(at) || at < 0 || at > 8.64e15) throw new PoppyError(503, 'temporarily_unavailable');
    return at;
  }
  const selector = frozen(options.selector), requiredScopes = frozen(options.requiredScopes);
  const basePath = endpoint.pathname.replace(/\/$/, '');

  async function authenticate(request: Json): Promise<PoppyPrincipal> {
    let principal: Json;
    try { principal = copy(await authenticateRequest(request)); } catch { throw new PoppyError(401, 'invalid_token'); }
    if (!object(principal) || !['clientId', 'userId', 'sessionId'].every(k => nonempty(principal[k]))
      || !(principal.accountId === null || nonempty(principal.accountId)) || !Array.isArray(principal.scopes)
      || !principal.scopes.every(nonempty) || principal.dpop?.verified !== true || !nonempty(principal.dpop?.jkt)
      || !object(principal.extensions)) throw new PoppyError(401, 'invalid_token');
    return frozen(principal);
  }
  function extensions(principal: PoppyPrincipal, approval = false): void {
    if (principal.extensions.operations?.version !== '1') throw new PoppyError(403, 'extension_required', { extension: 'operations' });
    if (approval && requireApprovalEvidence && principal.extensions[POPPY_APPROVAL_EXTENSION]?.version !== '1') {
      throw new PoppyError(403, 'extension_required', { extension: POPPY_APPROVAL_EXTENSION });
    }
  }
  const wire = (record: PoppyStoredRecord) => copy(record.operation);
  const nextRecord = (record: PoppyStoredRecord, operation: PoppyOperation) => ({ ...record, operation, version: record.version + 1 });
  async function read(id: string, principal: Owner): Promise<PoppyStoredRecord> {
    const record = await get(companyIssuer, id);
    if (!record || !owns(record, principal)) throw new PoppyError(404, 'operation_not_found');
    return copy(record);
  }
  async function expire(record: PoppyStoredRecord, principal: Owner): Promise<PoppyStoredRecord> {
    if (record.operation.state !== 'proposed' || now() < Date.parse(record.operation.expires_at)) return record;
    const expired = nextRecord(record, { ...record.operation, state: 'expired', result: { summary: 'The proposal expired before confirmation. No action was performed.' } });
    if (await cas(companyIssuer, record.operation.operation_id, record.version, record.ownerFence, expired)) return expired;
    return read(record.operation.operation_id, principal);
  }
  function scope(principal: PoppyPrincipal): void {
    if (!requiredScopes.every(s => principal.scopes.includes(s))) throw new PoppyError(403, principal.accountId === null ? 'sign_in_required' : 'insufficient_scope');
  }
  function nativeOperation(input: Json, id: string, revision: number): PoppyOperation {
    if (!ID.test(id) || !nonempty(input.summary) || !timestamp(input.expires_at) || now() >= Date.parse(input.expires_at)
      || (input.terms !== undefined && !object(input.terms)) || (input.user_approval_required !== undefined && typeof input.user_approval_required !== 'boolean')) {
      throw new PoppyError(400, 'invalid_request');
    }
    if (input.url !== undefined) {
      try { const url = new URL(input.url); if (url.protocol !== 'https:' || url.username || url.password) throw new Error(); }
      catch { throw new PoppyError(400, 'invalid_request'); }
    }
    return copy({ operation_id: id, revision, state: 'proposed', summary: input.summary,
      ...(input.terms !== undefined ? { terms: input.terms } : {}), expires_at: input.expires_at,
      ...(input.user_approval_required !== undefined ? { user_approval_required: input.user_approval_required } : {}),
      ...(input.url !== undefined ? { url: input.url } : {}), confirmation: null, result: null });
  }
  async function propose(input: Json): Promise<PoppyOperation> {
    const principal = await authenticate(input.request); extensions(principal, true);
    if (!nonempty(input.actionKey)) throw new PoppyError(400, 'invalid_request');
    const owner: Owner = { clientId: principal.clientId, userId: principal.userId, sessionId: principal.sessionId, accountId: principal.accountId };
    const operation = nativeOperation(input, input.operation_id ?? randomUUID(), 1);
    const action = copy(await resolveAction(frozen(operation), frozen(owner)));
    if (!object(action)) throw new PoppyError(400, 'invalid_action');
    const result = await insert({ companyIssuer, operation, owner, ownerFence: ownerFence(owner), actionKey: input.actionKey,
      observedAction: action, action_digest: poppyActionDigest(action), version: 1 });
    if (!owns(result.record, principal)) throw new PoppyError(404, 'operation_not_found');
    return wire(await expire(result.record, principal));
  }
  async function revise(input: Json): Promise<PoppyOperation> {
    const principal = await authenticate(input.request); extensions(principal);
    const record = await expire(await read(input.operation_id, principal), principal);
    if (record.operation.state !== 'proposed') throw new PoppyError(409, 'operation_not_proposed', { operation: wire(record) });
    if (input.revision !== record.operation.revision) throw new PoppyError(409, 'terms_changed', { operation: wire(record) });
    const operation = nativeOperation(input, record.operation.operation_id, record.operation.revision + 1);
    const action = copy(await resolveAction(frozen(operation), frozen(record.owner)));
    if (!object(action)) throw new PoppyError(400, 'invalid_action');
    const next = { ...nextRecord(record, operation), observedAction: action, action_digest: poppyActionDigest(action) };
    if (!(await cas(companyIssuer, operation.operation_id, record.version, record.ownerFence, next))) {
      throw new PoppyError(409, 'terms_changed', { operation: wire(await read(operation.operation_id, principal)) });
    }
    return wire(next);
  }
  function parseConfirm(body: Json): Json {
    if (typeof body !== 'string' || Buffer.byteLength(body, 'utf8') > 65_536 || !strictJsonGate(body).ok) throw new PoppyError(400, 'invalid_request');
    const parsed = JSON.parse(body);
    if (!object(parsed) || Object.keys(parsed).some(k => !['revision', 'approved_by', 'extensions'].includes(k))
      || !Number.isSafeInteger(parsed.revision) || parsed.revision < 1 || !['user', 'standing_permission'].includes(parsed.approved_by)) {
      throw new PoppyError(400, 'invalid_request');
    }
    if (parsed.extensions !== undefined) {
      const extension = parsed.extensions?.[POPPY_APPROVAL_EXTENSION];
      if (!object(parsed.extensions) || Object.keys(parsed.extensions).length !== 1 || !object(extension)
        || Object.keys(extension).some(k => !['version', 'evidence'].includes(k)) || extension.version !== '1' || !object(extension.evidence)) {
        throw new PoppyError(400, 'invalid_request');
      }
    }
    return parsed;
  }
  function response(record: PoppyStoredRecord, status = 200): Json {
    return { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
      ...(record.operation.state === 'in_progress' ? { 'Retry-After': '2' } : {}) }, body: wire(record) };
  }
  async function confirm(id: string, principal: PoppyPrincipal, body: Json): Promise<Json> {
    const confirmation = parseConfirm(body);
    let record = await read(id, principal); scope(principal);
    if (record.operation.revision !== confirmation.revision) throw new PoppyError(409, 'terms_changed', { operation: wire(record) });
    if (record.operation.user_approval_required === true && confirmation.approved_by !== 'user') throw new PoppyError(403, 'user_approval_required');
    record = await expire(record, principal);
    // Expiry CAS may lose to a concurrently issued new revision. Never admit
    // that newer revision with the previous revision's approval statement.
    if (record.operation.revision !== confirmation.revision) throw new PoppyError(409, 'terms_changed', { operation: wire(record) });
    if (record.operation.user_approval_required === true && confirmation.approved_by !== 'user') throw new PoppyError(403, 'user_approval_required');
    if (record.operation.state !== 'proposed') return response(record);
    extensions(principal, true);
    const evidence = confirmation.extensions?.[POPPY_APPROVAL_EXTENSION]?.evidence;
    if (requireApprovalEvidence && evidence === undefined) throw new PoppyError(403, 'extension_required', { extension: POPPY_APPROVAL_EXTENSION });
    let approval: Json = null;
    if (evidence !== undefined) {
      if (principal.extensions[POPPY_APPROVAL_EXTENSION]?.version !== '1' || !verifyApprovalEvidence) throw new PoppyError(403, 'extension_required', { extension: POPPY_APPROVAL_EXTENSION });
      try { approval = copy(await verifyApprovalEvidence({ operation: frozen(record.operation), owner: frozen(record.owner), evidence: frozen(evidence), approved_by: confirmation.approved_by })); }
      catch { throw new PoppyError(403, 'approval_evidence_rejected'); }
      if (approval?.satisfied !== true || approval.action_digest !== record.action_digest) throw new PoppyError(403, 'approval_evidence_rejected');
    }
    const observedAction = copy(await resolveAction(frozen(record.operation), frozen(record.owner)));
    if (poppyActionDigest(observedAction) !== record.action_digest) throw new PoppyError(409, 'terms_changed', { operation: wire(record) });
    const receipt = await resolveGateReceipt({ operation: frozen(record.operation), owner: frozen(record.owner), observedAction: frozen(observedAction), approval: approval === null ? null : frozen(approval) });
    if (evidence !== undefined && verifyApprovalEvidence) {
      // Slow action resolution or authority acquisition may outlast a receipt
      // or directory freshness window. Re-perform the pinned approval check
      // over the same snapshot after those callbacks, before confirmation CAS.
      try { approval = copy(await verifyApprovalEvidence({ operation: frozen(record.operation), owner: frozen(record.owner), evidence: frozen(evidence), approved_by: confirmation.approved_by })); }
      catch { throw new PoppyError(403, 'approval_evidence_rejected'); }
      if (approval?.satisfied !== true || approval.action_digest !== record.action_digest) throw new PoppyError(403, 'approval_evidence_rejected');
    }
    // Every asynchronous dependency finishes before the authoritative CAS. A
    // changed revision, cancellation or expiry wins without provider entry.
    if (now() >= Date.parse(record.operation.expires_at)) {
      const current = await expire(record, principal);
      if (current.operation.revision !== confirmation.revision) throw new PoppyError(409, 'terms_changed', { operation: wire(current) });
      return response(current);
    }
    const claimed = nextRecord(record, { ...record.operation, state: 'in_progress', confirmation: {
      revision: confirmation.revision, approved_by: confirmation.approved_by, confirmed_at: new Date(now()).toISOString(),
    } });
    if (!(await cas(companyIssuer, id, record.version, record.ownerFence, claimed))) {
      const current = await read(id, principal);
      if (current.operation.revision !== confirmation.revision) throw new PoppyError(409, 'terms_changed', { operation: wire(current) });
      return response(await expire(current, principal));
    }
    const work = performClaimed(claimed, principal, receipt, observedAction).catch(error => {
      const known = error instanceof PoppyError ? error : new PoppyError(503, 'temporarily_unavailable');
      return { status: known.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: { error: known.code, ...known.extra } };
    });
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([work, new Promise(resolve => { timeout = setTimeout(() => resolve(response(claimed)), confirmResponseWaitMs); })]);
    } finally { if (timeout !== undefined) clearTimeout(timeout); }
  }
  async function performClaimed(claimed: PoppyStoredRecord, principal: PoppyPrincipal, receipt: Json, observedAction: Json): Promise<Json> {
    const id = claimed.operation.operation_id;
    let entered = false;
    let outcome: Json;
    try {
      const result = await runGate({ selector, receipt, observedAction }, async (authorization: Json) => {
        entered = true;
        return executeAction({ operation: frozen(claimed.operation), owner: frozen(claimed.owner), observedAction: frozen(observedAction), actionKey: claimed.actionKey, authorization });
      });
      if (result?.ok !== true) {
        // The callback never ran, so this record may truthfully say no action
        // was performed. Do not serialize Gate/provider error payloads.
        if (entered) return response(claimed);
        const refused = nextRecord(claimed, { ...claimed.operation, state: 'failed', result: { summary: 'No action was performed. The configured authority checkpoint refused admission.' } });
        if (!(await cas(companyIssuer, id, claimed.version, claimed.ownerFence, refused))) throw new PoppyError(503, 'temporarily_unavailable');
        throw new PoppyError(403, 'gate_refused', { operation: wire(refused) });
      }
      outcome = copy(result.result);
    } catch (error) {
      if (error instanceof PoppyError) throw error;
      // A raw exception never proves non-effect, even if Gate evidence reports
      // an intermediate phase. Retain the confirmed operation for recovery.
      return response(claimed);
    }
    if (!object(outcome) || !['succeeded', 'failed'].includes(outcome.state) || !nonempty(outcome.summary)) return response(claimed);
    const complete = nextRecord(claimed, { ...claimed.operation, state: outcome.state, result: {
      summary: outcome.summary, ...(outcome.data !== undefined ? { data: outcome.data } : {}),
    } });
    if (!(await cas(companyIssuer, id, claimed.version, claimed.ownerFence, complete))) {
      const current = await read(id, principal);
      if (final(current.operation.state)) return response(current);
      throw new PoppyError(503, 'temporarily_unavailable', { operation: wire(current) });
    }
    return response(complete);
  }
  async function cancel(id: string, principal: PoppyPrincipal, body: Json): Promise<Json> {
    if (body !== undefined && body !== '') throw new PoppyError(400, 'invalid_request');
    const record = await expire(await read(id, principal), principal);
    if (record.operation.state !== 'proposed') return response(record);
    const cancelled = nextRecord(record, { ...record.operation, state: 'cancelled', result: { summary: 'The proposal was cancelled before confirmation. No action was performed.' } });
    if (await cas(companyIssuer, id, record.version, record.ownerFence, cancelled)) return response(cancelled);
    return response(await read(id, principal));
  }
  async function handle(request: Json): Promise<Json> {
    try {
      const principal = await authenticate(request); extensions(principal);
      let url: URL;
      try { url = new URL(request.url, endpoint); } catch { throw new PoppyError(404, 'operation_not_found'); }
      if (url.origin !== endpoint.origin || url.search || url.hash || !url.pathname.startsWith(`${basePath}/`)) throw new PoppyError(404, 'operation_not_found');
      const segments = url.pathname.slice(basePath.length + 1).split('/');
      if (!ID.test(segments[0]) || segments.length > 2) throw new PoppyError(404, 'operation_not_found');
      if (request.method === 'GET' && segments.length === 1) return response(await expire(await read(segments[0], principal), principal));
      if (request.method === 'POST' && segments[1] === 'confirm') return await confirm(segments[0], principal, request.body);
      if (request.method === 'POST' && segments[1] === 'cancel') return await cancel(segments[0], principal, request.body);
      throw new PoppyError(404, 'operation_not_found');
    } catch (error) {
      const known = error instanceof PoppyError ? error : new PoppyError(503, 'temporarily_unavailable');
      return { status: known.status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
        ...(known.status === 401 ? { 'WWW-Authenticate': 'DPoP' } : {}) }, body: { error: known.code, ...known.extra } };
    }
  }
  /** Host-only authenticated provider evidence hook. It never invokes an effect. */
  async function reconcile(input: Json): Promise<PoppyOperation> {
    if (!verifyProviderOutcome) throw new PoppyError(403, 'provider_reconciliation_unconfigured');
    const record = await get(companyIssuer, input.operation_id);
    if (!record) throw new PoppyError(404, 'operation_not_found');
    if (record.operation.revision !== input.revision || record.action_digest !== input.action_digest) throw new PoppyError(409, 'reconciliation_binding_mismatch');
    if (record.operation.state !== 'in_progress') return wire(record);
    const verified = copy(await verifyProviderOutcome({ operation: frozen(record.operation), owner: frozen(record.owner), ownerFence: record.ownerFence,
      observedAction: frozen(record.observedAction), action_digest: record.action_digest, evidence: frozen(input.evidence) }));
    if (verified?.valid !== true || verified.companyIssuer !== companyIssuer || verified.operation_id !== input.operation_id
      || verified.revision !== input.revision || verified.action_digest !== input.action_digest
      || verified.ownerFence !== record.ownerFence || !object(verified.observedAction) || poppyActionDigest(verified.observedAction) !== record.action_digest
      || !['succeeded', 'failed', 'cancelled'].includes(verified.state) || !nonempty(verified.summary)) throw new PoppyError(403, 'provider_evidence_rejected');
    const complete = nextRecord(record, { ...record.operation, state: verified.state,
      result: { summary: verified.summary, ...(verified.data !== undefined ? { data: verified.data } : {}) } });
    if (!(await cas(companyIssuer, input.operation_id, record.version, record.ownerFence, complete))) {
      const current = await get(companyIssuer, input.operation_id);
      if (current && final(current.operation.state)) return wire(current);
      throw new PoppyError(503, 'temporarily_unavailable');
    }
    return wire(complete);
  }
  return Object.freeze({ handle, propose, revise, reconcile });
}

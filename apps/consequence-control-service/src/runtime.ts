// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PREPARE_KEYS = Object.freeze(['profile_id', 'operation_id', 'action']);
const EXECUTE_KEYS = Object.freeze(['proposal', 'receipt', 'evaluation', 'evidence']);
const BEGIN_APPROVAL_KEYS = Object.freeze(['proposal', 'approver_id', 'idempotency_key']);
const POLL_APPROVAL_KEYS = Object.freeze(['proposal', 'request_id', 'poll_token']);
const LOOKUP_ATTEMPT_KEYS = Object.freeze(['proposal']);
const RECONCILE_KEYS = Object.freeze(['proposal', 'evaluation', 'attempt', 'provider_evidence', 'evidence']);
const REPAIR_KEYS = Object.freeze(['proposal', 'evaluation', 'attempt', 'evidence']);
const EVIDENCE_KEYS = Object.freeze(['artifacts', 'statuses']);
const ATTEMPT_KEYS = Object.freeze([
  'tenant_id',
  'provider_id',
  'provider_account_id',
  'environment',
  'attempt_id',
  'request_digest',
]);
const ATTEMPT_STATES = new Set([
  'RESERVED',
  'INVOKING',
  'INDETERMINATE',
  'COMMITTED',
  'RELEASED',
  'ESCALATED',
]);

type JsonObject = Record<string, any>;

export interface ConsequenceControlPrincipal {
  id: string;
}

export interface ConsequenceControlRuntimeConfig {
  controller: {
    verifyProposal(input: unknown, options?: JsonObject): { proposal: JsonObject; profile: JsonObject };
    prepare(input: JsonObject): JsonObject;
    beginApproval(input: JsonObject): Promise<JsonObject>;
    pollApproval(input: JsonObject): Promise<JsonObject>;
    execute(input: JsonObject, effect: (input: JsonObject) => Promise<unknown>): Promise<JsonObject>;
    reconcile(input: JsonObject): Promise<JsonObject>;
    repairAeb(input: JsonObject): Promise<JsonObject>;
    getReconciliationHandle(input: object): JsonObject | null;
  };
  authenticateRequest(request: unknown): Promise<unknown> | unknown;
  authorizeProfile(
    principal: ConsequenceControlPrincipal,
    profileId: string,
    action: unknown,
  ): Promise<boolean> | boolean;
  effectForProfile(input: {
    principal: ConsequenceControlPrincipal;
    profile_id: string;
    proposal: JsonObject;
  }): Promise<(input: JsonObject) => Promise<unknown>> | ((input: JsonObject) => Promise<unknown>);
  requesterAuthorization(input: {
    principal: ConsequenceControlPrincipal;
    proposal: JsonObject;
  }): Promise<string | (() => string | Promise<string>)> | string | (() => string | Promise<string>);
  lookupAttempt?(input: {
    principal: ConsequenceControlPrincipal;
    proposal: JsonObject;
    lookup: {
      tenant_id: string;
      provider_id: string;
      provider_account_id: string;
      environment: string;
      request_digest: string;
    };
  }): Promise<JsonObject | null> | JsonObject | null;
  recoverAttempt(input: {
    principal: ConsequenceControlPrincipal;
    proposal: JsonObject;
    attempt: JsonObject;
  }): Promise<JsonObject> | JsonObject;
  aebRecoveryAuthorization(input: {
    principal: ConsequenceControlPrincipal;
    proposal: JsonObject;
    attempt: JsonObject;
  }): Promise<unknown> | unknown;
  withEvidenceContext<T>(
    input: {
      principal: ConsequenceControlPrincipal;
      proposal: JsonObject;
      evidence: {
        artifacts: JsonObject;
        statuses: JsonObject;
      };
    },
    work: () => Promise<T>,
  ): Promise<T>;
  readiness(): Promise<{ ok: boolean }> | { ok: boolean };
  idFactory?: () => string;
  close?: () => Promise<unknown> | unknown;
}

function isPlainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: unknown, expected: readonly string[]): value is JsonObject {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function response(status: number, body: JsonObject, headers: Record<string, string> = {}) {
  return { status, body, headers };
}

function refused(status: number, code: string, state = status >= 500 ? 'unavailable' : 'refused') {
  return response(status, { status: state, error: { code } });
}

function normalizePrincipal(value: unknown): ConsequenceControlPrincipal | null {
  if (!isPlainObject(value) || !identifier(value.id)) return null;
  return Object.freeze({ id: value.id });
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function sanitizeControllerResult(value: unknown): unknown {
  if (!isPlainObject(value)) return clone(value);
  const result = clone(value);
  if (isPlainObject(result.attempt)) delete result.attempt.owner;
  if (isPlainObject(result.consequence) && isPlainObject(result.consequence.attempt)) {
    delete result.consequence.attempt.owner;
  }
  delete result.reconciliation_handle;
  return result;
}

function attemptShape(value: unknown): value is JsonObject {
  return exactKeys(value, ATTEMPT_KEYS)
    && identifier(value.tenant_id)
    && identifier(value.provider_id)
    && identifier(value.provider_account_id)
    && identifier(value.environment)
    && identifier(value.attempt_id)
    && typeof value.request_digest === 'string'
    && DIGEST.test(value.request_digest);
}

function evidenceShape(value: unknown): value is { artifacts: JsonObject; statuses: JsonObject } {
  if (!exactKeys(value, EVIDENCE_KEYS)
      || !isPlainObject(value.artifacts)
      || !isPlainObject(value.statuses)) return false;
  const refs = [...Object.keys(value.artifacts), ...Object.keys(value.statuses)];
  return refs.length <= 128 && refs.every((ref) => identifier(ref));
}

export function publicAttemptBinding(value: unknown): JsonObject | null {
  if (!isPlainObject(value)) return null;
  const full = ATTEMPT_KEYS.every((field) => Object.hasOwn(value, field));
  if (full) {
    const candidate = Object.fromEntries(ATTEMPT_KEYS.map((field) => [field, value[field]]));
    return attemptShape(candidate) ? candidate : null;
  }
  if (identifier(value.tenant_id) && identifier(value.attempt_id)) {
    return { tenant_id: value.tenant_id, attempt_id: value.attempt_id };
  }
  return null;
}

function statusForControllerResult(result: any): number {
  if (result?.ok === true) return 200;
  const reason = typeof result?.reason === 'string'
    ? result.reason
    : typeof result?.error?.code === 'string' ? result.error.code : '';
  if (/unavailable|store_|allocation_failed/.test(reason)) return 503;
  if (/not_found/.test(reason)) return 404;
  if (/conflict|replay|consumption|indeterminate|transition/.test(reason)) return 409;
  return 403;
}

export function createConsequenceControlRuntime(config: ConsequenceControlRuntimeConfig) {
  if (!isPlainObject(config)
      || !isPlainObject(config.controller)
      || typeof config.controller.verifyProposal !== 'function'
      || typeof config.controller.prepare !== 'function'
      || typeof config.controller.beginApproval !== 'function'
      || typeof config.controller.pollApproval !== 'function'
      || typeof config.controller.execute !== 'function'
      || typeof config.controller.reconcile !== 'function'
      || typeof config.controller.repairAeb !== 'function'
      || typeof config.controller.getReconciliationHandle !== 'function'
      || typeof config.authenticateRequest !== 'function'
      || typeof config.authorizeProfile !== 'function'
      || typeof config.effectForProfile !== 'function'
      || typeof config.requesterAuthorization !== 'function'
      || typeof config.recoverAttempt !== 'function'
      || typeof config.aebRecoveryAuthorization !== 'function'
      || typeof config.withEvidenceContext !== 'function'
      || typeof config.readiness !== 'function') {
    throw new Error('consequence_control_config_invalid');
  }
  const idFactory = config.idFactory ?? (() => `proposal:${crypto.randomUUID()}`);
  if (typeof idFactory !== 'function') throw new Error('consequence_control_id_factory_invalid');
  let initialized = false;
  let accepting = false;
  let closing = false;
  let activeRequests = 0;
  let closePromise: Promise<{ ok: true }> | null = null;
  const idleWaiters = new Set<() => void>();

  function stopAdmission() {
    accepting = false;
  }

  function admit(): (() => void) | null {
    if (!initialized || !accepting || closing) return null;
    activeRequests += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      activeRequests -= 1;
      if (activeRequests === 0) {
        for (const resolve of idleWaiters) resolve();
        idleWaiters.clear();
      }
    };
  }

  async function waitForIdle(timeoutMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 300_000) {
      throw new TypeError('consequence_control_drain_timeout_invalid');
    }
    if (activeRequests === 0) return true;
    if (timeoutMs === 0) return false;
    return new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (idle: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        idleWaiters.delete(onIdle);
        resolve(idle);
      };
      const onIdle = () => finish(true);
      const timer = setTimeout(() => finish(false), timeoutMs);
      timer.unref?.();
      idleWaiters.add(onIdle);
    });
  }

  async function authenticate(request: unknown) {
    try {
      return normalizePrincipal(await config.authenticateRequest(request));
    } catch {
      return null;
    }
  }

  async function authorized(
    principal: ConsequenceControlPrincipal,
    profileId: string,
    action: unknown,
  ) {
    try {
      return await config.authorizeProfile(principal, profileId, clone(action)) === true;
    } catch {
      return false;
    }
  }

  function verifiedProposal(
    candidate: unknown,
    proposalId: string,
    principal: ConsequenceControlPrincipal,
    options?: JsonObject,
  ): JsonObject | null {
    try {
      const verified = config.controller.verifyProposal(candidate, options);
      if (!isPlainObject(verified?.proposal)
          || verified.proposal.proposal_id !== proposalId
          || verified.proposal.initiator_id !== principal.id
          || !identifier(verified.proposal.profile_id)) {
        return null;
      }
      return clone(verified.proposal);
    } catch {
      return null;
    }
  }

  async function initialize() {
    if (closing) throw new Error('consequence_control_closing');
    const readiness = await config.readiness();
    if (readiness?.ok !== true) throw new Error('consequence_control_dependency_not_ready');
    initialized = true;
    accepting = true;
    return { ok: true };
  }

  function live() {
    return response(200, { status: 'ok', service: 'emilia-consequence-control' });
  }

  async function ready() {
    if (!initialized || !accepting || closing) {
      return refused(503, 'dependency_not_ready');
    }
    try {
      const readiness = await config.readiness();
      return readiness?.ok === true
        ? response(200, { status: 'ok', service: 'emilia-consequence-control' })
        : refused(503, 'dependency_not_ready');
    } catch {
      return refused(503, 'dependency_not_ready');
    }
  }

  async function prepare({ principal: candidate, body }: { principal?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!exactKeys(body, PREPARE_KEYS)
        || !identifier(body.profile_id)
        || !identifier(body.operation_id)
        || !isPlainObject(body.action)) {
      return refused(400, 'request_fields_invalid');
    }
    if (!await authorized(principal, body.profile_id, body.action)) {
      return refused(403, 'profile_not_authorized');
    }
    let proposalId: string;
    try {
      proposalId = idFactory();
      if (!identifier(proposalId)) throw new Error('proposal_id_invalid');
      const proposal = config.controller.prepare({
        proposal_id: proposalId,
        profile_id: body.profile_id,
        operation_id: body.operation_id,
        initiator_id: principal.id,
        action: clone(body.action),
      });
      return response(201, { status: 'prepared', proposal: sanitizeControllerResult(proposal) as JsonObject });
    } catch {
      return refused(503, 'proposal_preparation_failed');
    }
  }

  async function beginApproval({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, BEGIN_APPROVAL_KEYS)
        || !identifier(body.approver_id) || !identifier(body.idempotency_key)) {
      return refused(400, 'request_fields_invalid');
    }
    const proposal = verifiedProposal(body.proposal, proposalId, principal);
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    try {
      const requesterAuthorization = await config.requesterAuthorization({ principal, proposal: clone(proposal) });
      const result = await config.controller.beginApproval({
        proposal,
        approver_id: body.approver_id,
        idempotency_key: body.idempotency_key,
        requester_authorization: requesterAuthorization,
      });
      return response(202, { status: 'pending', approval: sanitizeControllerResult(result) as JsonObject });
    } catch {
      return refused(503, 'approval_acquisition_unavailable');
    }
  }

  async function pollApproval({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, POLL_APPROVAL_KEYS)
        || !identifier(body.request_id)
        || typeof body.poll_token !== 'string'
        || body.poll_token.length < 8
        || body.poll_token.length > 4096
        || /[\r\n\u0000]/.test(body.poll_token)) {
      return refused(400, 'request_fields_invalid');
    }
    const proposal = verifiedProposal(body.proposal, proposalId, principal, { allowExpired: true });
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    try {
      const result = await config.controller.pollApproval({
        proposal,
        request_id: body.request_id,
        poll_token: body.poll_token,
      });
      return response(200, { status: result?.status ?? 'unknown', approval: sanitizeControllerResult(result) as JsonObject });
    } catch {
      return refused(503, 'approval_poll_unavailable');
    }
  }

  async function lookupAttempt({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, LOOKUP_ATTEMPT_KEYS)) {
      return refused(400, 'request_fields_invalid');
    }
    const proposal = verifiedProposal(body.proposal, proposalId, principal, { allowExpired: true });
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    const consequence = proposal.consequence;
    if (!isPlainObject(consequence)
        || !identifier(consequence.tenant_id)
        || !identifier(consequence.provider_id)
        || !identifier(consequence.provider_account_id)
        || !identifier(consequence.environment)
        || typeof consequence.request_digest !== 'string'
        || !DIGEST.test(consequence.request_digest)
        || typeof config.lookupAttempt !== 'function') {
      return refused(503, 'attempt_lookup_unavailable');
    }
    const lookup = {
      tenant_id: consequence.tenant_id,
      provider_id: consequence.provider_id,
      provider_account_id: consequence.provider_account_id,
      environment: consequence.environment,
      request_digest: consequence.request_digest,
    };
    try {
      const found = await config.lookupAttempt({
        principal,
        proposal: clone(proposal),
        lookup: clone(lookup),
      });
      if (found === null) return refused(404, 'attempt_not_found');
      const attempt = publicAttemptBinding(found);
      if (!attempt
          || !ATTEMPT_STATES.has(found?.state)
          || ATTEMPT_KEYS.some((field) => attempt[field] !== (
            field === 'attempt_id' ? found.attempt_id : (lookup as JsonObject)[field]
          ))) {
        return refused(503, 'attempt_lookup_unavailable');
      }
      return response(200, {
        status: 'found',
        state: found.state,
        attempt,
      });
    } catch {
      return refused(503, 'attempt_lookup_unavailable');
    }
  }

  async function execute({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, EXECUTE_KEYS)) {
      return refused(400, 'request_fields_invalid');
    }
    if (!evidenceShape(body.evidence)) return refused(400, 'evidence_fields_invalid');
    const proposal = verifiedProposal(body.proposal, proposalId, principal);
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    let effect: (input: JsonObject) => Promise<unknown>;
    try {
      effect = await config.effectForProfile({
        principal,
        profile_id: proposal.profile_id,
        proposal: clone(proposal),
      });
      if (typeof effect !== 'function') throw new Error('effect_missing');
    } catch {
      return refused(503, 'effect_adapter_unavailable');
    }
    try {
      const result = await config.withEvidenceContext({
        principal,
        proposal: clone(proposal),
        evidence: clone(body.evidence),
      }, () => config.controller.execute({
        proposal,
        receipt: clone(body.receipt),
        evaluation: clone(body.evaluation),
      }, effect));
      return response(statusForControllerResult(result), {
        status: result?.ok === true ? 'completed' : 'refused',
        result: sanitizeControllerResult(result) as JsonObject,
      });
    } catch (error) {
      const objectError = error && (typeof error === 'object' || typeof error === 'function')
        ? error as object : null;
      const handle = objectError ? config.controller.getReconciliationHandle(objectError) : null;
      const detailedAttempt = isPlainObject((error as any)?.proposalToEffect?.attempt)
        ? (error as any).proposalToEffect.attempt : handle;
      const attempt = publicAttemptBinding(detailedAttempt);
      if (attempt) {
        return response(202, {
          status: 'indeterminate',
          retry_allowed: false,
          attempt,
          error: { code: 'provider_outcome_indeterminate' },
        });
      }
      return refused(503, 'execution_failed_closed');
    }
  }

  async function reconcile({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, RECONCILE_KEYS)) {
      return refused(400, 'request_fields_invalid');
    }
    if (!attemptShape(body.attempt)) return refused(400, 'attempt_fields_invalid');
    if (!evidenceShape(body.evidence)) return refused(400, 'evidence_fields_invalid');
    const proposal = verifiedProposal(body.proposal, proposalId, principal, { allowExpired: true });
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    try {
      const result = await config.withEvidenceContext({
        principal,
        proposal: clone(proposal),
        evidence: clone(body.evidence),
      }, async () => {
        const recovered = await config.recoverAttempt({
          principal,
          proposal: clone(proposal),
          attempt: clone(body.attempt),
        });
        if (!isPlainObject(recovered)
            || recovered.tenant_id !== body.attempt.tenant_id
            || recovered.attempt_id !== body.attempt.attempt_id
            || typeof recovered.owner !== 'string'
            || recovered.owner.length < 16
            || recovered.owner.length > 1024) {
          return { ok: false, reason: 'attempt_recovery_refused' };
        }
        const recoveryAuthorization = await config.aebRecoveryAuthorization({
          principal,
          proposal: clone(proposal),
          attempt: clone(body.attempt),
        });
        return config.controller.reconcile({
          proposal,
          evaluation: clone(body.evaluation),
          attempt: recovered,
          provider_evidence: clone(body.provider_evidence),
          aeb_recovery_authorization: recoveryAuthorization,
        });
      });
      if (result?.reason === 'attempt_recovery_refused') {
        return refused(409, 'attempt_recovery_refused');
      }
      return response(statusForControllerResult(result), {
        status: result?.ok === true ? 'reconciled' : 'refused',
        result: sanitizeControllerResult(result) as JsonObject,
      });
    } catch {
      return refused(503, 'reconciliation_unavailable');
    }
  }

  async function repair({
    principal: candidate,
    proposalId,
    body,
  }: { principal?: unknown; proposalId?: unknown; body?: unknown } = {}) {
    const principal = normalizePrincipal(candidate);
    if (!principal) return refused(401, 'authentication_required');
    if (!identifier(proposalId) || !exactKeys(body, REPAIR_KEYS)) {
      return refused(400, 'request_fields_invalid');
    }
    if (!attemptShape(body.attempt)) return refused(400, 'attempt_fields_invalid');
    if (!evidenceShape(body.evidence)) return refused(400, 'evidence_fields_invalid');
    const proposal = verifiedProposal(body.proposal, proposalId, principal, { allowExpired: true });
    if (!proposal) return refused(404, 'proposal_not_found');
    if (!await authorized(principal, proposal.profile_id, proposal.action)) {
      return refused(403, 'profile_not_authorized');
    }
    try {
      const recoveryAuthorization = await config.aebRecoveryAuthorization({
        principal,
        proposal: clone(proposal),
        attempt: clone(body.attempt),
      });
      const result = await config.withEvidenceContext({
        principal,
        proposal: clone(proposal),
        evidence: clone(body.evidence),
      }, () => config.controller.repairAeb({
        proposal,
        evaluation: clone(body.evaluation),
        attempt: clone(body.attempt),
        aeb_recovery_authorization: recoveryAuthorization,
      }));
      return response(statusForControllerResult(result), {
        status: result?.ok === true ? 'repaired' : 'refused',
        result: sanitizeControllerResult(result) as JsonObject,
      });
    } catch {
      return refused(503, 'repair_unavailable');
    }
  }

  async function close({ graceMs = 30_000 }: { graceMs?: number } = {}) {
    if (closePromise) return closePromise;
    closing = true;
    stopAdmission();
    closePromise = (async () => {
      await waitForIdle(graceMs);
      if (typeof config.close === 'function') await config.close();
      initialized = false;
      return { ok: true as const };
    })();
    return closePromise;
  }

  return Object.freeze({
    authenticate,
    initialize,
    admit,
    stopAdmission,
    waitForIdle,
    live,
    ready,
    prepare,
    beginApproval,
    pollApproval,
    lookupAttempt,
    execute,
    reconcile,
    repair,
    close,
    limits: Object.freeze({
      maxBodyBytes: 1024 * 1024,
      maxHeaderBytes: 32 * 1024,
      requestTimeoutMs: 30_000,
    }),
  });
}

export default Object.freeze({
  createConsequenceControlRuntime,
  publicAttemptBinding,
});

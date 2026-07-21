// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-REGISTRY-v1 — scoped human authority resolution.
 *
 * THE HOLE THIS FILLS
 * -------------------
 * A signature proves a key produced bytes. A Class-A signoff proves a named
 * human, with a device-bound ceremony, was present. NEITHER proves the human
 * was ENTITLED to approve THIS action, at THIS amount, under THIS policy, at
 * THAT time. The mint path fabricated that entitlement (a stub authority with
 * max_amount_usd = MAX_SAFE_INTEGER and scope = the requested action), so the
 * four authority-side hard-deny checks could never fire. This module resolves
 * real scoped authority from the registry and returns a CLOSED verdict set.
 *
 * DOCTRINE (matches docs/ADMISSIBILITY-INVARIANT-REGISTRY.md)
 * If authority cannot be resolved, the answer is never "unknown but allow." It
 * is a refusal with a reason. Every failure mode is one of a fixed, closed set
 * — never a boolean, never a silent default.
 *
 * Pure and deterministic: given the same resolution context (the authority
 * record, its delegation ancestry, and the registry snapshot commitment), the
 * verdict and its result hash are identical in every language and every run.
 * I/O (fetching the record + ancestry) lives in ./store.js and fails closed to
 * `registry_unavailable`.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';

export const AUTHORITY_REGISTRY_VERSION = 'EP-AUTHORITY-REGISTRY-v1';

/**
 * The CLOSED verdict set. Nothing outside this set may ever be returned. A
 * downstream reader can switch on these exhaustively and know it has covered
 * every case the resolver can produce.
 */
export const AUTHORITY_VERDICTS = Object.freeze([
  'authorized',
  'unknown_authority',
  'revoked_authority',
  'expired_authority',
  'not_yet_valid',
  'wrong_scope',
  'wrong_role',
  'amount_exceeded',
  'policy_mismatch',
  'delegation_broken',
  'insufficient_assurance',
  'registry_unavailable',
] as const);

const VERDICT = Object.freeze(
  Object.fromEntries(AUTHORITY_VERDICTS.map((v) => [v, v])),
);

const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function strictInstantMs(value: any): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, , offsetHourText, offsetMinuteText] = match;
  const localText = `${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondText}`;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(yearText), Number(monthText) - 1, Number(dayText));
  calendar.setUTCHours(Number(hourText), Number(minuteText), Number(secondText), 0);
  if (calendar.toISOString().slice(0, 19) !== localText) return NaN;
  if (offsetHourText !== undefined
    && (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

/** Assurance ordering: a higher class satisfies a lower requirement. */
const ASSURANCE_RANK = Object.freeze({ C: 1, B: 2, A: 3 });
function meetsAssurance(have: any, required: any): boolean {
  if (!required) return true;
  if (!Object.hasOwn(ASSURANCE_RANK, have) || !Object.hasOwn(ASSURANCE_RANK, required)) return false;
  return (ASSURANCE_RANK as any)[have] >= (ASSURANCE_RANK as any)[required];
}

const MAX_DELEGATION_DEPTH = 8;

function sha256hex(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * The authority-facts subset that is BOUND into the receipt and hashed. Kept
 * deliberately small and stable: an offline verifier re-derives this exact
 * shape to recompute `authority_result_hash`, so its field set and ordering
 * (via canonical JSON) are part of the wire contract.
 */
export function authorityResultCore(r: any): any {
  return {
    '@version': AUTHORITY_REGISTRY_VERSION,
    action_type: r.action_type ?? null,
    amount: typeof r.amount === 'number' ? r.amount : null,
    authority_id: r.authority_id ?? null,
    currency: r.currency ?? null,
    issued_at: r.issued_at ?? null,
    max_amount_usd: typeof r.max_amount_usd === 'number' ? r.max_amount_usd : null,
    policy_hash: r.policy_hash ?? null,
    registry_epoch: Number.isSafeInteger(r.registry_epoch) ? r.registry_epoch : null,
    role: r.role ?? null,
    scope: Array.isArray(r.scope) ? r.scope : null,
    subject_ref: r.subject_ref ?? null,
    verdict: r.verdict,
  };
}

/** sha256:<hex> over the canonical authority-result core (excludes the hash itself). */
export function authorityResultHash(r: any): string {
  return `sha256:${sha256hex(Buffer.from(canonicalize(authorityResultCore(r)), 'utf8'))}`;
}

/** Build the six receipt-binding fields from a resolver result. */
export function authorityBinding(r: any): any {
  return {
    authority_id: r.authority_id ?? null,
    authority_verdict: r.verdict,
    authority_result_hash: authorityResultHash(r),
    authority_registry_head: r.registry_head ?? null,
    authority_registry_epoch: Number.isSafeInteger(r.registry_epoch) ? r.registry_epoch : null,
    policy_hash: r.policy_hash ?? null,
  };
}

function fail(verdict: string, detail: string, extra: any = {}): any {
  return { verdict, authorized: false, detail: detail ?? verdict, ...extra };
}

/**
 * Normalize a raw `authorities` row (which may carry legacy column names) into
 * the resolver's record shape. Tolerant of the pre-131 schema: a row with no
 * action_scopes / max_amount_usd simply has null limits (see the resolver's
 * treatment of null scope/limit below).
 */
export function normalizeAuthorityRecord(row: any): any {
  if (!row) return null;
  const scopes = row.action_scopes ?? row.scope ?? null;
  return {
    authority_id: row.authority_id ?? null,
    subject_type: row.subject_type ?? null,
    subject_ref: row.subject_ref ?? null,
    organization_id: row.organization_id ?? null,
    role: row.role ?? null,
    assurance_class: row.assurance_class ?? null,
    status: row.status ?? 'active',
    valid_from: row.valid_from ?? null,
    valid_to: row.valid_to ?? null,
    revoked_at: row.revoked_at ?? null,
    action_scopes: Array.isArray(scopes) ? scopes : (scopes == null ? null : [scopes]),
    max_amount_usd: typeof row.max_amount_usd === 'number' ? row.max_amount_usd : (row.max_amount_usd == null ? null : Number(row.max_amount_usd)),
    currency: row.currency ?? 'USD',
    delegation_parent: row.delegation_parent ?? null,
    policy_hash: row.policy_hash ?? null,
  };
}

/**
 * Walk the delegation chain and confirm the record's scope+ceiling are
 * CONTAINED by every ancestor. A delegated authority may narrow, never widen,
 * what its parent granted. Fail-closed: a missing, revoked, expired, or
 * out-of-window ancestor, a scope the parent does not itself hold, an amount
 * ceiling above the parent's, or a cycle/over-deep chain, is `delegation_broken`.
 */
function checkDelegation(record: any, resolveParent: any, atISO: string): any {
  const at = strictInstantMs(atISO);
  let child = record;
  const seen = new Set([record.authority_id]);
  for (let depth = 0; depth < MAX_DELEGATION_DEPTH; depth++) {
    if (!child.delegation_parent) return { ok: true };
    const parent = normalizeAuthorityRecord(resolveParent ? resolveParent(child.delegation_parent) : null);
    if (!parent) return { ok: false, detail: 'delegation_parent_missing' };
    if (!parent.authority_id || seen.has(parent.authority_id)) return { ok: false, detail: 'delegation_cycle' };
    seen.add(parent.authority_id);

    if (!parent.organization_id || parent.organization_id !== child.organization_id) {
      return { ok: false, detail: 'delegation_organization_mismatch' };
    }

    if (parent.revoked_at || (parent.status && parent.status !== 'active')) {
      return { ok: false, detail: 'delegation_parent_revoked' };
    }
    const parentFrom = parent.valid_from ? strictInstantMs(parent.valid_from) : null;
    const parentTo = parent.valid_to ? strictInstantMs(parent.valid_to) : null;
    if ((parent.valid_from && !Number.isFinite(parentFrom)) || (parent.valid_to && !Number.isFinite(parentTo))) {
      return { ok: false, detail: 'delegation_parent_invalid_window' };
    }
    if (parentFrom !== null && parentFrom > at) return { ok: false, detail: 'delegation_parent_not_yet_valid' };
    if (parentTo !== null && parentTo < at) return { ok: false, detail: 'delegation_parent_expired' };

    if (Array.isArray(parent.action_scopes)) {
      if (!Array.isArray(child.action_scopes)) return { ok: false, detail: 'delegation_scope_widened' };
      const parentScopes = new Set(parent.action_scopes);
      if (!child.action_scopes.every((s: any) => parentScopes.has(s))) {
        return { ok: false, detail: 'delegation_scope_widened' };
      }
    }
    if (parent.max_amount_usd !== null) {
      if (!Number.isFinite(parent.max_amount_usd) || parent.max_amount_usd < 0
        || !Number.isFinite(child.max_amount_usd) || child.max_amount_usd < 0
        || parent.currency !== child.currency || child.max_amount_usd > parent.max_amount_usd) {
        return { ok: false, detail: 'delegation_amount_widened' };
      }
    }
    if (parent.policy_hash && child.policy_hash !== parent.policy_hash) {
      return { ok: false, detail: 'delegation_policy_widened' };
    }
    if (!Object.hasOwn(ASSURANCE_RANK, parent.assurance_class)
      || !Object.hasOwn(ASSURANCE_RANK, child.assurance_class)
      || (ASSURANCE_RANK as any)[child.assurance_class] > (ASSURANCE_RANK as any)[parent.assurance_class]) {
      return { ok: false, detail: 'delegation_assurance_widened' };
    }
    child = parent;
  }
  return { ok: false, detail: 'delegation_too_deep' };
}

/**
 * PURE verdict over a fully-resolved context. No I/O. This is the function an
 * offline verifier and every conformance vector run against.
 */
export function evaluateAuthorityVerdict(ctx: any, input: any): any {
  if (!input || typeof input !== 'object' || Array.isArray(input)) input = {};
  const at = input.issued_at;
  const atMs = strictInstantMs(at);
  const subjectRef = input.approver_id || input.principal_id || null;

  const base = {
    action_type: input.action_type ?? null,
    amount: typeof input.amount === 'number' ? input.amount : null,
    currency: input.currency ?? null,
    issued_at: input.issued_at ?? null,
    policy_hash: input.policy_hash ?? null,
    subject_ref: subjectRef,
    registry_epoch: ctx?.snapshot?.epoch ?? null,
    registry_head: ctx?.snapshot?.head ?? null,
  };
  const out = (r: any) => ({ ...base, ...r, verdict: r.verdict });

  if (ctx?.unavailable || !ctx?.snapshot) {
    return out(fail(VERDICT.registry_unavailable as any, 'registry_unavailable', { registry_epoch: null, registry_head: null }));
  }
  if (Number.isSafeInteger(input.expected_min_epoch) && ctx.snapshot.epoch < (input.expected_min_epoch as number)) {
    return out(fail(VERDICT.registry_unavailable as any, 'stale_registry'));
  }

  const record = ctx.record ? normalizeAuthorityRecord(ctx.record) : null;

  if (!record) return out(fail(VERDICT.unknown_authority as any, 'no_authority_record'));

  const facts = {
    authority_id: record.authority_id,
    role: record.role,
    scope: record.action_scopes,
    max_amount_usd: record.max_amount_usd,
  };

  if (!subjectRef || record.subject_ref !== subjectRef
    || !input.organization_id || record.organization_id !== input.organization_id) {
    return out({ ...facts, ...fail(VERDICT.unknown_authority as any, 'authority_subject_or_organization_mismatch') });
  }

  if (record.revoked_at) return out({ ...facts, ...fail(VERDICT.revoked_authority as any, 'revoked_at') });
  if (record.status && record.status !== 'active') {
    return out({ ...facts, ...fail(VERDICT.revoked_authority as any, `status_${record.status}`) });
  }

  if (!Number.isFinite(atMs)) {
    return out({ ...facts, ...fail(VERDICT.expired_authority as any, 'invalid_issued_at') });
  }
  const validToMs = record.valid_to ? strictInstantMs(record.valid_to) : null;
  const validFromMs = record.valid_from ? strictInstantMs(record.valid_from) : null;
  if ((record.valid_to && !Number.isFinite(validToMs)) || (record.valid_from && !Number.isFinite(validFromMs))) {
    return out({ ...facts, ...fail(VERDICT.expired_authority as any, 'invalid_authority_window') });
  }
  if (validToMs !== null && validToMs < atMs) {
    return out({ ...facts, ...fail(VERDICT.expired_authority as any, 'valid_to_passed') });
  }
  if (validFromMs !== null && validFromMs > atMs) {
    return out({ ...facts, ...fail(VERDICT.not_yet_valid as any, 'valid_from_future') });
  }

  if (input.required_role && record.role !== input.required_role) {
    return out({ ...facts, ...fail(VERDICT.wrong_role as any, 'role_mismatch') });
  }

  if (Array.isArray(record.action_scopes) && !record.action_scopes.includes(input.action_type)) {
    return out({ ...facts, ...fail(VERDICT.wrong_scope as any, 'action_not_in_scope') });
  }

  if (record.max_amount_usd !== null && record.max_amount_usd !== undefined) {
    if (!Number.isFinite(record.max_amount_usd) || record.max_amount_usd < 0
      || !Number.isFinite(input.amount) || (input.amount as number) < 0
      || typeof input.currency !== 'string' || input.currency.length === 0) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded as any, 'amount_or_ceiling_unprovable') });
    }
    const ceilingCurrency = record.currency || 'USD';
    const amountCurrency = input.currency;
    if (amountCurrency !== ceilingCurrency) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded as any, 'currency_mismatch') });
    }
    if ((input.amount as number) > record.max_amount_usd) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded as any, 'over_ceiling') });
    }
  }

  if (record.policy_hash && record.policy_hash !== input.policy_hash) {
    return out({ ...facts, ...fail(VERDICT.policy_mismatch as any, 'policy_hash_mismatch') });
  }

  const deleg = checkDelegation(record, ctx.resolveParent, at as string);
  if (!deleg.ok) return out({ ...facts, ...fail(VERDICT.delegation_broken as any, deleg.detail) });

  if (!meetsAssurance(record.assurance_class, input.requiredAssurance)) {
    return out({ ...facts, ...fail(VERDICT.insufficient_assurance as any, 'assurance_below_required', { assurance_class: record.assurance_class ?? null }) });
  }

  return out({
    ...facts,
    verdict: VERDICT.authorized,
    authorized: true,
    detail: 'ok',
    assurance_class: record.assurance_class ?? null,
    currency: record.currency || 'USD',
  });
}

const resolverApi = {
  AUTHORITY_REGISTRY_VERSION,
  AUTHORITY_VERDICTS,
  evaluateAuthorityVerdict,
  authorityResultCore,
  authorityResultHash,
  authorityBinding,
  normalizeAuthorityRecord,
};
export default resolverApi;

// Test-only visibility for mutation/property oracles. Not part of the public
// authority protocol API.
export const __authoritySecurityInternals = Object.freeze({
  strictInstantMs,
  meetsAssurance,
  checkDelegation,
});

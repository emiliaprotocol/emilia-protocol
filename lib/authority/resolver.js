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
]);

const VERDICT = Object.freeze(
  Object.fromEntries(AUTHORITY_VERDICTS.map((v) => [v, v])),
);

const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function strictInstantMs(value) {
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
function meetsAssurance(have, required) {
  if (!required) return true;
  if (!Object.hasOwn(ASSURANCE_RANK, have) || !Object.hasOwn(ASSURANCE_RANK, required)) return false;
  return ASSURANCE_RANK[have] >= ASSURANCE_RANK[required];
}

const MAX_DELEGATION_DEPTH = 8;

function sha256hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * The authority-facts subset that is BOUND into the receipt and hashed. Kept
 * deliberately small and stable: an offline verifier re-derives this exact
 * shape to recompute `authority_result_hash`, so its field set and ordering
 * (via canonical JSON) are part of the wire contract.
 *
 * @param {object} r a resolver result
 */
export function authorityResultCore(r) {
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
export function authorityResultHash(r) {
  return `sha256:${sha256hex(canonicalize(authorityResultCore(r)))}`;
}

/** Build the six receipt-binding fields from a resolver result. */
export function authorityBinding(r) {
  return {
    authority_id: r.authority_id ?? null,
    authority_verdict: r.verdict,
    authority_result_hash: authorityResultHash(r),
    authority_registry_head: r.registry_head ?? null,
    authority_registry_epoch: Number.isSafeInteger(r.registry_epoch) ? r.registry_epoch : null,
    policy_hash: r.policy_hash ?? null,
  };
}

function fail(verdict, detail, extra = {}) {
  return { verdict, authorized: false, detail: detail ?? verdict, ...extra };
}

/**
 * Normalize a raw `authorities` row (which may carry legacy column names) into
 * the resolver's record shape. Tolerant of the pre-131 schema: a row with no
 * action_scopes / max_amount_usd simply has null limits (see the resolver's
 * treatment of null scope/limit below).
 */
export function normalizeAuthorityRecord(row) {
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
 *
 * @param {object} record   the (already validated) leaf authority record
 * @param {(id:string)=>object|null} resolveParent  synchronous ancestor lookup
 * @param {string} atISO
 */
function checkDelegation(record, resolveParent, atISO) {
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

    // The parent must itself be a live authority at authorization time.
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

    // Containment: null means unbounded only at a root. Under a constrained
    // parent, omission cannot reopen scope or amount. Currency, policy,
    // assurance, and organization are equally monotone delegation dimensions.
    if (Array.isArray(parent.action_scopes)) {
      if (!Array.isArray(child.action_scopes)) return { ok: false, detail: 'delegation_scope_widened' };
      const parentScopes = new Set(parent.action_scopes);
      if (!child.action_scopes.every((s) => parentScopes.has(s))) {
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
      || ASSURANCE_RANK[child.assurance_class] > ASSURANCE_RANK[parent.assurance_class]) {
      return { ok: false, detail: 'delegation_assurance_widened' };
    }
    child = parent;
  }
  return { ok: false, detail: 'delegation_too_deep' };
}

/**
 * PURE verdict over a fully-resolved context. No I/O. This is the function an
 * offline verifier and every conformance vector run against.
 *
 * @param {object} ctx
 * @param {object|null} ctx.record        the resolved authorities row (normalized) or null
 * @param {(id:string)=>object|null} [ctx.resolveParent]  ancestry lookup for delegation
 * @param {object|null} ctx.snapshot      { epoch:int, head:'sha256:...' } | null when unavailable
 * @param {boolean} [ctx.unavailable]     store could not be reached — fail closed
 * @param {object} input
 * @param {string} input.organization_id
 * @param {string} [input.principal_id]
 * @param {string} [input.approver_id]    the subject whose authority is being relied on (approver > principal)
 * @param {string} input.action_type
 * @param {number} [input.amount]
 * @param {string} [input.currency]
 * @param {string} [input.policy_hash]
 * @param {string} input.issued_at        ISO-8601 — authority is judged AS OF this instant
 * @param {number} [input.expected_min_epoch]  relying-party pin: reject a registry older than this
 * @param {string} [input.requiredAssurance]   'A' | 'B' | 'C'
 * @param {string} [input.required_role]        when set, the record's role must equal it
 * @returns {object} { verdict, authorized, detail, authority_id?, ...facts, registry_epoch, registry_head, ...binding-source fields }
 */
export function evaluateAuthorityVerdict(ctx, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) input = {};
  const at = input.issued_at;
  const atMs = strictInstantMs(at);
  const subjectRef = input.approver_id || input.principal_id || null;

  // Carry the request facts onto every result so the result hash binds WHAT was
  // asked, not only the verdict — an offline verifier recomputes the same core.
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
  const out = (r) => ({ ...base, ...r, verdict: r.verdict });

  // 0. Registry commitment must be present and fresh, or nothing can be relied on.
  if (ctx?.unavailable || !ctx?.snapshot) {
    return out(fail(VERDICT.registry_unavailable, 'registry_unavailable', { registry_epoch: null, registry_head: null }));
  }
  if (Number.isSafeInteger(input.expected_min_epoch) && ctx.snapshot.epoch < input.expected_min_epoch) {
    return out(fail(VERDICT.registry_unavailable, 'stale_registry'));
  }

  const record = ctx.record ? normalizeAuthorityRecord(ctx.record) : null;

  // 1. No record for this subject in this org — unknown, never assumed.
  if (!record) return out(fail(VERDICT.unknown_authority, 'no_authority_record'));

  // Carry the record's granted facts for the result core.
  const facts = {
    authority_id: record.authority_id,
    role: record.role,
    scope: record.action_scopes,
    max_amount_usd: record.max_amount_usd,
  };

  // A store lookup is not itself proof that the returned row belongs to the
  // request. Re-bind the record to both requested dimensions so a poisoned or
  // mis-keyed cache cannot substitute another human's or tenant's authority.
  if (!subjectRef || record.subject_ref !== subjectRef
    || !input.organization_id || record.organization_id !== input.organization_id) {
    return out({ ...facts, ...fail(VERDICT.unknown_authority, 'authority_subject_or_organization_mismatch') });
  }

  // 2. Revocation and lifecycle status.
  if (record.revoked_at) return out({ ...facts, ...fail(VERDICT.revoked_authority, 'revoked_at') });
  if (record.status && record.status !== 'active') {
    return out({ ...facts, ...fail(VERDICT.revoked_authority, `status_${record.status}`) });
  }

  // 3. Validity window, judged as of issued_at (NOT wall-clock now).
  if (!Number.isFinite(atMs)) {
    return out({ ...facts, ...fail(VERDICT.expired_authority, 'invalid_issued_at') });
  }
  const validToMs = record.valid_to ? strictInstantMs(record.valid_to) : null;
  const validFromMs = record.valid_from ? strictInstantMs(record.valid_from) : null;
  if ((record.valid_to && !Number.isFinite(validToMs)) || (record.valid_from && !Number.isFinite(validFromMs))) {
    return out({ ...facts, ...fail(VERDICT.expired_authority, 'invalid_authority_window') });
  }
  if (validToMs !== null && validToMs < atMs) {
    return out({ ...facts, ...fail(VERDICT.expired_authority, 'valid_to_passed') });
  }
  if (validFromMs !== null && validFromMs > atMs) {
    return out({ ...facts, ...fail(VERDICT.not_yet_valid, 'valid_from_future') });
  }

  // 4. Role.
  if (input.required_role && record.role !== input.required_role) {
    return out({ ...facts, ...fail(VERDICT.wrong_role, 'role_mismatch') });
  }

  // 5. Action scope. A null scope means "unscoped" and is only acceptable for a
  //    non-critical caller; the enforcement layer decides whether an unscoped
  //    authority may stand for a critical action. Here: a PRESENT scope that
  //    omits the action is a hard wrong_scope.
  if (Array.isArray(record.action_scopes) && !record.action_scopes.includes(input.action_type)) {
    return out({ ...facts, ...fail(VERDICT.wrong_scope, 'action_not_in_scope') });
  }

  // 6. Amount ceiling (currency-aware, fail-closed on any currency it cannot
  //    prove containment in — EP holds no FX oracle).
  if (record.max_amount_usd !== null && record.max_amount_usd !== undefined) {
    if (!Number.isFinite(record.max_amount_usd) || record.max_amount_usd < 0
      || !Number.isFinite(input.amount) || input.amount < 0
      || typeof input.currency !== 'string' || input.currency.length === 0) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded, 'amount_or_ceiling_unprovable') });
    }
    const ceilingCurrency = record.currency || 'USD';
    const amountCurrency = input.currency;
    if (amountCurrency !== ceilingCurrency) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded, 'currency_mismatch') });
    }
    if (input.amount > record.max_amount_usd) {
      return out({ ...facts, ...fail(VERDICT.amount_exceeded, 'over_ceiling') });
    }
  }

  // 7. Policy pinning. If the authority was granted against a specific policy
  //    hash, the action's policy must match it exactly.
  if (record.policy_hash && record.policy_hash !== input.policy_hash) {
    return out({ ...facts, ...fail(VERDICT.policy_mismatch, 'policy_hash_mismatch') });
  }

  // 8. Delegation containment.
  const deleg = checkDelegation(record, ctx.resolveParent, at);
  if (!deleg.ok) return out({ ...facts, ...fail(VERDICT.delegation_broken, deleg.detail) });

  // 9. Assurance floor (a real, pre-existing gate — kept in the closed set).
  if (!meetsAssurance(record.assurance_class, input.requiredAssurance)) {
    return out({ ...facts, ...fail(VERDICT.insufficient_assurance, 'assurance_below_required', { assurance_class: record.assurance_class ?? null }) });
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

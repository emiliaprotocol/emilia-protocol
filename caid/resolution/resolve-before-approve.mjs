// SPDX-License-Identifier: Apache-2.0
//
// resolve-before-approve.mjs - reference-typed argument resolution, frozen
// before the Action Object is formed and re-checked at dispatch.
//
// THE HOLE THIS CLOSES
//
// A CAID commits an identifier to canonical typed content (caid/DESIGN.md
// section 1 and 4). If a material argument is a REFERENCE rather than an
// identity - a filesystem path, a URL, a payee label - then the digest
// commits to the reference, not to the thing the reference names. The
// reference can re-resolve between the moment a human is shown the action
// and the moment the executor dispatches it. The argument bytes never
// change, so the CAID never changes, and the approval silently covers a
// different target.
//
// The public statement of this attack class, cited here as the rule and
// nothing more:
//   - Wiz, "GhostApproval".
//   - Adversa, "SymJack".
//   - OWASP AI Agent Security cheat sheet.
// These are cited as prior public description of the class. No claim is
// made here that any of those parties reviewed, tested, or endorsed this
// code.
//
// THE RULE
//
//   1. Before the Action Object is formed, every declared reference-typed
//      argument is resolved and the RESOLVED IDENTITY is frozen into the
//      observed action as a digest. The Action Object presented to the
//      human therefore commits to the resolved target, not to the label.
//   2. At dispatch the executor re-resolves the same references from the
//      same supplied values and compares. Any divergence is a refusal with
//      a stated reason. Dispatch never repairs, re-freezes, or proceeds on
//      a resolution it could not perform.
//
// SCOPE, stated the same way CAID states its own
//
// This profile establishes only that a named reference resolved to the
// same identity at two moments, under the resolvers the relying party
// supplied. It establishes nothing about identity, authority,
// authorization, safety, or execution. A divergence refusal says the
// resolved target changed; it does not say who changed it or that anyone
// acted in bad faith. An agreement says the two resolutions matched; it
// does not say the target is the one the human meant.
//
// Fail-closed: every export returns a refusal object with reasons. Nothing
// here throws, including on hostile input and on a resolver that throws.
//
// Dependencies: node:crypto only. Resolvers are injected by the caller;
// see resolvers.mjs for the filesystem, URL-origin, and beneficiary-label
// reference resolvers.

import { createHash } from 'node:crypto';

export const RESOLUTION_PROFILE = 'EP-RESOLVE-BEFORE-APPROVE-v1';

/** The field the resolution binding is written into inside the observed action. */
export const BINDING_FIELD = 'resolved_references';

/** Closed set of reference kinds. An unknown kind is never resolved. */
export const REFERENCE_KINDS = Object.freeze([
  'filesystem-path',
  'url-origin',
  'beneficiary-label',
]);

/**
 * Closed set of refusal base codes. Field-scoped codes are emitted as
 * "<code>:<field>"; kind-scoped codes as "<code>:<kind>". Nothing outside
 * this set is ever returned.
 */
export const REFUSAL_CODES = Object.freeze([
  'invalid_arguments',
  'invalid_resolution_spec',
  'resolver_missing',
  'missing_reference_field',
  'mistyped_reference_field',
  'resolution_failed',
  'resolution_unstable',
  'resolution_binding_preexisting',
  'resolution_binding_absent',
  'resolution_binding_mismatch',
  'resolved_reference_diverged',
]);

const FIELD_RE = /^[a-z][a-z0-9_]*$/;
const IDENTITY_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const MAX_REFERENCES = 64;
const MAX_REFERENCE_BYTES = 4096;
const MAX_IDENTITY_BYTES = 4096;
const SPEC_KEYS = new Set(['@profile', 'references']);
const REFERENCE_ENTRY_KEYS = new Set(['field', 'kind']);
const BINDING_ENTRY_KEYS = new Set(['kind', 'identity_digest']);

function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Own-key read that refuses accessors, non-enumerable members, symbol keys,
 * and exotic prototypes. A getter on a reference argument would let the
 * value read at capture differ from the value read at dispatch inside one
 * process, which is the same bug one layer down.
 */
function safeOwnEntries(value) {
  if (!isPlainObject(value)) return null;
  const entries = [];
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) return null;
    entries.push([key, descriptor.value]);
  }
  return entries;
}

function utf8Bytes(text) {
  return Buffer.byteLength(text, 'utf8');
}

/**
 * Domain-separated identity digest.
 *
 * The preimage is exactly:
 *   RESOLUTION_PROFILE + "\n" + kind + "\n" + identity
 * encoded UTF-8. The kind is inside the preimage so a resolved identity of
 * one kind can never stand in for the same string resolved under another
 * kind - a beneficiary directory must not be able to speak for a
 * filesystem target.
 *
 * Returns null for input outside the profile's bounds; callers turn that
 * into a refusal.
 */
export function referenceIdentityDigest(kind, identity) {
  if (typeof kind !== 'string' || !REFERENCE_KINDS.includes(kind)) return null;
  if (typeof identity !== 'string' || identity.length === 0) return null;
  if (utf8Bytes(identity) > MAX_IDENTITY_BYTES) return null;
  const preimage = `${RESOLUTION_PROFILE}\n${kind}\n${identity}`;
  // Content-addressing commitment over a resolved reference identity, not
  // password or credential storage.
  // codeql[js/insufficient-password-hash]
  return 'sha256:' + createHash('sha256').update(Buffer.from(preimage, 'utf8')).digest('hex');
}

/**
 * Validate the resolution spec. The spec is a relying-party input pinned
 * alongside the action-type definition; it is not evidence, and a spec
 * carried by the caller alongside the arguments proves nothing.
 *
 * Returns [] when valid, else ['invalid_resolution_spec'].
 */
function validateSpec(spec) {
  const entries = safeOwnEntries(spec);
  if (entries === null) return ['invalid_resolution_spec'];
  if (entries.some(([key]) => !SPEC_KEYS.has(key))) return ['invalid_resolution_spec'];
  if (spec['@profile'] !== RESOLUTION_PROFILE) return ['invalid_resolution_spec'];
  const references = spec.references;
  if (!Array.isArray(references) || references.length === 0 || references.length > MAX_REFERENCES) {
    return ['invalid_resolution_spec'];
  }
  const seen = new Set();
  for (const entry of references) {
    const entryFields = safeOwnEntries(entry);
    if (entryFields === null) return ['invalid_resolution_spec'];
    if (entryFields.length !== REFERENCE_ENTRY_KEYS.size) return ['invalid_resolution_spec'];
    if (entryFields.some(([key]) => !REFERENCE_ENTRY_KEYS.has(key))) return ['invalid_resolution_spec'];
    if (typeof entry.field !== 'string' || !FIELD_RE.test(entry.field)) return ['invalid_resolution_spec'];
    if (entry.field === BINDING_FIELD || entry.field === 'action_type') return ['invalid_resolution_spec'];
    if (!REFERENCE_KINDS.includes(entry.kind)) return ['invalid_resolution_spec'];
    if (seen.has(entry.field)) return ['invalid_resolution_spec'];
    seen.add(entry.field);
  }
  return [];
}

/**
 * @returns {{ok: true, value: string} | {ok: false, code: string}}
 */
function readReferenceValue(source, field) {
  if (!Object.prototype.hasOwnProperty.call(source, field)) {
    return { ok: false, code: `missing_reference_field:${field}` };
  }
  const value = source[field];
  if (typeof value !== 'string' || value.length === 0 || utf8Bytes(value) > MAX_REFERENCE_BYTES) {
    return { ok: false, code: `mistyped_reference_field:${field}` };
  }
  return { ok: true, value };
}

/**
 * Run one resolver twice and require agreement. A single call cannot tell a
 * stable answer from a coin flip, and freezing a coin flip into the
 * approved action is the bug this module exists to prevent.
 *
 * Returns {ok:true, identity, evidence} or {ok:false, code}.
 *
 * @returns {Promise<{ok: true, identity: string, evidence: any} | {ok: false, code: string}>}
 */
async function resolveOnce(resolver, reference, field) {
  let first;
  let second;
  try {
    first = await resolver(reference);
    second = await resolver(reference);
  } catch {
    return { ok: false, code: `resolution_failed:${field}` };
  }
  const check = (result) => {
    if (!isPlainObject(result) || result.ok !== true) return null;
    const identity = result.identity;
    if (typeof identity !== 'string' || identity.length === 0) return null;
    if (utf8Bytes(identity) > MAX_IDENTITY_BYTES) return null;
    return identity;
  };
  const a = check(first);
  const b = check(second);
  if (a === null || b === null) return { ok: false, code: `resolution_failed:${field}` };
  if (a !== b) return { ok: false, code: `resolution_unstable:${field}` };
  return { ok: true, identity: a, evidence: first.evidence ?? null };
}

function resolverFor(resolvers, kind) {
  if (!isPlainObject(resolvers)) return null;
  const fn = resolvers[kind];
  return typeof fn === 'function' ? fn : null;
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.getOwnPropertyNames(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

/**
 * Resolve every declared reference-typed argument and freeze the resolved
 * identities into the observed action.
 *
 * freezeResolvedReferences(args, spec, resolvers)
 *   -> {ok: true, observed, report}
 *   -> {ok: false, refusals: [string]}
 *
 * `observed` is the supplied arguments plus one added field,
 * `resolved_references`, mapping each declared field to its kind and the
 * domain-separated digest of its resolved identity. CAID permits
 * additional fields and covers them in the digest (DESIGN.md section 1),
 * so the resulting Action Object commits to the resolved target. Two
 * different resolved identities produce two different CAIDs; that is the
 * whole mechanism.
 *
 * `report` carries the plaintext resolved identity and resolver evidence
 * for PRESENTATION to the approver. It is deliberately not part of the
 * digested object: the digest binds the identity, the presentation layer
 * shows it. Callers that want the plaintext inside the digest can add it
 * as an ordinary material field; this profile does not, because resolved
 * identities are frequently account or path data (see CAID DESIGN.md
 * section 7 on low-entropy references).
 *
 * Refusals are returned in spec declaration order; structural refusals
 * (invalid_arguments, invalid_resolution_spec, resolution_binding_preexisting)
 * are returned alone.
 */
export async function freezeResolvedReferences(args, spec, resolvers) {
  const specRefusals = validateSpec(spec);
  if (specRefusals.length > 0) return { ok: false, refusals: specRefusals };

  const entries = safeOwnEntries(args);
  if (entries === null) return { ok: false, refusals: ['invalid_arguments'] };
  if (Object.prototype.hasOwnProperty.call(args, BINDING_FIELD)) {
    // A caller-supplied binding would let the caller state its own resolved
    // identity, which is the attack wearing the defense's clothes.
    return { ok: false, refusals: ['resolution_binding_preexisting'] };
  }

  /** @type {string[]} */
  const refusals = [];
  const binding = {};
  const reported = [];

  for (const declared of spec.references) {
    const { field, kind } = declared;
    const resolver = resolverFor(resolvers, kind);
    if (resolver === null) {
      refusals.push(`resolver_missing:${kind}`);
      continue;
    }
    const read = readReferenceValue(args, field);
    if (!read.ok) {
      refusals.push(read.code);
      continue;
    }
    const resolved = await resolveOnce(resolver, read.value, field);
    if (!resolved.ok) {
      refusals.push(resolved.code);
      continue;
    }
    const digest = referenceIdentityDigest(kind, resolved.identity);
    if (digest === null) {
      refusals.push(`resolution_failed:${field}`);
      continue;
    }
    binding[field] = { identity_digest: digest, kind };
    reported.push({
      field,
      kind,
      reference: read.value,
      identity: resolved.identity,
      identity_digest: digest,
      evidence: resolved.evidence,
    });
  }

  if (refusals.length > 0) return { ok: false, refusals };

  const observed = {};
  for (const [key, value] of entries) observed[key] = value;
  observed[BINDING_FIELD] = binding;

  return {
    ok: true,
    observed: deepFreeze(observed),
    report: deepFreeze({ '@profile': RESOLUTION_PROFILE, fields: reported }),
  };
}

/**
 * Re-resolve at dispatch and refuse on divergence.
 *
 * checkResolvedReferencesAtDispatch(observed, spec, resolvers)
 *   -> {ok: true, report}
 *   -> {ok: false, refusals: [string]}
 *
 * The executor calls this immediately before it dispatches, against the
 * exact observed action the approval covered. It never writes a binding,
 * never repairs one, and never treats a failed resolution as agreement.
 */
export async function checkResolvedReferencesAtDispatch(observed, spec, resolvers) {
  const specRefusals = validateSpec(spec);
  if (specRefusals.length > 0) return { ok: false, refusals: specRefusals };

  const entries = safeOwnEntries(observed);
  if (entries === null) return { ok: false, refusals: ['invalid_arguments'] };

  const binding = observed[BINDING_FIELD];
  const bindingEntries = safeOwnEntries(binding);
  if (!Object.prototype.hasOwnProperty.call(observed, BINDING_FIELD) || bindingEntries === null) {
    return { ok: false, refusals: ['resolution_binding_absent'] };
  }

  const declaredFields = spec.references.map((entry) => entry.field);
  const boundFields = bindingEntries.map(([key]) => key);
  if (boundFields.length !== declaredFields.length
      || !declaredFields.every((field) => boundFields.includes(field))) {
    // Set inequality either drops a reference the spec requires or smuggles
    // one it does not. Both are refusals, not partial checks.
    return { ok: false, refusals: ['resolution_binding_mismatch'] };
  }

  /** @type {string[]} */
  const refusals = [];
  const reported = [];

  for (const declared of spec.references) {
    const { field, kind } = declared;
    const entryFields = safeOwnEntries(binding[field]);
    if (entryFields === null
        || entryFields.length !== BINDING_ENTRY_KEYS.size
        || entryFields.some(([key]) => !BINDING_ENTRY_KEYS.has(key))
        || binding[field].kind !== kind
        || typeof binding[field].identity_digest !== 'string'
        || !IDENTITY_DIGEST_RE.test(binding[field].identity_digest)) {
      refusals.push(`resolution_binding_mismatch:${field}`);
      continue;
    }
    const resolver = resolverFor(resolvers, kind);
    if (resolver === null) {
      refusals.push(`resolver_missing:${kind}`);
      continue;
    }
    const read = readReferenceValue(observed, field);
    if (!read.ok) {
      refusals.push(read.code);
      continue;
    }
    const resolved = await resolveOnce(resolver, read.value, field);
    if (!resolved.ok) {
      refusals.push(resolved.code);
      continue;
    }
    const digest = referenceIdentityDigest(kind, resolved.identity);
    if (digest === null) {
      refusals.push(`resolution_failed:${field}`);
      continue;
    }
    if (digest !== binding[field].identity_digest) {
      // The approved reference now names something else. State that, and
      // nothing more: this says the resolved target changed, not who
      // changed it.
      refusals.push(`resolved_reference_diverged:${field}`);
      continue;
    }
    reported.push({
      field,
      kind,
      reference: read.value,
      identity: resolved.identity,
      identity_digest: digest,
      evidence: resolved.evidence,
    });
  }

  if (refusals.length > 0) return { ok: false, refusals };
  return { ok: true, report: deepFreeze({ '@profile': RESOLUTION_PROFILE, fields: reported }) };
}

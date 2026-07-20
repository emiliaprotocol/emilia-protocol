// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA Gate — signer-roster sync from an enterprise IdP (EP-GATE-ROSTER-v1).
 *
 * The boring key story: WHO may approve is an HR fact, not a crypto fact. This
 * module turns a SCIM-like IdP export into a versioned signer roster and
 * reconciles a key registry (key-registry.js) against it, so a deprovisioned
 * employee STOPS being an acceptable approver on the next sync. Fail closed:
 *   - only `active === true` users' keys are ever pinned; anything else
 *     (false, missing, truthy-but-not-boolean) never pins;
 *   - a user absent from the import — offboarded, or silently dropped by a
 *     broken IdP export — has every previously pinned key revoked;
 *   - a kid claimed by two principals (or carrying two different key
 *     materials) is CONTESTED: it pins nothing and is revoked if present;
 *   - an import that would leave ZERO active signers requires an explicit
 *     `allowEmpty` acknowledgment, so an empty/broken IdP response cannot
 *     silently mass-revoke every approver.
 *
 * importRoster/diffRoster are pure (inputs in, artifact out; `importedAt` is
 * the caller-supplied clock). applyRosterToRegistry mutates the given registry
 * through its real API: key-registry CAN express revocation (`revoke(kid, at)`,
 * hard and fail-closed), so reconciliation performs it directly and the
 * returned `revoked` list is the exact set of revocations performed.
 */

export const ROSTER_VERSION = 'EP-GATE-ROSTER-v1';

/**
 * Import a SCIM-like IdP user export into a signer roster.
 * @param {Array<{id:string, userName:string, active:boolean, emails?:any, keys?:Array<{kid:string, publicKey:string}>}>} idpUsers
 * @param {object} [o]
 * @param {string} [o.source]        IdP provenance, e.g. 'scim:okta:acme' (required)
 * @param {string|number} [o.importedAt]  import time (ISO or ms); the caller's clock
 * @param {boolean} [o.allowEmpty=false]  acknowledge an import with zero active signers
 * @returns {{version:string, source:string, imported_at:string, signers:Array<{principal:string, kid:string, publicKey:string, active:boolean}>, integrity_warnings:object[]}}
 */
export function importRoster(idpUsers, {
  source,
  importedAt,
  allowEmpty = false,
}: {
  source?: string;
  importedAt?: string | number;
  allowEmpty?: boolean;
} = {}) {
  if (!Array.isArray(idpUsers)) throw new Error('roster import: idpUsers must be an array');
  if (!source || typeof source !== 'string') {
    throw new Error('roster import: source (IdP provenance, e.g. "scim:okta:acme") is required');
  }
  const atMs = importedAt == null
    ? Date.now()
    : (typeof importedAt === 'number' ? importedAt : Date.parse(importedAt));
  if (!Number.isFinite(atMs)) throw new Error('roster import: importedAt is not a valid time');

  const warnings: Record<string, any>[] = [];
  const candidates: { principal: string; kid: string; publicKey: string; active: boolean }[] = [];
  const usersByPrincipal = new Map();

  for (const u of idpUsers) {
    // A user without a stable id AND a userName cannot be diffed or revoked
    // reliably later — excluded, never an approver.
    if (!u || typeof u !== 'object'
      || typeof u.id !== 'string' || !u.id
      || typeof u.userName !== 'string' || !u.userName) {
      warnings.push({ code: 'malformed_user', id: u?.id ?? null, userName: u?.userName ?? null });
      continue;
    }
    const principal = u.userName;
    usersByPrincipal.set(principal, (usersByPrincipal.get(principal) || 0) + 1);
    const active = u.active === true; // strictly boolean true; anything else never pins
    for (const k of Array.isArray(u.keys) ? u.keys : []) {
      if (!k || typeof k.kid !== 'string' || !k.kid
        || typeof k.publicKey !== 'string' || !k.publicKey) {
        warnings.push({ code: 'malformed_key', principal, kid: k?.kid ?? null });
        continue;
      }
      candidates.push({ principal, kid: k.kid, publicKey: k.publicKey, active });
    }
  }

  // Two IdP users claiming one principal: identity is ambiguous — neither pins.
  const contestedPrincipals = new Set();
  for (const [principal, count] of usersByPrincipal) {
    if (count > 1) {
      contestedPrincipals.add(principal);
      warnings.push({ code: 'duplicate_principal', principal, users: count });
    }
  }
  let entries = candidates.filter((c) => !contestedPrincipals.has(c.principal));

  // Exact-duplicate rows collapse silently (same principal + kid + key).
  const seen = new Set();
  entries = entries.filter((c) => {
    const id = `${c.principal}\n${c.kid}\n${c.publicKey}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  // One kid claimed by two principals, or one kid carrying two key materials,
  // is an integrity failure: the contested kid pins NOTHING for anyone.
  const byKid = new Map();
  for (const c of entries) {
    const g = byKid.get(c.kid) || { principals: new Set(), keys: new Set() };
    g.principals.add(c.principal);
    g.keys.add(c.publicKey);
    byKid.set(c.kid, g);
  }
  const contestedKids = new Set();
  for (const [kid, g] of byKid) {
    if (g.principals.size > 1 || g.keys.size > 1) {
      contestedKids.add(kid);
      warnings.push({ code: 'duplicate_kid', kid, principals: [...g.principals].sort() });
    }
  }
  entries = entries.filter((c) => !contestedKids.has(c.kid));

  // Mass-deprovision guard: a roster with zero active signers would, on apply,
  // revoke EVERY approver. That is indistinguishable from a broken IdP export,
  // so it requires the operator's explicit acknowledgment.
  if (!allowEmpty && !entries.some((e) => e.active)) {
    throw new Error('roster import: zero active signers (mass-deprovision guard) — pass allowEmpty:true to acknowledge revoking every approver');
  }

  entries.sort((a, b) => (a.principal < b.principal ? -1 : a.principal > b.principal ? 1
    : a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));

  return {
    version: ROSTER_VERSION,
    source,
    imported_at: new Date(atMs).toISOString(),
    signers: entries.map(({ principal, kid, publicKey, active }) => ({ principal, kid, publicKey, active })),
    integrity_warnings: warnings,
  };
}

/** A roster must be well-formed before it can drive a diff or a registry mutation. */
function assertRoster(r, name) {
  if (!r || r.version !== ROSTER_VERSION || !Array.isArray(r.signers)) {
    throw new Error(`roster: ${name} is not an ${ROSTER_VERSION} roster`);
  }
  for (const s of r.signers) {
    if (!s || typeof s.principal !== 'string' || !s.principal
      || typeof s.kid !== 'string' || !s.kid
      || typeof s.publicKey !== 'string' || !s.publicKey
      || typeof s.active !== 'boolean') {
      throw new Error(`roster: ${name} contains a malformed signer entry`);
    }
  }
}

function groupByPrincipal(roster) {
  const m = new Map();
  for (const s of roster.signers) {
    const g = m.get(s.principal) || { kids: new Set(), active: false };
    g.kids.add(s.kid);
    if (s.active === true) g.active = true;
    m.set(s.principal, g);
  }
  return m;
}

/**
 * Diff two rosters at the principal level.
 * `removed`/`deactivated` carry the PREVIOUS roster's kids — the revocation
 * candidates; `added` carries the next roster's kids.
 * @returns {{added:Array<{principal:string,kids:string[]}>, removed:Array<{principal:string,kids:string[]}>, deactivated:Array<{principal:string,kids:string[]}>}}
 */
export function diffRoster(previous, next) {
  assertRoster(previous, 'previous');
  assertRoster(next, 'next');
  const prev = groupByPrincipal(previous);
  const nxt = groupByPrincipal(next);
  const added: { principal: string; kids: string[] }[] = [];
  const removed: { principal: string; kids: string[] }[] = [];
  const deactivated: { principal: string; kids: string[] }[] = [];
  for (const [principal, g] of nxt) {
    if (!prev.has(principal)) added.push({ principal, kids: [...g.kids].sort() });
  }
  for (const [principal, g] of prev) {
    if (!nxt.has(principal)) { removed.push({ principal, kids: [...g.kids].sort() }); continue; }
    if (g.active && !nxt.get(principal).active) deactivated.push({ principal, kids: [...g.kids].sort() });
  }
  const byPrincipal = (a, b) => (a.principal < b.principal ? -1 : a.principal > b.principal ? 1 : 0);
  added.sort(byPrincipal); removed.sort(byPrincipal); deactivated.sort(byPrincipal);
  return { added, removed, deactivated };
}

/**
 * Reconcile a key registry (createKeyRegistry) against a roster:
 *   - PIN each ACTIVE, uncontested signer's key not already present;
 *   - REVOKE every registry kid not owned by an active roster signer — absent
 *     or inactive means deprovisioned. The registry passed here must therefore
 *     be DEDICATED to roster-managed approver keys.
 * key-registry's API DOES express revocation (revoke(kid, at) — hard,
 * fail-closed), so revocations are performed directly; `revoked` is the exact
 * set performed, returned for the caller's evidence trail.
 * A kid the registry has EVER revoked is never re-pinned (a rehire gets a new
 * key; revoked key material stays dead).
 * @param {object} roster    an EP-GATE-ROSTER-v1 roster
 * @param {object} registry  createKeyRegistry() instance (add/revoke/status)
 * @param {object} [o]
 * @param {string|number} [o.revokedAt=roster.imported_at]  revocation timestamp
 * @returns {{pinned:Array<{principal:string,kid:string}>, already_pinned:string[], revoked:Array<{kid:string,revoked_at:string|number,reason:string}>, refused:Array<{principal:string,kid:string,reason:string}>}}
 */
export function applyRosterToRegistry(roster, registry, { revokedAt }: { revokedAt?: string | number } = {}) {
  assertRoster(roster, 'roster');
  // Fail closed on the registry too: never coerce a flat key array here —
  // asKeyRegistry would build a DETACHED registry and every revocation this
  // function performs would be silently lost.
  if (!registry || typeof registry.add !== 'function'
    || typeof registry.revoke !== 'function' || typeof registry.status !== 'function') {
    throw new Error('roster apply: registry must expose add/revoke/status (createKeyRegistry)');
  }
  const at = revokedAt ?? roster.imported_at;

  // Recompute kid contests here as well — a hand-built roster must not bypass
  // the import-time duplicate-kid integrity check.
  const byKid = new Map();
  for (const s of roster.signers) {
    const g = byKid.get(s.kid) || { principals: new Set(), keys: new Set() };
    g.principals.add(s.principal);
    g.keys.add(s.publicKey);
    byKid.set(s.kid, g);
  }
  const contested = new Set();
  for (const [kid, g] of byKid) {
    if (g.principals.size > 1 || g.keys.size > 1) contested.add(kid);
  }

  const activeByKid = new Map();
  for (const s of roster.signers) {
    if (s.active === true && !contested.has(s.kid)) activeByKid.set(s.kid, s);
  }

  const status = registry.status();
  const everRevoked = new Set(status.filter((e) => e.revoked).map((e) => e.kid));
  const present = new Set(status.map((e) => e.kid));

  const pinned: { principal: string; kid: string }[] = [];
  const alreadyPinned: string[] = [];
  const revoked: { kid: string; revoked_at: string | number; reason: string }[] = [];
  const refused: { principal: string; kid: string; reason: string }[] = [];

  for (const s of roster.signers) {
    if (s.active === true && contested.has(s.kid)) {
      refused.push({ principal: s.principal, kid: s.kid, reason: 'contested_kid' });
    }
  }

  for (const [kid, s] of activeByKid) {
    if (everRevoked.has(kid)) {
      refused.push({ principal: s.principal, kid, reason: 'kid_previously_revoked' });
      continue;
    }
    if (present.has(kid)) { alreadyPinned.push(kid); continue; }
    registry.add({ kid, key: s.publicKey });
    pinned.push({ principal: s.principal, kid });
  }

  // Absent-or-inactive (and contested) kids stop being acceptable NOW.
  const done = new Set();
  for (const e of status) {
    if (e.revoked || done.has(e.kid) || activeByKid.has(e.kid)) continue;
    registry.revoke(e.kid, at);
    done.add(e.kid);
    revoked.push({ kid: e.kid, revoked_at: at, reason: contested.has(e.kid) ? 'contested_kid' : 'absent_or_inactive' });
  }

  return { pinned, already_pinned: alreadyPinned, revoked, refused };
}

export default { ROSTER_VERSION, importRoster, diffRoster, applyRosterToRegistry };

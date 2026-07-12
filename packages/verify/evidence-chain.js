// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AEC-v1 — Authorization Evidence Chain (EXPERIMENTAL reference verifier).
 *
 * THE GAP THIS FILLS
 * ------------------
 * The agent-authorization-receipt space has fragmented into ~14 IETF drafts —
 * delegation receipts (draft-nelson-agent-delegation-receipts), policy-permit
 * receipts (draft-lee-orprg-permit-receipts), decision receipts
 * (draft-farley-acta-signed-receipts), compliance receipts
 * (draft-marques-asqav-compliance-receipts), route authorization
 * (draft-nivalto-agentroa-route-authorization), and others. Each defines its own
 * signed receipt about an agent action, and the mature ones all bind the action
 * with an RFC 8785 (JCS) digest + a signature.
 *
 * NONE defines how a relying party verifies that, for ONE action, the several
 * heterogeneous receipts (a) all bind the SAME canonical action and (b) each
 * verify under its own rules — producing a single, offline, fail-closed
 * ALLOW/DENY. In practice people are hand-rolling ad-hoc "composite proofs"
 * (see the 2026 arXiv literature). That composition layer is the gap.
 *
 * EP-AEC is that thin layer. It is deliberately NOT another receipt type: it
 * references existing receipts, checks they all bind one canonical action digest,
 * dispatches each to its type verifier, and evaluates a fail-closed requirement
 * expression. EP supplies the one leg none of the other efforts do — a named
 * human's (or a distinct-human quorum's) authorization — via the built-in
 * `ep-receipt` / `ep-quorum` verifiers; every other receipt type plugs in through
 * `opts.verifiers`, so DRP / Permit Receipts / ACTA compose without EP owning them.
 *
 * This turns EP from "receipt #N" into the verifier-side convergence point — the
 * executable form of the multi-effort survey matrix.
 */
import crypto from 'node:crypto';
import { canonicalize, verifyReceipt, verifyQuorum } from './index.js';

export const AEC_VERSION = 'EP-AEC-v1';

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** Canonical action digest (hex). NOTE: uses EP's canonicalize(); see the JCS
 *  conformance note in the spec — the shared substrate MUST be true RFC 8785. */
export function actionDigest(action) {
  return sha256hex(canonicalize(action));
}

/** Normalize a digest claim to bare lowercase hex (strip any "sha256:" prefix). */
function normDigest(d) {
  if (typeof d !== 'string') return null;
  return d.replace(/^sha256:/i, '').toLowerCase();
}

/**
 * Built-in component verifiers. Each takes (evidence, ctx) and returns
 * { valid: boolean, action_digest: string|null, detail?: any }.
 * `action_digest` is the digest the component ITSELF attests it authorized — the
 * chain then checks every component's attested digest equals the chain's digest.
 */
function builtinVerifiers() {
  return {
    // A distinct-human quorum (EP-QUORUM-v1) — the two-person-rule leg.
    'ep-quorum': (evidence, ctx) => {
      // Every counted approver key MUST be pinned FOR THE ep-quorum role.
      // verifyQuorum checks only INTERNAL consistency against the quorum's OWN
      // declared keys and policy — its own docstring warns callers to source the
      // policy and every approver_public_key out of band, "never from the
      // receipt/quorum document." Without pinning, an attacker forges an entire
      // distinct-human quorum under device keys it generated. Require every member
      // key to be pinned under keysByType['ep-quorum']; fail closed otherwise.
      const scoped = ctx?.keysByType?.['ep-quorum'];
      const members = Array.isArray(evidence?.members) ? evidence.members : null;
      if (!scoped || !members || members.length === 0) {
        return { valid: false, action_digest: null, detail: { reason: 'no approver key pinned for the ep-quorum role' } };
      }
      for (const m of members) {
        const k = m?.approver_public_key;
        if (typeof k !== 'string' || !scoped[k]) {
          return { valid: false, action_digest: null, detail: { reason: 'a quorum member key is not pinned for the ep-quorum role' } };
        }
      }
      // Keys are pinned humans; verifyQuorum then confirms threshold, distinct
      // humans, initiator exclusion, ordering/window, and action_binding (every
      // signoff over THIS action_hash), so the top-level digest is bound on success.
      const r = verifyQuorum(evidence) || {};
      return { valid: !!r.valid, action_digest: r.valid ? (evidence?.action_hash ?? null) : null, detail: r.checks };
    },
    // A single named-human authorization receipt (EP-RECEIPT-v1).
    'ep-receipt': (evidence, ctx) => {
      // The signing key MUST be pinned FOR THE ep-receipt ROLE. A globally pinned
      // key is not enough: a relying party that also pins its policy engine's key
      // (in a flat bag) would otherwise let that machine relabel its own signed
      // object EP-RECEIPT-v1, name its own — pinned — key, and fill the human role
      // (cross-role key confusion). Trust anchors are role-scoped: keysByType maps
      // a component type to the keys the relying party accepts FOR THAT ROLE ONLY.
      // No key pinned for ep-receipt => fail closed. (verifyReceipt still checks the
      // signature against the pinned value, so naming a key pinned for another role
      // does not help an attacker who cannot sign under it — and even a valid
      // signature under such a key is refused here because it is out of scope.)
      const named = evidence?.operator_public_key;
      const scoped = ctx?.keysByType?.['ep-receipt'];
      const pinned = scoped && typeof named === 'string' ? scoped[named] : undefined;
      if (!pinned) return { valid: false, action_digest: null, detail: { reason: 'operator key is not pinned for the ep-receipt role' } };
      let r = {};
      try { r = verifyReceipt(evidence, pinned) || {}; } catch { r = { valid: false }; }
      // The bound digest MUST come from the SIGNED payload, never an unsigned
      // sibling field. verifyReceipt covers payload bytes only; a top-level
      // action_hash is attacker-malleable and would let a receipt signed over a
      // DIFFERENT action pass as binding this one. Absent a signed digest, the
      // leg cannot bind an action and fails the chain's bound check.
      const boundDigest = evidence?.payload?.action_digest ?? evidence?.payload?.action_hash ?? null;
      return { valid: !!r.valid, action_digest: r.valid ? boundDigest : null, detail: r.checks };
    },
  };
}

/**
 * Evaluate a tiny boolean requirement expression over the SET of component
 * type/label tokens that verified. Grammar (safe, no eval):
 *   expr   := term (('AND'|'OR') term)*       // left-assoc, AND binds like OR here; use parens
 *   term   := '(' expr ')' | IDENT
 * IDENT matches a verified component `type` or `label`. Unknown token => false.
 */
function evalRequirement(expr, satisfied) {
  const toks = String(expr).match(/\(|\)|[A-Za-z0-9_.:-]+/g) || [];
  let i = 0;
  const peek = () => toks[i];
  const eat = () => toks[i++];
  function parseExpr() {
    let v = parseTerm();
    while (peek() === 'AND' || peek() === 'OR' || peek() === '&&' || peek() === '||') {
      const op = eat();
      const r = parseTerm();
      v = (op === 'AND' || op === '&&') ? (v && r) : (v || r);
    }
    return v;
  }
  function parseTerm() {
    if (peek() === '(') { eat(); const v = parseExpr(); if (peek() === ')') eat(); return v; }
    const id = eat();
    if (id === undefined) return false;
    return satisfied.has(id);
  }
  try { const v = parseExpr(); return i === toks.length ? !!v : false; }
  catch { return false; }
}

/**
 * Verify an Authorization Evidence Chain. FAIL-CLOSED: anything missing,
 * malformed, unverifiable, or binding a different action yields allow=false.
 *
 * TRUST BOUNDARY — whose requirement is it? The chain document's `requirement`
 * is PRESENTER-supplied: it is the presenter's claim of what the bundle
 * satisfies, and a presenter must never choose its own sufficiency bar. A
 * relying party SHOULD pin its own bar via `opts.requirement`, which takes
 * precedence over the document's; the result records which was used
 * (`requirement_source: 'relying_party' | 'presenter'`). Same discipline as
 * pinned quorum policies and pinned federation issuers.
 *
 * TRUST ANCHORS ARE ROLE-SCOPED. `opts.keysByType` maps a component type to the
 * keys the relying party accepts FOR THAT ROLE ONLY, e.g.
 * `{ 'ep-receipt': { [humanSpki]: humanSpki } }`. A key pinned for one role (a
 * policy engine's key) can never satisfy another (the human-authorization role):
 * that would be cross-role key confusion. There is deliberately no flat global
 * key bag for the built-in verifiers.
 *
 * @param {object} aec  { '@version', action, action_digest?, components:[{type,label?,evidence}], requirement }
 * @param {object} opts { verifiers?: {[type]:fn}, keysByType?: {[type]:{[spki]:spki}}, requirement?: string }
 * @returns {{allow:boolean, action_digest:string|null, components:Array, reasons:string[], requirement_source:string}}
 */
export function verifyAuthorizationChain(aec, opts = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const reasons = [];
  const pinned = typeof opts.requirement === 'string' && opts.requirement.trim() ? opts.requirement : null;
  const requirementSource = pinned ? 'relying_party' : 'presenter';
  const fail = (why) => { reasons.push(why); return { allow: false, action_digest: null, components: [], reasons, requirement_source: requirementSource }; };

  if (!aec || typeof aec !== 'object') return fail('chain is not an object');
  if (aec['@version'] !== AEC_VERSION) return fail(`unexpected @version (want ${AEC_VERSION})`);
  if (!aec.action || typeof aec.action !== 'object') return fail('missing action object');
  if (!Array.isArray(aec.components) || aec.components.length === 0) return fail('no components');
  const requirement = pinned ?? aec.requirement;
  if (typeof requirement !== 'string' || !requirement.trim()) return fail('missing requirement expression');

  const chainDigest = actionDigest(aec.action);
  if (aec.action_digest != null && normDigest(aec.action_digest) !== chainDigest) {
    return fail('declared action_digest does not match canonical digest of the action');
  }

  const verifiers = { ...builtinVerifiers(), ...(opts.verifiers || {}) };
  const satisfied = new Set();
  const components = aec.components.map((c, idx) => {
    const label = c.label || c.type || `#${idx}`;
    const row = { type: c.type, label, valid: false, bound: false, reason: null };
    const v = verifiers[c.type];
    if (typeof v !== 'function') { row.reason = `no verifier registered for type "${c.type}"`; return row; }
    let res;
    try { res = v(c.evidence, { keysByType: opts.keysByType, action: aec.action }) || {}; }
    catch (e) { row.reason = `verifier threw: ${e.message}`; return row; }
    row.valid = !!res.valid;
    row.bound = normDigest(res.action_digest) === chainDigest;
    if (!row.valid) row.reason = 'component evidence did not verify';
    else if (!row.bound) row.reason = 'component binds a DIFFERENT action than the chain';
    if (row.valid && row.bound) {
      satisfied.add(c.type);
      // A presenter-controlled label MAY name a distinct leg of the same type
      // (e.g. 'cfo' vs 'ceo' among two ep-receipt legs), but it must NEVER
      // satisfy a requirement token that names a registered verifier TYPE.
      // Otherwise a policy_decision leg labeled 'ep-receipt' would fill the
      // human-authorization role by string alone. A label colliding with a type
      // is ignored for satisfaction (the leg still counts under its own type).
      if (c.label && !(c.label in verifiers)) satisfied.add(c.label);
    }
    return row;
  });

  const allow = evalRequirement(requirement, satisfied);
  if (!allow) reasons.push(`requirement not satisfied: "${requirement}" over {${[...satisfied].join(', ') || '∅'}}`);
  if (pinned && typeof aec.requirement === 'string' && aec.requirement.trim() && aec.requirement !== pinned) {
    reasons.push(`presenter requirement ignored in favor of relying-party requirement (presenter claimed: "${aec.requirement}")`);
  }
  return { allow, action_digest: chainDigest, components, reasons, requirement_source: requirementSource };
}

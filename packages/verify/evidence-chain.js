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
    'ep-quorum': (evidence) => {
      const r = verifyQuorum(evidence) || {};
      return { valid: !!r.valid, action_digest: evidence?.action_hash ?? null, detail: r.checks };
    },
    // A single named-human authorization receipt (EP-RECEIPT-v1).
    'ep-receipt': (evidence, ctx) => {
      const key = ctx?.keys?.[evidence?.operator_public_key] ?? evidence?.operator_public_key;
      let r = {};
      try { r = verifyReceipt(evidence, key) || {}; } catch { r = { valid: false }; }
      return { valid: !!r.valid, action_digest: evidence?.action_hash ?? null, detail: r.checks };
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
 * @param {object} aec  { '@version', action, action_digest?, components:[{type,label?,evidence}], requirement }
 * @param {object} opts { verifiers?: {[type]:fn}, keys?: {[spki]:spki}, requirement?: string }
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
    try { res = v(c.evidence, { keys: opts.keys, action: aec.action }) || {}; }
    catch (e) { row.reason = `verifier threw: ${e.message}`; return row; }
    row.valid = !!res.valid;
    row.bound = normDigest(res.action_digest) === chainDigest;
    if (!row.valid) row.reason = 'component evidence did not verify';
    else if (!row.bound) row.reason = 'component binds a DIFFERENT action than the chain';
    if (row.valid && row.bound) { satisfied.add(c.type); if (c.label) satisfied.add(c.label); }
    return row;
  });

  const allow = evalRequirement(requirement, satisfied);
  if (!allow) reasons.push(`requirement not satisfied: "${requirement}" over {${[...satisfied].join(', ') || '∅'}}`);
  if (pinned && typeof aec.requirement === 'string' && aec.requirement.trim() && aec.requirement !== pinned) {
    reasons.push(`presenter requirement ignored in favor of relying-party requirement (presenter claimed: "${aec.requirement}")`);
  }
  return { allow, action_digest: chainDigest, components, reasons, requirement_source: requirementSource };
}

// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/mcp-guard — EP-MCP MIDDLEWARE (reference implementation).
 *
 * Wraps an MCP server's tool-call handler so that *irreversible* tool calls are
 * forced through accountability before they execute, while everything else passes
 * straight through untouched.
 *
 *   reversible / read-only tool  → pass through (no overhead)
 *   irreversible tool, no proof  → 402-style refusal (the demand hook)
 *   irreversible tool, gated     → consent → Class-A signoff → EP-RECEIPT-v1
 *                                  emitted + a provenance entry appended → run
 *
 * Framework-agnostic: it wraps the function the MCP server already calls to
 * dispatch a tool (e.g. `handleTool(name, args)` behind CallToolRequestSchema).
 * Nothing here is MCP-transport-specific; it works with any tool-dispatch shape.
 *
 * Honesty / status:
 *   - This is a REFERENCE IMPLEMENTATION, experimental. It exercises the control
 *     flow, the 402 demand hook, the EP-RECEIPT-v1 emission shape, and the
 *     provenance ledger purely in-process with pluggable adapters.
 *   - The EP CORE is FROZEN. This package NEVER mints, mutates, re-canonicalizes,
 *     or re-signs an EP-RECEIPT-v1. Receipt issuance and consent/signoff are
 *     delegated to caller-supplied adapters (an EP host, @emilia-protocol/issue,
 *     a WebAuthn authenticator, etc.). The "provenance entry" is an ADDITIVE
 *     composite that BUNDLES references to existing v1 receipts — it is not a new
 *     wire format for receipts and changes nothing about Core.
 *   - To exercise end-to-end against a LIVE signer you must supply real adapters
 *     (`issueReceipt`, `requestConsent`, `requestClassASignoff`); see README
 *     "What needs a live MCP host / signer to exercise".
 *
 * Agent identity is carried as a CLAIM (scoped, attestable) — this package does
 * not assert EP proves strong agent identity. Liability attestation names an
 * accountable owner; it is evidence, not a legal determination.
 *
 * Verification reuses @emilia-protocol/require-receipt — NO new trust
 * assumptions. The demand hook fails CLOSED.
 */

import crypto from 'node:crypto';
import { verifyEmiliaReceipt, receiptChallenge } from '@emilia-protocol/require-receipt';

// ---------------------------------------------------------------------------
// Canonicalization (RFC 8785-style, key-sorted) — used ONLY for the additive
// provenance bundle and for hashing tool-call inputs. It is byte-identical to
// the canonicalize() in @emilia-protocol/issue and /require-receipt. It is NEVER
// applied to an EP-RECEIPT-v1 payload here; Core canonicalization is untouched.
// ---------------------------------------------------------------------------

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(v[k]))
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** "sha256:<hex>" over canonical JSON — the project-wide hash format. */
export function hashObject(obj) {
  return `sha256:${sha256Hex(canonicalize(obj))}`;
}

// ---------------------------------------------------------------------------
// Decision vocabulary — mirrors lib/guard-policies.js exactly.
// ---------------------------------------------------------------------------

export const GUARD_DECISIONS = Object.freeze({
  ALLOW: 'allow',
  ALLOW_WITH_SIGNOFF: 'allow_with_signoff',
  DENY: 'deny',
});

// ---------------------------------------------------------------------------
// Irreversibility classification
// ---------------------------------------------------------------------------

/**
 * Decide whether a tool call is irreversible and therefore must be gated.
 *
 * Resolution order (first hit wins):
 *   1. Per-call override:        args.__ep?.irreversible === true|false
 *   2. Tool annotation:          annotations[name].irreversible (or the MCP
 *      `readOnlyHint`/`destructiveHint` tool annotations, if provided)
 *   3. Policy function:          policy(name, args) → boolean
 *   4. Default:                  treated as reversible (fail-open ONLY for the
 *      *classification*; the demand hook itself always fails closed once a call
 *      IS classified irreversible). Set `defaultIrreversible: true` to invert.
 *
 * @param {string} name  tool name
 * @param {object} args  tool arguments
 * @param {object} opts  { annotations, policy, defaultIrreversible }
 * @returns {{ irreversible: boolean, reason: string }}
 */
export function classifyToolCall(name, args = {}, opts = {}) {
  const { annotations = {}, policy, defaultIrreversible = false } = opts;

  const override = args && args.__ep ? args.__ep.irreversible : undefined;
  if (override === true) return { irreversible: true, reason: 'per_call_override' };
  if (override === false) return { irreversible: false, reason: 'per_call_override' };

  const ann = annotations[name];
  if (ann) {
    if (ann.irreversible === true) return { irreversible: true, reason: 'annotation' };
    if (ann.irreversible === false) return { irreversible: false, reason: 'annotation' };
    // Honor standard MCP tool annotations when present.
    if (ann.destructiveHint === true) return { irreversible: true, reason: 'destructiveHint' };
    if (ann.readOnlyHint === true) return { irreversible: false, reason: 'readOnlyHint' };
  }

  if (typeof policy === 'function') {
    try {
      const p = policy(name, args);
      if (p === true) return { irreversible: true, reason: 'policy_fn' };
      if (p === false) return { irreversible: false, reason: 'policy_fn' };
    } catch {
      // A throwing classifier is treated as "irreversible" — fail safe.
      return { irreversible: true, reason: 'policy_fn_threw' };
    }
  }

  return { irreversible: !!defaultIrreversible, reason: 'default' };
}

// ---------------------------------------------------------------------------
// The demand hook — "no irreversible tool call without a valid receipt".
// Reuses @emilia-protocol/require-receipt for offline verification. NO new
// trust. Returns a clear 402-style refusal OBJECT (not an HTTP response) so it
// works inside any MCP tool-dispatch path. FAILS CLOSED.
// ---------------------------------------------------------------------------

/**
 * Pull a candidate EP-RECEIPT-v1 document off a tool call, mirroring how
 * require-receipt reads HTTP. We look, in order, at:
 *   args.__ep.receipt           (the receipt object inline)
 *   args.__ep.receipt_b64       (base64(JSON))
 *   args.emilia_receipt         (object, body-style)
 *   meta['x-emilia-receipt']    (base64(JSON), header-style; MCP _meta passthrough)
 */
function extractReceipt(args = {}, meta = {}) {
  const ep = args.__ep || {};
  if (ep.receipt && typeof ep.receipt === 'object') return ep.receipt;
  if (typeof ep.receipt_b64 === 'string') {
    try {
      return JSON.parse(Buffer.from(ep.receipt_b64, 'base64').toString('utf8'));
    } catch {
      /* fallthrough */
    }
  }
  if (args.emilia_receipt && typeof args.emilia_receipt === 'object') return args.emilia_receipt;
  const hdr = meta && (meta['x-emilia-receipt'] || meta['X-EMILIA-Receipt']);
  if (typeof hdr === 'string') {
    try {
      return JSON.parse(Buffer.from(hdr, 'base64').toString('utf8'));
    } catch {
      /* fallthrough */
    }
  }
  return null;
}

/**
 * Build the 402-style refusal object an MCP tool can return verbatim. Same
 * problem-details shape as require-receipt's HTTP 402 challenge, framed for a
 * tool result so a well-behaved agent knows exactly what to bring and retry.
 */
export function refusal(action, reason, extra = {}) {
  const challenge = receiptChallenge(action, reason);
  return {
    ep_refused: true,
    status: 402,
    code: 'emilia_receipt_required',
    ...challenge,
    // Tool-call-flavored guidance (require-receipt's `how` is HTTP-flavored).
    required: {
      ...challenge.required,
      how:
        'Gate this action first (ep_guard_action / the trust gate), obtain an ' +
        'EP-RECEIPT-v1, then retry this tool with __ep.receipt set.',
      retry_with: '__ep.receipt = <EP-RECEIPT-v1 JSON>  (or __ep.receipt_b64 = base64(JSON))',
    },
    ...extra,
  };
}

/**
 * Enforce "no irreversible tool call without a valid receipt".
 *
 * Verifies the presented receipt OFFLINE via require-receipt (pinned issuer
 * keys, freshness, action binding, allowed outcomes). Returns either
 * `{ ok: true, verified }` or `{ ok: false, refusal }` — the refusal is the
 * 402-style object. FAILS CLOSED: anything missing/invalid → refusal.
 *
 * @param {object} p
 * @param {string} p.action            canonical action bound into the receipt
 * @param {object} p.args              tool arguments (carrier for the receipt)
 * @param {object} [p.meta]            MCP _meta (header-style carrier)
 * @param {object} p.verifyOpts        require-receipt options { trustedKeys, maxAgeSec, allowedOutcomes, ... }
 * @returns {{ok:true, verified:object} | {ok:false, refusal:object}}
 */
export function demandReceipt({ action, args = {}, meta = {}, verifyOpts = {} }) {
  const doc = extractReceipt(args, meta);
  if (!doc) {
    return { ok: false, refusal: refusal(action, 'No EMILIA receipt presented.') };
  }
  const v = verifyEmiliaReceipt(doc, { ...verifyOpts, action });
  if (!v.ok) {
    return {
      ok: false,
      refusal: refusal(action, `Receipt rejected: ${v.reason}.`, { rejected: v }),
    };
  }
  return { ok: true, verified: v };
}

// ---------------------------------------------------------------------------
// Provenance ledger — an ADDITIVE, append-only record that BUNDLES references
// to existing EP-RECEIPT-v1 receipts (by receipt_id + content hash). It is NOT
// a receipt, NOT a new wire format for Core, and adds NO trust: each entry only
// points at a v1 receipt that was independently verified. Re-verifying the
// ledger = re-verifying each linked v1 receipt + checking the append-only hash
// chain. This is the in-process anchor for the EP-PROVENANCE-CHAIN-v1 composite
// proposed by PIP (spec proposal), kept deliberately minimal here.
// ---------------------------------------------------------------------------

export class ProvenanceLedger {
  constructor() {
    /** @type {Array<object>} */
    this.entries = [];
  }

  /** sha256: of the previous entry, "" for genesis. */
  get headHash() {
    if (this.entries.length === 0) return '';
    return this.entries[this.entries.length - 1].entry_hash;
  }

  /**
   * Append an entry that REFERENCES a v1 receipt for an executed irreversible
   * tool call. Stores only references + the verified summary, never a re-signed
   * receipt.
   * @returns {object} the appended entry (with its own entry_hash)
   */
  append({ tool, action, actionDigest, receiptRef, verified, agentClaim, liability, at }) {
    const prev = this.headHash;
    const body = {
      '@version': 'EP-PROVENANCE-ENTRY-v1', // additive composite, governed by PIP
      sequence: this.entries.length,
      at: at || new Date().toISOString(),
      tool,
      action,
      action_digest: actionDigest, // hash of the tool call inputs
      // Reference to the existing v1 receipt — NOT a copy of its signed bytes.
      receipt_ref: receiptRef, // { receipt_id, receipt_hash }
      // Summary of the OFFLINE verification that already passed (no new trust).
      verified: verified
        ? { outcome: verified.outcome, subject: verified.subject, signer: verified.signer }
        : null,
      // Agent identity is a scoped CLAIM, not a proof of strong identity.
      agent_claim: agentClaim || null,
      // Liability attestation: a named accountable owner. Evidence, not a ruling.
      liability: liability || null,
      prev_entry_hash: prev || null,
    };
    const entry = { ...body, entry_hash: hashObject(body) };
    this.entries.push(entry);
    return entry;
  }

  /**
   * Re-verify the append-only chain offline. Does NOT re-verify the underlying
   * v1 receipts (that is the verifier's job via require-receipt); it only proves
   * the ledger is internally consistent and untampered. Returns the first
   * break, fail-closed.
   */
  verifyChain() {
    let prev = '';
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      const { entry_hash, ...body } = e;
      if (e.sequence !== i) return { ok: false, reason: 'sequence_gap', index: i };
      if ((body.prev_entry_hash || '') !== (prev || '')) {
        return { ok: false, reason: 'broken_link', index: i };
      }
      if (hashObject(body) !== entry_hash) return { ok: false, reason: 'tampered_entry', index: i };
      prev = entry_hash;
    }
    return { ok: true, length: this.entries.length };
  }
}

// ---------------------------------------------------------------------------
// The middleware — wrap a single MCP tool-call dispatcher.
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} McpGuardOptions
 * @property {(name:string, args:object)=>boolean} [policy]
 *   Returns true if a tool is irreversible. Used when no annotation/override.
 * @property {Object.<string, {irreversible?:boolean, action?:string|((args)=>string),
 *   readOnlyHint?:boolean, destructiveHint?:boolean}>} [annotations]
 *   Per-tool flags. `action` is the canonical action bound into the receipt.
 * @property {boolean} [defaultIrreversible=false]
 *   How to classify a tool with no annotation/policy answer.
 * @property {(name:string, args:object)=>string} [action]
 *   Global fallback to derive the canonical action when an annotation has none.
 * @property {object} [verifyOpts]
 *   Passed to require-receipt: { trustedKeys, maxAgeSec, allowedOutcomes, allowInlineKey }.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, by?:string}>} [requestConsent]
 *   ADAPTER. Obtain end-user/operator consent for an irreversible action.
 *   No-op default REFUSES (fail closed) unless requireSignoff is false.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, signoff?:object, approver?:string}>} [requestClassASignoff]
 *   ADAPTER. Obtain a Class-A (WebAuthn/hardware) human signoff. Needs a live
 *   authenticator. No-op default REFUSES (fail closed).
 * @property {(ctx:object)=>Promise<{receipt:object, receipt_id?:string}>} [issueReceipt]
 *   ADAPTER. Emit an EP-RECEIPT-v1 for the approved action. Delegated to an EP
 *   host or @emilia-protocol/issue. This package never signs a receipt itself.
 * @property {ProvenanceLedger} [ledger]  shared ledger; one is created if absent.
 * @property {boolean} [enforceDemand=true]
 *   If true, an irreversible call that arrives WITH a receipt is verified by the
 *   demand hook and runs without re-gating (the agent already did the loop).
 *   If it arrives WITHOUT a receipt, it is routed through consent→signoff→issue.
 * @property {(name:string)=>object|undefined} [getAnnotations]
 *   Optional resolver if annotations live elsewhere (e.g. the MCP tool registry).
 */

/**
 * Wrap an MCP tool-call handler with EP accountability.
 *
 * @param {(name:string, args:object, extra?:object)=>Promise<any>} handler
 *   The MCP server's existing tool dispatcher. `extra` may carry MCP `_meta`.
 * @param {McpGuardOptions} options
 * @returns {(name:string, args:object, extra?:object)=>Promise<any>} guarded dispatcher
 */
export function withMcpGuard(handler, options = {}) {
  if (typeof handler !== 'function') {
    throw new TypeError('withMcpGuard: first argument must be the tool-call handler');
  }
  const {
    policy,
    annotations = {},
    getAnnotations,
    defaultIrreversible = false,
    action: globalAction,
    verifyOpts = {},
    requestConsent,
    requestClassASignoff,
    issueReceipt,
    enforceDemand = true,
  } = options;
  const ledger = options.ledger instanceof ProvenanceLedger ? options.ledger : new ProvenanceLedger();

  const resolveAnnotations = (name) => {
    const fromResolver = typeof getAnnotations === 'function' ? getAnnotations(name) : undefined;
    return { ...(annotations[name] || {}), ...(fromResolver || {}) };
  };

  const resolveAction = (name, args, ann) => {
    let a = ann && ann.action;
    if (typeof a === 'function') a = a(args);
    if (!a && typeof globalAction === 'function') a = globalAction(name, args);
    return a || name; // fall back to the tool name as the action label
  };

  const guarded = async function guardedDispatch(name, args = {}, extra = {}) {
    const ann = resolveAnnotations(name);
    const { irreversible } = classifyToolCall(name, args, {
      annotations: { [name]: ann },
      policy,
      defaultIrreversible,
    });

    // Reversible / read-only → pass straight through. Zero added trust surface.
    if (!irreversible) return handler(name, args, extra);

    const action = resolveAction(name, args, ann);
    const meta = (extra && (extra._meta || extra.meta)) || {};
    const actionDigest = hashObject({ tool: name, action, args: stripEpFields(args) });

    // ---- Path A: a receipt was presented → demand hook verifies it offline.
    if (enforceDemand) {
      const carriesReceipt = !!extractReceipt(args, meta);
      if (carriesReceipt) {
        const d = demandReceipt({ action, args, meta, verifyOpts });
        if (!d.ok) return d.refusal; // FAIL CLOSED — 402-style object, do not run.
        // Verified. Record provenance referencing the (already v1) receipt, run.
        const doc = extractReceipt(args, meta);
        ledger.append({
          tool: name,
          action,
          actionDigest,
          receiptRef: { receipt_id: d.verified.receipt_id, receipt_hash: receiptHashOf(doc) },
          verified: d.verified,
          agentClaim: ann.agent_claim || (args.__ep && args.__ep.agent_claim) || null,
          liability: ann.liability || (args.__ep && args.__ep.liability) || null,
        });
        return handler(name, stripEpFields(args), extra);
      }
    }

    // ---- Path B: no receipt → consent → Class-A signoff → issue → run.
    const ctx = {
      tool: name,
      action,
      action_digest: actionDigest,
      args: stripEpFields(args),
      meta,
      agent_claim: ann.agent_claim || (args.__ep && args.__ep.agent_claim) || null,
      liability: ann.liability || (args.__ep && args.__ep.liability) || null,
    };

    // 1) Consent.
    const consent = await callAdapter(requestConsent, ctx, {
      approved: false,
      reason: 'no_consent_adapter',
    });
    if (!consent.approved) {
      return refusal(action, `Consent not granted: ${consent.reason || 'denied'}.`, {
        stage: 'consent',
      });
    }

    // 2) Class-A signoff (named human, hardware-backed).
    const signoff = await callAdapter(requestClassASignoff, ctx, {
      approved: false,
      reason: 'no_signoff_adapter',
    });
    if (!signoff.approved) {
      return refusal(action, `Class-A signoff not obtained: ${signoff.reason || 'denied'}.`, {
        stage: 'signoff',
      });
    }

    // 3) Issue EP-RECEIPT-v1 (delegated; this package never signs).
    if (typeof issueReceipt !== 'function') {
      return refusal(action, 'No receipt issuer configured; cannot mint EP-RECEIPT-v1.', {
        stage: 'issue',
      });
    }
    const issued = await issueReceipt({ ...ctx, consent, signoff });
    const doc = issued && issued.receipt;
    if (!doc) {
      return refusal(action, 'Receipt issuer returned no EP-RECEIPT-v1.', { stage: 'issue' });
    }

    // 4) Verify what we just issued, offline, via the SAME demand hook. No new
    //    trust: even our own issuer must produce a receipt that verifies. Fail
    //    closed if it doesn't (e.g. issuer misconfigured, wrong action binding).
    const selfCheck = verifyEmiliaReceipt(doc, { ...verifyOpts, action });
    if (!selfCheck.ok) {
      return refusal(action, `Issued receipt failed self-verification: ${selfCheck.reason}.`, {
        stage: 'issue',
        rejected: selfCheck,
      });
    }

    // 5) Append provenance referencing the issued v1 receipt, then run.
    ledger.append({
      tool: name,
      action,
      actionDigest,
      receiptRef: {
        receipt_id: issued.receipt_id || selfCheck.receipt_id,
        receipt_hash: receiptHashOf(doc),
      },
      verified: selfCheck,
      agentClaim: ctx.agent_claim,
      liability: ctx.liability,
    });

    return handler(name, ctx.args, extra);
  };

  // Expose the ledger so the host can persist / re-verify it.
  guarded.ledger = ledger;
  return guarded;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Remove EP control fields so the underlying tool sees clean args. */
function stripEpFields(args = {}) {
  if (!args || typeof args !== 'object') return args;
  const { __ep, emilia_receipt, ...rest } = args;
  return rest;
}

/** Content hash of a receipt DOCUMENT for the provenance reference (not a re-sign). */
function receiptHashOf(doc) {
  try {
    return hashObject(doc);
  } catch {
    return null;
  }
}

async function callAdapter(fn, ctx, fallback) {
  if (typeof fn !== 'function') return fallback;
  try {
    const r = await fn(ctx);
    return r && typeof r === 'object' ? r : fallback;
  } catch (e) {
    return { approved: false, reason: `adapter_error: ${e.message}` };
  }
}

export default {
  withMcpGuard,
  demandReceipt,
  refusal,
  classifyToolCall,
  ProvenanceLedger,
  hashObject,
  GUARD_DECISIONS,
};

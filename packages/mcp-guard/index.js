// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/mcp-guard — EP-MCP MIDDLEWARE (reference implementation).
 *
 * Wraps an MCP server's tool-call handler so that *irreversible* tool calls are
 * forced through accountability before they execute, while everything else passes
 * straight through untouched.
 *
 *   reversible / read-only tool  → pass through (no overhead)
 *   irreversible tool, no proof  → legacy refusal object (the demand hook)
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
const {
  verifyEmiliaReceipt,
  receiptChallenge,
  evaluateReceiptAssurance,
  makeReceiptGate,
  parseReceiptCarrier,
} = await import('@emilia-protocol/require-receipt').catch(() => import('../require-receipt/index.js'));

// ---------------------------------------------------------------------------
// Canonicalization (RFC 8785-style, key-sorted) — used ONLY for the additive
// provenance bundle and for hashing tool-call inputs. It is byte-identical to
// the canonicalize() in @emilia-protocol/issue and /require-receipt. It is NEVER
// applied to an EP-RECEIPT-v1 payload here; Core canonicalization is untouched.
// ---------------------------------------------------------------------------

function canonicalize(v, seen = new Set()) {
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new TypeError('value_outside_ep_canonical_profile');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    if (seen.has(v)) throw new TypeError('cyclic_value');
    seen.add(v);
    try {
      return `[${v.map((entry) => canonicalize(entry, seen)).join(',')}]`;
    } finally {
      seen.delete(v);
    }
  }
  if (typeof v === 'object') {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('non_json_object');
    if (seen.has(v)) throw new TypeError('cyclic_value');
    seen.add(v);
    try {
      return `{${Object.keys(v)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canonicalize(v[k], seen))
        .join(',')}}`;
    } finally {
      seen.delete(v);
    }
  }
  throw new TypeError('value_outside_ep_canonical_profile');
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** "sha256:<hex>" over canonical JSON — the project-wide hash format. */
export function hashObject(obj) {
  return `sha256:${sha256Hex(canonicalize(obj))}`;
}

/**
 * Bind an MCP tool call to the exact material argument object. A receipt for
 * `payment.release` with one amount or destination cannot authorize another.
 * Control carriers under `__ep` / `emilia_receipt` are deliberately excluded;
 * they transport the proof and are not tool inputs.
 */
export function bindToolAction(name, args = {}, baseAction = name) {
  if (typeof name !== 'string' || !name || typeof baseAction !== 'string' || !baseAction) {
    throw new TypeError('action_binding_invalid');
  }
  const digest = hashObject({ tool: name, args: stripEpFields(args) });
  return `${baseAction}:${digest}`;
}

// ---------------------------------------------------------------------------
// Decision vocabulary — mirrors lib/guard-policies.js exactly.
// ---------------------------------------------------------------------------

export const GUARD_DECISIONS = Object.freeze({
  ALLOW: 'allow',
  ALLOW_WITH_SIGNOFF: 'allow_with_signoff',
  DENY: 'deny',
});

function inMemoryConsumptionStore() {
  const states = new Map();
  return {
    ownershipFenced: true,
    async reserve(id) {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id) {
      if (states.get(id) !== 'reserved') throw new Error('reservation_not_owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id) {
      if (states.get(id) !== 'reserved') throw new Error('reservation_not_owned');
      states.delete(id);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// Irreversibility classification
// ---------------------------------------------------------------------------

/**
 * Decide whether a tool call is irreversible and therefore must be gated.
 *
 * Resolution order:
 *   1. Per-call escalation:      args.__ep?.irreversible === true
 *      (agent/tool-call metadata may only make a call stricter, never downgrade
 *      trusted server annotations or policy)
 *   2. Trusted tool annotation:  annotations[name].irreversible
 *      (MCP destructiveHint can escalate; readOnlyHint is advisory by default)
 *   3. Policy function:          policy(name, args) → boolean
 *   4. Default:                  treated as irreversible. New or misspelled
 *      tools cannot silently bypass the guard; explicitly mark trusted read-only
 *      tools with `irreversible: false` or set `defaultIrreversible: false` only
 *      when a complete external classifier is guaranteed.
 *
 * @param {string} name  tool name
 * @param {object} args  tool arguments
 * @param {object} opts  { annotations, policy, defaultIrreversible }
 * @returns {{ irreversible: boolean, reason: string }}
 */
export function classifyToolCall(name, args = {}, opts = {}) {
  const { annotations = {}, policy, defaultIrreversible = true, trustReadOnlyHints = false } = opts;

  const override = args && args.__ep ? args.__ep.irreversible : undefined;
  if (override === true) return { irreversible: true, reason: 'per_call_override' };

  const ann = annotations[name];
  if (ann) {
    if (ann.irreversible === true) return { irreversible: true, reason: 'annotation' };
    if (ann.irreversible === false) return { irreversible: false, reason: 'annotation' };
    // Destructive hints can only escalate. Read-only hints are advisory and do
    // not downgrade the default unless the host explicitly opts in.
    if (ann.destructiveHint === true) return { irreversible: true, reason: 'destructiveHint' };
    if (ann.readOnlyHint === true && trustReadOnlyHints === true) {
      return { irreversible: false, reason: 'trusted_readOnlyHint' };
    }
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
// trust. Returns a clear legacy refusal OBJECT (not an HTTP response) so it
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
    const parsed = parseBase64Receipt(ep.receipt_b64);
    if (parsed) return parsed;
  }
  if (args.emilia_receipt && typeof args.emilia_receipt === 'object') return args.emilia_receipt;
  const hdr = meta && (meta['x-emilia-receipt'] || meta['X-EMILIA-Receipt']);
  if (typeof hdr === 'string') {
    const parsed = parseBase64Receipt(hdr);
    if (parsed) return parsed;
  }
  return null;
}

function parseBase64Receipt(value) {
  return parseReceiptCarrier(value);
}

/**
 * Build the legacy refusal object an MCP tool can return verbatim. Same
 * problem-details shape as require-receipt's challenge, framed for a
 * tool result so a well-behaved agent knows exactly what to bring and retry.
 */
export function refusal(action, reason, extra = {}) {
  const challenge = receiptChallenge(action, reason);
  return {
    ep_refused: true,
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
 * Verify "no irreversible tool call without a valid receipt".
 *
 * Verifies the presented receipt OFFLINE via require-receipt (pinned issuer
 * keys, freshness, action binding, allowed outcomes). Returns either
 * `{ ok: true, verified }` or `{ ok: false, refusal }` — the refusal is the
 * legacy MCP object. FAILS CLOSED: anything missing/invalid → refusal.
 * This low-level function does not consume the receipt; middleware that can
 * execute an effect MUST use `withMcpGuard`, which composes verification with
 * atomic reserve/commit semantics.
 *
 * @param {object} p
 * @param {string} p.action            canonical action bound into the receipt
 * @param {object} p.args              tool arguments (carrier for the receipt)
 * @param {object} [p.meta]            MCP _meta (header-style carrier)
 * @param {object} p.verifyOpts        require-receipt options including pinned
 *   issuer keys and, for Class-A/quorum, rpId, allowedOrigins, quorumPolicy,
 *   and the relying party's approver keys.
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
  const requiredTier = verifyOpts.assuranceClass || verifyOpts.assurance_class || 'software';
  const assurance = evaluateReceiptAssurance(doc, requiredTier, verifyOpts);
  if (!assurance.ok) {
    return {
      ok: false,
      refusal: refusal(action, `Receipt rejected: ${assurance.reason}.`, {
        rejected: { ok: false, reason: assurance.reason, have_tier: assurance.have, need_tier: assurance.need },
      }),
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
   * @param {{tool:string, action:string, actionDigest:string,
   *   receiptRef:{receipt_id?:string, receipt_hash?:string},
   *   verified?:{outcome?:string, subject?:any, signer?:any}|null,
   *   agentClaim?:any, liability?:any, at?:string}} entry
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
 * @property {Object.<string, {irreversible?:boolean, action?:string|((args,extra)=>string),
 *   readOnlyHint?:boolean, destructiveHint?:boolean, assuranceClass?:string,
 *   assurance_class?:string, agent_claim?:any, liability?:any,
 *   onSignoffRequired?:any}>} [annotations]
 *   Per-tool flags. `action` is the canonical action bound into the receipt.
 *   `assuranceClass`/`assurance_class` set the required receipt tier;
 *   `agent_claim`/`liability` seed the provenance-ledger entry.
 * @property {boolean} [defaultIrreversible=true]
 *   How to classify a tool with no annotation/policy answer.
 * @property {boolean} [trustReadOnlyHints=false]
 *   Opt-in downgrade for MCP readOnlyHint. False by default because hints are
 *   presenter-authored metadata, not enforcement policy.
 * @property {(name:string, args:object, extra:object)=>string} [action]
 *   Global fallback to choose the action family when an annotation has none.
 *   The guard always appends an exact digest of the material tool arguments.
 * @property {object} [verifyOpts]
 *   Offline verifier policy. Class-A requires pinned rpId + allowedOrigins;
 *   quorum requires a relying-party-pinned quorumPolicy and approver keys.
 *   Passed to require-receipt: { trustedKeys, maxAgeSec, allowedOutcomes, allowInlineKey }.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, by?:string}>} [requestConsent]
 *   ADAPTER. Obtain end-user/operator consent for an irreversible action.
 *   No-op default REFUSES (fail closed) unless requireSignoff is false.
 * @property {(ctx:object)=>Promise<{approved:boolean, reason?:string, signoff?:object, approver?:string}>} [requestClassASignoff]
 *   ADAPTER. Obtain a Class-A (WebAuthn/hardware) human signoff. Needs a live
 *   authenticator. No-op default REFUSES (fail closed).
 * @property {(ctx:object)=>Promise<{receipt:object, receipt_id?:string}>} [issueReceipt]
 *   ADAPTER. Emit an EP-RECEIPT-v1 for the approved action. Delegated to an EP
 *   host or `@emilia-protocol/issue`. This package never signs a receipt itself.
 * @property {ProvenanceLedger} [ledger]  shared ledger; one is created if absent.
 * @property {boolean} [enforceDemand=true]
 *   If true, an irreversible call that arrives WITH a receipt is verified by the
 *   demand hook and runs without re-gating (the agent already did the loop).
 *   If it arrives WITHOUT a receipt, it is routed through consent→signoff→issue.
 * @property {{reserve:Function, commit:Function, release:Function}} [store]
 *   Ownership-fenced one-time consumption store. The process-local default is
 *   for demos only; fleets provide one shared durable store.
 * @property {(name:string)=>object|undefined} [getAnnotations]
 *   Optional resolver for untrusted MCP metadata. Only destructiveHint may
 *   escalate by default; it cannot override local action/policy annotations.
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
    defaultIrreversible = true,
    trustReadOnlyHints = false,
    action: globalAction,
    verifyOpts = {},
    requestConsent,
    requestClassASignoff,
    issueReceipt,
    enforceDemand = true,
    store = inMemoryConsumptionStore(),
  } = options;
  const ledger = options.ledger instanceof ProvenanceLedger ? options.ledger : new ProvenanceLedger();

  const resolveAnnotations = (name) => {
    let fromResolver;
    try { fromResolver = typeof getAnnotations === 'function' ? getAnnotations(name) : undefined; }
    catch { fromResolver = { destructiveHint: true }; }
    const externalHints = fromResolver && typeof fromResolver === 'object' ? {
      ...(fromResolver.destructiveHint === true ? { destructiveHint: true } : {}),
      ...(fromResolver.readOnlyHint === true ? { readOnlyHint: true } : {}),
    } : {};
    return { ...externalHints, ...(annotations[name] || {}) };
  };

  const resolveAction = (name, args, extra, ann) => {
    let a = ann && ann.action;
    if (typeof a === 'function') a = a(args, extra);
    if (!a && typeof globalAction === 'function') a = globalAction(name, args, extra);
    return bindToolAction(name, args, a || name);
  };

  const gates = new Map();
  const gateFor = (action, requiredTier) => {
    const key = `${requiredTier}\u0000${action}`;
    if (!gates.has(key)) {
      gates.set(key, makeReceiptGate({
        ...verifyOpts,
        action,
        assuranceClass: requiredTier,
        store,
      }));
    }
    return gates.get(key);
  };

  const guarded = async function guardedDispatch(name, args = {}, extra = {}) {
    const ann = resolveAnnotations(name);
    const { irreversible } = classifyToolCall(name, args, {
      annotations: { [name]: ann },
      policy,
      defaultIrreversible,
      trustReadOnlyHints,
    });

    // Reversible / read-only → pass straight through. Zero added trust surface.
    if (!irreversible) return handler(name, args, extra);

    let action;
    try {
      action = resolveAction(name, args, extra, ann);
    } catch {
      return refusal(String(name || 'mcp.tool'), 'Tool call cannot be bound to the EP canonical JSON profile.', {
        stage: 'bind',
        rejected: { ok: false, reason: 'action_binding_invalid' },
      });
    }
    const requiredTier = ann.assuranceClass || ann.assurance_class || verifyOpts.assuranceClass || verifyOpts.assurance_class || 'class_a';
    const meta = (extra && (extra._meta || extra.meta)) || {};
    const actionDigest = hashObject({ tool: name, action, args: stripEpFields(args) });

    // ---- Path A: a receipt was presented → demand hook verifies it offline.
    if (enforceDemand) {
      const carriesReceipt = !!extractReceipt(args, meta);
      if (carriesReceipt) {
        const doc = extractReceipt(args, meta);
        const run = await gateFor(action, requiredTier).run(doc, {}, async (verified) => {
          ledger.append({
            tool: name,
            action,
            actionDigest,
            receiptRef: { receipt_id: verified.receiptId, receipt_hash: /** @type {string} */ (receiptHashOf(doc)) },
            verified: {
              outcome: verified.outcome,
              subject: verified.subject,
              signer: verified.signer,
            },
            agentClaim: ann.agent_claim || (args.__ep && args.__ep.agent_claim) || null,
            liability: ann.liability || (args.__ep && args.__ep.liability) || null,
          });
          return handler(name, stripEpFields(args), extra);
        });
        if (!run.ok) {
          const reason = run.body?.rejected?.reason || 'receipt_required';
          return refusal(action, `Receipt rejected: ${reason}.`, {
            rejected: { ok: false, reason },
          });
        }
        return run.result;
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
    if (consent.approved !== true) {
      return refusal(action, `Consent not granted: ${consent.reason || 'denied'}.`, {
        stage: 'consent',
      });
    }

    // 2) Class-A signoff (named human, hardware-backed).
    const signoff = await callAdapter(requestClassASignoff, ctx, {
      approved: false,
      reason: 'no_signoff_adapter',
    });
    if (signoff.approved !== true) {
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
    const issuedAssurance = evaluateReceiptAssurance(doc, requiredTier, verifyOpts);
    if (!issuedAssurance.ok) {
      return refusal(action, `Issued receipt failed assurance check: ${issuedAssurance.reason}.`, {
        stage: 'issue',
        rejected: {
          ok: false,
          reason: issuedAssurance.reason,
          have_tier: issuedAssurance.have,
          need_tier: issuedAssurance.need,
        },
      });
    }

    // 5) Atomically reserve the issued receipt, append provenance, invoke the
    // effect, and commit after any invocation attempt. The newly issued receipt
    // cannot later be replayed through Path A.
    const run = await gateFor(action, requiredTier).run(doc, {}, async (verified) => {
      ledger.append({
        tool: name,
        action,
        actionDigest,
        receiptRef: {
          receipt_id: issued.receipt_id || verified.receiptId,
          receipt_hash: /** @type {string} */ (receiptHashOf(doc)),
        },
        verified: {
          outcome: verified.outcome,
          subject: verified.subject,
          signer: verified.signer,
        },
        agentClaim: ctx.agent_claim,
        liability: ctx.liability,
      });
      return handler(name, ctx.args, extra);
    });
    if (!run.ok) {
      const reason = run.body?.rejected?.reason || 'receipt_required';
      return refusal(action, `Issued receipt could not be consumed: ${reason}.`, {
        stage: 'consume',
        rejected: { ok: false, reason },
      });
    }
    return run.result;
  };

  // Expose the ledger so the host can persist / re-verify it.
  guarded.ledger = ledger;
  return guarded;
}

/**
 * Wrap an MCP dispatcher with the live v1 enforcement loop from
 * @emilia-protocol/sdk's `client.requireReceipt()`.
 *
 * This is the tiny adoption path for tool authors who want the system-of-record
 * guarantee, not just a demand-side 402 proof check: irreversible calls are
 * classified here, but the SDK performs create → signoff → consume → mutate →
 * execution-attest. If consume fails, the handler is never called.
 *
 * Required option:
 *   client: an object with `requireReceipt(params, mutate)` (EPClient).
 *
 * Per-tool annotations may include:
 *   actionType, targetResourceId, afterState, beforeState, amount, currency,
 *   riskFlags, approverId, executingSystem, onSignoffRequired, executionId.
 * Values may be constants or functions of (args, extra).
 */
export function withMcpReceiptGuard(handler, options = {}) {
  if (typeof handler !== 'function') {
    throw new TypeError('withMcpReceiptGuard: first argument must be the tool-call handler');
  }
  const client = options.client;
  if (!client || typeof client.requireReceipt !== 'function') {
    throw new TypeError('withMcpReceiptGuard: options.client must expose requireReceipt(params, mutate)');
  }

  const {
    policy,
    annotations = {},
    getAnnotations,
    defaultIrreversible = true,
    trustReadOnlyHints = false,
    executingSystem = 'mcp-server',
    receiptParams,
    returnEnvelope = false,
  } = options;

  const resolveAnnotations = (name) => {
    let fromResolver;
    try { fromResolver = typeof getAnnotations === 'function' ? getAnnotations(name) : undefined; }
    catch { fromResolver = { destructiveHint: true }; }
    const externalHints = fromResolver && typeof fromResolver === 'object' ? {
      ...(fromResolver.destructiveHint === true ? { destructiveHint: true } : {}),
      ...(fromResolver.readOnlyHint === true ? { readOnlyHint: true } : {}),
    } : {};
    return { ...externalHints, ...(annotations[name] || {}) };
  };

  const guarded = async function guardedReceiptDispatch(name, args = {}, extra = {}) {
    const ann = resolveAnnotations(name);
    const { irreversible } = classifyToolCall(name, args, {
      annotations: { [name]: ann },
      policy,
      defaultIrreversible,
      trustReadOnlyHints,
    });

    if (!irreversible) return handler(name, args, extra);

    const cleanArgs = stripEpFields(args);
    const rawBase = typeof receiptParams === 'function'
      ? await receiptParams({ name, args: cleanArgs, extra, annotation: ann })
      : (receiptParams || {});
    const base = rawBase && typeof rawBase === 'object' ? rawBase : {};
    const params = {
      ...base,
      actionType: readAnnotation(ann, 'actionType', cleanArgs, extra)
        || base.actionType
        || readAnnotation(ann, 'action', cleanArgs, extra)
        || name,
      targetResourceId: readAnnotation(ann, 'targetResourceId', cleanArgs, extra) || base.targetResourceId,
      beforeState: readAnnotation(ann, 'beforeState', cleanArgs, extra) || base.beforeState,
      afterState: readAnnotation(ann, 'afterState', cleanArgs, extra) || base.afterState || cleanArgs,
      amount: readAnnotation(ann, 'amount', cleanArgs, extra) ?? base.amount,
      currency: readAnnotation(ann, 'currency', cleanArgs, extra) || base.currency,
      riskFlags: readAnnotation(ann, 'riskFlags', cleanArgs, extra) || base.riskFlags,
      approverId: readAnnotation(ann, 'approverId', cleanArgs, extra) || base.approverId,
      executingSystem: readAnnotation(ann, 'executingSystem', cleanArgs, extra) || base.executingSystem || executingSystem,
      executionId: readAnnotation(ann, 'executionId', cleanArgs, extra) || base.executionId,
      onSignoffRequired: ann.onSignoffRequired || base.onSignoffRequired,
    };

    if (!params.actionType || !params.targetResourceId || !params.executingSystem) {
      return refusal(String(params.actionType || name), 'MCP receipt guard is missing actionType, targetResourceId, or executingSystem.', {
        stage: 'configure',
      });
    }

    const lifecycle = await client.requireReceipt(params, () => handler(name, cleanArgs, extra));
    return returnEnvelope ? lifecycle : lifecycle.result;
  };

  return guarded;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Remove EP control fields so the underlying tool sees clean args.
 * @param {{__ep?:object, emilia_receipt?:object, [key:string]:any}} [args]
 * @returns {object}
 */
function stripEpFields(args = {}) {
  if (!args || typeof args !== 'object') return args;
  const { __ep, emilia_receipt, ...rest } = args;
  return rest;
}

/** Content hash of a receipt DOCUMENT for the provenance reference (not a re-sign).
 * Fingerprints only the validated receipt fields. verifyEmiliaReceipt signs and
 * checks payload alone, so an unsigned, non-canonicalizable extra top-level field
 * (e.g. a float or non-plain-object) would make canonicalize() throw and this
 * would silently record a null hash into the append-only provenance ledger,
 * breaking the auditor's re-hash link even though authorization succeeded. Both
 * callers reach here only after successful verification, so these fields are
 * guaranteed canonicalizable; for a well-formed receipt the hash is unchanged. */
function receiptHashOf(doc) {
  if (!doc || typeof doc !== 'object') return null;
  const core = { '@version': doc['@version'], payload: doc.payload, signature: doc.signature };
  if (doc.public_key !== undefined) core.public_key = doc.public_key;
  try {
    return hashObject(core);
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

function readAnnotation(ann, key, args, extra) {
  const value = ann && ann[key];
  return typeof value === 'function' ? value(args, extra) : value;
}

export default {
  withMcpGuard,
  withMcpReceiptGuard,
  demandReceipt,
  refusal,
  classifyToolCall,
  bindToolAction,
  ProvenanceLedger,
  hashObject,
  GUARD_DECISIONS,
};

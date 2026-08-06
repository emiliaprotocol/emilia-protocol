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
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  evaluateReceiptAssurance,
  canonicalizeStrictJson,
  bindToolAction as bindExecutorToolAction,
  snapshotToolArguments,
  makeReceiptGate,
  parseReceiptCarrier,
// Package specifier, not a relative path. '../../require-receipt/index.js'
// escapes this package's own root: it resolved only by accident of npm's flat
// node_modules layout and pointed at whatever require-receipt happened to be
// hoisted beside it, which under a strict layout (pnpm, Yarn PnP) resolves to
// nothing at all.
} from '@emilia-protocol/require-receipt';

type AnyRecord = Record<string, any>;

// ---------------------------------------------------------------------------
// Canonicalization (RFC 8785-style, key-sorted) — used ONLY for the additive
// provenance bundle and for hashing tool-call inputs. It is byte-identical to
// the canonicalize() in @emilia-protocol/issue and /require-receipt. It is NEVER
// applied to an EP-RECEIPT-v1 payload here; Core canonicalization is untouched.
// ---------------------------------------------------------------------------

const canonicalize = canonicalizeStrictJson;

function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** "sha256:<hex>" over canonical JSON — the project-wide hash format. */
export function hashObject(obj: any): string {
  return `sha256:${sha256Hex(canonicalize(obj))}`;
}

/**
 * Bind an MCP tool call to the exact material argument object. A receipt for
 * `payment.release` with one amount or destination cannot authorize another.
 * Control carriers under `__ep` / `emilia_receipt` are deliberately excluded;
 * they transport the proof and are not tool inputs.
 */
export function bindToolAction(name: string, args: AnyRecord = {}, baseAction: string = name): string {
  return bindExecutorToolAction(name, args, baseAction);
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
  const states = new Map<string, string>();
  return {
    ownershipFenced: true,
    async reserve(id: string): Promise<boolean> {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id: string): Promise<boolean> {
      if (states.get(id) !== 'reserved') throw new Error('reservation_not_owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id: string): Promise<boolean> {
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
 *   3. Policy function:          policy(name, args) → boolean, or
 *                                { irreversible: boolean }
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
export function classifyToolCall(name: string, args: AnyRecord = {}, opts: AnyRecord = {}): AnyRecord {
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
      // Also honour the shape this very function returns. A policy written as
      // `(name) => ({ irreversible: false })` mirrors classifyToolCall's own
      // output and is the obvious thing to write, but only a bare boolean was
      // read, so the object fell through to defaultIrreversible. That failed
      // CLOSED, which is the safe direction and exactly why it went unnoticed:
      // the operator's intent was dropped in silence and every call was gated.
      if (p !== null && typeof p === 'object' && typeof (p as AnyRecord).irreversible === 'boolean') {
        return { irreversible: (p as AnyRecord).irreversible, reason: 'policy_fn' };
      }

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
function extractReceipt(args: AnyRecord = {}, meta: AnyRecord = {}): AnyRecord | null {
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

function parseBase64Receipt(value: string): AnyRecord | null {
  return parseReceiptCarrier(value);
}

/**
 * Build the legacy refusal object an MCP tool can return verbatim. Same
 * problem-details shape as require-receipt's challenge, framed for a
 * tool result so a well-behaved agent knows exactly what to bring and retry.
 */
export function refusal(action: string, reason: string, extra: AnyRecord = {}): AnyRecord {
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
 * Bounded identical-call circuit breaker for MCP dispatchers. It fingerprints
 * the material tool name + arguments with the same binder as receipt authority,
 * ignores receipt transport fields, and keeps only a bounded sliding window.
 */
export function createMcpLoopBreaker(options: AnyRecord = {}): AnyRecord {
  const {
    maxIdenticalCalls = 3,
    windowMs = 10_000,
    maxEntries = 2_048,
    now = () => Date.now(),
  } = options;
  if (!Number.isSafeInteger(maxIdenticalCalls) || maxIdenticalCalls < 1 || maxIdenticalCalls > 100) {
    throw new TypeError('createMcpLoopBreaker: maxIdenticalCalls must be a safe integer from 1 to 100');
  }
  if (!Number.isSafeInteger(windowMs) || windowMs < 1 || windowMs > 3_600_000) {
    throw new TypeError('createMcpLoopBreaker: windowMs must be a safe integer from 1 to 3600000');
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 100_000) {
    throw new TypeError('createMcpLoopBreaker: maxEntries must be a safe integer from 1 to 100000');
  }
  if (typeof now !== 'function') throw new TypeError('createMcpLoopBreaker: now must be a function');

  const windows = new Map<string, number[]>();
  let lastNow = Number.NEGATIVE_INFINITY;
  const check = (name: string, args: AnyRecord = {}): AnyRecord => {
    const at = now();
    if (!Number.isFinite(at)) return { ok: false, reason: 'circuit_clock_invalid' };
    if (at < lastNow) return { ok: false, reason: 'circuit_clock_rollback' };
    lastNow = at;
    let fingerprint: string;
    try {
      fingerprint = bindToolAction(name, args, 'mcp.tool.call');
    } catch {
      return { ok: false, reason: 'action_binding_invalid' };
    }
    const cutoff = at - windowMs;
    // Expire old windows before enforcing capacity. Never evict a live
    // fingerprint to admit attacker-controlled key churn: at capacity, new
    // identities fail closed until a real window expires.
    for (const [key, timestamps] of windows) {
      const live = timestamps.filter((timestamp) => timestamp > cutoff && timestamp <= at);
      if (live.length === 0) windows.delete(key);
      else if (live.length !== timestamps.length) windows.set(key, live);
    }
    if (!windows.has(fingerprint) && windows.size >= maxEntries) {
      return { ok: false, reason: 'circuit_capacity_exhausted' };
    }
    const recent = (windows.get(fingerprint) || []).filter((timestamp) => timestamp > cutoff && timestamp <= at);
    if (recent.length >= maxIdenticalCalls) {
      return {
        ok: false,
        reason: 'identical_tool_loop',
        fingerprint,
        retry_after_ms: Math.max(1, Math.ceil(recent[0] + windowMs - at)),
      };
    }
    recent.push(at);
    windows.delete(fingerprint);
    windows.set(fingerprint, recent);
    return { ok: true, fingerprint, remaining: maxIdenticalCalls - recent.length };
  };
  return {
    check,
    reset: () => { windows.clear(); lastNow = Number.NEGATIVE_INFINITY; },
    get size() { return windows.size; },
  };
}

/** Wrap any MCP dispatcher with the local Sentinel identical-call breaker. */
export function withMcpLoopBreaker(handler: (...args: any[]) => any, options: AnyRecord = {}): any {
  if (typeof handler !== 'function') throw new TypeError('withMcpLoopBreaker: handler must be a function');
  const breaker = options.breaker || createMcpLoopBreaker(options);
  if (!breaker || typeof breaker.check !== 'function') {
    throw new TypeError('withMcpLoopBreaker: breaker must implement check(name, args)');
  }
  return async function loopGuardedDispatch(name: string, args: AnyRecord = {}, extra: AnyRecord = {}): Promise<any> {
    const decision = breaker.check(name, args);
    if (decision?.ok !== true) {
      const code = decision?.reason === 'identical_tool_loop'
        ? 'emilia_identical_tool_loop'
        : decision?.reason === 'circuit_capacity_exhausted'
          ? 'emilia_circuit_capacity_exhausted'
          : 'emilia_circuit_breaker_invalid_input';
      return {
        ep_refused: true,
        status: 429,
        code,
        title: 'EMILIA MCP Circuit Open',
        detail: decision?.reason === 'identical_tool_loop'
          ? 'An identical MCP tool call exceeded the local sliding-window limit.'
          : decision?.reason === 'circuit_capacity_exhausted'
            ? 'The bounded circuit-breaker table is full of live call windows; new calls fail closed.'
            : 'The MCP tool call could not be safely fingerprinted.',
        reason: decision?.reason || 'circuit_breaker_failed_closed',
        retry_after_ms: decision?.retry_after_ms || null,
      };
    }
    let materialArgs;
    try { materialArgs = snapshotToolArguments(args); }
    catch {
      return {
        ep_refused: true,
        status: 429,
        code: 'emilia_circuit_breaker_invalid_input',
        title: 'EMILIA MCP Circuit Open',
        detail: 'The MCP tool call could not be safely snapshotted.',
        reason: 'action_binding_invalid',
        retry_after_ms: null,
      };
    }
    return handler(name, materialArgs, extra);
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
export function demandReceipt({ action, args = {}, meta = {}, verifyOpts = {} }: AnyRecord): AnyRecord {
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

export interface ProvenanceLedgerStoreAppendInput {
  expectedSequence: number;
  expectedPreviousHash: string;
  entry: Readonly<AnyRecord>;
}

export interface ProvenanceLedgerStore {
  readonly durable: true;
  load(): Promise<readonly AnyRecord[]>;
  append(input: ProvenanceLedgerStoreAppendInput): Promise<
    { ok: true } | { ok: false; reason: 'head_conflict' | 'storage_refused' }
  >;
}

export interface ProvenancePostgresQueryResult {
  rowCount: number;
  rows?: Array<Record<string, unknown>>;
}

export type ProvenancePostgresQuery = (
  text: string,
  params: readonly unknown[],
) => Promise<ProvenancePostgresQueryResult>;

export const PROVENANCE_POSTGRES_SQL = Object.freeze({
  load: 'SELECT public.ep_mcp_provenance_load($1::text, $2::text) AS result',
  append: 'SELECT public.ep_mcp_provenance_append($1::text, $2::text, $3::bigint, $4::text, $5::jsonb) AS result',
});

const PROVENANCE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;

function provenanceIdentifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !PROVENANCE_IDENTIFIER.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
  return value;
}

function provenanceResult(value: unknown, operation: string): AnyRecord {
  let parsed = value;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); }
    catch (error) {
      throw new ProvenanceLedgerIntegrityError(`${operation}: malformed JSON result`, { cause: error });
    }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || typeof (parsed as AnyRecord).ok !== 'boolean') {
    throw new ProvenanceLedgerIntegrityError(`${operation}: malformed result`);
  }
  return parsed as AnyRecord;
}

export function createPostgresProvenanceLedgerStore(options: {
  query: ProvenancePostgresQuery;
  tenantId: string;
  ledgerId: string;
}): ProvenanceLedgerStore {
  if (!options || typeof options.query !== 'function') {
    throw new TypeError('createPostgresProvenanceLedgerStore requires a pg-style query function');
  }
  const query = options.query;
  const tenantId = provenanceIdentifier(options.tenantId, 'tenantId');
  const ledgerId = provenanceIdentifier(options.ledgerId, 'ledgerId');

  const rpc = async (operation: string, text: string, params: readonly unknown[]): Promise<AnyRecord> => {
    const response = await query(text, params);
    if (!response || response.rowCount !== 1 || !Array.isArray(response.rows)
        || response.rows.length !== 1 || !Object.hasOwn(response.rows[0], 'result')) {
      throw new ProvenanceLedgerIntegrityError(`${operation}: malformed PostgreSQL response`);
    }
    return provenanceResult(response.rows[0].result, operation);
  };

  return Object.freeze({
    durable: true as const,
    async load(): Promise<readonly AnyRecord[]> {
      const result = await rpc('provenance load', PROVENANCE_POSTGRES_SQL.load, [
        tenantId,
        ledgerId,
      ]);
      if (!result.ok || !Array.isArray(result.entries)) {
        throw new ProvenanceLedgerIntegrityError('provenance load: store refused or omitted entries');
      }
      const expectedLength = Number(result.head_sequence) + 1;
      if (!Number.isSafeInteger(expectedLength)
          || expectedLength < 0
          || result.entries.length !== expectedLength
          || (result.entries.at(-1)?.entry_hash ?? '') !== (result.head_hash ?? '')) {
        throw new ProvenanceLedgerIntegrityError('provenance load: durable head does not match entries');
      }
      return immutableCopy(result.entries);
    },
    async append(input: ProvenanceLedgerStoreAppendInput) {
      if (!Number.isSafeInteger(input.expectedSequence) || input.expectedSequence < 0) {
        throw new TypeError('expectedSequence is invalid');
      }
      if (typeof input.expectedPreviousHash !== 'string') {
        throw new TypeError('expectedPreviousHash is invalid');
      }
      const result = await rpc('provenance append', PROVENANCE_POSTGRES_SQL.append, [
        tenantId,
        ledgerId,
        input.expectedSequence,
        input.expectedPreviousHash,
        JSON.stringify(input.entry),
      ]);
      if (result.ok) return { ok: true as const };
      if (result.reason === 'head_conflict') {
        return { ok: false as const, reason: 'head_conflict' as const };
      }
      return { ok: false as const, reason: 'storage_refused' as const };
    },
  });
}

export class ProvenanceLedgerIntegrityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ProvenanceLedgerIntegrityError';
  }
}

function immutableCopy<T>(value: T): Readonly<T> {
  const copy = structuredClone(value);
  const freeze = (candidate: unknown): void => {
    if (candidate === null || typeof candidate !== 'object' || Object.isFrozen(candidate)) return;
    for (const child of Object.values(candidate)) freeze(child);
    Object.freeze(candidate);
  };
  freeze(copy);
  return copy;
}

export class ProvenanceLedger {
  #entries: Readonly<AnyRecord>[] = [];
  #store: ProvenanceLedgerStore | null = null;
  #tail: Promise<void> = Promise.resolve();
  readonly durable: boolean = false;

  constructor() {
  }

  static async open({ store }: { store: ProvenanceLedgerStore }): Promise<ProvenanceLedger> {
    if (!store || store.durable !== true
        || typeof store.load !== 'function'
        || typeof store.append !== 'function') {
      throw new TypeError('ProvenanceLedger.open requires a durable provenance store');
    }
    const loaded = await store.load();
    if (!Array.isArray(loaded)) {
      throw new ProvenanceLedgerIntegrityError('durable provenance store returned no entry array');
    }
    const ledger = new ProvenanceLedger();
    ledger.#store = store;
    Object.defineProperty(ledger, 'durable', { value: true });
    ledger.#entries = loaded.map((entry) => immutableCopy(entry));
    const verified = ledger.verifyChain();
    if (!verified.ok) {
      throw new ProvenanceLedgerIntegrityError(
        `durable provenance chain failed startup verification: ${verified.reason} at ${verified.index}`,
      );
    }
    return ledger;
  }

  get entries(): readonly Readonly<AnyRecord>[] {
    return immutableCopy(this.#entries);
  }

  /** sha256: of the previous entry, "" for genesis. */
  get headHash() {
    if (this.#entries.length === 0) return '';
    return this.#entries[this.#entries.length - 1].entry_hash;
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
  append({ tool, action, actionDigest, receiptRef, verified, agentClaim, liability, at }: AnyRecord): Promise<Readonly<AnyRecord>> {
    let resolveResult!: (entry: Readonly<AnyRecord>) => void;
    let rejectResult!: (error: unknown) => void;
    const result = new Promise<Readonly<AnyRecord>>((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });
    const operation = async (): Promise<void> => {
      try {
        const prev = this.headHash;
        const body = {
          '@version': 'EP-PROVENANCE-ENTRY-v1',
          sequence: this.#entries.length,
          at: at || new Date().toISOString(),
          tool,
          action,
          action_digest: actionDigest,
          receipt_ref: receiptRef,
          verified: verified
            ? { outcome: verified.outcome, subject: verified.subject, signer: verified.signer }
            : null,
          agent_claim: agentClaim || null,
          liability: liability || null,
          prev_entry_hash: prev || null,
        };
        const entry = immutableCopy({ ...body, entry_hash: hashObject(body) });
        if (this.#store) {
          const stored = await this.#store.append({
            expectedSequence: body.sequence,
            expectedPreviousHash: prev,
            entry,
          });
          if (!stored.ok) {
            throw new ProvenanceLedgerIntegrityError(
              `durable provenance append refused: ${stored.reason}`,
            );
          }
        }
        this.#entries = [...this.#entries, entry];
        resolveResult(entry);
      } catch (error) {
        rejectResult(error);
      }
    };
    this.#tail = this.#tail.then(operation, operation);
    return result;
  }

  /**
   * Re-verify the append-only chain offline. Does NOT re-verify the underlying
   * v1 receipts (that is the verifier's job via require-receipt); it only proves
   * the ledger is internally consistent and untampered. Returns the first
   * break, fail-closed.
   */
  verifyChain(): AnyRecord {
    let prev = '';
    for (let i = 0; i < this.#entries.length; i++) {
      const e = this.#entries[i];
      const { entry_hash, ...body } = e;
      if (e.sequence !== i) return { ok: false, reason: 'sequence_gap', index: i };
      if ((body.prev_entry_hash || '') !== (prev || '')) {
        return { ok: false, reason: 'broken_link', index: i };
      }
      if (hashObject(body) !== entry_hash) return { ok: false, reason: 'tampered_entry', index: i };
      prev = entry_hash;
    }
    return { ok: true, length: this.#entries.length };
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
 * @property {ProvenanceLedger} [ledger] durable, startup-verified ledger.
 * @property {boolean} [allowEphemeralLedger=false] explicit demo/test escape hatch.
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
export function withMcpGuard(handler: (...args: any[]) => any, options: AnyRecord = {}): any {
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
  const suppliedLedger = options.ledger;
  if (suppliedLedger !== undefined && !(suppliedLedger instanceof ProvenanceLedger)) {
    throw new TypeError('withMcpGuard: ledger must be a ProvenanceLedger');
  }
  const ledger = suppliedLedger instanceof ProvenanceLedger
    ? suppliedLedger
    : options.allowEphemeralLedger === true
      ? new ProvenanceLedger()
      : null;
  if (!ledger || (!ledger.durable && options.allowEphemeralLedger !== true)) {
    throw new TypeError(
      'withMcpGuard: a durable provenance ledger is required; use allowEphemeralLedger only for demos/tests',
    );
  }

  const resolveAnnotations = (name: string): AnyRecord => {
    let fromResolver;
    try { fromResolver = typeof getAnnotations === 'function' ? getAnnotations(name) : undefined; }
    catch { fromResolver = { destructiveHint: true }; }
    // An external resolver may only ever ESCALATE. `readOnlyHint` is deliberately
    // not forwarded: it is presenter-authored metadata, and forwarding it let a
    // remote hint outrank the operator's own `policy` function, whose result is
    // evaluated after the readOnlyHint downgrade branch. Locally authored
    // `annotations[name].readOnlyHint` is unaffected and still honoured below.
    const externalHints = fromResolver && typeof fromResolver === 'object' ? {
      ...(fromResolver.destructiveHint === true ? { destructiveHint: true } : {}),
    } : {};
    return { ...externalHints, ...(annotations[name] || {}) };
  };

  const resolveAction = (name: string, args: AnyRecord, extra: AnyRecord, ann: AnyRecord): string => {
    let a = ann && ann.action;
    if (typeof a === 'function') a = a(snapshotToolArguments(args), extra);
    if (!a && typeof globalAction === 'function') {
      a = globalAction(name, snapshotToolArguments(args), extra);
    }
    return bindToolAction(name, args, a || name);
  };

  const gateFor = (action: string, requiredTier: string): any => {
    // Gate objects carry no authority state. The shared atomic consumption
    // store does. Retaining one gate per attacker-controlled action string made
    // this middleware a remotely growable memory cache and unsafe eviction
    // would have risked confusing the state boundary. Build the lightweight
    // wrapper per invocation and retain only the authoritative store.
    return makeReceiptGate({
      ...verifyOpts,
      action,
      assuranceClass: requiredTier,
      store,
    });
  };

  const guarded = async function guardedDispatch(name: string, args: AnyRecord = {}, extra: AnyRecord = {}): Promise<any> {
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
    let materialArgs;
    try {
      materialArgs = snapshotToolArguments(args);
      action = resolveAction(name, materialArgs, extra, ann);
    } catch {
      return refusal(String(name || 'mcp.tool'), 'Tool call cannot be bound to the EP canonical JSON profile.', {
        stage: 'bind',
        rejected: { ok: false, reason: 'action_binding_invalid' },
      });
    }
    const requiredTier = ann.assuranceClass || ann.assurance_class || verifyOpts.assuranceClass || verifyOpts.assurance_class || 'class_a';
    const meta = (extra && (extra._meta || extra.meta)) || {};
    // `action` already contains the complete finite-JSON argument digest. Hash
    // that closed string envelope for additive provenance instead of applying
    // the stricter signed-record numeric profile to raw executor measurements.
    const actionDigest = hashObject({ tool: name, action });

    // ---- Path A: a receipt was presented → demand hook verifies it offline.
    if (enforceDemand) {
      const carriesReceipt = !!extractReceipt(args, meta);
      if (carriesReceipt) {
        const doc = extractReceipt(args, meta) as AnyRecord;
        const run = await gateFor(action, requiredTier).run(doc, {}, async (verified: AnyRecord) => {
          await ledger.append({
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
          return handler(name, materialArgs, extra);
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
      args: materialArgs,
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
    const run = await gateFor(action, requiredTier).run(doc, {}, async (verified: AnyRecord) => {
      await ledger.append({
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
export function withMcpReceiptGuard(handler: (...args: any[]) => any, options: AnyRecord = {}): any {
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

  const resolveAnnotations = (name: string): AnyRecord => {
    let fromResolver;
    try { fromResolver = typeof getAnnotations === 'function' ? getAnnotations(name) : undefined; }
    catch { fromResolver = { destructiveHint: true }; }
    // An external resolver may only ever ESCALATE. `readOnlyHint` is deliberately
    // not forwarded: it is presenter-authored metadata, and forwarding it let a
    // remote hint outrank the operator's own `policy` function, whose result is
    // evaluated after the readOnlyHint downgrade branch. Locally authored
    // `annotations[name].readOnlyHint` is unaffected and still honoured below.
    const externalHints = fromResolver && typeof fromResolver === 'object' ? {
      ...(fromResolver.destructiveHint === true ? { destructiveHint: true } : {}),
    } : {};
    return { ...externalHints, ...(annotations[name] || {}) };
  };

  const guarded = async function guardedReceiptDispatch(name: string, args: AnyRecord = {}, extra: AnyRecord = {}): Promise<any> {
    const ann = resolveAnnotations(name);
    const { irreversible } = classifyToolCall(name, args, {
      annotations: { [name]: ann },
      policy,
      defaultIrreversible,
      trustReadOnlyHints,
    });

    if (!irreversible) return handler(name, args, extra);

    let cleanArgs;
    try { cleanArgs = snapshotToolArguments(args); }
    catch {
      return refusal(String(name || 'mcp.tool'), 'Tool call cannot be bound to the executor JSON profile.', {
        stage: 'bind',
        rejected: { ok: false, reason: 'action_binding_invalid' },
      });
    }
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

/** Content hash of a receipt DOCUMENT for the provenance reference (not a re-sign).
 * Fingerprints only the validated receipt fields. verifyEmiliaReceipt signs and
 * checks payload alone, so an unsigned, non-canonicalizable extra top-level field
 * (e.g. a float or non-plain-object) would make canonicalize() throw and this
 * would silently record a null hash into the append-only provenance ledger,
 * breaking the auditor's re-hash link even though authorization succeeded. Both
 * callers reach here only after successful verification, so these fields are
 * guaranteed canonicalizable; for a well-formed receipt the hash is unchanged. */
function receiptHashOf(doc: AnyRecord): string | null {
  if (!doc || typeof doc !== 'object') return null;
  const core: AnyRecord = { '@version': doc['@version'], payload: doc.payload, signature: doc.signature };
  if (doc.public_key !== undefined) core.public_key = doc.public_key;
  try {
    return hashObject(core);
  } catch {
    return null;
  }
}

async function callAdapter(fn: any, ctx: AnyRecord, fallback: AnyRecord): Promise<AnyRecord> {
  if (typeof fn !== 'function') return fallback;
  try {
    const r = await fn(ctx);
    return r && typeof r === 'object' ? r : fallback;
  } catch (e: any) {
    return { approved: false, reason: `adapter_error: ${e?.message}` };
  }
}

function readAnnotation(ann: AnyRecord, key: string, args: AnyRecord, extra: AnyRecord): any {
  const value = ann && ann[key];
  return typeof value === 'function' ? value(args, extra) : value;
}

export default {
  withMcpGuard,
  withMcpLoopBreaker,
  createMcpLoopBreaker,
  withMcpReceiptGuard,
  demandReceipt,
  refusal,
  classifyToolCall,
  bindToolAction,
  createPostgresProvenanceLedgerStore,
  ProvenanceLedger,
  hashObject,
  GUARD_DECISIONS,
};

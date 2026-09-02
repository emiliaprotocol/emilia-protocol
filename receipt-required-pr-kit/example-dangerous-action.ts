// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required, in front of your dangerous actions — built on the canonical
// hardened gate from @emilia-protocol/require-receipt.
//
//   unlisted tool     -> 403 refused (DEFAULT CLOSED; see below)
//   missing receipt   -> 428 Receipt Required (refused)
//   valid receipt     -> the action runs (and the receipt is consumed)
//   replayed receipt  -> refused (one-time consumption; see store note below)
//   forged receipt    -> refused (signature / action-binding fails)
//
// DEFAULT CLOSED: a tool this dispatcher cannot resolve to EXACTLY ONE manifest
// entry is refused, never run. This is the same posture as
// @emilia-protocol/mcp-guard's `defaultIrreversible = true`: a new, renamed,
// misspelled, or differently-cased tool must not be able to walk around the
// rail simply by not appearing in agent-actions.json. An ambiguous or
// conflicting selector resolution is a refusal too — "the manifest does not
// name one policy for this call" is never "no policy applies, proceed".
//
// SECURE BY DEFAULT: a destructive action will NOT accept a self-signed
// (inline-key) receipt. Pin the issuer key(s) you trust via EMILIA_TRUSTED_KEYS
// (comma-separated base64url SPKI). With enforcement on and no trusted keys
// configured, the gate FAILS CLOSED — the action is refused, never run under an
// untrusted key. EMILIA_ALLOW_INLINE_KEY=1 accepts inline keys for local demos
// and is IGNORED when NODE_ENV=production.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  makeReceiptGate,
  resolveActionRequirement,
  bindToolAction,
  snapshotToolArguments,
  RECEIPT_REQUIRED_STATUS,
} from '@emilia-protocol/require-receipt';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));

// Posture is read from the environment at call time, so deployment config — not
// a hardcoded demo default — decides how receipts are trusted.
const trustedKeys = () =>
  (process.env.EMILIA_TRUSTED_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
// A demo escape that survives into a production image is not a demo escape, it
// is a bypass. NODE_ENV=production disables inline keys and the demo approver
// outright, whatever the environment asks for.
const demoModeAvailable = () => process.env.NODE_ENV !== 'production';
const allowInlineKey = () =>
  demoModeAvailable() && /^(1|true)$/i.test(process.env.EMILIA_ALLOW_INLINE_KEY || '');
// Only advertise a manifest URL the host actually serves. Set EMILIA_MANIFEST_URL
// once you serve agent-actions.json (e.g. at /.well-known/agent-actions.json);
// otherwise the 428 challenge won't point at a URL that 404s.
const manifestUrl = () => process.env.EMILIA_MANIFEST_URL || undefined;

function productionAssuranceConfiguration() {
  try {
    const approverKeys = JSON.parse(process.env.EMILIA_APPROVER_KEYS_JSON || 'null');
    const rpId = process.env.EMILIA_RP_ID || '';
    const allowedOrigins = (process.env.EMILIA_ALLOWED_ORIGINS || '')
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean);
    if (!approverKeys || typeof approverKeys !== 'object' || Array.isArray(approverKeys)
        || !Object.keys(approverKeys).length || !rpId || !allowedOrigins.length) return null;
    return { approverKeys, rpId, allowedOrigins };
  } catch {
    return null;
  }
}

async function assuranceConfiguration(requiredClass: string | undefined) {
  if (requiredClass === 'software') return {};
  const pinned = productionAssuranceConfiguration();
  if (pinned) return pinned;
  if (!allowInlineKey()) return null;
  // Loaded ONLY here, so the approver key material and the proof minter that
  // signs with it are never reachable from this module's exports.
  const { demoAssuranceConfiguration } = await import('./demo-approver.js');
  return demoAssuranceConfiguration();
}

// The actual dangerous work. Replace the body with your real action. It receives
// the SNAPSHOT the receipt was bound to, never the caller's live argument
// object, so a mutation racing the await cannot change what actually executes.
// Once this function is invoked, any exception is an indeterminate effect and
// burns the approval so automatic retry cannot duplicate an action whose
// response was lost.
function performDangerousAction(name: string, material: Record<string, any>) {
  return { ran: true, tool: name, ...material };
}

// One-time consumption is process-wide, not per action type: a receipt_id spent
// on one action must not be spendable on another.
// NOTE: this default store is process-local (in-memory) — it does NOT survive a
// restart and does NOT span multiple instances. For durable / multi-instance
// one-time consumption, replace it with an ownership-fenced durable store
// ({ reserve, commit, release }) backed by Redis/DB.
function processLocalConsumptionStore() {
  const states = new Map<string, string>();
  return {
    durable: false,
    ownershipFenced: true,
    async reserve(id: string) {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id: string) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id: string) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.delete(id);
      return true;
    },
  };
}
const consumptionStore = processLocalConsumptionStore();

// Built per call, never memoized: the posture helpers above read the
// environment at call time, and a gate cached on first use would freeze
// whichever posture happened to be in effect then.
function gateFor(boundAction: string, req: Record<string, any>, assurance: Record<string, any>) {
  const keys = trustedKeys();
  return makeReceiptGate({
    action: boundAction,
    // Pinned issuer keys (secure) if configured; inline only in explicit demo
    // mode. dispatch() fails closed before we get here if neither is set.
    ...(keys.length ? { trustedKeys: keys } : { allowInlineKey: true }),
    maxAgeSec: req.max_age_sec,
    statusCode: RECEIPT_REQUIRED_STATUS,
    ...(manifestUrl() ? { manifestUrl: manifestUrl() } : {}),
    assuranceClass: req.assurance_class,
    // The material fields the manifest says a human actually approved. The gate
    // refuses unless the receipt carries a signed canonical_action whose hash
    // matches what this executor is about to run, and which names every one of
    // these fields.
    requiredFields: req.execution_binding.required_fields,
    ...assurance,
    store: consumptionStore,
  });
}

function refused(status: number, reason: string, detail: string) {
  return { status, body: { rejected: { reason }, detail } };
}

const manifestActions = () => (Array.isArray(MANIFEST.actions) ? MANIFEST.actions : []);

/** Name the near-miss instead of silently treating it as "no such action". */
function caseInsensitiveNearMatch(name: string): string | null {
  const wanted = name.toLowerCase();
  for (const entry of manifestActions()) {
    const tool = entry?.match?.tool;
    if (typeof tool === 'string' && tool !== name && tool.toLowerCase() === wanted) {
      return String(entry.id || tool);
    }
  }
  return null;
}

export async function dispatch(name: string, args: Record<string, any> = {}, receipt: any = null): Promise<{ status: number; body: Record<string, any> }> {
  // DEFAULT CLOSED, step 1: the manifest must name this tool at all. Selector
  // matching is exact and case-sensitive, so `DELETE_ALL_RECORDS` lands here
  // rather than sliding past a `delete_all_records` entry.
  if (!manifestActions().some((entry) => entry?.match?.tool === name)) {
    const nearMatch = caseInsensitiveNearMatch(name);
    return refused(403, 'action_not_in_manifest',
      `No agent-actions.json entry matches tool "${name}", so this dispatcher `
      + 'cannot tell whether the call is irreversible. '
      + (nearMatch
        ? `Manifest selectors are case-sensitive and "${nearMatch}" differs only in case. `
        : '')
      + 'Add the tool to the manifest (receipt_required: false for genuinely '
      + 'reversible tools) rather than relying on absence to mean safe.');
  }

  // DEFAULT CLOSED, step 2: it must resolve to EXACTLY ONE policy. Ambiguous or
  // conflicting resolutions are refusals, never a fall-through to "unguarded".
  const resolution = resolveActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });
  if (resolution.status !== 'one') {
    const candidates = resolution.status === 'none' ? [] : resolution.action_ids;
    return refused(403,
      resolution.status === 'conflict' || resolution.status === 'none'
        ? 'manifest_selector_conflict'
        : 'manifest_selector_ambiguous',
      `agent-actions.json does not name one policy for { protocol: "mcp", tool: "${name}" }`
      + (candidates.length ? ` (candidates: ${candidates.join(', ')})` : '')
      + '. Split or narrow the selectors so exactly one entry matches.');
  }
  const req = resolution.action;

  // Bind to the WHOLE call, not one convenient field, and do it BEFORE the
  // first await. `material` is a finite-JSON snapshot and it is what actually
  // executes: the receipt cannot be verified against `{ table: "customers" }`
  // while a live, still-mutable `args` object carries `hard_delete: true` past
  // the gate.
  let material: Record<string, any>;
  try {
    material = Object.freeze(snapshotToolArguments(args));
  } catch {
    return refused(400, 'action_binding_invalid',
      'Tool arguments are not finite JSON, so they cannot be bound to a receipt.');
  }

  // An explicit `receipt_required: false` is an author's decision on record.
  // Absence of an entry is not, which is why it refuses above.
  if (!req.receipt_required) {
    return { status: 200, body: performDangerousAction(name, material) };
  }

  // FAIL CLOSED: enforcement is on but no issuer key is trusted. Refuse the
  // destructive action rather than accept a self-signed receipt. Configure
  // EMILIA_TRUSTED_KEYS (pinned issuer SPKI), or EMILIA_ALLOW_INLINE_KEY=1 for
  // non-production demos only.
  if (!trustedKeys().length && !allowInlineKey()) {
    return refused(500, 'receipt_enforcement_misconfigured',
      'Set EMILIA_TRUSTED_KEYS to the issuer key(s) you trust; '
      + 'refusing to accept self-signed receipts for a destructive action.');
  }

  // A guarded entry that names no material fields would bind the receipt to the
  // action TYPE only, which lets a receipt for one payload authorize another.
  // validateActionRiskManifest refuses such a manifest at author time; this is
  // the same floor for a manifest loaded without re-validation.
  if (!Array.isArray(req.execution_binding?.required_fields)
      || req.execution_binding.required_fields.length === 0) {
    return refused(500, 'manifest_execution_binding_missing',
      `agent-actions.json entry "${req.id}" is receipt_required but declares no `
      + 'execution_binding.required_fields; refusing to run a type-bound-only action.');
  }

  const assurance = await assuranceConfiguration(req.assurance_class);
  if (!assurance) {
    return refused(500, 'receipt_assurance_misconfigured',
      'Configure EMILIA_APPROVER_KEYS_JSON, EMILIA_RP_ID, and '
      + 'EMILIA_ALLOWED_ORIGINS; refusing to trust presenter-supplied human assurance.');
  }

  const boundAction = bindToolAction(name, material, req.action_type);

  const r = await gateFor(boundAction, req, assurance).run(
    receipt,
    { observedAction: material },
    async () => performDangerousAction(name, material),
  );

  if (r.ok) {
    return { status: 200, body: { ...r.result, evidence: { receipt_id: r.receiptId, outcome: r.outcome, signer: r.signer } } };
  }
  return { status: r.status, body: r.body };
}

/**
 * The exact action string a receipt for this call must be issued against, and
 * the canonical action it must carry. Callers use it to REQUEST an approval;
 * it grants nothing on its own.
 */
export function receiptRequestFor(name: string, args: Record<string, any> = {}) {
  const resolution = resolveActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });
  if (resolution.status !== 'one') return null;
  const material = snapshotToolArguments(args);
  return {
    action_type: bindToolAction(name, material, resolution.action.action_type),
    canonical_action: material,
    required_fields: resolution.action.execution_binding?.required_fields ?? [],
    assurance_class: resolution.action.assurance_class,
  };
}

// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required, in front of ONE dangerous action — built on the canonical
// hardened gate from @emilia-protocol/require-receipt.
//
//   missing receipt   -> 428 Receipt Required (refused)
//   valid receipt     -> the action runs (and the receipt is consumed)
//   replayed receipt  -> refused (one-time consumption; see store note below)
//   forged receipt    -> refused (signature / action-binding fails)
//
// SECURE BY DEFAULT: a destructive action will NOT accept a self-signed
// (inline-key) receipt. Pin the issuer key(s) you trust via EMILIA_TRUSTED_KEYS
// (comma-separated base64url SPKI). With enforcement on and no trusted keys
// configured, the gate FAILS CLOSED — the action is refused, never run under an
// untrusted key. Set EMILIA_ALLOW_INLINE_KEY=1 to accept inline keys for
// NON-PRODUCTION demos only.

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  makeReceiptGate,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
} from '@emilia-protocol/require-receipt';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));

const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v));
const DEMO_RP_ID = 'receipt-required-demo.emiliaprotocol.ai';
const DEMO_ORIGIN = `https://${DEMO_RP_ID}`;
const DEMO_APPROVER_ID = 'jane.doe@yourco.example';
const DEMO_APPROVER_KEY_ID = 'receipt-required-demo-approver';
const DEMO_APPROVER = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const DEMO_APPROVER_PUBLIC_KEY = DEMO_APPROVER.publicKey
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');
const DEMO_APPROVER_KEYS = Object.freeze({
  [DEMO_APPROVER_KEY_ID]: Object.freeze({
    public_key: DEMO_APPROVER_PUBLIC_KEY,
    key_class: 'A',
    approver_id: DEMO_APPROVER_ID,
  }),
});
const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');

/**
 * Create the self-contained demo's real P-256 WebAuthn-shaped assurance proof.
 * Production callers use a platform passkey ceremony and configure the gate
 * with their enrolled approver directory, RP ID, and allowed origins instead.
 */
export function createDemoClassAAssuranceProof(payload) {
  const context = {
    '@version': 'EP-ASSURANCE-CONTEXT-v1',
    receipt_id: payload.receipt_id,
    claim_hash: `sha256:${sha256Hex(canonicalize(payload.claim || {}))}`,
  };
  const contextHash = `sha256:${sha256Hex(canonicalize(context))}`;
  const digest = Buffer.from(contextHash.slice('sha256:'.length), 'hex');
  const clientDataBytes = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: digest.toString('base64url'),
    origin: DEMO_ORIGIN,
    crossOrigin: false,
  }), 'utf8');
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  const authenticatorData = Buffer.concat([
    sha256(DEMO_RP_ID),
    Buffer.from([0x05]),
    counter,
  ]);
  const signature = crypto.sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientDataBytes)]),
    DEMO_APPROVER.privateKey,
  );
  return {
    '@version': 'EP-ASSURANCE-PROOF-v1',
    context_hash: contextHash,
    signoffs: [{
      approver_key_id: DEMO_APPROVER_KEY_ID,
      key_class: 'A',
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientDataBytes.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    }],
  };
}

// Posture is read from the environment at call time, so deployment config — not
// a hardcoded demo default — decides how receipts are trusted.
const trustedKeys = () =>
  (process.env.EMILIA_TRUSTED_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
const allowInlineKey = () => /^(1|true)$/i.test(process.env.EMILIA_ALLOW_INLINE_KEY || '');
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

function assuranceConfiguration(requiredClass) {
  if (requiredClass === 'software') return {};
  if (allowInlineKey()) {
    return {
      approverKeys: DEMO_APPROVER_KEYS,
      rpId: DEMO_RP_ID,
      allowedOrigins: [DEMO_ORIGIN],
    };
  }
  return productionAssuranceConfiguration();
}

// The actual dangerous work. Replace the body with your real action. Once this
// function is invoked, any exception is an indeterminate effect and burns the
// approval so automatic retry cannot duplicate an action whose response was lost.
function performDangerousAction(name, args) {
  return { ran: true, tool: name, ...args };
}

// One gate per action type (each keeps its own one-time-consumption store).
// NOTE: the default store is process-local (in-memory) — it does NOT survive a
// restart and does NOT span multiple instances. For durable / multi-instance
// one-time consumption, pass an ownership-fenced durable `store`
// ({ reserve, commit, release }) below (Redis/DB).
const gates = new Map();
function gateFor(req, assurance) {
  if (!gates.has(req.action_type)) {
    const keys = trustedKeys();
    gates.set(req.action_type, makeReceiptGate({
      action: req.action_type,
      // Pinned issuer keys (secure) if configured; inline only in explicit demo
      // mode. dispatch() fails closed before we get here if neither is set.
      ...(keys.length ? { trustedKeys: keys } : { allowInlineKey: true }),
      maxAgeSec: req.max_age_sec,
      statusCode: RECEIPT_REQUIRED_STATUS,
      ...(manifestUrl() ? { manifestUrl: manifestUrl() } : {}),
      assuranceClass: req.assurance_class,
      ...assurance,
      // store: <durable atomic {reserve,commit,release}> for fleet-wide one-time use.
    }));
  }
  return gates.get(req.action_type);
}

// dispatch(toolName, args, receipt|null) -> { status, body }
export async function dispatch(name, args = {}, receipt = null) {
  const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });

  // Tools not listed as receipt_required pass straight through.
  if (!req || !req.receipt_required) {
    return { status: 200, body: performDangerousAction(name, args) };
  }

  // FAIL CLOSED: enforcement is on but no issuer key is trusted. Refuse the
  // destructive action rather than accept a self-signed receipt. Configure
  // EMILIA_TRUSTED_KEYS (pinned issuer SPKI), or EMILIA_ALLOW_INLINE_KEY=1 for
  // non-production demos only.
  if (!trustedKeys().length && !allowInlineKey()) {
    return {
      status: 500,
      body: {
        rejected: { reason: 'receipt_enforcement_misconfigured' },
        detail: 'Set EMILIA_TRUSTED_KEYS to the issuer key(s) you trust; '
          + 'refusing to accept self-signed receipts for a destructive action.',
      },
    };
  }

  const assurance = assuranceConfiguration(req.assurance_class);
  if (!assurance) {
    return {
      status: 500,
      body: {
        rejected: { reason: 'receipt_assurance_misconfigured' },
        detail: 'Configure EMILIA_APPROVER_KEYS_JSON, EMILIA_RP_ID, and '
          + 'EMILIA_ALLOWED_ORIGINS; refusing to trust presenter-supplied human assurance.',
      },
    };
  }

  // Bind the receipt to the SPECIFIC target (e.g. the table), so a receipt
  // approving "wipe customers" can't also wipe "orders". The gate runs the
  // action and consumes the receipt after any execution attempt.
  const r = await gateFor(req, assurance).run(
    receipt,
    { target: args?.table },
    async () => performDangerousAction(name, args),
  );

  if (r.ok) {
    return { status: 200, body: { ...r.result, evidence: { receipt_id: r.receiptId, outcome: r.outcome, signer: r.signer } } };
  }
  return { status: r.status, body: r.body };
}

// SPDX-License-Identifier: Apache-2.0
//
// Shared kit for the canonical MCP examples — the "Receipt Required" rail.
//
// The gate is MANIFEST-DRIVEN: it reads /.well-known/agent-actions.json to
// learn which tools require a receipt (and at what assurance/quorum), then
// enforces the full ritual against the REAL verifier in
// @emilia-protocol/require-receipt — no API, no key, no EP server trusted:
//
//   1. dangerous tool, NO receipt        -> 428 Receipt Required (refused)
//   2. named human signs the exact action -> EP-RECEIPT-v1, retry -> runs
//   3. the SAME receipt replayed          -> refused (one-time consumption)
//   4. a forged receipt                   -> refused (signature fails)

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  receiptChallenge,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
} from '../../packages/require-receipt/index.js';
import { makeReceiptGate } from '../../packages/require-receipt/gate.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, '../../public/.well-known/agent-actions.json'), 'utf8'));
const MANIFEST_URL = MANIFEST.service?.manifest_url || '/.well-known/agent-actions.json';
const RR = RECEIPT_REQUIRED_STATUS; // 428

const FAST = !!process.env.FAST;
const pause = (ms: number): Promise<void> => (FAST ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));
export const line = (s = ''): void => console.log(s);
const rule = (): void => line('─'.repeat(66));

// EP-RECEIPT-v1 canonical signer (byte-identical to @emilia-protocol/verify).
const canonicalize = (v: any): string => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v));

// Self-contained DEMO ceremony. The gate still verifies a real P-256
// WebAuthn-shaped assertion against relying-party-pinned keys, RP ID, origin,
// and quorum policy. Production integrations replace these process-local demo
// keys with enrolled passkey credentials and their own organizational policy.
const DEMO_RP_ID = 'mcp-demo.emiliaprotocol.ai';
const DEMO_ORIGIN = `https://${DEMO_RP_ID}`;
const makeDemoApprover = (keyId: string, approverId: string): any => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    keyId,
    approverId,
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
};
const DEMO_APPROVERS = [
  makeDemoApprover('mcp-demo-approver-1', 'ep:approver:demo-primary'),
  makeDemoApprover('mcp-demo-approver-2', 'ep:approver:demo-secondary'),
];
const DEMO_APPROVER_KEYS = Object.freeze(Object.fromEntries(DEMO_APPROVERS.map((entry) => [
  entry.keyId,
  Object.freeze({
    public_key: entry.publicKey,
    key_class: 'A',
    approver_id: entry.approverId,
  }),
])));
const DEMO_QUORUM_POLICY = Object.freeze({
  mode: 'threshold',
  required: 2,
  distinct_humans: true,
  window_sec: 900,
  approvers: Object.freeze(DEMO_APPROVERS.map((entry, index) => Object.freeze({
    role: index === 0 ? 'operator' : 'reviewer',
    approver: entry.approverId,
  }))),
});
const sha256 = (value: string | Buffer): Buffer => crypto.createHash('sha256').update(value).digest();
const sha256Hex = (value: string | Buffer): string => crypto.createHash('sha256').update(value).digest('hex');

function demoWebAuthnSignoff(payload: any, approver: any): any {
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
    Buffer.from([0x05]), // user present + user verified
    counter,
  ]);
  const signature = crypto.sign(
    'sha256',
    Buffer.concat([authenticatorData, sha256(clientDataBytes)]),
    approver.privateKey,
  );
  return {
    contextHash,
    signoff: {
      approver_key_id: approver.keyId,
      key_class: 'A',
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientDataBytes.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
  };
}

function demoAssuranceProof(payload: any, { outcome, quorum, duplicateQuorum = false }: { outcome: any; quorum?: any; duplicateQuorum?: boolean }): any {
  if (outcome !== 'allow_with_signoff') return null;
  const approvers = quorum?.required
    ? (duplicateQuorum ? [DEMO_APPROVERS[0], DEMO_APPROVERS[0]] : DEMO_APPROVERS)
    : [DEMO_APPROVERS[0]];
  const signed = approvers.map((entry) => demoWebAuthnSignoff(payload, entry));
  return {
    '@version': 'EP-ASSURANCE-PROOF-v1',
    context_hash: signed[0].contextHash,
    signoffs: signed.map((entry) => entry.signoff),
  };
}

type DemoQuorum = {
  required?: boolean;
  m?: number;
  second_approver?: string;
};

type SignActionOptions = {
  approver?: string;
  outcome?: string;
  quorum?: DemoQuorum | null;
  tamper?: boolean;
};

// A named human's device signs the EXACT action. Minted locally here so the
// demo is self-contained; in production it's a real Face ID / passkey signoff.
export function signAction(
  action: string,
  { approver, outcome = 'allow_with_signoff', quorum = null, tamper = false }: SignActionOptions = {}
): any {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const duplicateQuorum = quorum?.required && quorum.second_approver === approver;
  const quorumClaim = quorum?.required
    ? {
        quorum: {
          threshold: quorum.m || 2,
          signers: duplicateQuorum
            ? [DEMO_APPROVERS[0].approverId, DEMO_APPROVERS[0].approverId]
            : DEMO_APPROVERS.map((entry) => entry.approverId),
        },
      }
    : {};
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome,
      approver: DEMO_APPROVERS[0].approverId,
      approver_display: approver || DEMO_APPROVERS[0].approverId,
      ...quorumClaim,
    },
  };
  const assuranceProof = demoAssuranceProof(payload, { outcome, quorum, duplicateQuorum });
  if (assuranceProof) (payload as any).assurance_proof = assuranceProof;
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
  if (tamper) doc.payload = { ...payload, claim: { ...payload.claim, action_type: 'something.harmless' } };
  return doc;
}

// Per-tool identifying argument — the resource a dangerous tool actually acts on.
// The receipt is bound to action_type PLUS this target id, so a receipt approving
// (e.g.) "delete repo acme/billing-core" can't be replayed to delete a different
// repo. Tools/args not listed here bind to the bare action_type.
const TARGET_ARG = {
  release_payment: 'destination',
  delete_repo: 'repo',
  deploy_production: 'service',
  run_destructive_sql: 'database',
  export_customer_data: 'workspace',
};

// The exact action a receipt must be bound to for this call: action_type, plus
// the specific target id when the tool acts on an identifiable resource.
export function actionForCall(tool: string, action: string, args: any = {}): string {
  const target = args?.[TARGET_ARG[tool as keyof typeof TARGET_ARG]];
  return target != null ? `${action}:${target}` : action;
}

// A manifest-driven MCP tool dispatcher. The manifest decides whether a tool
// requires a receipt; the canonical makeReceiptGate enforces verify + per-target
// action-binding + reserve→run→commit-after-invocation (replay-safe, one-time
// consumption) + sanitized {reason} rejections. Read-only / unlisted
// tools pass straight through. One gate PER action_type (each keeps its own
// consumed store) so the binding/replay guarantees are per-resource.
export function makeGuardedServer({ tool }: { tool: string }): any {
  const gates = new Map(); // action_type -> makeReceiptGate (own consumed store)
  const gateFor = (req: any): any => {
    let gate = gates.get(req.action_type);
    if (!gate) {
      gate = makeReceiptGate({
        action: req.action_type, // gate appends ":<target>" for the bound action
        allowInlineKey: true,
        maxAgeSec: req.max_age_sec,
        statusCode: RR,
        manifestUrl: MANIFEST_URL,
        assuranceClass: req.assurance_class,
        quorum: req.quorum,
        approverKeys: DEMO_APPROVER_KEYS,
        rpId: DEMO_RP_ID,
        allowedOrigins: [DEMO_ORIGIN],
        ...(req.assurance_class === 'quorum' ? { quorumPolicy: DEMO_QUORUM_POLICY } : {}),
      });
      gates.set(req.action_type, gate);
    }
    return gate;
  };

  return async function callTool(name: string, args: Record<string, any> = {}, receipt: any = null): Promise<any> {
    const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });
    if (!req || !req.receipt_required) {
      return { status: 200, body: { ran: true, note: 'read-only / unlisted in manifest — passes through' } };
    }
    // The identifying arg (the resource this dangerous tool acts on); the gate
    // folds it into the bound action as action_type:<target>, so a receipt for
    // one resource can't drive another. null -> binds to the bare action_type.
    const target = args?.[TARGET_ARG[name]] ?? undefined;
    const gate = gateFor(req);
    const action = gate.boundActionFor(target);

    // run() = verify+reserve → perform → commit after any invocation attempt.
    // An exception is indeterminate and burns the approval to prevent replay.
    const res = await gate.run(receipt, { target }, async () => ({ ran: true, action, ...args }));
    if (!res.ok) return { status: res.status, body: res.body }; // 428 challenge / {rejected:{reason}}
    return {
      status: 200,
      body: { ...res.result, evidence: { receipt_id: res.receiptId, outcome: res.outcome, signer: res.signer } },
    };
  };
}

const show = (r: any): void => line(`     ← ${r.status} ${r.status === 200 ? 'OK — tool ran' : (r.body.title || 'REFUSED')}${r.body.rejected ? ` (${r.body.rejected.reason})` : ''}`);

// Runs the full Receipt Required ritual for one dangerous tool.
export async function runDemo({ title, tool, args, approver, agentLine }: { title: string; tool: string; args: any; approver: string; agentLine: string }): Promise<void> {
  const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool });
  if (!req) throw new Error(`tool "${tool}" not found in the Action Risk Manifest`);
  const action = req.action_type;
  const server = makeGuardedServer({ tool });
  line();
  line(`  ${title}`);
  rule();
  line(`  manifest: ${tool} → ${action} · receipt_required=${req.receipt_required} · assurance=${req.assurance_class}${req.quorum?.required ? ` · quorum ${req.quorum.m}-of-N` : ''}`);
  await pause(700);

  line(`\n  [agent]  ${agentLine}`);
  line(`           → ${tool}(${Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})`);
  await pause(900);

  line('\n  1. Agent calls the tool with NO receipt');
  let res = await server(tool, args, null);
  show(res);
  line(`     ${res.status} Receipt-Required → bring an ${res.body?.required?.proof_header || 'X-EMILIA-Receipt'} bound to "${action}"`);
  await pause(1000);

  line(`\n  2. A named human reviews the exact action and signs it (${approver})`);
  // The signoff is bound to the SPECIFIC target (action_type:<resource>), so it
  // authorizes exactly this resource — not any other repo/payment/deploy.
  const boundAction = actionForCall(tool, action, args);
  const receipt = signAction(boundAction, { approver, quorum: req.quorum });
  line(`     receipt_id ${receipt.payload.receipt_id} · outcome ${receipt.payload.claim.outcome}`);
  if (receipt.payload.claim.quorum) {
    line(`     quorum ${receipt.payload.claim.quorum.threshold}-of-N · signers ${receipt.payload.claim.quorum.signers.join(', ')}`);
  }
  line('     agent retries WITH the receipt:');
  res = await server(tool, args, receipt);
  show(res);
  if (res.status === 200) line(`     tool performed; evidence ${res.body.evidence.receipt_id} verifies offline, trusting no one`);
  await pause(900);

  line('\n  3. The SAME receipt is presented again (replay)');
  res = await server(tool, args, receipt);
  show(res);
  await pause(700);

  line('\n  4. A forged receipt (a signed field altered) is presented');
  res = await server(tool, args, signAction(boundAction, { approver, quorum: req.quorum, tamper: true }));
  show(res);

  if (req.quorum?.required) {
    line(`\n  note: the manifest escalates ${tool} to a ${req.quorum.m}-of-N quorum (EP-QUORUM-v1);`);
    line('        the demo receipt carries two distinct human approvers, and a single-signoff receipt is refused.');
  }
  line('\n  No receipt, no irreversible action. If it ran, anyone can verify who authorized exactly what.');
  line();
}

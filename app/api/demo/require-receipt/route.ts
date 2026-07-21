/**
 * POST /api/demo/require-receipt
 * @license Apache-2.0
 *
 * Public, unauthenticated demo of the DEMAND side of EMILIA: the
 * "No receipt, no irreversible action" loop made runnable over HTTP.
 *
 * The route guards three consequential actions:
 *   - release funds
 *   - delete a repository
 *   - change a vendor bank account
 *
 * The sequence is the product:
 *   - No receipt      -> 428 Receipt Required
 *   - Valid receipt   -> 200 + evidence packet
 *   - Same receipt    -> 428 replay_refused
 *   - Forged receipt  -> 428 verifier rejection
 *
 * This is not auth ("who are you") and not permissions ("are you allowed").
 * It is portable accountability evidence the service keeps: proof that a named
 * human accountably authorized this exact action, under this policy.
 *
 * Reference semantics: integrity-only trust (`allowInlineKey: true`) so anyone
 * can try the loop with a self-signed EP-RECEIPT-v1 document. Production
 * integrations pin trusted issuer keys.
 *
 * Present a receipt via header `X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)`
 * or body `{ "emilia_receipt": <doc> }`.
 */

import { NextResponse, NextRequest } from 'next/server';
import crypto from 'node:crypto';
import {
  RECEIPT_PROOF_HEADER,
  RECEIPT_REQUIRED_HEADER,
  RECEIPT_REQUIRED_STATUS,
  parseReceiptCarrier,
  receiptChallenge,
  receiptRequiredHeader,
} from '../../../../packages/require-receipt/index.js';
import { makeReceiptGate } from '../../../../packages/require-receipt/gate.js';
import { readLimitedJson } from '@/lib/http/body-limit';

export const runtime = 'nodejs';

const MAX_RECEIPT_DEMO_BYTES = 256 * 1024;
const MANIFEST_URL = '/.well-known/agent-actions.json';
const RR = RECEIPT_REQUIRED_STATUS;

const DEMO_ACTIONS = {
  release_funds: {
    id: 'release_funds',
    label: 'Release funds',
    action_type: 'payment.release',
    target: 'wire:vendor-acme-250000',
    assurance_class: 'class_a',
    quorum: { required: false },
    policy_id: 'demo.payment-release.class-a.v1',
    mutation: 'Release a $250,000 vendor payment.',
    evidence_kind: 'money_movement',
  },
  delete_repo: {
    id: 'delete_repo',
    label: 'Delete repository',
    action_type: 'github.repo.delete',
    target: 'repo:emilia/prod-ledger',
    assurance_class: 'quorum',
    quorum: { required: true, mode: 'm_of_n', m: 2, distinct_humans: true },
    policy_id: 'demo.github-repo-delete.quorum.v1',
    mutation: 'Delete the emilia/prod-ledger repository.',
    evidence_kind: 'code_state',
  },
  change_bank_account: {
    id: 'change_bank_account',
    label: 'Change bank account',
    action_type: 'payment.bank_details.change',
    target: 'vendor:acme-routing-9124',
    assurance_class: 'class_a',
    quorum: { required: false },
    policy_id: 'demo.vendor-bank-change.class-a.v1',
    mutation: 'Change ACME vendor payout destination.',
    evidence_kind: 'payment_destination',
  },
};

const DEFAULT_DEMO = 'release_funds';
const gates = new Map();
const DEMO_RP_ID = 'www.emiliaprotocol.ai';
const DEMO_ORIGIN = `https://${DEMO_RP_ID}`;

function createDemoApprover(keyId: string, approverId: string): any {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    keyId,
    approverId,
    privateKey,
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const DEMO_APPROVERS = [
  createDemoApprover('http-demo-approver-1', 'ep:approver:demo-primary'),
  createDemoApprover('http-demo-approver-2', 'ep:approver:demo-secondary'),
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

function canonicalize(v: any): string {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

function sha256(value: Buffer | string): Buffer {
  return crypto.createHash('sha256').update(value).digest();
}

function sha256Hex(value: Buffer | string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

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
    Buffer.from([0x05]),
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

function demoAssuranceProof(payload: any, requiresQuorum: boolean): any {
  const signed = (requiresQuorum ? DEMO_APPROVERS : [DEMO_APPROVERS[0]])
    .map((entry) => demoWebAuthnSignoff(payload, entry));
  return {
    '@version': 'EP-ASSURANCE-PROOF-v1',
    context_hash: signed[0].contextHash,
    signoffs: signed.map((entry) => entry.signoff),
  };
}

function boundActionFor(demo: any): string {
  return `${demo.action_type}:${demo.target}`;
}

function selectDemo(body: Record<string, any> = {}): any {
  const selector = body?.demo || body?.scenario || body?.action || body?.action_type || DEFAULT_DEMO;
  return Object.values(DEMO_ACTIONS).find((demo: any) =>
    selector === demo.id || selector === demo.action_type || selector === boundActionFor(demo),
  ) || DEMO_ACTIONS[DEFAULT_DEMO];
}

function gateFor(demo: any): any {
  if (!gates.has(demo.id)) {
    gates.set(demo.id, makeReceiptGate({
      action: demo.action_type,
      allowInlineKey: true,
      allowedOutcomes: ['allow', 'allow_with_signoff'],
      assuranceClass: demo.assurance_class,
      quorum: demo.quorum,
      manifestUrl: MANIFEST_URL,
      maxAgeSec: 900,
      statusCode: RR,
      approverKeys: DEMO_APPROVER_KEYS,
      rpId: DEMO_RP_ID,
      allowedOrigins: [DEMO_ORIGIN],
      ...(demo.quorum?.required ? { quorumPolicy: DEMO_QUORUM_POLICY } : {}),
    }));
  }
  return gates.get(demo.id);
}

function challengeHeaders(demo: any): Record<string, string> {
  return {
    [RECEIPT_REQUIRED_HEADER]: receiptRequiredHeader({
      action: boundActionFor(demo),
      assuranceClass: demo.assurance_class,
      quorum: demo.quorum,
      manifestUrl: MANIFEST_URL,
      maxAgeSec: 900,
      proofHeader: RECEIPT_PROOF_HEADER,
    }),
    'Cache-Control': 'no-store',
  };
}

function bodySummary(demo: any): any {
  return {
    id: demo.id,
    label: demo.label,
    action: boundActionFor(demo),
    action_type: demo.action_type,
    target: demo.target,
    assurance_class: demo.assurance_class,
    quorum: demo.quorum,
    policy_id: demo.policy_id,
  };
}

function refusedResponse(demo: any, body: any, status: number = RR): NextResponse {
  return NextResponse.json(
    {
      ...body,
      demo: bodySummary(demo),
      loop: {
        invariant: 'No receipt, no irreversible action.',
        product: 'EMILIA makes agent accountability verifiable.',
      },
    },
    { status, headers: challengeHeaders(demo) },
  );
}

function receiptOptions(demo: any): any {
  return {
    status: RR,
    manifestUrl: MANIFEST_URL,
    assuranceClass: demo.assurance_class,
    quorum: demo.quorum,
    maxAgeSec: 900,
  };
}

function signDemoReceipt(demo: any): any {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const quorumClaim = demo.quorum?.required
    ? {
        quorum: {
          threshold: demo.quorum.m || 2,
          signers: DEMO_APPROVERS.map((entry) => entry.approverId),
        },
      }
    : {};
  const payload: any = {
    receipt_id: `rcpt_demo_${crypto.randomBytes(8).toString('hex')}`,
    subject: 'agent:demo-breaker',
    created_at: new Date().toISOString(),
    claim: {
      action_type: boundActionFor(demo),
      outcome: 'allow_with_signoff',
      approver: DEMO_APPROVERS[0].approverId,
      policy_id: demo.policy_id,
      assurance_class: demo.assurance_class,
      ...quorumClaim,
    },
  };
  payload.assurance_proof = demoAssuranceProof(payload, demo.quorum?.required === true);
  const value = crypto
    .sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey)
    .toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value },
    public_key: publicKeyB64u,
  };
}

export async function POST(request: NextRequest) {
  const parsed = await readLimitedJson(request, MAX_RECEIPT_DEMO_BYTES, { invalidValue: {} });
  const body = parsed.ok ? parsed.value : {};
  const demo = selectDemo(body as Record<string, any>);

  if (!parsed.ok) {
    return refusedResponse(
      demo,
      receiptChallenge(
        boundActionFor(demo),
        'Refusing a consequential action: request body is too large.',
        receiptOptions(demo),
      ),
      413,
    );
  }

  if (body?.sign_demo_receipt === true || body?.intent === 'sign_demo_receipt') {
    const receipt = signDemoReceipt(demo);
    return NextResponse.json({
      status: 200,
      demo: bodySummary(demo),
      receipt,
      note: 'Automated test fixture only: it demonstrates verification and enforcement, not a real human ceremony. Production gates pin issuer and enrolled approver keys.',
      signed: {
        action: boundActionFor(demo),
        policy_id: demo.policy_id,
        assurance_class: demo.assurance_class,
        receipt_id: receipt.payload.receipt_id,
      },
    }, { headers: { 'Cache-Control': 'no-store' } });
  }

  let doc: any = null;
  if (body?.emilia_receipt) doc = body.emilia_receipt;
  if (!doc) {
    const hdr = request.headers.get('x-emilia-receipt');
    if (hdr) doc = parseReceiptCarrier(hdr, { maxBytes: MAX_RECEIPT_DEMO_BYTES });
  }

  if (!doc) {
    return refusedResponse(
      demo,
      {
        ...receiptChallenge(
          boundActionFor(demo),
          'Refusing a consequential action: no EMILIA authorization receipt was presented.',
          receiptOptions(demo),
        ),
        to_proceed: [
          `Sign an EP-RECEIPT-v1 receipt bound to "${boundActionFor(demo)}".`,
          `Retry with header ${RECEIPT_PROOF_HEADER}: base64(<EP-RECEIPT-v1 JSON>) or body { "emilia_receipt": <doc> }.`,
        ],
        verifier: 'Offline Ed25519 over canonical JSON. Demo accepts inline self-signed keys; production pins trusted issuer keys.',
      },
    );
  }

  const out = await gateFor(demo).run(doc, { target: demo.target }, async (verified: any) => ({
    simulated: true,
    mutation: demo.mutation,
    authorized_action: verified.boundAction,
  }));
  if (!out.ok) {
    return refusedResponse(demo, out.body, out.status);
  }

  return NextResponse.json({
    status: 200,
    allowed: true,
    demo: bodySummary(demo),
    action: out.result.authorized_action,
    note: 'Demo only - no money moved, repo was deleted, or bank account changed.',
    result: out.result,
    evidence: {
      receipt_id: out.receiptId,
      outcome: out.outcome,
      signer: out.signer,
    },
    evidence_packet: {
      '@version': 'EP-DEMO-EVIDENCE-v1',
      statement: 'This automated fixture demonstrates exact-action verification, pinned ceremony checks, and one-time enforcement. It is not evidence that a real person approved an action.',
      receipt_id: out.receiptId,
      authorized_action: out.result.authorized_action,
      policy_id: demo.policy_id,
      evidence_kind: demo.evidence_kind,
      checks: [
        'missing_receipt_refuses_428',
        'exact_action_receipt_verifies_offline',
        'receipt_consumed_once',
        'replay_refused',
        'tamper_refused',
      ],
      verifier: {
        offline: true,
        algorithm: 'Ed25519 receipt plus P-256 WebAuthn-shaped assurance over a bound context',
        production_note: 'Pin trusted issuer keys, enrolled approver keys, RP ID, and origins. Inline receipt keys and server-generated ceremony fixtures are accepted here only for a public self-contained demo.',
      },
    },
  }, { headers: { 'Cache-Control': 'no-store' } });
}

export async function GET(): Promise<NextResponse> {
  return NextResponse.json({
    title: 'EMILIA Receipt Required HTTP demo',
    invariant: 'No receipt, no irreversible action.',
    core_message: 'EMILIA makes agent accountability verifiable. Before an agent changes money, code, permissions, records, or regulated state, the system requires a receipt. If the action runs, anyone can verify who approved exactly what, under which policy, without trusting our server.',
    actions: Object.values(DEMO_ACTIONS).map(bodySummary),
    try_it: {
      refuse: `POST here with { "demo": "${DEFAULT_DEMO}" } and no receipt -> 428 Receipt Required.`,
      sign: 'POST here with { "demo": "release_funds", "sign_demo_receipt": true } -> demo EP-RECEIPT-v1 bound to the exact action.',
      allow: `POST here with ${RECEIPT_PROOF_HEADER}: base64(<EP-RECEIPT-v1 JSON>) bound to the demo action -> 200 + evidence_packet.`,
      replay: 'POST the same receipt again -> 428 replay_refused.',
      forged: 'Tamper with the receipt payload -> 428 untrusted_or_invalid_signature.',
    },
    docs: 'https://www.emiliaprotocol.ai/gate',
  }, { headers: { 'Cache-Control': 'no-store' } });
}

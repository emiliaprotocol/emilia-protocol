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

import { NextResponse } from 'next/server';
import crypto from 'node:crypto';
import {
  RECEIPT_PROOF_HEADER,
  RECEIPT_REQUIRED_HEADER,
  RECEIPT_REQUIRED_STATUS,
  receiptChallenge,
  receiptRequiredHeader,
} from '@/packages/require-receipt/index.js';
import { makeReceiptGate } from '@/packages/require-receipt/gate.js';
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
    policy_id: 'demo.vendor-bank-change.class-a.v1',
    mutation: 'Change ACME vendor payout destination.',
    evidence_kind: 'payment_destination',
  },
};

const DEFAULT_DEMO = 'release_funds';
const gates = new Map();

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

function boundActionFor(demo) {
  return `${demo.action_type}:${demo.target}`;
}

function selectDemo(body = {}) {
  const selector = body?.demo || body?.scenario || body?.action || body?.action_type || DEFAULT_DEMO;
  return Object.values(DEMO_ACTIONS).find((demo) =>
    selector === demo.id || selector === demo.action_type || selector === boundActionFor(demo),
  ) || DEMO_ACTIONS[DEFAULT_DEMO];
}

function gateFor(demo) {
  if (!gates.has(demo.id)) {
    gates.set(demo.id, makeReceiptGate({
      action: demo.action_type,
      allowInlineKey: true,
      allowedOutcomes: ['allow', 'allow_with_signoff'],
      assuranceClass: demo.assurance_class,
      manifestUrl: MANIFEST_URL,
      maxAgeSec: 900,
      statusCode: RR,
    }));
  }
  return gates.get(demo.id);
}

function challengeHeaders(demo) {
  return {
    [RECEIPT_REQUIRED_HEADER]: receiptRequiredHeader({
      action: boundActionFor(demo),
      assuranceClass: demo.assurance_class,
      manifestUrl: MANIFEST_URL,
      maxAgeSec: 900,
      proofHeader: RECEIPT_PROOF_HEADER,
    }),
    'Cache-Control': 'no-store',
  };
}

function bodySummary(demo) {
  return {
    id: demo.id,
    label: demo.label,
    action: boundActionFor(demo),
    action_type: demo.action_type,
    target: demo.target,
    assurance_class: demo.assurance_class,
    policy_id: demo.policy_id,
  };
}

function refusedResponse(demo, body, status = RR) {
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

function receiptOptions(demo) {
  return {
    status: RR,
    manifestUrl: MANIFEST_URL,
    assuranceClass: demo.assurance_class,
    maxAgeSec: 900,
  };
}

function signDemoReceipt(demo, approver) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const signer = approver || 'ep:approver:demo-human';
  const quorumClaim = demo.assurance_class === 'quorum'
    ? { quorum: { signers: [signer, 'ep:approver:demo-second-human'], threshold: 2 } }
    : {};
  const payload = {
    receipt_id: `rcpt_demo_${crypto.randomBytes(8).toString('hex')}`,
    subject: 'agent:demo-breaker',
    created_at: new Date().toISOString(),
    claim: {
      action_type: boundActionFor(demo),
      outcome: 'allow_with_signoff',
      approver: signer,
      policy_id: demo.policy_id,
      assurance_class: demo.assurance_class,
      ...quorumClaim,
    },
  };
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

export async function POST(request) {
  const parsed = await readLimitedJson(request, MAX_RECEIPT_DEMO_BYTES, { invalidValue: {} });
  const body = parsed.ok ? parsed.value : {};
  const demo = selectDemo(body);

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
    const receipt = signDemoReceipt(demo, body?.approver);
    return NextResponse.json({
      status: 200,
      demo: bodySummary(demo),
      receipt,
      note: 'Demo-only self-signed receipt. Production gates pin trusted issuer keys.',
      signed: {
        action: boundActionFor(demo),
        policy_id: demo.policy_id,
        assurance_class: demo.assurance_class,
        receipt_id: receipt.payload.receipt_id,
      },
    }, { headers: { 'Cache-Control': 'no-store' } });
  }

  let doc = null;
  if (body?.emilia_receipt) doc = body.emilia_receipt;
  if (!doc) {
    const hdr = request.headers.get('x-emilia-receipt');
    if (hdr) {
      try {
        doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8'));
      } catch {
        doc = null;
      }
    }
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

  const out = await gateFor(demo).run(doc, { target: demo.target }, async (verified) => ({
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
      statement: "EMILIA makes agent accountability verifiable. If the action runs, anyone can verify who approved exactly what, under which policy, without trusting EMILIA's server.",
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
        algorithm: 'Ed25519 over canonical JSON',
        production_note: 'Pin trusted issuer keys; inline keys are accepted here only for a public self-contained demo.',
      },
    },
  }, { headers: { 'Cache-Control': 'no-store' } });
}

export async function GET() {
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

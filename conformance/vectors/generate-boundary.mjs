// SPDX-License-Identifier: Apache-2.0
//
// Generates boundary.v1.json — the authorization/attribution boundary suite
// (claim-matrix rows C-011 accepted-result and C-012 authorization/attribution
// boundary; see docs/standards-engagement/EP-CLAIM-MATRIX-MAPPING.md).
//
// Two named negative cases the mapping promised:
//   • attribution_substituted_for_authorization — a VALIDLY SIGNED
//     post-execution attribution record presented in the pre-execution
//     authorization (receipt) slot MUST be refused. The signature is genuine;
//     the refusal comes from the version gate. Attribution is not authority.
//   • raw_claim_pass_through — a document whose payload SELF-ASSERTS authority
//     ("authorized": true, an embedded verifier_result claiming valid) over a
//     signature that does not verify. An implementation that consumes raw
//     peer-provided claims instead of its own verifier's constrained result
//     answers true here and diverges from every conforming implementation.
//
//   node conformance/vectors/generate-boundary.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalize } from '../../packages/verify/index.js';

const here = dirname(fileURLToPath(import.meta.url));

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyB64u = publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const sign = (payload) =>
  crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');

// A genuine pre-execution authorization receipt (control case).
const authorizedPayload = {
  receipt_id: 'tr_boundary_pre',
  issuer: 'ep:approver:boundary-demo',
  subject: 'wire_transfer/vendor-482',
  action_digest: 'sha256:7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
  created_at: '2026-07-05T12:00:00Z',
};

// A post-execution attribution record: who was RECORDED as having executed the
// action, after it ran. Signed with the SAME genuine key and convention — the
// signature verifies; the artifact class is what must be refused.
const attributionPayload = {
  attribution_id: 'attr_boundary_post',
  executor: 'ep:entity:payments-agent',
  executed_at: '2026-07-05T12:00:07Z',
  action_digest: 'sha256:7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
  recorded_by: 'ep:log:boundary-demo',
};

// A payload that carries its own claims of authority and a forged embedded
// "verifier result". The signature below is computed over DIFFERENT bytes, so
// no conforming verifier accepts it — only an implementation that trusts the
// raw payload would.
const passThroughPayload = {
  receipt_id: 'tr_boundary_raw',
  issuer: 'ep:approver:boundary-demo',
  subject: 'wire_transfer/vendor-482',
  authorized: true,
  scope: 'unlimited',
  verifier_result: { valid: true, checks: { version: true, signature: true } },
  created_at: '2026-07-05T12:00:00Z',
};

const suite = {
  suite: 'EP-BOUNDARY-v1',
  vectors_version: '1.0.0',
  description:
    'Authorization/attribution boundary suite (claim-matrix C-011/C-012). ' +
    'Pre-execution authority and post-execution attribution are different claims: ' +
    'a validly signed attribution record presented as authorization is refused at ' +
    'the version gate, and a payload self-asserting authority over a bad signature ' +
    'is refused because conforming implementations consume the verifier result, ' +
    'never raw peer-provided claims.',
  algorithm: 'Ed25519 over RFC 8785 (JCS) canonical payload bytes',
  count: 3,
  vectors: [
    {
      id: 'accept_pre_execution_receipt',
      description:
        'Control: a genuine EP-RECEIPT-v1 signed before execution over the canonical action verifies.',
      expect: { valid: true },
      public_key: publicKeyB64u,
      document: {
        '@version': 'EP-RECEIPT-v1',
        payload: authorizedPayload,
        signature: { algorithm: 'Ed25519', value: sign(authorizedPayload) },
      },
    },
    {
      id: 'attribution_substituted_for_authorization',
      description:
        'A post-execution attribution record (EP-ATTRIBUTION-v1), signed with a GENUINE key, ' +
        'presented in the pre-execution authorization slot. MUST be refused: the version gate ' +
        'rejects the artifact class even though the signature verifies. Attribution states who ' +
        'was recorded as executing; it never grants or proves authority (C-012).',
      expect: { valid: false },
      public_key: publicKeyB64u,
      document: {
        '@version': 'EP-ATTRIBUTION-v1',
        payload: attributionPayload,
        signature: { algorithm: 'Ed25519', value: sign(attributionPayload) },
      },
    },
    {
      id: 'raw_claim_pass_through',
      description:
        'The payload self-asserts authority ("authorized": true, "scope": "unlimited") and embeds ' +
        'a forged verifier_result claiming valid — but the signature does not cover these bytes. ' +
        'MUST be refused. An implementation that consumes raw peer-provided claims instead of its ' +
        'own verifier’s constrained result answers true here and diverges (C-011).',
      expect: { valid: false },
      public_key: publicKeyB64u,
      document: {
        '@version': 'EP-RECEIPT-v1',
        payload: passThroughPayload,
        // Signed over the attribution payload, NOT passThroughPayload: a real
        // signature, wrong bytes. The embedded verifier_result is a lie.
        signature: { algorithm: 'Ed25519', value: sign(attributionPayload) },
      },
    },
  ],
};

writeFileSync(resolve(here, 'boundary.v1.json'), JSON.stringify(suite, null, 1) + '\n');
console.log('wrote boundary.v1.json (3 vectors)');

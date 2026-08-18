// SPDX-License-Identifier: Apache-2.0
//
// EP-POLICY-DECISION-EVIDENCE-v2 hostile matrix. The PQ leg runs for real.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';

import { digestAeb } from '../packages/verify/src/aeb-adapter-contract.ts';
import {
  POLICY_DECISION_EVIDENCE_VERSION,
  POLICY_DECISION_EVIDENCE_CONFIG_VERSION,
  POLICY_DECISION_EVIDENCE_V2_VERSION,
  POLICY_DECISION_EVIDENCE_V2_TYP,
  POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS,
  policyDecisionEvidenceV2ProtectedHeader,
  signPolicyDecisionEvidence,
  signPolicyDecisionEvidenceV2,
  verifyPolicyDecisionEvidenceV2,
  type PolicyDecisionEvidenceHybridStatement,
} from '../packages/verify/src/policy-decision-evidence.ts';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');

const KEY_ID = 'opa-bridge-1';
const PQ_KEY_ID = 'opa-bridge-pq-1';
const PIN = { key_id: KEY_ID, public_key: edPubB64u, pq_key_id: PQ_KEY_ID, pq_public_key: pqPubB64u };
const SIGNER = {
  key_id: KEY_ID, private_key: ed.privateKey, pq_key_id: PQ_KEY_ID, pq_secret_key: pq.secretKey,
};

const ACTION = { action_type: 'payment.transfer.1', parameters: { amount: 100 } };
const POLICY_DIGEST = digestAeb({ policy: 'bundle' });

const CONFIG = {
  '@version': POLICY_DECISION_EVIDENCE_CONFIG_VERSION,
  evidence_role: 'policy-decision',
  subject: { id: 'opa-bridge', kind: 'workload' },
  issuer: 'https://opa.example',
  audience: 'https://gate.example',
  action_type: 'payment.transfer.1',
  allowed_engines: ['opa'],
  allowed_policy_digests: [POLICY_DIGEST],
  clock_skew_seconds: 60,
  max_decision_age_seconds: 900,
} as any;

const CLAIMS = {
  ep_version: POLICY_DECISION_EVIDENCE_V2_VERSION,
  iss: 'https://opa.example',
  sub: 'opa-bridge',
  aud: 'https://gate.example',
  iat: 1_770_000_000,
  exp: 1_770_000_600,
  jti: 'jti-1',
  engine: 'opa',
  policy_id: 'policy.transfer',
  policy_digest: POLICY_DIGEST,
  policy_decision: 'ALLOW',
  action: ACTION,
  action_digest: digestAeb(ACTION),
  native_decision_ref: 'opa:decision:1',
  native_result_digest: digestAeb({ result: 1 }),
} as any;

const build = () => signPolicyDecisionEvidenceV2(CLAIMS, SIGNER);
const clone = (s: PolicyDecisionEvidenceHybridStatement) =>
  JSON.parse(JSON.stringify(s)) as PolicyDecisionEvidenceHybridStatement;
const b64uJson = (v: unknown) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');

describe('EP-POLICY-DECISION-EVIDENCE-v2 happy path', () => {
  it('the real ML-DSA-65 backend is present (never a silent skip)', () => {
    expect(pq.publicKey.length).toBe(1952);
  });

  it('round-trips a hybrid statement under both pinned keys', async () => {
    const statement = await build();
    expect(statement.signatures.map((s) => s.alg)).toEqual(['Ed25519', 'ML-DSA-65']);
    expect(Buffer.from(statement.signatures[1].sig, 'base64url').length).toBe(3309);
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.claims?.policy_decision).toBe('ALLOW');
  });

  it('carries no JOSE alg header and commits the required set inside the signing input', async () => {
    const statement = await build();
    const header = JSON.parse(Buffer.from(statement.protected, 'base64url').toString('utf8'));
    expect(header.alg).toBeUndefined();
    expect(header.typ).toBe(POLICY_DECISION_EVIDENCE_V2_TYP);
    expect(header.required_algorithms).toEqual([...POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS]);
  });
});

describe('EP-POLICY-DECISION-EVIDENCE-v2 hostile matrix', () => {
  it('refuses a stripped ML-DSA leg with the set left intact', async () => {
    const statement = clone(await build());
    statement.signatures = statement.signatures.filter((s) => s.alg !== 'ML-DSA-65');
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.legs_present).toBe(false);
  });

  it('refuses a narrowed set, and the surviving Ed25519 leg no longer verifies', async () => {
    const statement = clone(await build());
    statement.signatures = statement.signatures.filter((s) => s.alg !== 'ML-DSA-65');
    const header = JSON.parse(Buffer.from(statement.protected, 'base64url').toString('utf8'));
    header.required_algorithms = ['Ed25519'];
    statement.protected = b64uJson(header);
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses a widened algorithm set', async () => {
    const statement = clone(await build());
    const header = JSON.parse(Buffer.from(statement.protected, 'base64url').toString('utf8'));
    header.required_algorithms = ['Ed25519', 'ML-DSA-65', 'Ed448'];
    statement.protected = b64uJson(header);
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.algorithm_set).toBe(false);
  });

  it('refuses a wrong-length Ed25519 signature', async () => {
    const statement = clone(await build());
    statement.signatures[0].sig = Buffer.alloc(65).toString('base64url');
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('malformed_signature');
  });

  it('refuses a wrong-length ML-DSA-65 signature', async () => {
    const statement = clone(await build());
    statement.signatures[1].sig = Buffer.alloc(3308).toString('base64url');
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
  });

  it('refuses an Ed448 SPKI pinned as the Ed25519 half', async () => {
    const ed448 = crypto.generateKeyPairSync('ed448');
    const statement = await build();
    const result = await verifyPolicyDecisionEvidenceV2(
      statement,
      { ...PIN, public_key: ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') },
      CONFIG,
    );
    expect(result.valid).toBe(false);
    expect(result.checks.engine_key_pinned).toBe(false);
  });

  it('refuses a tampered payload', async () => {
    const statement = clone(await build());
    statement.payload = b64uJson({ ...CLAIMS, policy_decision: 'DENY' });
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.signature_valid).toBe(false);
    expect(result.checks.signature_binds_statement).toBe(false);
  });

  it('refuses pq_backend_unavailable rather than passing on the classical leg', async () => {
    const statement = await build();
    const result = await verifyPolicyDecisionEvidenceV2(
      statement, PIN, CONFIG, { mldsaBackendLoader: () => null },
    );
    expect(result.valid).toBe(false);
    expect(result.errors.join(' ')).toContain('pq_backend_unavailable');
  });

  it('refuses an unpinned engine key', async () => {
    const statement = await build();
    const result = await verifyPolicyDecisionEvidenceV2(statement, null, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.engine_key_pinned).toBe(false);
  });

  it('never throws on hostile caller input', async () => {
    for (const bad of [null, undefined, 'x', 7, [], { payload: 1 }]) {
      const result = await verifyPolicyDecisionEvidenceV2(bad, PIN, CONFIG);
      expect(result.valid).toBe(false);
    }
  });

  it('the protected-header builder refuses a non-registered algorithm set', () => {
    expect(() => policyDecisionEvidenceV2ProtectedHeader(KEY_ID, PQ_KEY_ID, ['ML-DSA-65']))
      .toThrow(/registered EP-POLICY-DECISION-EVIDENCE-v2 set/);
  });
});

describe('v1 / v2 separation', () => {
  it('the unchanged v1 signer still mints a compact JWS and refuses v2 claims', () => {
    const v1Claims = { ...CLAIMS, ep_version: POLICY_DECISION_EVIDENCE_VERSION };
    const token = signPolicyDecisionEvidence(v1Claims, { key_id: KEY_ID, private_key: ed.privateKey });
    expect(token.split('.')).toHaveLength(3);
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
    expect(header.alg).toBe('EdDSA');
    expect(() => signPolicyDecisionEvidence(CLAIMS, { key_id: KEY_ID, private_key: ed.privateKey }))
      .toThrow(TypeError);
  });

  it('the v2 verifier refuses a v1-versioned header', async () => {
    const statement = clone(await build());
    const header = JSON.parse(Buffer.from(statement.protected, 'base64url').toString('utf8'));
    header.ep_version = POLICY_DECISION_EVIDENCE_VERSION;
    statement.protected = b64uJson(header);
    const result = await verifyPolicyDecisionEvidenceV2(statement, PIN, CONFIG);
    expect(result.valid).toBe(false);
    expect(result.checks.version).toBe(false);
  });
});

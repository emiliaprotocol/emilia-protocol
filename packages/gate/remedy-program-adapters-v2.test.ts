// SPDX-License-Identifier: Apache-2.0
//
// EP-GATE-REMEDY-EVIDENCE-v2 -- hostile matrix for the hybrid Remedy Program
// evidence envelope and the v2 adapter factory. Package-root node:test file
// importing the compatibility shim './remedy-program-adapters.js' (which
// re-exports ./dist/remedy-program-adapters.js), matching this package's
// convention; the v1 adapter suites are untouched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

import {
  REMEDY_PROGRAM_EVIDENCE_VERSION,
  REMEDY_PROGRAM_EVIDENCE_V2_VERSION,
  REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS,
  createRemedyProgramAdapters,
  createRemedyProgramAdaptersV2,
  remedyProgramEvidenceDigest,
  remedyProgramEvidenceSigningBytes,
  signRemedyProgramEvidenceV2,
} from './remedy-program-adapters.js';
import { canonicalize } from './execution-binding.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const HASH = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = (operation: string, character: string) => `caid:1:${operation}.1:jcs-sha256:${character.repeat(43)}`;

const TENANT = 'tenant-a';
const ENVIRONMENT = 'production';
const AUDIENCE = 'remedy-auditor';
const INSTANCE = 'remedy-case-1';
const AUTHORITY_ID = 'authority:dispute-desk';
const KEY_ID = 'dispute-key-1';

function keyFixture() {
  const ed = crypto.generateKeyPairSync('ed25519');
  const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
  return {
    ed,
    keys: {
      ed: { privateKey: ed.privateKey, publicKey: edPubB64u },
      pq: { secretKey: pq.secretKey, publicKey: pqPubB64u },
    },
    edPubB64u,
    pqPubB64u,
  };
}

const ESCROW_KEY = keyFixture();

function disputePayload(over: Record<string, unknown> = {}) {
  return {
    evidence_id: 'dispute-evidence-1',
    tenant_id: TENANT,
    instance_id: INSTANCE,
    dispute_id: 'dispute-1',
    challenger_id: 'buyer-1',
    requested_units: 10_000,
    opened_at: '2026-07-21T18:20:00.000Z',
    original_operation_id: 'payment-op-1',
    original_action_digest: HASH('0'),
    ...over,
  };
}

function storedOriginal() {
  return {
    caid: CAID('payments.capture', 'A'),
    action_digest: HASH('0'),
    operation_id: 'payment-op-1',
    consequence_mode: 'action-escrow',
    consequence_digest: HASH('1'),
    terminal_evidence_digest: HASH('4'),
    outcome: 'executed',
    occurred_at: '2026-07-21T18:10:00.000Z',
    evidence_digest: HASH('4'),
  };
}

function adapterOptions(authority: any, evidence: unknown, over: Record<string, unknown> = {}) {
  return {
    tenantId: TENANT,
    environment: ENVIRONMENT,
    audience: AUDIENCE,
    evidenceSource: { get: async () => evidence },
    actionEscrow: {
      trustedKeys: {
        'escrow-key-1': {
          operator_id: 'operator:escrow',
          public_key: ESCROW_KEY.edPubB64u,
          pq_public_key: ESCROW_KEY.pqPubB64u,
        },
      },
      originalEffects: {
        'payment-op-1': {
          agreementId: 'agreement-1',
          caid: CAID('payments.capture', 'A'),
          bindingDigest: HASH('1'),
          profileDigest: HASH('2'),
          amendmentDigests: [],
        },
      },
    },
    revokerKeys: {},
    // Distinct objects: the pinned-config snapshot canonicalizes the whole
    // options graph, and canonicalize() refuses an aliased reference.
    disputeAuthority: structuredClone(authority),
    remedyAuthority: structuredClone(authority),
    providerAuthority: structuredClone(authority),
    ...over,
  };
}

function disputeInput(evidenceDigest: string) {
  return {
    dispute: {
      evidence_id: 'dispute-evidence-1',
      evidence_digest: evidenceDigest,
      dispute_id: 'dispute-1',
      challenger_id: 'buyer-1',
      requested_units: 10_000,
      opened_at: '2026-07-21T18:20:00.000Z',
    },
    expected: {
      tenant_id: TENANT,
      environment: ENVIRONMENT,
      audience: AUDIENCE,
      instance_id: INSTANCE,
      original: storedOriginal(),
    },
  };
}

async function hybridFixture() {
  const issuer = keyFixture();
  const evidence = await signRemedyProgramEvidenceV2(
    { kind: 'dispute', issuer: { authority_id: AUTHORITY_ID, key_id: KEY_ID }, payload: disputePayload() },
    issuer.keys,
  );
  const authority = {
    authorityId: AUTHORITY_ID,
    trustedKeys: { [KEY_ID]: { public_key: issuer.edPubB64u, pq_public_key: issuer.pqPubB64u } },
  };
  return { issuer, evidence, authority, digest: remedyProgramEvidenceDigest(evidence) };
}

/** Mint a v1 evidence envelope by hand for the v1-refuses-v2 direction. */
function mintV1Evidence(privateKey: crypto.KeyObject) {
  const unsigned = {
    version: REMEDY_PROGRAM_EVIDENCE_VERSION,
    kind: 'dispute',
    issuer: { authority_id: AUTHORITY_ID, key_id: KEY_ID },
    payload: disputePayload(),
  };
  const contentDigest = `sha256:${crypto.createHash('sha256').update(canonicalize(unsigned)).digest('hex')}`;
  const signedBody = { ...unsigned, content_digest: contentDigest };
  const value = crypto.sign(null, remedyProgramEvidenceSigningBytes(signedBody), privateKey)
    .toString('base64url');
  return { ...signedBody, signature: { algorithm: 'Ed25519', value } };
}

/** Run one dispute verification against a possibly-tampered evidence artifact. */
async function verifyDisputeWith(evidence: unknown, authority: any, over: Record<string, unknown> = {}) {
  const digest = remedyProgramEvidenceDigest(evidence);
  const adapters = createRemedyProgramAdaptersV2(adapterOptions(authority, evidence, over) as any);
  return adapters.verifyDispute(disputeInput(digest));
}

describe('EP-GATE-REMEDY-EVIDENCE-v2 hybrid evidence envelope', () => {
  it('valid v2 roundtrip: the hybrid adapters accept a correctly signed dispute', async () => {
    const { evidence, authority } = await hybridFixture();
    assert.equal(evidence.version, REMEDY_PROGRAM_EVIDENCE_V2_VERSION);
    assert.deepEqual(
      evidence.signature.required_algorithms,
      [...REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS],
    );
    assert.deepEqual(
      evidence.signature.signatures.map((s: any) => s.alg),
      [...REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS],
    );

    const result = await verifyDisputeWith(evidence, authority);
    assert.equal(result.ok, true);
    assert.equal((result as any).dispute_id, 'dispute-1');
  });

  it('v1-refuses-v2 and v2-refuses-v1: neither factory accepts the other profile', async () => {
    const { evidence, authority, issuer } = await hybridFixture();
    const v1Authority = { authorityId: AUTHORITY_ID, trustedKeys: { [KEY_ID]: issuer.edPubB64u } };
    const v1Adapters = createRemedyProgramAdapters(adapterOptions(v1Authority, evidence, {
      actionEscrow: {
        trustedKeys: { 'escrow-key-1': { operator_id: 'operator:escrow', public_key: ESCROW_KEY.edPubB64u } },
        originalEffects: adapterOptions(v1Authority, evidence).actionEscrow.originalEffects,
      },
    }) as any);
    assert.equal(
      (await v1Adapters.verifyDispute(disputeInput(remedyProgramEvidenceDigest(evidence)))).ok,
      false,
    );

    const v1Evidence = mintV1Evidence(issuer.ed.privateKey);
    assert.equal((await verifyDisputeWith(v1Evidence, authority)).ok, false);
  });

  it('an authority pinned WITHOUT the ML-DSA half is rejected at construction, never partial credit', async () => {
    const { evidence, issuer } = await hybridFixture();
    const classicalOnly = { authorityId: AUTHORITY_ID, trustedKeys: { [KEY_ID]: issuer.edPubB64u } };
    assert.throws(
      () => createRemedyProgramAdaptersV2(adapterOptions(classicalOnly, evidence) as any),
      /configuration invalid/,
    );
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const { evidence, authority } = await hybridFixture();
    const stripped = {
      ...evidence,
      signature: {
        ...evidence.signature,
        signatures: evidence.signature.signatures.filter((s: any) => s.alg !== 'ML-DSA-65'),
      },
    };
    assert.equal((await verifyDisputeWith(stripped, authority)).ok, false);
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] refuses structurally AND cryptographically', async () => {
    const { evidence, authority } = await hybridFixture();
    const narrowed = {
      ...evidence,
      signature: {
        ...evidence.signature,
        required_algorithms: ['Ed25519'],
        signatures: evidence.signature.signatures.filter((s: any) => s.alg === 'Ed25519'),
      },
    };
    assert.equal((await verifyDisputeWith(narrowed, authority)).ok, false);
    const setIntact = {
      ...narrowed,
      signature: {
        ...narrowed.signature,
        required_algorithms: [...REMEDY_PROGRAM_EVIDENCE_V2_REQUIRED_ALGORITHMS],
      },
    };
    assert.equal((await verifyDisputeWith(setIntact, authority)).ok, false);
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const { evidence, authority } = await hybridFixture();
    const tampered = {
      ...evidence,
      signature: {
        ...evidence.signature,
        signatures: evidence.signature.signatures.map((s: any) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: crypto.randomBytes(16).toString('base64url') } : s
        )),
      },
    };
    assert.equal((await verifyDisputeWith(tampered, authority)).ok, false);
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI as the classical half is rejected at construction', async () => {
    const { evidence, issuer } = await hybridFixture();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueradedAuthority = {
      authorityId: AUTHORITY_ID,
      trustedKeys: { [KEY_ID]: { public_key: ed448PubB64u, pq_public_key: issuer.pqPubB64u } },
    };
    assert.throws(
      () => createRemedyProgramAdaptersV2(adapterOptions(masqueradedAuthority, evidence) as any),
      /configuration invalid/,
    );
  });

  it('an absent ML-DSA backend refuses, never a pass on the Ed25519 leg', async () => {
    const { evidence, authority } = await hybridFixture();
    const result = await verifyDisputeWith(evidence, authority, { mldsaBackend: {} });
    assert.equal(result.ok, false);
  });

  it('a tampered payload breaks the recomputed content digest', async () => {
    const { evidence, authority } = await hybridFixture();
    const tampered = {
      ...evidence,
      payload: { ...evidence.payload, requested_units: 1 },
    };
    assert.equal((await verifyDisputeWith(tampered, authority)).ok, false);
  });

  it('never throws on hostile evidence', async () => {
    const { authority } = await hybridFixture();
    for (const bad of [null, 42, [], { version: REMEDY_PROGRAM_EVIDENCE_V2_VERSION }]) {
      const adapters = createRemedyProgramAdaptersV2(adapterOptions(authority, bad) as any);
      assert.equal((await adapters.verifyDispute(disputeInput(HASH('9')))).ok, false);
    }
  });

  it('refuses to issue an envelope without both halves of the key material', async () => {
    const issuer = keyFixture();
    await assert.rejects(
      signRemedyProgramEvidenceV2(
        { kind: 'dispute', issuer: { authority_id: AUTHORITY_ID, key_id: KEY_ID }, payload: disputePayload() },
        { ed: issuer.keys.ed, pq: { secretKey: issuer.keys.pq.secretKey, publicKey: 'not-a-key' } } as any,
      ),
      /ML-DSA-65 public key/,
    );
  });

  it('the revocation seam is a ROUTER: a v1 revocation statement still verifies under the v2 adapters', async () => {
    const { evidence, authority } = await hybridFixture();
    const revoker = crypto.generateKeyPairSync('ed25519');
    const der = revoker.publicKey.export({ type: 'spki', format: 'der' });
    const publicKeyB64u = der.toString('base64url');
    const body = {
      '@version': 'EP-REVOCATION-v1',
      action_hash: HASH('0'),
      reason: 'authority withdrawn',
      revoked_at: '2026-07-22T00:00:00Z',
      revoker_id: 'revoker:compliance',
      target_id: 'payment-op-1',
      target_type: 'commit',
    };
    const statement = {
      '@version': body['@version'],
      target_type: body.target_type,
      target_id: body.target_id,
      action_hash: body.action_hash,
      revoker_id: body.revoker_id,
      revoked_at: body.revoked_at,
      reason: body.reason,
      proof: {
        algorithm: 'Ed25519',
        revoker_key_id: `ep:revoker-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`,
        signature_b64u: crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), revoker.privateKey)
          .toString('base64url'),
        public_key: publicKeyB64u,
      },
    };
    const adapters = createRemedyProgramAdaptersV2(adapterOptions(authority, statement, {
      revokerKeys: { 'revoker:compliance': { public_key: publicKeyB64u } },
      now: () => Date.parse('2026-07-23T00:00:00Z'),
    }) as any);
    const result = await adapters.verifyRevocation({
      evidence: { id: 'revocation-evidence-1', digest: remedyProgramEvidenceDigest(statement) },
      expected: {
        tenant_id: TENANT,
        environment: ENVIRONMENT,
        audience: AUDIENCE,
        instance_id: INSTANCE,
        original: storedOriginal(),
      },
    });
    assert.equal(result.ok, true);
    assert.equal((result as any).authority_id, 'revoker:compliance');
    // Unrelated evidence still refuses through the same seam.
    const wrong = createRemedyProgramAdaptersV2(adapterOptions(authority, evidence, {
      revokerKeys: { 'revoker:compliance': { public_key: publicKeyB64u } },
      now: () => Date.parse('2026-07-23T00:00:00Z'),
    }) as any);
    assert.equal((await wrong.verifyRevocation({
      evidence: { id: 'revocation-evidence-1', digest: remedyProgramEvidenceDigest(evidence) },
      expected: {
        tenant_id: TENANT,
        environment: ENVIRONMENT,
        audience: AUDIENCE,
        instance_id: INSTANCE,
        original: storedOriginal(),
      },
    })).ok, false);
  });

  it('the revocation loader uses bundle-analyzable imports and resolves the published v2 router', async () => {
    const source = await readFile(
      new URL('./src/remedy-program-adapters.ts', import.meta.url),
      'utf8',
    );
    const importSpecifiers = [...source.matchAll(/\bimport\(([^)]+)\)/g)]
      .map((match) => match[1].trim());
    assert.deepEqual(importSpecifiers, [
      "'@emilia-protocol/verify/revocation.js'",
      "'../../verify/revocation.js'",
    ]);

    const router = await import('@emilia-protocol/verify/revocation.js');
    assert.equal(typeof router.verifyRevocationStatement, 'function');
  });

  it('a v2-marked revocation statement with an empty proof is fail-closed even though the EP-REVOCATION-v2 router now resolves', async () => {
    const { authority } = await hybridFixture();
    // @emilia-protocol/verify now exports the "./revocation" subpath, so the v2
    // router IS resolvable from this package: assert that first, so the refusal
    // below cannot be silently attributed to an unresolvable router. The seam
    // must then REFUSE this malformed v2 statement on its own merits, never
    // downgrade to the v1-only verifier and never pass.
    const router = await import('@emilia-protocol/verify/revocation.js');
    assert.equal(typeof (router as any).verifyRevocationStatement, 'function');
    const statement = {
      '@version': 'EP-REVOCATION-v2',
      target_type: 'commit',
      target_id: 'payment-op-1',
      action_hash: HASH('0'),
      revoker_id: 'revoker:compliance',
      revoked_at: '2026-07-22T00:00:00Z',
      reason: 'authority withdrawn',
      proof: {},
    };
    const adapters = createRemedyProgramAdaptersV2(adapterOptions(authority, statement, {
      revokerKeys: { 'revoker:compliance': {} },
      now: () => Date.parse('2026-07-23T00:00:00Z'),
    }) as any);
    const result = await adapters.verifyRevocation({
      evidence: { id: 'revocation-evidence-1', digest: remedyProgramEvidenceDigest(statement) },
      expected: {
        tenant_id: TENANT,
        environment: ENVIRONMENT,
        audience: AUDIENCE,
        instance_id: INSTANCE,
        original: storedOriginal(),
      },
    });
    assert.equal(result.ok, false);
  });

  it('the v1 factory still accepts the v1 pin shape and a v1 envelope, unchanged', async () => {
    const issuer = keyFixture();
    const v1Evidence = mintV1Evidence(issuer.ed.privateKey);
    const v1Authority = { authorityId: AUTHORITY_ID, trustedKeys: { [KEY_ID]: issuer.edPubB64u } };
    const adapters = createRemedyProgramAdapters({
      ...adapterOptions(v1Authority, v1Evidence),
      actionEscrow: {
        trustedKeys: { 'escrow-key-1': { operator_id: 'operator:escrow', public_key: ESCROW_KEY.edPubB64u } },
        originalEffects: adapterOptions(v1Authority, v1Evidence).actionEscrow.originalEffects,
      },
    } as any);
    const result = await adapters.verifyDispute(disputeInput(remedyProgramEvidenceDigest(v1Evidence)));
    assert.equal(result.ok, true);
  });
});

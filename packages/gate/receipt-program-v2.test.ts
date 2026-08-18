// SPDX-License-Identifier: Apache-2.0
//
// EP-RECEIPT-PROGRAM-CERTIFICATE-v2 / EP-RECEIPT-PROGRAM-v2 -- hostile matrix
// for the hybrid execution certificate. Package-root node:test file importing
// the compatibility shim './receipt-program.js' (which re-exports
// ./dist/receipt-program.js), matching this package's convention;
// packages/gate/receipt-program.test.js keeps covering v1 and is untouched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';

import { canonicalize } from './execution-binding.js';
import {
  RECEIPT_PROGRAM_VERSION,
  RECEIPT_PROGRAM_CERTIFICATE_VERSION,
  RECEIPT_PROGRAM_V2_VERSION,
  RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION,
  RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS,
  issueReceiptProgramCertificateV2,
  verifyReceiptProgramCertificate,
  verifyReceiptProgramCertificateV2,
  verifyReceiptProgramCertificateStatement,
} from './receipt-program.js';
import type { FipsPosture } from '@emilia-protocol/verify/fips-mode';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const KEY_ID = 'certificate-key-1';
const CONTEXT = {
  issuer: 'emilia-gate-operator',
  tenant: 'tenant-a',
  environment: 'production',
  audience: 'certificate-auditor',
  key_id: KEY_ID,
};

function canonicalDigest(value: unknown) {
  return `sha256:${crypto.createHash('sha256').update(Buffer.from(canonicalize(value), 'utf8')).digest('hex')}`;
}

/**
 * A REFUSED certificate over a deliberately non-executable program: the
 * smallest core that exercises the whole shared post-signature body without
 * needing a live Gate, a CAID resolver, or evidence references.
 */
function coreInput(programVersion = RECEIPT_PROGRAM_V2_VERSION) {
  const program = { '@version': programVersion, program_id: 'receipt-program-1' };
  return {
    context: CONTEXT,
    program,
    programDigest: canonicalDigest(program),
    outcome: 'refused',
    reason: 'capability_receipt_missing',
    result: null,
    authorizationRef: null,
    executionRef: null,
    steps: [
      { sequence: 0, opcode: 'RECEIPT' },
      { sequence: 1, opcode: 'REFUSE' },
      { sequence: 2, opcode: 'CERTIFY' },
    ],
    startedAt: '2026-08-17T12:00:00.000Z',
    completedAt: '2026-08-17T12:00:01.000Z',
  };
}

function issuerFixture() {
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
    hybridPin: { [KEY_ID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } },
    classicalPin: { [KEY_ID]: edPubB64u },
  };
}

async function issued() {
  const issuer = issuerFixture();
  const certificate = await issueReceiptProgramCertificateV2(coreInput(), { keys: issuer.keys });
  return { issuer, certificate: certificate as any };
}

/** Mint a v1 certificate by hand: the v1 signer lives inside the kernel. */
function mintV1Certificate(privateKey: crypto.KeyObject, publicKeyB64u: string) {
  const input = coreInput(RECEIPT_PROGRAM_VERSION);
  const core = {
    '@version': RECEIPT_PROGRAM_CERTIFICATE_VERSION,
    context: input.context,
    program: input.program,
    program_digest: input.programDigest,
    outcome: input.outcome,
    reason: input.reason,
    result: null,
    result_digest: null,
    authorization_ref: null,
    execution_ref: null,
    steps: input.steps,
    started_at: input.startedAt,
    completed_at: input.completedAt,
  };
  const signed = { ...core, state_root: canonicalDigest(core) };
  const value = crypto.sign(null, Buffer.from(canonicalize(signed), 'utf8'), privateKey).toString('base64url');
  return { ...signed, signature: { algorithm: 'Ed25519', public_key: publicKeyB64u, value } };
}

/** An ACTIVE posture with an undeclared Ed25519 boundary: a deterministic deny. */
const DENYING_POSTURE: FipsPosture = {
  version: 'EP-FIPS-MODE-v1',
  fips_status: 'active',
  fips_mode_active: true,
  openssl_version: '3.9.9',
  node_version: process.version,
  openssl_operational: true,
  ed25519_operational: true,
  ed25519_in_validated_boundary: null,
  mldsa_backend: '@noble/post-quantum (pure JavaScript, FIPS 204 ML-DSA-65)',
  mldsa_validated_module: false,
};

describe('EP-RECEIPT-PROGRAM-CERTIFICATE-v2 hybrid execution certificate', () => {
  it('valid v2 roundtrip: both legs verify under the pinned key pair', async () => {
    const { issuer, certificate } = await issued();
    assert.equal(certificate['@version'], RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION);
    assert.equal(certificate.program['@version'], RECEIPT_PROGRAM_V2_VERSION);
    assert.deepEqual(
      certificate.signature.required_algorithms,
      [...RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS],
    );
    assert.deepEqual(
      certificate.signature.signatures.map((s: any) => s.alg),
      [...RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS],
    );

    const verified = await verifyReceiptProgramCertificateV2(certificate, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(verified.ok, true);
    assert.equal(verified.certificate_valid, true);
    assert.equal(verified.execution_succeeded, false);
    assert.equal(verified.state_root, certificate.state_root);
  });

  it('v1-refuses-v2: the SYNC v1 verifier refuses on the version marker as its FIRST check', async () => {
    const { issuer, certificate } = await issued();
    // No await: verifyReceiptProgramCertificate remains synchronous and untouched.
    const result = verifyReceiptProgramCertificate(certificate, {
      trustedCertificateKeys: issuer.classicalPin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'certificate_version_invalid');
  });

  it('the router keeps the exact v1 verdict for a v1 certificate and hybrid-checks a v2 one', async () => {
    const issuer = issuerFixture();
    const v1 = mintV1Certificate(issuer.ed.privateKey, issuer.classicalPin[KEY_ID]);
    const routedV1 = await verifyReceiptProgramCertificateStatement(v1, {
      trustedCertificateKeys: issuer.classicalPin,
      expectedContext: CONTEXT,
    });
    assert.equal(routedV1.ok, true);

    const v2 = await issueReceiptProgramCertificateV2(coreInput(), { keys: issuer.keys });
    const routedV2 = await verifyReceiptProgramCertificateStatement(v2, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(routedV2.ok, true);
  });

  it('a key id pinned WITHOUT the ML-DSA half never satisfies a v2 pin', async () => {
    const { issuer, certificate } = await issued();
    const result = await verifyReceiptProgramCertificateV2(certificate, {
      trustedCertificateKeys: issuer.classicalPin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'certificate_signer_not_trusted');
  });

  it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
    const { issuer, certificate } = await issued();
    const stripped = {
      ...certificate,
      signature: {
        ...certificate.signature,
        signatures: certificate.signature.signatures.filter((s: any) => s.alg !== 'ML-DSA-65'),
      },
    };
    const result = await verifyReceiptProgramCertificateV2(stripped, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'certificate_signature_leg_missing');
  });

  it('narrowed set: claiming required_algorithms=["Ed25519"] is refused structurally AND cryptographically', async () => {
    const { issuer, certificate } = await issued();
    const options = { trustedCertificateKeys: issuer.hybridPin, expectedContext: CONTEXT };
    const narrowed = {
      ...certificate,
      signature: {
        ...certificate.signature,
        required_algorithms: ['Ed25519'],
        signatures: certificate.signature.signatures.filter((s: any) => s.alg === 'Ed25519'),
      },
    };
    assert.equal(
      (await verifyReceiptProgramCertificateV2(narrowed, options)).reason,
      'certificate_algorithm_set_unsupported',
    );
    const setIntact = {
      ...narrowed,
      signature: {
        ...narrowed.signature,
        required_algorithms: [...RECEIPT_PROGRAM_V2_REQUIRED_ALGORITHMS],
      },
    };
    assert.equal(
      (await verifyReceiptProgramCertificateV2(setIntact, options)).reason,
      'certificate_signature_leg_missing',
    );
  });

  it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
    const { issuer, certificate } = await issued();
    const tampered = {
      ...certificate,
      signature: {
        ...certificate.signature,
        signatures: certificate.signature.signatures.map((s: any) => (
          s.alg === 'ML-DSA-65' ? { ...s, sig: crypto.randomBytes(16).toString('base64url') } : s
        )),
      },
    };
    const result = await verifyReceiptProgramCertificateV2(tampered, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.ok(String(result.reason).includes('certificate_signature_invalid'));
  });

  it('Ed448-masquerade: a non-Ed25519 SPKI pinned as the classical half is refused, never verified', async () => {
    const { issuer, certificate } = await issued();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const masqueraded = {
      ...certificate,
      signature: { ...certificate.signature, public_key: ed448PubB64u },
    };
    const pin = {
      [KEY_ID]: {
        public_key: ed448PubB64u,
        pq_public_key: issuer.hybridPin[KEY_ID].pq_public_key,
      },
    };
    const result = await verifyReceiptProgramCertificateV2(masqueraded, {
      trustedCertificateKeys: pin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'certificate_signer_not_trusted');
  });

  it('an absent ML-DSA backend is pq_backend_unavailable, never a pass on the Ed25519 leg', async () => {
    const { issuer, certificate } = await issued();
    const result = await verifyReceiptProgramCertificateV2(certificate, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
      mldsaBackend: {},
    });
    assert.equal(result.ok, false);
    assert.ok(String(result.reason).includes('pq_backend_unavailable'));
  });

  it('a tampered core breaks the signature over the rebuilt bytes', async () => {
    const { issuer, certificate } = await issued();
    const tampered = { ...certificate, reason: 'something_else' };
    const result = await verifyReceiptProgramCertificateV2(tampered, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(result.ok, false);
    assert.ok(String(result.reason).includes('certificate_signature_invalid'));
  });

  it('a v1-marked program inside a v2 certificate is refused by the shared body, at issuance', async () => {
    const issuer = issuerFixture();
    // The issuer's own self-check runs the full v2 verifier, so a certificate
    // pairing the v2 envelope with a v1 program marker is never emitted.
    await assert.rejects(
      issueReceiptProgramCertificateV2(coreInput(RECEIPT_PROGRAM_VERSION), { keys: issuer.keys }),
      /self-verification failed: certificate_program_invalid/,
    );
  });

  it('the shared post-signature body still enforces the context pin on a cryptographically valid certificate', async () => {
    const { issuer, certificate } = await issued();
    const result = await verifyReceiptProgramCertificateV2(certificate, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: { ...CONTEXT, tenant: 'someone-else' },
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'certificate_context_mismatch');
  });

  it('never throws on hostile input', async () => {
    for (const bad of [null, undefined, '', 42, [], { '@version': RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION }]) {
      assert.equal((await verifyReceiptProgramCertificateV2(bad, { trustedCertificateKeys: {} })).ok, false);
      assert.equal((await verifyReceiptProgramCertificateStatement(bad, { trustedCertificateKeys: {} })).ok, false);
    }
  });
});

describe('EP-RECEIPT-PROGRAM-CERTIFICATE-v2 FIPS consult and signer configuration', () => {
  it('a denied FIPS policy refuses issuance BEFORE the signer runs, named reason, never a silent sign', async () => {
    const issuer = issuerFixture();
    let signCalls = 0;
    const signer = {
      keyId: KEY_ID,
      custody: 'hsm',
      publicKeys: issuer.hybridPin[KEY_ID],
      async signSet() {
        signCalls += 1;
        return [];
      },
    };
    await assert.rejects(
      issueReceiptProgramCertificateV2(coreInput(), { signer, fipsPosture: DENYING_POSTURE }),
      /fips_policy_denied:Ed25519:ed25519_boundary_undeclared/,
    );
    assert.equal(signCalls, 0);
  });

  it('an ACTIVE posture refuses the ML-DSA leg until the unvalidated implementation is acknowledged', async () => {
    const issuer = issuerFixture();
    const active: FipsPosture = { ...DENYING_POSTURE, ed25519_in_validated_boundary: true };
    await assert.rejects(
      issueReceiptProgramCertificateV2(coreInput(), { keys: issuer.keys, fipsPosture: active }),
      /fips_policy_denied:ML-DSA-65:mldsa_implementation_unvalidated/,
    );

    const certificate = await issueReceiptProgramCertificateV2(coreInput(), {
      keys: issuer.keys, fipsPosture: active, allowUnvalidatedMldsa: true,
    }) as any;
    assert.equal(certificate['@version'], RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION);
  });

  it('an inactive posture (the normal case) permits both legs with no acknowledgment required', async () => {
    const issuer = issuerFixture();
    const inactive: FipsPosture = { ...DENYING_POSTURE, fips_status: 'inactive', fips_mode_active: false };
    const certificate = await issueReceiptProgramCertificateV2(coreInput(), {
      keys: issuer.keys, fipsPosture: inactive,
    }) as any;
    assert.equal(certificate.signature.profile, RECEIPT_PROGRAM_CERTIFICATE_V2_VERSION);
  });

  it('exactly one signer must be configured, and an incomplete set refuses issuance', async () => {
    const issuer = issuerFixture();
    await assert.rejects(
      issueReceiptProgramCertificateV2(coreInput(), {}),
      /exactly one receipt program certificate v2 signer/,
    );
    const signer = {
      keyId: KEY_ID,
      custody: 'hsm',
      publicKeys: issuer.hybridPin[KEY_ID],
      async signSet(bytes: Uint8Array | Buffer) {
        return [{
          alg: 'Ed25519',
          sig: crypto.sign(null, Buffer.from(bytes), issuer.ed.privateKey).toString('base64url'),
        }];
      },
    };
    await assert.rejects(
      issueReceiptProgramCertificateV2(coreInput(), { signer }),
      /malformed signature set/,
    );
  });

  it('an injected signSet signer that supplies both legs issues a verifiable certificate', async () => {
    const issuer = issuerFixture();
    const pqSecret = issuer.keys.pq.secretKey as Uint8Array;
    const signer = {
      keyId: KEY_ID,
      custody: 'hsm',
      publicKeys: issuer.hybridPin[KEY_ID],
      async signSet(bytes: Uint8Array | Buffer) {
        const message = new Uint8Array(Buffer.from(bytes));
        return [
          { alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(message), issuer.ed.privateKey).toString('base64url') },
          { alg: 'ML-DSA-65', sig: Buffer.from(ml_dsa65.sign(message, pqSecret)).toString('base64url') },
        ];
      },
    };
    const certificate = await issueReceiptProgramCertificateV2(coreInput(), { signer }) as any;
    const verified = await verifyReceiptProgramCertificateV2(certificate, {
      trustedCertificateKeys: issuer.hybridPin,
      expectedContext: CONTEXT,
    });
    assert.equal(verified.ok, true);
  });
});

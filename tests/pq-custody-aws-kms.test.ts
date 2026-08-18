// SPDX-License-Identifier: Apache-2.0
//
// EP-PQ-CUSTODY-AWS-KMS-v1 adapter tests.
//
// NO LIVE AWS CALL IS MADE ANYWHERE IN THIS FILE, and none has ever been made
// against this adapter. Every "KMS" here is a hand-built fake that mimics the
// documented GetPublicKey and Sign response shapes. Nothing below is an
// interop result and nothing below is evidence that a real KMS ML-DSA-65 key
// behaves as this adapter expects. It is evidence about the adapter's own
// logic against responses of the documented shape, which is a different and
// smaller claim.
//
// Real ML-DSA-65 runs here (@noble/post-quantum, root devDependency), the same
// choice tests/pq-custody-external.test.ts makes: a fake signature backend
// would make "the remote lied about the signature" cases vacuous.
//
// AWS signs with the hedged (randomized) FIPS 204 variant, so signatures are
// NOT byte-stable across calls. Nothing here asserts a fixed signature value;
// one test pins the opposite.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  AWS_KMS_PQ_CUSTODY_PROFILE,
  AWS_KMS_PQ_REASONS,
  AWS_KMS_RAW_MESSAGE_MAX_BYTES,
  AWS_KMS_ML_DSA_65_KEY_SPEC,
  AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
  createAwsKmsPqCustodySigner,
  isAwsKmsPqCustodySigner,
  isNamedAwsKmsPqReason,
  unwrapSpkiPublicKey,
  type AwsKmsGetPublicKeyOutput,
  type AwsKmsPqClient,
  type AwsKmsPqCustodyOptions,
  type AwsKmsPqCustodySigner,
  type AwsKmsSignInput,
  type AwsKmsSignOutput,
} from '../lib/pq-custody-aws-kms.js';
import {
  EXTERNAL_PQ_REASONS,
  EXTERNAL_PQ_CUSTODY_PROFILE,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  isExternalPqCustodySigner,
  runExternalPqCustodyConformance,
  ExternalPqCustodyError,
} from '../lib/pq-custody-external.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const KEYPAIR = ml_dsa65.keygen(crypto.randomBytes(32));
const OTHER_KEYPAIR = ml_dsa65.keygen(crypto.randomBytes(32));
const PUBLIC_KEY = Buffer.from(KEYPAIR.publicKey);
const PUBLIC_KEY_B64U = PUBLIC_KEY.toString('base64url');
const KEY_ARN = 'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const MESSAGE = Buffer.from('EP-PQ-CUSTODY-AWS-KMS-v1 test message', 'utf8');

// --------------------------------------------------------------------------
// DER helpers: build the SubjectPublicKeyInfo shape GetPublicKey returns.
//
// GetPublicKey does NOT return the raw 1952-byte key; it returns a DER X.509
// SubjectPublicKeyInfo wrapping it. These builders exist so the hostile cases
// can bend one field at a time.
// --------------------------------------------------------------------------

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const out: number[] = [];
  let n = len;
  while (n > 0) {
    out.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | out.length, ...out]);
}

function der(tag: number, contents: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(contents.length), contents]);
}

/** id-ml-dsa-65, 2.16.840.1.101.3.4.3.18, as a DER OBJECT IDENTIFIER body. */
const ML_DSA_65_OID_BODY = Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]);
const ML_DSA_65_OID_DOTTED = '2.16.840.1.101.3.4.3.18';

function spki(publicKey: Buffer, oidBody: Buffer = ML_DSA_65_OID_BODY, unusedBits = 0x00): Buffer {
  const algId = der(0x30, der(0x06, oidBody));
  const bits = der(0x03, Buffer.concat([Buffer.from([unusedBits]), publicKey]));
  return der(0x30, Buffer.concat([algId, bits]));
}

const GOOD_SPKI = spki(PUBLIC_KEY);

// --------------------------------------------------------------------------
// Fake clients. All of them. There is no network here.
// --------------------------------------------------------------------------

interface FakeCounts {
  getPublicKey: number;
  sign: number;
  signInputs: AwsKmsSignInput[];
  getPublicKeyInputs: { KeyId: string }[];
}

function goodGetPublicKey(): AwsKmsGetPublicKeyOutput {
  return {
    KeyId: KEY_ARN,
    PublicKey: new Uint8Array(GOOD_SPKI),
    KeySpec: AWS_KMS_ML_DSA_65_KEY_SPEC,
    KeyUsage: 'SIGN_VERIFY',
    SigningAlgorithms: [AWS_KMS_ML_DSA_SIGNING_ALGORITHM],
  };
}

/**
 * A fake KMS. `describe` and `signImpl` are overridable so a hostile case
 * changes exactly one thing about an otherwise well-behaved client.
 */
function fakeKms(overrides: {
  describe?: () => AwsKmsGetPublicKeyOutput | Promise<AwsKmsGetPublicKeyOutput>;
  signImpl?: (input: AwsKmsSignInput, signal?: AbortSignal) => AwsKmsSignOutput | Promise<AwsKmsSignOutput>;
} = {}): AwsKmsPqClient & { counts: FakeCounts } {
  const counts: FakeCounts = { getPublicKey: 0, sign: 0, signInputs: [], getPublicKeyInputs: [] };
  const client = {
    counts,
    async getPublicKey(input: { KeyId: string }) {
      counts.getPublicKey += 1;
      counts.getPublicKeyInputs.push(input);
      return overrides.describe ? await overrides.describe() : goodGetPublicKey();
    },
    async sign(input: AwsKmsSignInput, options?: { abortSignal?: AbortSignal }) {
      counts.sign += 1;
      counts.signInputs.push(input);
      if (overrides.signImpl) return await overrides.signImpl(input, options?.abortSignal);
      return {
        KeyId: KEY_ARN,
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey),
      };
    },
  };
  return client;
}

async function build(
  overrides: Partial<AwsKmsPqCustodyOptions> = {},
  client: AwsKmsPqClient = fakeKms(),
) {
  return createAwsKmsPqCustodySigner({ client, awsKeyId: KEY_ARN, ...overrides } as AwsKmsPqCustodyOptions);
}

async function mustBuild(
  overrides: Partial<AwsKmsPqCustodyOptions> = {},
  client: AwsKmsPqClient = fakeKms(),
): Promise<AwsKmsPqCustodySigner> {
  const built = await build(overrides, client);
  if (!built.ok) throw new Error(`fixture did not build: ${built.reason}: ${built.detail}`);
  return built.signer;
}

/** Build against a client whose only deviation is the one under test. */
async function buildWith(
  overrides: Parameters<typeof fakeKms>[0],
  options: Partial<AwsKmsPqCustodyOptions> = {},
) {
  return build(options, fakeKms(overrides));
}

// --------------------------------------------------------------------------
// The happy path
// --------------------------------------------------------------------------

describe('createAwsKmsPqCustodySigner: the happy path', () => {
  it('unwraps the SPKI, pins the raw 1952-byte key, and declares kms custody', async () => {
    const client = fakeKms();
    const signer = await mustBuild({}, client);

    expect(signer.algorithm).toBe('ML-DSA-65');
    expect(signer.custody).toBe('kms');
    expect(signer.profile).toBe(EXTERNAL_PQ_CUSTODY_PROFILE);
    expect(signer.adapterProfile).toBe(AWS_KMS_PQ_CUSTODY_PROFILE);
    expect(signer.publicKeyRawB64u).toBe(PUBLIC_KEY_B64U);
    expect(Buffer.from(signer.publicKeyRawB64u, 'base64url').length).toBe(ML_DSA_65_PUBLIC_KEY_BYTES);
    expect(signer.awsKeyId).toBe(KEY_ARN);
    expect(signer.awsKeySpec).toBe(AWS_KMS_ML_DSA_65_KEY_SPEC);
    expect(signer.awsKeyUsage).toBe('SIGN_VERIFY');
    expect(signer.awsSigningAlgorithm).toBe(AWS_KMS_ML_DSA_SIGNING_ALGORITHM);
    expect(signer.awsMessageType).toBe('RAW');
    expect(signer.maxMessageBytes).toBe(AWS_KMS_RAW_MESSAGE_MAX_BYTES);
    expect(signer.keyId).toBe(`aws-kms:${KEY_ARN}`);
    expect(isAwsKmsPqCustodySigner(signer)).toBe(true);
    // Satisfies the provider-agnostic seam's own predicate, which is what the
    // hybrid custody seam consumes.
    expect(isExternalPqCustodySigner(signer)).toBe(true);

    // Exactly one GetPublicKey at construction; the SPKI is recorded verbatim.
    expect(client.counts.getPublicKey).toBe(1);
    expect(client.counts.getPublicKeyInputs[0]).toEqual({ KeyId: KEY_ARN });
    expect(Buffer.from(signer.publicKeySpkiDerB64u, 'base64url').equals(GOOD_SPKI)).toBe(true);
  });

  it('records the SPKI algorithm OID without gating on it', async () => {
    const signer = await mustBuild();
    expect(signer.publicKeyAlgorithmOid).toBe(ML_DSA_65_OID_DOTTED);

    // A different OID over an otherwise correct key still builds: the gates are
    // the KeySpec KMS reports and the unwrapped length, not an OID this code
    // did not verify from a primary source.
    const odd = await buildWith({
      describe: () => ({ ...goodGetPublicKey(), PublicKey: new Uint8Array(spki(PUBLIC_KEY, Buffer.from([0x2a, 0x86, 0x48]))) }),
    });
    expect(odd.ok).toBe(true);
  });

  it('signs RAW with ML_DSA_SHAKE_256 and the signature verifies under the pinned key', async () => {
    const client = fakeKms();
    const signer = await mustBuild({}, client);

    const sig = await signer.sign(MESSAGE);
    const sigBytes = Buffer.from(sig, 'base64url');
    expect(sigBytes.length).toBe(ML_DSA_65_SIGNATURE_BYTES);
    expect(ml_dsa65.verify(new Uint8Array(sigBytes), new Uint8Array(MESSAGE), KEYPAIR.publicKey)).toBe(true);

    expect(client.counts.sign).toBe(1);
    const input = client.counts.signInputs[0];
    expect(input.KeyId).toBe(KEY_ARN);
    expect(input.MessageType).toBe('RAW');
    expect(input.SigningAlgorithm).toBe(AWS_KMS_ML_DSA_SIGNING_ALGORITHM);
    expect(Buffer.from(input.Message).equals(MESSAGE)).toBe(true);
  });

  it('accepts the base64-string response forms an SDK variant may return', async () => {
    const client = fakeKms({
      describe: () => ({ ...goodGetPublicKey(), PublicKey: GOOD_SPKI.toString('base64') }),
      signImpl: (input) => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: Buffer.from(ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey)).toString('base64'),
      }),
    });
    const signer = await mustBuild({}, client);
    const sig = await signer.sign(MESSAGE);
    expect(Buffer.from(sig, 'base64url').length).toBe(ML_DSA_65_SIGNATURE_BYTES);
  });

  it('does not assume byte-stable signatures: AWS signs the hedged FIPS 204 variant', async () => {
    const signer = await mustBuild();
    const first = await signer.sign(MESSAGE);
    const second = await signer.sign(MESSAGE);
    expect(first).not.toBe(second);
    for (const sig of [first, second]) {
      expect(ml_dsa65.verify(Buffer.from(sig, 'base64url'), new Uint8Array(MESSAGE), KEYPAIR.publicKey)).toBe(true);
    }
  });

  it('is honest about the custody declaration it records', async () => {
    const signer = await mustBuild({ attestation: 'ticket EP-1234' });
    expect(signer.custodyDeclaration.kind).toBe('kms');
    expect(signer.custodyDeclaration.declared_by).toBe('operator');
    // The whole point: no code in this repository can observe a KMS boundary.
    expect(signer.custodyDeclaration.verified_by_code).toBe(false);
    expect(signer.custodyDeclaration.attestation).toBe('ticket EP-1234');
  });
});

// --------------------------------------------------------------------------
// The DER unwrap, alone
// --------------------------------------------------------------------------

describe('unwrapSpkiPublicKey', () => {
  it('unwraps a well-formed SubjectPublicKeyInfo to the raw key bytes', () => {
    const result = unwrapSpkiPublicKey(GOOD_SPKI);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.publicKey.equals(PUBLIC_KEY)).toBe(true);
    expect(result.algorithmOid).toBe(ML_DSA_65_OID_DOTTED);
  });

  const malformed: [string, unknown][] = [
    ['empty input', Buffer.alloc(0)],
    ['not a SEQUENCE', Buffer.from([0x04, 0x02, 0x01, 0x02])],
    ['truncated outer length', Buffer.from([0x30, 0x82, 0x07, 0xb0, 0x01])],
    ['trailing bytes after the SPKI', Buffer.concat([GOOD_SPKI, Buffer.from([0x00])])],
    ['indefinite length', Buffer.from([0x30, 0x80, 0x00, 0x00])],
    ['non-minimal long-form length', Buffer.from([0x30, 0x81, 0x01, 0x05])],
    ['no AlgorithmIdentifier', der(0x30, der(0x03, Buffer.concat([Buffer.from([0x00]), PUBLIC_KEY])))],
    ['no BIT STRING', der(0x30, der(0x30, der(0x06, ML_DSA_65_OID_BODY)))],
    ['BIT STRING with unused bits', spki(PUBLIC_KEY, ML_DSA_65_OID_BODY, 0x03)],
    ['empty BIT STRING', der(0x30, Buffer.concat([der(0x30, der(0x06, ML_DSA_65_OID_BODY)), der(0x03, Buffer.alloc(0))]))],
    ['not bytes at all', { PublicKey: 'nope' }],
    ['non-base64 string', 'not base64 !!!'],
  ];

  it.each(malformed)('refuses %s by name', (_name, input) => {
    const result = unwrapSpkiPublicKey(input);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED);
    expect(isNamedAwsKmsPqReason(result.reason)).toBe(true);
    expect(typeof result.detail).toBe('string');
    expect(result.detail.length).toBeGreaterThan(0);
  });

  it('never throws on hostile input', () => {
    const inputs: unknown[] = [null, undefined, 0, [], () => {}, Symbol('x'), new Map()];
    for (const input of inputs) {
      expect(() => unwrapSpkiPublicKey(input)).not.toThrow();
      expect(unwrapSpkiPublicKey(input).ok).toBe(false);
    }
  });
});

// --------------------------------------------------------------------------
// Hostile KMS clients: construction
// --------------------------------------------------------------------------

describe('construction refuses a KMS key that is not what EP pins', () => {
  it('refuses an SPKI wrapping the wrong key length', async () => {
    // 1312 bytes is the FIPS 204 ML-DSA-44 public key size: a plausible wrong
    // key, not random noise.
    const built = await buildWith({
      describe: () => ({ ...goodGetPublicKey(), PublicKey: new Uint8Array(spki(Buffer.alloc(1312, 0x11))) }),
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.PUBLIC_KEY_LENGTH_INVALID);
    expect(built.detail).toContain('1312');
    expect(built.detail).toContain(String(ML_DSA_65_PUBLIC_KEY_BYTES));
  });

  it('refuses malformed DER', async () => {
    const built = await buildWith({
      describe: () => ({ ...goodGetPublicKey(), PublicKey: new Uint8Array([0x30, 0x05, 0x01]) }),
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.SPKI_UNWRAP_FAILED);
  });

  it('refuses a client returning an ECDSA key spec', async () => {
    const built = await buildWith({
      describe: () => ({
        KeyId: KEY_ARN,
        KeySpec: 'ECC_NIST_P256',
        KeyUsage: 'SIGN_VERIFY',
        SigningAlgorithms: ['ECDSA_SHA_256'],
        PublicKey: new Uint8Array(spki(PUBLIC_KEY)),
      }),
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.KEY_SPEC_INVALID);
    expect(built.detail).toContain('ECC_NIST_P256');
  });

  it('refuses the neighbouring ML-DSA key specs', async () => {
    for (const spec of ['ML_DSA_44', 'ML_DSA_87']) {
      const built = await buildWith({
        describe: () => ({ ...goodGetPublicKey(), KeySpec: spec }),
      });
      expect(built.ok, spec).toBe(false);
      if (built.ok) continue;
      expect(built.reason).toBe(AWS_KMS_PQ_REASONS.KEY_SPEC_INVALID);
    }
  });

  it('refuses a key whose KeyUsage cannot sign', async () => {
    const built = await buildWith({
      describe: () => ({ ...goodGetPublicKey(), KeyUsage: 'ENCRYPT_DECRYPT' }),
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.KEY_USAGE_INVALID);
  });

  it('refuses a key that does not advertise ML_DSA_SHAKE_256', async () => {
    const built = await buildWith({
      describe: () => ({ ...goodGetPublicKey(), SigningAlgorithms: ['ECDSA_SHA_256'] }),
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.SIGNING_ALGORITHM_INVALID);
  });

  it('refuses when GetPublicKey throws', async () => {
    const built = await buildWith({
      describe: () => { throw new Error('AccessDeniedException: not authorized to perform kms:GetPublicKey'); },
    });
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.GET_PUBLIC_KEY_FAILED);
    expect(built.detail).toContain('AccessDeniedException');
  });

  it('refuses when GetPublicKey hangs, at the deadline', async () => {
    const built = await buildWith(
      { describe: () => new Promise<AwsKmsGetPublicKeyOutput>(() => {}) },
      { timeoutMs: 40 },
    );
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.GET_PUBLIC_KEY_TIMEOUT);
    expect(built.detail).toContain('40 ms');
  });

  it('refuses a client that is not a client', async () => {
    for (const client of [null, undefined, {}, { getPublicKey: () => ({}) }, 'kms']) {
      const built = await createAwsKmsPqCustodySigner({ client, awsKeyId: KEY_ARN } as never);
      expect(built.ok).toBe(false);
      if (built.ok) continue;
      expect(built.reason).toBe(AWS_KMS_PQ_REASONS.CLIENT_INVALID);
    }
  });

  it('refuses a missing or empty awsKeyId', async () => {
    for (const awsKeyId of [undefined, '', '   ', 42]) {
      const built = await createAwsKmsPqCustodySigner({ client: fakeKms(), awsKeyId } as never);
      expect(built.ok).toBe(false);
      if (built.ok) continue;
      expect(built.reason).toBe(AWS_KMS_PQ_REASONS.KEY_ID_INVALID);
    }
  });

  it('refuses a secret-key-shaped option instead of ignoring it', async () => {
    for (const name of ['secretKey', 'privateKey', 'seed', 'pkcs8', 'key']) {
      const built = await createAwsKmsPqCustodySigner({
        client: fakeKms(),
        awsKeyId: KEY_ARN,
        [name]: Buffer.alloc(4032),
      } as never);
      expect(built.ok, name).toBe(false);
      if (built.ok) continue;
      expect(built.reason).toBe(EXTERNAL_PQ_REASONS.SECRET_KEY_OFFERED);
    }
  });

  it('refuses an out-of-range deadline with the seam own reason name', async () => {
    for (const timeoutMs of [0, -1, 1.5, 60_001]) {
      const built = await build({ timeoutMs } as Partial<AwsKmsPqCustodyOptions>);
      expect(built.ok, String(timeoutMs)).toBe(false);
      if (built.ok) continue;
      expect(built.reason).toBe(EXTERNAL_PQ_REASONS.TIMEOUT_INVALID);
    }
  });

  it('refuses EXTERNAL_MU by name rather than silently implementing it', async () => {
    const built = await build({ messageType: 'EXTERNAL_MU' } as never);
    expect(built.ok).toBe(false);
    if (built.ok) return;
    expect(built.reason).toBe(AWS_KMS_PQ_REASONS.MESSAGE_TYPE_UNSUPPORTED);
    expect(built.detail).toContain('EXTERNAL_MU');
    expect(built.detail).toContain('mu');
  });
});

// --------------------------------------------------------------------------
// Hostile KMS clients: signing
// --------------------------------------------------------------------------

describe('signing refuses every way a KMS response can be wrong', () => {
  it('refuses a signature one byte too long or too short', async () => {
    for (const delta of [1, -1]) {
      const signer = await mustBuild({}, fakeKms({
        signImpl: (input) => {
          const good = Buffer.from(ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey));
          const bent = delta > 0
            ? Buffer.concat([good, Buffer.alloc(1)])
            : good.subarray(0, good.length - 1);
          return { SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM, Signature: new Uint8Array(bent) };
        },
      }));
      const result = await signer.trySign(MESSAGE);
      expect(result.ok, String(delta)).toBe(false);
      if (result.ok) continue;
      // The seam owns the 3309-byte pin; the adapter does not duplicate it.
      expect(result.reason).toBe(EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID);
      expect(result.detail).toContain(String(ML_DSA_65_SIGNATURE_BYTES + delta));
    }
  });

  it('refuses a valid signature made over different bytes (verify-on-sign)', async () => {
    const signer = await mustBuild({}, fakeKms({
      // Correct key, correct length, correct algorithm, wrong message. Only a
      // real cryptographic check catches this.
      signImpl: () => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: ml_dsa65.sign(new Uint8Array(Buffer.from('some other bytes', 'utf8')), KEYPAIR.secretKey),
      }),
    }));
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(EXTERNAL_PQ_REASONS.SIGNATURE_INVALID);
  });

  it('refuses a signature under a different key', async () => {
    const signer = await mustBuild({}, fakeKms({
      signImpl: (input) => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: ml_dsa65.sign(new Uint8Array(input.Message), OTHER_KEYPAIR.secretKey),
      }),
    }));
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(EXTERNAL_PQ_REASONS.SIGNATURE_INVALID);
  });

  it('refuses a response that echoes a different signing algorithm', async () => {
    const signer = await mustBuild({}, fakeKms({
      signImpl: (input) => ({
        SigningAlgorithm: 'ECDSA_SHA_256',
        Signature: ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey),
      }),
    }));
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(AWS_KMS_PQ_REASONS.SIGNING_ALGORITHM_INVALID);
    expect(result.detail).toContain('ECDSA_SHA_256');
  });

  it('refuses a response carrying no signature', async () => {
    for (const signImpl of [
      () => ({ SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM }),
      () => null as unknown as AwsKmsSignOutput,
    ]) {
      const signer = await mustBuild({}, fakeKms({ signImpl }));
      const result = await signer.trySign(MESSAGE);
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.reason).toBe(AWS_KMS_PQ_REASONS.SIGNATURE_MISSING);
    }
  });

  it('refuses when the SDK throws, naming the adapter reason not a generic one', async () => {
    const signer = await mustBuild({}, fakeKms({
      signImpl: () => { throw new Error('ThrottlingException: Rate exceeded'); },
    }));
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(AWS_KMS_PQ_REASONS.SIGN_FAILED);
    expect(result.detail).toContain('ThrottlingException');
    expect(isNamedAwsKmsPqReason(result.reason)).toBe(true);
  });

  it('refuses at the deadline when the SDK hangs, and aborts the call', async () => {
    let sawAbort = false;
    const signer = await mustBuild({ timeoutMs: 40 }, fakeKms({
      signImpl: (_input, signal) => new Promise<AwsKmsSignOutput>(() => {
        signal?.addEventListener('abort', () => { sawAbort = true; }, { once: true });
      }),
    }));
    const started = Date.now();
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // The seam owns the deadline; a hung remote is its named timeout refusal.
    expect(result.reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_TIMEOUT);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(sawAbort).toBe(true);
  });

  it('refuses an oversize message by name and says why EXTERNAL_MU is not the answer', async () => {
    const client = fakeKms();
    const signer = await mustBuild({}, client);
    const oversize = Buffer.alloc(AWS_KMS_RAW_MESSAGE_MAX_BYTES + 1, 0x41);
    const result = await signer.trySign(oversize);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(AWS_KMS_PQ_REASONS.MESSAGE_TOO_LARGE);
    expect(result.detail).toContain(String(AWS_KMS_RAW_MESSAGE_MAX_BYTES));
    expect(result.detail).toContain('EXTERNAL_MU');
    // Refused before any call reaches KMS, and never silently retried on the
    // EXTERNAL_MU path.
    expect(client.counts.sign).toBe(0);
  });

  it('signs a message exactly at the RAW ceiling', async () => {
    const client = fakeKms();
    const signer = await mustBuild({}, client);
    const atCeiling = Buffer.alloc(AWS_KMS_RAW_MESSAGE_MAX_BYTES, 0x42);
    const result = await signer.trySign(atCeiling);
    expect(result.ok).toBe(true);
    expect(client.counts.sign).toBe(1);
    expect(client.counts.signInputs[0].MessageType).toBe('RAW');
  });

  it('refuses caller input that is not bytes, and never throws doing it', async () => {
    const signer = await mustBuild();
    for (const bad of ['not-bytes', null, undefined, 42, {}, []]) {
      const result = await signer.trySign(bad as never);
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.reason).toBe(EXTERNAL_PQ_REASONS.MESSAGE_INVALID);
    }
  });

  it('sign() rejects with a reason-carrying error rather than resolving to junk', async () => {
    const signer = await mustBuild({}, fakeKms({
      signImpl: () => { throw new Error('KMSInternalException'); },
    }));
    await expect(signer.sign(MESSAGE)).rejects.toBeInstanceOf(ExternalPqCustodyError);
    const err = await signer.sign(MESSAGE).catch((e: ExternalPqCustodyError) => e);
    expect((err as ExternalPqCustodyError).reason).toBe(AWS_KMS_PQ_REASONS.SIGN_FAILED);
  });

  it('keeps concurrent refusals from bleeding into each other', async () => {
    // The adapter carries its named refusal on a per-call slot. Two calls
    // failing differently at the same time must report their own reason.
    const signer = await mustBuild({}, fakeKms({
      signImpl: async (input) => {
        if (input.Message.length === 3) throw new Error('ThrottlingException');
        return { SigningAlgorithm: 'ECDSA_SHA_256', Signature: ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey) };
      },
    }));
    const [a, b] = await Promise.all([
      signer.trySign(Buffer.from([1, 2, 3])),
      signer.trySign(Buffer.from([1, 2, 3, 4])),
    ]);
    expect(a.ok).toBe(false);
    expect(b.ok).toBe(false);
    if (a.ok || b.ok) return;
    expect(a.reason).toBe(AWS_KMS_PQ_REASONS.SIGN_FAILED);
    expect(b.reason).toBe(AWS_KMS_PQ_REASONS.SIGNING_ALGORITHM_INVALID);
  });
});

// --------------------------------------------------------------------------
// The conformance harness, unchanged
// --------------------------------------------------------------------------

describe('runExternalPqCustodyConformance: the adapter passes it unchanged', () => {
  it('passes every case against a well-behaved fake KMS', async () => {
    const report = await runExternalPqCustodyConformance(() => createAwsKmsPqCustodySigner({
      client: fakeKms(),
      awsKeyId: KEY_ARN,
    }));
    expect(report.failed, JSON.stringify(report.cases, null, 2)).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.custody).toBe('kms');
    expect(report.keyId).toBe(`aws-kms:${KEY_ARN}`);
  });

  const hostile: [string, Parameters<typeof fakeKms>[0], string][] = [
    ['a signature one byte too long', {
      signImpl: (input) => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: Buffer.concat([Buffer.from(ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey)), Buffer.alloc(1)]),
      }),
    }, 'signs_bound_message'],
    ['a signature one byte too short', {
      signImpl: (input) => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: Buffer.from(ml_dsa65.sign(new Uint8Array(input.Message), KEYPAIR.secretKey)).subarray(0, ML_DSA_65_SIGNATURE_BYTES - 1),
      }),
    }, 'signs_bound_message'],
    ['a constant signature over other bytes', {
      signImpl: () => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: ml_dsa65.sign(new Uint8Array(MESSAGE), KEYPAIR.secretKey),
      }),
    }, 'signs_bound_message'],
    ['a signature under a different key', {
      signImpl: (input) => ({
        SigningAlgorithm: AWS_KMS_ML_DSA_SIGNING_ALGORITHM,
        Signature: ml_dsa65.sign(new Uint8Array(input.Message), OTHER_KEYPAIR.secretKey),
      }),
    }, 'signs_bound_message'],
    ['an SDK that throws on Sign', {
      signImpl: () => { throw new Error('ThrottlingException'); },
    }, 'signs_bound_message'],
  ];

  it.each(hostile)('fails the harness on %s', async (_name, overrides, expectedCase) => {
    const report = await runExternalPqCustodyConformance(() => createAwsKmsPqCustodySigner({
      client: fakeKms(overrides),
      awsKeyId: KEY_ARN,
    }));
    expect(report.ok).toBe(false);
    expect(report.failed).toContain(expectedCase);
  });

  it('fails the harness, at construction, on a KMS key of the wrong spec', async () => {
    const report = await runExternalPqCustodyConformance(() => createAwsKmsPqCustodySigner({
      client: fakeKms({ describe: () => ({ ...goodGetPublicKey(), KeySpec: 'ECC_NIST_P256' }) }),
      awsKeyId: KEY_ARN,
    }));
    expect(report.ok).toBe(false);
    expect(report.failed[0]).toBe('adapter_constructs');
    // Adapter reason names are not in the seam registry, so the harness reports
    // its own unnamed-refusal marker. Documented, expected, and the reason the
    // adapter also exports isNamedAwsKmsPqReason().
    expect(report.cases[0].reason).toBe(EXTERNAL_PQ_REASONS.REFUSAL_UNNAMED);
  });
});

// --------------------------------------------------------------------------
// Dependency and claim hygiene
// --------------------------------------------------------------------------

describe('the adapter adds no dependency and makes no network call of its own', () => {
  const SOURCE = readFileSync(fileURLToPath(new URL('../lib/pq-custody-aws-kms.ts', import.meta.url)), 'utf8');

  /** Source with comment lines removed: the header SHOWS the operator's own
   *  SDK v3 wiring, and that example must not be mistaken for an import. */
  const CODE = SOURCE.split('\n').filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line)).join('\n');

  it('imports no AWS package and no HTTP client', () => {
    const specs = [...CODE.matchAll(/from\s+'([^']+)'/g)].map((m) => m[1]);
    expect(specs.length).toBeGreaterThan(0);
    for (const spec of specs) {
      expect(/aws-sdk|@aws|aws4|node:https?$|undici|axios|node-fetch/.test(spec), `import ${spec}`).toBe(false);
    }
    // And the package manifest gained nothing.
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
    const declared = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies });
    expect(declared.filter((name) => /aws/i.test(name))).toEqual([]);
  });

  it('never calls fetch, http, or a global AWS client itself', () => {
    // Every byte that leaves this process leaves through the operator's
    // injected client. There is no other egress path to audit.
    expect(/\bfetch\s*\(/.test(CODE)).toBe(false);
    expect(/require\s*\(/.test(CODE)).toBe(false);
    expect(/\bnew\s+(XMLHttpRequest|WebSocket)\b/.test(CODE)).toBe(false);
  });

  it('states in the module header that no live KMS call has ever been made', () => {
    expect(SOURCE).toContain('NO LIVE AWS CALL HAS EVER BEEN MADE AGAINST THIS ADAPTER');
  });

  it('states in the module header that this does not improve EP FIPS posture', () => {
    expect(SOURCE).toContain('THIS ADAPTER DOES NOT IMPROVE EP');
    expect(SOURCE).toContain('4884');
  });

  it('exposes no key-material-shaped member on the built signer', async () => {
    const signer = await mustBuild();
    for (const [name, value] of Object.entries(signer as unknown as Record<string, unknown>)) {
      expect(/(secret|private|seed|passphrase|password|pkcs8|pem)/i.test(name), name).toBe(false);
      if (value instanceof Uint8Array) expect(value.length, name).not.toBe(4032);
    }
  });
});

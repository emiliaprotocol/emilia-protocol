// SPDX-License-Identifier: Apache-2.0
//
// EP-PQ-CUSTODY-EXTERNAL-v1: the external ML-DSA-65 custody seam.
//
// Each property the module claims is pinned by its own test here, and the
// hostile battery is run through the SAME exported conformance harness a
// provider adapter has to pass. Real ML-DSA-65 runs in this file
// (@noble/post-quantum, root devDependency): a fake backend would make the
// "the remote lied about the signature" cases vacuous.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  EXTERNAL_PQ_CUSTODY_PROFILE,
  EXTERNAL_PQ_CUSTODY_KINDS,
  EXTERNAL_PQ_REASONS,
  DEFAULT_EXTERNAL_PQ_TIMEOUT_MS,
  MAX_EXTERNAL_PQ_TIMEOUT_MS,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  createExternalPqCustodySigner,
  isExternalPqCustodySigner,
  requireExternalPqLeg,
  runExternalPqCustodyConformance,
  validateRemoteSignature,
  validateMldsaPublicKey,
  type ExternalPqCustodyOptions,
  type ExternalPqSignFn,
  type ExternalPqCustodySigner,
} from '../lib/pq-custody-external.js';
import {
  createExternalCustodySigner,
  createHybridCustodySigner,
  ML_DSA_65_SECRET_KEY_BYTES,
} from '../lib/key-custody.js';
import { softwareMldsaSigner } from '../lib/custody-signers.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const KEYPAIR = ml_dsa65.keygen(crypto.randomBytes(32));
const OTHER_KEYPAIR = ml_dsa65.keygen(crypto.randomBytes(32));
const PUBLIC_KEY_B64U = Buffer.from(KEYPAIR.publicKey).toString('base64url');
const MESSAGE = Buffer.from('EP-PQ-CUSTODY-EXTERNAL-v1 test message', 'utf8');

/** A correct remote: signs the exact bytes it was handed with the pinned key. */
const correctRemote: ExternalPqSignFn = ({ bytes }) => ml_dsa65.sign(new Uint8Array(bytes), KEYPAIR.secretKey);

function build(overrides: Partial<ExternalPqCustodyOptions> = {}) {
  return createExternalPqCustodySigner({
    keyId: 'ep:key:pq#external-1',
    custody: 'hsm',
    publicKey: PUBLIC_KEY_B64U,
    sign: correctRemote,
    ...overrides,
  } as ExternalPqCustodyOptions);
}

function mustBuild(overrides: Partial<ExternalPqCustodyOptions> = {}): ExternalPqCustodySigner {
  const built = build(overrides);
  if (!built.ok) throw new Error(`fixture did not build: ${built.reason}: ${built.detail}`);
  return built.signer;
}

// --------------------------------------------------------------------------
// The contract
// --------------------------------------------------------------------------

describe('createExternalPqCustodySigner: the contract', () => {
  it('returns a PqCustodySigner-shaped ML-DSA-65 leg with the declared custody kind', async () => {
    const signer = mustBuild({ custody: 'kms' });
    expect(signer.algorithm).toBe('ML-DSA-65');
    expect(signer.custody).toBe('kms');
    expect(signer.profile).toBe(EXTERNAL_PQ_CUSTODY_PROFILE);
    expect(signer.publicKeyRawB64u).toBe(PUBLIC_KEY_B64U);
    expect(signer.timeoutMs).toBe(DEFAULT_EXTERNAL_PQ_TIMEOUT_MS);
    expect(signer.verifiesOnSign).toBe(true);
    expect(isExternalPqCustodySigner(signer)).toBe(true);

    const sig = await signer.sign(MESSAGE);
    expect(Buffer.from(sig, 'base64url').length).toBe(ML_DSA_65_SIGNATURE_BYTES);
    expect(ml_dsa65.verify(Buffer.from(sig, 'base64url'), new Uint8Array(MESSAGE), KEYPAIR.publicKey)).toBe(true);
  });

  it('never reports software custody, whatever the caller asks for', () => {
    for (const kind of ['software', 'local-dev', 'env', '', 'SOFTWARE']) {
      const built = build({ custody: kind as never });
      expect(built.ok).toBe(false);
      expect((built as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.CUSTODY_KIND_INVALID);
    }
    for (const kind of EXTERNAL_PQ_CUSTODY_KINDS) {
      expect(mustBuild({ custody: kind }).custody).toBe(kind);
    }
  });

  it('records the custody claim as an operator declaration the code did not verify', () => {
    const signer = mustBuild({ custody: 'hsm', attestation: 'ticket EP-1234' });
    expect(signer.custodyDeclaration).toEqual({
      profile: EXTERNAL_PQ_CUSTODY_PROFILE,
      kind: 'hsm',
      declared_by: 'operator',
      verified_by_code: false,
      attestation: 'ticket EP-1234',
    });
  });
});

// --------------------------------------------------------------------------
// Property 1: no secret key ever enters the process
// --------------------------------------------------------------------------

describe('property: no ML-DSA secret key can enter this process', () => {
  it('refuses any secret-key-shaped option rather than ignoring it', () => {
    const secret = Buffer.from(KEYPAIR.secretKey).toString('base64url');
    for (const name of ['secretKey', 'privateKey', 'seed', 'sk', 'key', 'keyMaterial', 'pkcs8', 'pem', 'passphrase']) {
      const built = build({ [name]: secret } as never);
      expect(built.ok, `option ${name} must be refused`).toBe(false);
      expect((built as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SECRET_KEY_OFFERED);
    }
  });

  it('exposes no key-material-shaped member on the signer', () => {
    const signer = mustBuild();
    for (const [name, value] of Object.entries(signer as unknown as Record<string, unknown>)) {
      expect(/secret|private|seed/i.test(name), `member ${name}`).toBe(false);
      if (value instanceof Uint8Array) expect(value.length).not.toBe(ML_DSA_65_SECRET_KEY_BYTES);
    }
  });

  it('has no source-level path to a software-held key', () => {
    const source = readFileSync(fileURLToPath(new URL('../lib/pq-custody-external.ts', import.meta.url)), 'utf8');
    // The module must not reach the software backend, import an ML-DSA
    // implementation, hold key material, or know how to generate a key. Those
    // are the paths a silent downgrade would need. (Prose references to
    // softwareMldsaSigner inside refusal text are the point, not a path: they
    // tell an operator where the software option lives.)
    const specifiers = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1]);
    expect(specifiers).not.toContain('./custody-signers.js');
    for (const spec of specifiers) {
      expect(/custody-signers|noble|post-quantum/.test(spec), `import ${spec}`).toBe(false);
    }
    expect(source).not.toMatch(/\brequire\s*\(/);
    expect(source).not.toMatch(/\bawait import\(/);
    expect(source).not.toMatch(/\bkeygen\b/);
    expect(source).not.toMatch(/ML_DSA_65_SECRET_KEY_BYTES/);
    expect(source).not.toMatch(/\bsecretKey\b|\bprivateKey\b/);
  });
});

// --------------------------------------------------------------------------
// Property 2: the remote's output shape is never trusted
// --------------------------------------------------------------------------

describe('property: the remote output is validated on the way back', () => {
  const goodSig = () => ml_dsa65.sign(new Uint8Array(MESSAGE), KEYPAIR.secretKey);

  const hostile: Array<[string, ExternalPqSignFn, string]> = [
    [
      'one byte too long',
      () => Buffer.concat([Buffer.from(goodSig()), Buffer.alloc(1)]),
      EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
    ],
    [
      'one byte too short',
      () => Buffer.from(goodSig()).subarray(0, ML_DSA_65_SIGNATURE_BYTES - 1),
      EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
    ],
    [
      'truncated hard',
      () => Buffer.from(goodSig()).subarray(0, 100),
      EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
    ],
    [
      'Ed25519-length signature',
      () => crypto.randomBytes(64),
      EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID,
    ],
    [
      'right length, all zeros',
      () => Buffer.alloc(ML_DSA_65_SIGNATURE_BYTES, 0),
      EXTERNAL_PQ_REASONS.SIGNATURE_INVALID,
    ],
    [
      'valid signature over different bytes',
      () => ml_dsa65.sign(new Uint8Array(Buffer.from('some other bytes', 'utf8')), KEYPAIR.secretKey),
      EXTERNAL_PQ_REASONS.SIGNATURE_INVALID,
    ],
    [
      'valid signature under a different key',
      ({ bytes }) => ml_dsa65.sign(new Uint8Array(bytes), OTHER_KEYPAIR.secretKey),
      EXTERNAL_PQ_REASONS.SIGNATURE_INVALID,
    ],
    [
      'not base64url',
      () => 'this is not base64url!!',
      EXTERNAL_PQ_REASONS.SIGNATURE_ENCODING_INVALID,
    ],
    [
      'not a signature at all',
      () => ({ signature: 'yes' }),
      EXTERNAL_PQ_REASONS.SIGNATURE_MALFORMED,
    ],
    [
      'nothing at all',
      () => null,
      EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
    ],
    [
      'remote throws',
      () => { throw new Error('kms exploded'); },
      EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
    ],
    [
      'remote rejects',
      () => Promise.reject(new Error('403 from the signing service')),
      EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE,
    ],
  ];

  for (const [label, remote, expected] of hostile) {
    it(`refuses a remote that returns ${label}: ${expected}`, async () => {
      const signer = mustBuild({ sign: remote });
      const result = await signer.trySign(MESSAGE);
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe(expected);
    });
  }

  it('accepts a base64url string from the remote as readily as bytes', async () => {
    const signer = mustBuild({
      sign: ({ bytes }) => Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), KEYPAIR.secretKey)).toString('base64url'),
    });
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(true);
  });

  it('pins the public key length at construction', () => {
    for (const bad of [
      Buffer.alloc(ML_DSA_65_PUBLIC_KEY_BYTES - 1),
      Buffer.alloc(ML_DSA_65_PUBLIC_KEY_BYTES + 1),
      Buffer.alloc(32),
    ]) {
      const built = build({ publicKey: bad });
      expect(built.ok).toBe(false);
      expect((built as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.PUBLIC_KEY_INVALID);
    }
    for (const bad of ['not base64url!!', '', 'AAAA']) {
      const built = build({ publicKey: bad });
      expect(built.ok).toBe(false);
      expect((built as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.PUBLIC_KEY_INVALID);
    }
    expect(validateMldsaPublicKey(KEYPAIR.publicKey).ok).toBe(true);
  });

  it('keeps the length pin even when verify-on-sign is switched off', async () => {
    const signer = mustBuild({
      verifyOnSign: false,
      sign: () => Buffer.alloc(ML_DSA_65_SIGNATURE_BYTES - 1),
    });
    const result = await signer.trySign(MESSAGE);
    expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID);
  });

  it('refuses rather than emitting an unchecked signature when no ML-DSA backend is available', async () => {
    const signer = mustBuild({
      // A backend with no verify() is what "not resolvable" looks like to the
      // agility module; absence is a refusal, never a skipped check.
      mldsaBackend: {} as never,
    });
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE);
  });

  it('gives the remote a private copy of the bytes', async () => {
    const signer = mustBuild({
      sign: ({ bytes }) => {
        const sig = ml_dsa65.sign(new Uint8Array(bytes), KEYPAIR.secretKey);
        bytes.fill(0); // a hostile adapter scribbling on the caller's buffer
        return sig;
      },
    });
    const message = Buffer.from(MESSAGE);
    const result = await signer.trySign(message);
    expect(result.ok).toBe(true);
    expect(message.equals(MESSAGE)).toBe(true);
  });
});

// --------------------------------------------------------------------------
// Property 3: no silent downgrade
// --------------------------------------------------------------------------

describe('property: a failed external signer cannot downgrade', () => {
  function classicalSigner() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return createExternalCustodySigner({
      mode: 'hsm',
      keyId: 'pkcs11:ep-issuer#1',
      sign: async (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey).toString('base64url'),
      getPublicKey: () => publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    });
  }

  it('fails the whole signature set rather than emitting a classical-only one', async () => {
    const hybrid = createHybridCustodySigner({
      classical: classicalSigner(),
      pq: mustBuild({ sign: () => { throw new Error('signing service down'); } }),
    });

    let emitted: unknown = 'NOT SET';
    let caught: unknown = null;
    try {
      emitted = await hybrid.signSet(MESSAGE);
    } catch (err) {
      caught = err;
    }
    expect(emitted).toBe('NOT SET');
    expect((caught as { reason?: string })?.reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE);
    // The classical leg alone is never handed back under any shape.
    expect(Array.isArray(emitted)).toBe(false);
  });

  it('has no fallback: a broken remote refuses every time, it does not degrade to software', async () => {
    const signer = mustBuild({ sign: () => { throw new Error('down'); } });
    for (let i = 0; i < 3; i += 1) {
      const result = await signer.trySign(MESSAGE);
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE);
    }
  });

  it('requireExternalPqLeg refuses a software PQ leg dressed up as a configured external one', () => {
    const softwareHybrid = createHybridCustodySigner({
      classical: classicalSigner(),
      pq: softwareMldsaSigner({
        keyId: 'ep:key:pq#software-1',
        secretKey: KEYPAIR.secretKey,
        publicKeyRawB64u: KEYPAIR.publicKey,
      }),
    });
    const verdict = requireExternalPqLeg(softwareHybrid);
    expect(verdict.ok).toBe(false);
    expect((verdict as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.LEG_NOT_EXTERNAL);

    const classicalOnly = requireExternalPqLeg(classicalSigner());
    expect(classicalOnly.ok).toBe(false);
    expect((classicalOnly as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.LEG_MISSING);
    expect(requireExternalPqLeg(null).ok).toBe(false);

    const externalHybrid = createHybridCustodySigner({ classical: classicalSigner(), pq: mustBuild() });
    const good = requireExternalPqLeg(externalHybrid);
    expect(good.ok).toBe(true);
    expect((good as { signer: ExternalPqCustodySigner }).signer.custody).toBe('hsm');
  });
});

// --------------------------------------------------------------------------
// Property 4: timeout and cancellation
// --------------------------------------------------------------------------

describe('property: a hung remote is a refusal, not a hang', () => {
  it('refuses at the deadline', async () => {
    const signer = mustBuild({ timeoutMs: 60, sign: () => new Promise(() => {}) });
    const started = Date.now();
    const result = await signer.trySign(MESSAGE);
    expect(result.ok).toBe(false);
    expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_TIMEOUT);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('aborts the signal it handed the remote when the deadline passes', async () => {
    let seen: AbortSignal | null = null;
    const signer = mustBuild({
      timeoutMs: 50,
      sign: ({ signal }) => { seen = signal; return new Promise(() => {}); },
    });
    await signer.trySign(MESSAGE);
    expect(seen).not.toBeNull();
    expect((seen as unknown as AbortSignal).aborted).toBe(true);
  });

  it('refuses on a pre-aborted caller signal without calling the remote', async () => {
    let called = false;
    const signer = mustBuild({ sign: () => { called = true; return Buffer.alloc(ML_DSA_65_SIGNATURE_BYTES); } });
    const result = await signer.trySign(MESSAGE, { signal: AbortSignal.abort() });
    expect(called).toBe(false);
    expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_CANCELLED);
  });

  it('refuses when the caller cancels an in-flight call', async () => {
    const controller = new AbortController();
    const signer = mustBuild({ timeoutMs: 5000, sign: () => new Promise(() => {}) });
    const pending = signer.trySign(MESSAGE, { signal: controller.signal });
    controller.abort();
    const result = await pending;
    expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_CANCELLED);
  });

  it('refuses on a lifetime (shutdown) signal', async () => {
    const controller = new AbortController();
    const signer = mustBuild({ signal: controller.signal, timeoutMs: 5000, sign: () => new Promise(() => {}) });
    const pending = signer.trySign(MESSAGE);
    controller.abort();
    expect(((await pending) as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.SIGNER_CANCELLED);
  });

  it('bounds the configurable deadline', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_EXTERNAL_PQ_TIMEOUT_MS + 1, '5000']) {
      const built = build({ timeoutMs: bad as never });
      expect(built.ok, `timeoutMs ${String(bad)}`).toBe(false);
      expect((built as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.TIMEOUT_INVALID);
    }
    expect(mustBuild({ timeoutMs: MAX_EXTERNAL_PQ_TIMEOUT_MS }).timeoutMs).toBe(MAX_EXTERNAL_PQ_TIMEOUT_MS);
  });
});

// --------------------------------------------------------------------------
// Property 5: nothing throws on caller input
// --------------------------------------------------------------------------

describe('property: caller input yields named refusals, never throws', () => {
  it('never throws out of the factory', () => {
    const cases: unknown[] = [
      undefined, null, 42, 'nonsense', [],
      {}, { keyId: '' }, { keyId: 'k' }, { keyId: 'k', custody: 'hsm' },
      { keyId: 'k', custody: 'hsm', sign: 'not a function', publicKey: PUBLIC_KEY_B64U },
      { keyId: 'k', custody: 'hsm', sign: correctRemote, publicKey: PUBLIC_KEY_B64U, signal: 'not a signal' },
    ];
    for (const input of cases) {
      let built: unknown;
      expect(() => { built = createExternalPqCustodySigner(input as never); }).not.toThrow();
      expect((built as { ok: boolean }).ok).toBe(false);
      expect(typeof (built as { reason: string }).reason).toBe('string');
      expect((built as { reason: string }).reason.startsWith('external_pq_')).toBe(true);
    }
  });

  it('refuses non-byte messages instead of signing them', async () => {
    const signer = mustBuild();
    for (const bad of [undefined, null, 'MESSAGE', 42, {}, []]) {
      const result = await signer.trySign(bad);
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toBe(EXTERNAL_PQ_REASONS.MESSAGE_INVALID);
    }
    await expect(signer.sign('MESSAGE' as never)).rejects.toMatchObject({
      reason: EXTERNAL_PQ_REASONS.MESSAGE_INVALID,
    });
  });

  it('validateRemoteSignature is total over arbitrary values', () => {
    for (const value of [undefined, null, 0, '', {}, [], Buffer.alloc(0), Symbol('x')]) {
      expect(() => validateRemoteSignature(value as never)).not.toThrow();
      expect(validateRemoteSignature(value as never).ok).toBe(false);
    }
  });
});

// --------------------------------------------------------------------------
// The conformance harness every provider adapter must pass unchanged
// --------------------------------------------------------------------------

describe('runExternalPqCustodyConformance', () => {
  it('passes a correct adapter on every case', async () => {
    const report = await runExternalPqCustodyConformance(mustBuild());
    expect(report.failed).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.profile).toBe(EXTERNAL_PQ_CUSTODY_PROFILE);
    expect(report.custody).toBe('hsm');
    expect(report.cases.every((c) => c.ok)).toBe(true);
  });

  it('accepts a factory or a construction result as the candidate', async () => {
    expect((await runExternalPqCustodyConformance(() => build())).ok).toBe(true);
    expect((await runExternalPqCustodyConformance(build())).ok).toBe(true);
  });

  it('reports a construction refusal instead of throwing', async () => {
    const report = await runExternalPqCustodyConformance(build({ custody: 'software' as never }));
    expect(report.ok).toBe(false);
    expect(report.cases[0]).toMatchObject({
      name: 'adapter_constructs',
      ok: false,
      reason: EXTERNAL_PQ_REASONS.CUSTODY_KIND_INVALID,
    });
    expect(report.failed).toContain('signs_bound_message');
  });

  it('reports an adapter that throws instead of returning', async () => {
    const report = await runExternalPqCustodyConformance(() => { throw new Error('adapter boom'); });
    expect(report.ok).toBe(false);
    expect(report.cases[0].reason).toBe(EXTERNAL_PQ_REASONS.ADAPTER_THREW);
  });

  const hostileAdapters: Array<[string, Partial<ExternalPqCustodyOptions>, string, string]> = [
    ['one byte too long', { sign: ({ bytes }) => Buffer.concat([Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), KEYPAIR.secretKey)), Buffer.alloc(1)]) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID],
    ['one byte too short', { sign: ({ bytes }) => Buffer.from(ml_dsa65.sign(new Uint8Array(bytes), KEYPAIR.secretKey)).subarray(0, ML_DSA_65_SIGNATURE_BYTES - 1) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID],
    ['truncated', { sign: () => Buffer.alloc(7) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID],
    ['Ed25519-length', { sign: () => crypto.randomBytes(64) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_LENGTH_INVALID],
    ['all zeros', { sign: () => Buffer.alloc(ML_DSA_65_SIGNATURE_BYTES, 0) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_INVALID],
    ['signature over different bytes', { sign: () => ml_dsa65.sign(new Uint8Array(MESSAGE), KEYPAIR.secretKey) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_INVALID],
    ['signature under a different key', { sign: ({ bytes }) => ml_dsa65.sign(new Uint8Array(bytes), OTHER_KEYPAIR.secretKey) }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNATURE_INVALID],
    ['remote throws', { sign: () => { throw new Error('down'); } }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNER_UNAVAILABLE],
    ['remote never resolves', { sign: () => new Promise(() => {}), timeoutMs: 40 }, 'signs_bound_message', EXTERNAL_PQ_REASONS.SIGNER_TIMEOUT],
  ];

  for (const [label, overrides, failingCase, reason] of hostileAdapters) {
    it(`fails an adapter whose remote returns ${label}`, async () => {
      const report = await runExternalPqCustodyConformance(mustBuild(overrides));
      expect(report.ok).toBe(false);
      expect(report.failed).toContain(failingCase);
      expect(report.cases.find((c) => c.name === failingCase)?.reason).toBe(reason);
    });
  }

  it('catches a replayed signature that the signer own shape pins let through', async () => {
    // verifyOnSign is off, so the shape pins alone let a constant signature
    // through the signer. The harness signs bytes the adapter has never seen,
    // so it refuses anyway.
    const constant = ml_dsa65.sign(new Uint8Array(MESSAGE), KEYPAIR.secretKey);
    const report = await runExternalPqCustodyConformance(mustBuild({
      verifyOnSign: false,
      sign: () => constant,
    }));
    expect(report.ok).toBe(false);
    expect(report.failed).toContain('signs_bound_message');
  });

  it('fails an adapter that surfaces key material', async () => {
    const signer = mustBuild();
    const leaky = Object.assign(Object.create(Object.getPrototypeOf(signer)), signer, {
      secretKey: Buffer.alloc(ML_DSA_65_SECRET_KEY_BYTES),
    }) as ExternalPqCustodySigner;
    const report = await runExternalPqCustodyConformance(leaky);
    expect(report.failed).toContain('no_secret_key_surface');
    expect(report.cases.find((c) => c.name === 'no_secret_key_surface')?.reason)
      .toBe(EXTERNAL_PQ_REASONS.SECRET_KEY_SURFACE);
  });

  it('refuses to pass an adapter when no ML-DSA backend can check it', async () => {
    const report = await runExternalPqCustodyConformance(
      mustBuild({ mldsaBackend: {} as never }),
      { mldsaBackend: {} as never },
    );
    expect(report.ok).toBe(false);
    expect(report.cases.find((c) => c.name === 'signs_bound_message')?.reason)
      .toBe(EXTERNAL_PQ_REASONS.PQ_BACKEND_UNAVAILABLE);
  });
});

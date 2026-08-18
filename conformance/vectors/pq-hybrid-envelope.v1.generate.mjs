// SPDX-License-Identifier: Apache-2.0
// Generator for EP-HYBRID-v1 envelope conformance vectors
// (conformance/vectors/pq-hybrid-envelope.v1.json).
//
// WHY THIS FILE EXISTS. conformance/pq-agility covers EP-SIG-AGILITY-v1
// (relying-party policy over a presented signature set) and
// conformance/hybrid-receipts covers EP-RECEIPT-HYBRID-v1 (issued receipts
// whose signed material commits to the required algorithm set). Neither
// exercises EP-HYBRID-v1 (packages/verify/src/pq-hybrid.ts), the INFRASTRUCTURE
// envelope whose two signatures are computed over a domain-separated signing
// input that includes the algorithm set, and whose verifier carries the two
// refusals no other suite reaches: algorithm_key_mismatch (Ed25519 curve pin)
// and signature_length_invalid (exact length pin). Both pins are required;
// this vector set proves neither alone closes the masquerade.
//
// Every byte here is produced by the SHIPPED verifier's own signing path
// (signHybrid from packages/verify/pq-hybrid.js), never hand-written, and
// `--check` re-verifies every emitted vector through the shipped verifyHybrid
// so the JSON and the JS implementation can never drift apart silently.
//
// Run:
//   node conformance/vectors/pq-hybrid-envelope.v1.generate.mjs          # emit
//   node conformance/vectors/pq-hybrid-envelope.v1.generate.mjs --check  # verify
//
// TEST KEYS ONLY. Every key is derived from a fixed public seed label. Never
// use any of this material for anything real.

import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  HYBRID_ALG,
  HYBRID_SIGNATURE_ALGOS,
  signHybrid,
  verifyHybrid,
} from '../../packages/verify/pq-hybrid.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, 'pq-hybrid-envelope.v1.json');

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const seedOf = (label) => crypto.createHash('sha256').update(label, 'utf8').digest();

// RFC 8410 PKCS#8 prefix for a raw Ed25519 seed.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function ed25519FromSeedLabel(label) {
  const seed = seedOf(label);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    spki_b64url: b64u(publicKey.export({ format: 'der', type: 'spki' })),
  };
}

// Ed448 is NOT deterministic from a seed through node's generateKeyPairSync, so
// the masquerade key pair is generated from a fixed PKCS#8 seed the same way:
// RFC 8410 assigns Ed448 its own OID and a 57-byte seed.
const ED448_PKCS8_PREFIX = Buffer.from('3047020100300506032b6571043b0439', 'hex');

function ed448FromSeedLabel(label) {
  // 57 bytes of seed material from two SHA-256 blocks, truncated.
  const a = seedOf(label);
  const b = seedOf(`${label}/2`);
  const seed = Buffer.concat([a, b]).subarray(0, 57);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([ED448_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    spki_b64url: b64u(publicKey.export({ format: 'der', type: 'spki' })),
  };
}

/**
 * Deterministic ML-DSA-65 backend. signHybrid does not thread FIPS 204 signing
 * options through, so the deterministic variant (extraEntropy=false) is reached
 * by injecting the backend directly. Verification is unaffected by this choice.
 */
async function deterministicMldsaBackend() {
  const mod = await import('@noble/post-quantum/ml-dsa.js');
  const impl = mod.ml_dsa65;
  return {
    keygen: (seed) => impl.keygen(seed),
    sign: (messageBytes, secretKeyBytes) => impl.sign(messageBytes, secretKeyBytes, { extraEntropy: false }),
    verify: (signatureBytes, messageBytes, publicKeyBytes) => {
      try {
        return impl.verify(signatureBytes, messageBytes, publicKeyBytes) === true;
      } catch {
        return false;
      }
    },
  };
}

const MESSAGE = JSON.stringify({
  '@profile': 'EP-HYBRID-v1/conformance',
  checkpoint: {
    log_id: 'ep:log:hybrid-envelope-conformance',
    root: 'sha256:0f2c0a5f4c9d1f7a0f4d5b6c7e8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2',
    size: 4096,
  },
  issued_at: '2026-08-17T00:00:00Z',
});

/** Flip the first byte of a base64url-encoded blob without changing its length. */
function tamperFirstByte(b64) {
  const bytes = Buffer.from(b64, 'base64url');
  bytes[0] ^= 0x01;
  return b64u(bytes);
}

/** Truncate a base64url-encoded blob by one byte. */
function truncateOneByte(b64) {
  const bytes = Buffer.from(b64, 'base64url');
  return b64u(bytes.subarray(0, bytes.length - 1));
}

async function build() {
  const backend = await deterministicMldsaBackend();

  const ed = ed25519FromSeedLabel('EP-HYBRID-v1/vectors/ed25519/1');
  const edOther = ed25519FromSeedLabel('EP-HYBRID-v1/vectors/ed25519/other');
  const ed448 = ed448FromSeedLabel('EP-HYBRID-v1/vectors/ed448/1');

  const pqSeed = seedOf('EP-HYBRID-v1/vectors/ml-dsa-65/1');
  const pq = backend.keygen(pqSeed);
  const pqPublic = b64u(pq.publicKey);

  // The reference envelope, produced by the shipped signHybrid.
  const envelope = await signHybrid(MESSAGE, {
    ed25519PrivateKey: ed.privateKey,
    mldsaSecretKey: pq.secretKey,
  }, { mldsaBackend: backend });

  // The Ed448 masquerade leg: a REAL Ed448 signature over the same committed
  // signing input, relabeled as the envelope's Ed25519 slot. It is 114 bytes.
  const signingInput = Buffer.concat([
    Buffer.from('emilia-protocol/pq-hybrid/v1', 'utf8'), Buffer.from([0x00]),
    Buffer.from(JSON.stringify([...HYBRID_SIGNATURE_ALGOS]), 'utf8'), Buffer.from([0x00]),
    Buffer.from(MESSAGE, 'utf8'),
  ]);
  const ed448Sig = b64u(crypto.sign(null, signingInput, ed448.privateKey));

  const keys = {
    ed25519: {
      seed_label: 'EP-HYBRID-v1/vectors/ed25519/1',
      spki_b64url: ed.spki_b64url,
    },
    'ed25519-other': {
      seed_label: 'EP-HYBRID-v1/vectors/ed25519/other',
      spki_b64url: edOther.spki_b64url,
    },
    ed448: {
      seed_label: 'EP-HYBRID-v1/vectors/ed448/1',
      spki_b64url: ed448.spki_b64url,
    },
    'ml-dsa-65': {
      seed_label: 'EP-HYBRID-v1/vectors/ml-dsa-65/1',
      public_key_b64url: pqPublic,
    },
    'ml-dsa-65-truncated': {
      description: 'The registered ML-DSA-65 public key with one byte removed (1951 bytes).',
      public_key_b64url: truncateOneByte(pqPublic),
    },
  };

  const env = (over = {}) => ({
    alg: HYBRID_ALG,
    signature_algos: [...HYBRID_SIGNATURE_ALGOS],
    sigs: { ...envelope.sigs },
    ...over,
  });

  const vectors = [
    {
      id: 'pq-hybrid-valid',
      description:
        'Both legs over the domain-separated signing input that commits to the full algorithm set.',
      message: MESSAGE,
      envelope: env(),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: true, reason: null },
    },
    {
      id: 'pq-hybrid-pq-leg-stripped',
      description:
        'The post-quantum leg is removed and the committed set left intact. One signature for a two-algorithm commitment.',
      message: MESSAGE,
      envelope: env({ sigs: { Ed25519: envelope.sigs.Ed25519 } }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'missing_signature' },
    },
    {
      id: 'pq-hybrid-classical-leg-stripped',
      description: 'The classical leg is removed. Same structural refusal in the other direction.',
      message: MESSAGE,
      envelope: env({ sigs: { 'ML-DSA-65': envelope.sigs['ML-DSA-65'] } }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'missing_signature' },
    },
    {
      id: 'pq-hybrid-algo-set-narrowed',
      description:
        'The attacker strips the PQ leg AND narrows signature_algos so the envelope looks complete. Refused structurally; the surviving signature also no longer covers these bytes.',
      message: MESSAGE,
      envelope: env({
        signature_algos: ['Ed25519'],
        sigs: { Ed25519: envelope.sigs.Ed25519 },
      }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'algo_set_mismatch' },
    },
    {
      id: 'pq-hybrid-algo-set-reordered',
      description:
        'The committed set is reordered. EP-HYBRID-v1 pins canonical order, so this is a different commitment.',
      message: MESSAGE,
      envelope: env({ signature_algos: ['ML-DSA-65', 'Ed25519'] }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'algo_set_mismatch' },
    },
    {
      id: 'pq-hybrid-unknown-algorithm-in-set',
      description:
        'An algorithm outside the registered EP-HYBRID-v1 set. An unknown algorithm never verifies; INDETERMINATE never authorizes.',
      message: MESSAGE,
      envelope: env({
        signature_algos: ['Ed25519', 'ML-DSA-87'],
        sigs: { Ed25519: envelope.sigs.Ed25519, 'ML-DSA-87': envelope.sigs['ML-DSA-65'] },
      }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'algo_set_mismatch' },
    },
    {
      id: 'pq-hybrid-extra-signature',
      description: 'A third signature beyond the committed set. Extras refuse; the envelope is exact.',
      message: MESSAGE,
      envelope: env({
        sigs: { ...envelope.sigs, 'RSA-PSS': 'AAAA' },
      }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'invalid_envelope' },
    },
    {
      id: 'pq-hybrid-wrong-alg-marker',
      description: 'The envelope claims a version this verifier does not implement.',
      message: MESSAGE,
      envelope: env({ alg: 'EP-HYBRID-v2' }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'invalid_envelope' },
    },
    {
      id: 'pq-hybrid-ed448-key-masquerade',
      description:
        'A real Ed448 signature in the Ed25519 slot, presented with the matching Ed448 public key. The CURVE PIN refuses before any verify call: crypto.verify picks the algorithm from the key object, so without this pin the attacker verifies under their own curve.',
      message: MESSAGE,
      envelope: env({ sigs: { ...envelope.sigs, Ed25519: ed448Sig } }),
      keys: { ed25519: 'ed448', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'algorithm_key_mismatch' },
    },
    {
      id: 'pq-hybrid-ed448-signature-length',
      description:
        'The same Ed448 leg presented against the pinned Ed25519 key. This is the OTHER half of the anti-masquerade control: a 114-byte signature fails the exact length pin. Neither pin alone closes the masquerade.',
      message: MESSAGE,
      envelope: env({ sigs: { ...envelope.sigs, Ed25519: ed448Sig } }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'signature_length_invalid' },
    },
    {
      id: 'pq-hybrid-classical-signature-length',
      description: 'The classical leg truncated to 63 bytes. Exact length pin, not a range.',
      message: MESSAGE,
      envelope: env({ sigs: { ...envelope.sigs, Ed25519: truncateOneByte(envelope.sigs.Ed25519) } }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'signature_length_invalid' },
    },
    {
      id: 'pq-hybrid-pq-signature-length',
      description: 'The post-quantum leg truncated to 3308 bytes.',
      message: MESSAGE,
      envelope: env({
        sigs: { ...envelope.sigs, 'ML-DSA-65': truncateOneByte(envelope.sigs['ML-DSA-65']) },
      }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'signature_length_invalid' },
    },
    {
      id: 'pq-hybrid-pq-public-key-length',
      description: 'The ML-DSA-65 public key is one byte short of the FIPS 204 parameter set.',
      message: MESSAGE,
      envelope: env(),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65-truncated' },
      backend: 'default',
      expect: { verified: false, reason: 'public_key_length_invalid' },
    },
    {
      id: 'pq-hybrid-classical-signature-invalid',
      description: 'The classical leg tampered in place, correct length. Cryptographic refusal.',
      message: MESSAGE,
      envelope: env({ sigs: { ...envelope.sigs, Ed25519: tamperFirstByte(envelope.sigs.Ed25519) } }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'classical_signature_invalid' },
    },
    {
      id: 'pq-hybrid-classical-key-substituted',
      description: 'A different, well-formed Ed25519 key. The curve pin passes; the signature does not.',
      message: MESSAGE,
      envelope: env(),
      keys: { ed25519: 'ed25519-other', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'classical_signature_invalid' },
    },
    {
      id: 'pq-hybrid-pq-signature-invalid',
      description:
        'The post-quantum leg tampered in place, correct length. The classical leg still verifies, and the envelope still refuses: one leg of two never carries it.',
      message: MESSAGE,
      envelope: env({
        sigs: { ...envelope.sigs, 'ML-DSA-65': tamperFirstByte(envelope.sigs['ML-DSA-65']) },
      }),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'pq_signature_invalid' },
    },
    {
      id: 'pq-hybrid-message-tampered',
      description: 'The signed message changed. Both legs cover it; the classical leg reports first.',
      message: MESSAGE.replace('"size":4096', '"size":4097'),
      envelope: env(),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'default',
      expect: { verified: false, reason: 'classical_signature_invalid' },
    },
    {
      id: 'pq-hybrid-backend-absent',
      description:
        'A fully valid envelope with NO ML-DSA backend available. Absence of the backend is a REFUSAL, never a skipped check and never verified:true on the classical leg alone.',
      message: MESSAGE,
      envelope: env(),
      keys: { ed25519: 'ed25519', mldsa: 'ml-dsa-65' },
      backend: 'absent',
      expect: { verified: false, reason: 'pq_backend_unavailable' },
    },
  ];

  return {
    '@version': 'EP-HYBRID-ENVELOPE-VECTORS-v1',
    profile: HYBRID_ALG,
    description:
      'Deterministic conformance vectors for the EP-HYBRID-v1 infrastructure envelope '
      + '(packages/verify/src/pq-hybrid.ts). Both signatures are computed over a '
      + 'domain-separated signing input that commits to the full algorithm set, so removing '
      + 'or reordering an algorithm changes what was signed. Consumed by the JS generator in '
      + '--check mode and by conformance/py/run_pq.py.',
    generated_by: 'conformance/vectors/pq-hybrid-envelope.v1.generate.mjs',
    signing_input:
      "UTF8('emilia-protocol/pq-hybrid/v1') || 0x00 || UTF8(JSON.stringify(signature_algos)) || 0x00 || message",
    registered_algorithms: [...HYBRID_SIGNATURE_ALGOS],
    lengths: {
      ed25519_signature_bytes: 64,
      ml_dsa_65_signature_bytes: 3309,
      ml_dsa_65_public_key_bytes: 1952,
    },
    generation: {
      ed25519:
        'Private key seed = SHA-256(seed_label), wrapped in the RFC 8410 PKCS#8 prefix '
        + '302e020100300506032b657004220420. Ed25519 signatures are deterministic per RFC 8032.',
      ed448:
        'Private key seed = first 57 bytes of SHA-256(seed_label) || SHA-256(seed_label + "/2"), '
        + 'wrapped in the RFC 8410 Ed448 PKCS#8 prefix 3047020100300506032b6571043b0439.',
      ml_dsa_65:
        'Keygen seed = SHA-256("EP-HYBRID-v1/vectors/ml-dsa-65/1"), expanded by ML-DSA.KeyGen '
        + '(FIPS 204). Signing uses the FIPS 204 deterministic variant (extraEntropy=false), so '
        + 'the 3309-byte signature is fixed by seed and message. Generated with '
        + '@noble/post-quantum 0.6.1, a pure-JS FIPS 204 implementation that is self-audited by '
        + 'its authors and is NOT a FIPS-validated module.',
      keys_are_test_only: true,
    },
    keys,
    vectors,
  };
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function verifyEmitted(doc) {
  const backend = await deterministicMldsaBackend();
  const absentLoader = () => null;
  let failures = 0;
  for (const v of doc.vectors) {
    const edEntry = doc.keys[v.keys.ed25519];
    const pqEntry = doc.keys[v.keys.mldsa];
    const options = v.backend === 'absent'
      ? { mldsaBackendLoader: absentLoader }
      : { mldsaBackend: backend };
    const result = await verifyHybrid(
      v.message,
      v.envelope,
      {
        ed25519PublicKey: edEntry.spki_b64url,
        mldsaPublicKey: pqEntry.public_key_b64url,
      },
      options,
    );
    const ok = result.verified === v.expect.verified && result.reason === v.expect.reason;
    if (!ok) {
      failures += 1;
      console.error(
        `FAIL ${v.id}: expected verified=${v.expect.verified} reason=${v.expect.reason}, `
        + `got verified=${result.verified} reason=${result.reason}`,
      );
    }
  }
  return failures;
}

const check = process.argv.includes('--check');
const doc = await build();
const serialized = stableJson(doc);

const failures = await verifyEmitted(doc);
if (failures > 0) {
  console.error(`${failures} vector(s) do not match the shipped EP-HYBRID-v1 verifier.`);
  process.exit(1);
}

if (check) {
  let onDisk;
  try {
    onDisk = readFileSync(OUT, 'utf8');
  } catch {
    console.error(`missing ${OUT}; run the generator without --check first`);
    process.exit(1);
  }
  if (onDisk !== serialized) {
    console.error(`${OUT} differs from the generator output`);
    process.exit(1);
  }
  console.log(`pq-hybrid-envelope.v1.json OK: ${doc.vectors.length} vectors reproduce and verify`);
} else {
  writeFileSync(OUT, serialized);
  console.log(`wrote ${OUT}: ${doc.vectors.length} vectors`);
}

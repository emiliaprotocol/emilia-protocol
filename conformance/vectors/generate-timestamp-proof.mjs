// SPDX-License-Identifier: Apache-2.0
//
// Generator for conformance/vectors/timestamp-proof.v1.json — the cross-language
// EP-TIMESTAMP-PROOF-v1 (RFC 3161) suite. It mints a purpose-built, LOCAL test
// TSA (an RSA/SHA-256 X.509 signing cert marked extendedKeyUsage=timeStamping)
// with `openssl`, stamps two real RFC 3161 TimeStampTokens (CMS SignedData with
// the RFC 5652 signed-attributes form openssl always emits), and derives the
// reject variants from those authentic tokens (tampered signature, wrong pinned
// key, wrong expected digest, non-token DER, garbage). The signer SPKI (pinned
// key) and a second unrelated RSA SPKI (the "wrong pin") are embedded so the
// suite is self-contained and reproducible offline.
//
// The vectors mirror packages/verify/timestamp-proof.test.js, but are shaped for
// the polymorphic conformance runners: each vector carries
//   { id, expect:{valid}, timestamp_proof, expected_digest, pinned_tsa_keys }
// and the JS/Python/Go runners each call verifyTimestampProof and compare
// .verified to expect.valid.
//
//   node conformance/vectors/generate-timestamp-proof.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { verifyTimestampProof } from '../../packages/verify/timestamp-proof.js';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, 'timestamp-proof.v1.json');

const dir = mkdtempSync(join(tmpdir(), 'ep-tsp-'));
const ossl = (args, opts = {}) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], ...opts });

function mintTsaAndTokens() {
  // 1. TSA signing key + self-signed cert with the timeStamping EKU (openssl ts
  //    refuses to sign otherwise).
  ossl(['req', '-new', '-newkey', 'rsa:2048', '-keyout', 'tsa.key', '-nodes', '-x509',
    '-days', '3650', '-subj', '/CN=EP Conformance TSA/O=EMILIA Conformance',
    '-addext', 'extendedKeyUsage=critical,timeStamping', '-out', 'tsa.crt']);

  // Minimal TSA config so `openssl ts -reply` does not fall back to the system
  // openssl.cnf (which points at a non-existent ./demoCA). Defines a signing
  // policy OID, the accepted digest, and disables the requirement that the
  // request carry a nonce / cert.
  writeFileSync(join(dir, 'serial.txt'), '01\n');
  const tsaCnf = [
    '[tsa_config]',
    'signer_cert = tsa.crt',
    'signer_key = tsa.key',
    'signer_digest = sha256',
    'default_policy = 1.2.3.4.1',
    'serial = serial.txt',
    'digests = sha256, sha384, sha512',
    'accuracy = secs:1',
    'clock_precision_digits = 0',
    'ordering = yes',
    'tsa_name = no',
    'ess_cert_id_chain = no',
    'ess_cert_id_alg = sha256',
    '',
  ].join('\n');
  writeFileSync(join(dir, 'tsa.cnf'), tsaCnf);

  // A second, unrelated RSA keypair — its SPKI is the "wrong pin" (a valid key
  // that did NOT sign the token; must yield bad_signature).
  ossl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'other.key']);
  ossl(['pkey', '-in', 'other.key', '-pubout', '-outform', 'DER', '-out', 'other.spki.der']);

  // Signer SPKI DER (the pinned key that MUST verify the token).
  ossl(['x509', '-in', 'tsa.crt', '-noout', '-pubkey'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const signerPubPem = ossl(['x509', '-in', 'tsa.crt', '-noout', '-pubkey']).toString('utf8');
  writeFileSync(join(dir, 'signer.pub.pem'), signerPubPem);
  ossl(['pkey', '-pubin', '-in', 'signer.pub.pem', '-pubout', '-outform', 'DER', '-out', 'signer.spki.der']);

  const mkToken = (dataStr, name) => {
    writeFileSync(join(dir, `${name}.txt`), dataStr);
    ossl(['ts', '-query', '-data', `${name}.txt`, '-sha256', '-no_nonce', '-out', `${name}.tsq`]);
    ossl(['ts', '-reply', '-queryfile', `${name}.tsq`, '-signer', 'tsa.crt', '-inkey', 'tsa.key',
      '-config', 'tsa.cnf', '-section', 'tsa_config', '-token_out', '-out', `${name}.der`]);
    const der = readFileSync(join(dir, `${name}.der`));
    const digest = crypto.createHash('sha256').update(dataStr).digest('hex');
    return { der, digest };
  };

  const t1 = mkToken('emilia-protocol conformance timestamp-proof vector one', 'tok1');
  const t2 = mkToken('emilia-protocol conformance timestamp-proof vector two', 'tok2');

  const signerSpki = readFileSync(join(dir, 'signer.spki.der')).toString('base64');
  const otherSpki = readFileSync(join(dir, 'other.spki.der')).toString('base64');
  return { t1, t2, signerSpki, otherSpki };
}

const { t1, t2, signerSpki, otherSpki } = mintTsaAndTokens();
rmSync(dir, { recursive: true, force: true });

const TOKEN1 = t1.der.toString('base64');
const TOKEN2 = t2.der.toString('base64');
const DIGEST1 = t1.digest;
const DIGEST2 = t2.digest;

// Tamper: flip one byte deep inside the signature region (last 40 bytes) so the
// DER still parses but the RSA signature no longer verifies -> bad_signature.
const tamperedBuf = Buffer.from(t1.der);
const flipAt = tamperedBuf.length - 20;
tamperedBuf[flipAt] ^= 0x01;
const TOKEN1_TAMPERED = tamperedBuf.toString('base64');

// A well-formed ContentInfo whose contentType OID is pkcs7-data, not signedData
// -> not_signed_data (distinct from unparseable_token).
const dataOid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
const explicit0 = Buffer.from([0xa0, 0x00]);
const dataBody = Buffer.concat([dataOid, explicit0]);
const NOT_SIGNED_DATA = Buffer.concat([Buffer.from([0x30, dataBody.length]), dataBody]).toString('base64');

const vectors = [
  // ── ACCEPT ────────────────────────────────────────────────────────────────
  {
    id: 'accept_authentic_pinned_rsa_sha256',
    expect: { valid: true },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'accept_second_token_bound_to_other_digest',
    expect: { valid: true },
    timestamp_proof: TOKEN2,
    expected_digest: 'sha256:' + DIGEST2,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'accept_pinned_key_in_array_with_decoy',
    expect: { valid: true },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: [otherSpki, signerSpki],
  },
  {
    id: 'accept_expected_digest_bare_hex',
    expect: { valid: true },
    timestamp_proof: TOKEN1,
    expected_digest: DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  // ── REJECT (each pins a distinct refusal path) ──────────────────────────────
  {
    id: 'reject_missing_token',
    expect: { valid: false },
    timestamp_proof: '',
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'reject_malformed_expected_digest',
    expect: { valid: false },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:xyz',
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'reject_unpinned_tsa_empty',
    expect: { valid: false },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: {},
  },
  {
    id: 'reject_unloadable_pinned_key',
    expect: { valid: false },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: 'not-a-real-spki-key',
  },
  {
    id: 'reject_digest_mismatch',
    expect: { valid: false },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST2,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'reject_wrong_pinned_key',
    expect: { valid: false },
    timestamp_proof: TOKEN1,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: otherSpki },
  },
  {
    id: 'reject_tampered_signature',
    expect: { valid: false },
    timestamp_proof: TOKEN1_TAMPERED,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'reject_unparseable_garbage',
    expect: { valid: false },
    timestamp_proof: '!!!!not base64 at all????',
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
  {
    id: 'reject_not_signed_data',
    expect: { valid: false },
    timestamp_proof: NOT_SIGNED_DATA,
    expected_digest: 'sha256:' + DIGEST1,
    pinned_tsa_keys: { tsa: signerSpki },
  },
];

// Self-check: the JS reference verifier MUST agree with every expected outcome
// before we write the suite (a generator that emits a vector its own reference
// rejects is a bug, not a vector).
for (const v of vectors) {
  /** @type {any} */
  const r = verifyTimestampProof(v.timestamp_proof, v.expected_digest, v.pinned_tsa_keys);
  if (r.verified !== v.expect.valid) {
    throw new Error(`self-check failed for ${v.id}: JS verified=${r.verified} reason=${r.reason} expected valid=${v.expect.valid}`);
  }
}

const suite = {
  suite: 'EP-TIMESTAMP-PROOF-v1',
  profile: 'Executable RFC 3161 timestamp-proof vectors (real openssl-minted TimeStampTokens, local test TSA). verifyTimestampProof(timestamp_proof, expected_digest, pinned_tsa_keys) must return .verified === expect.valid.',
  vectors_version: '1.0.0',
  count: vectors.length,
  note: 'Self-contained: signer SPKI (pinned key) and a decoy SPKI are embedded per vector. Tokens are RSA/SHA-256, CMS SignedData with RFC 5652 signed attributes. Regenerate with `node conformance/vectors/generate-timestamp-proof.mjs`.',
  vectors,
};

writeFileSync(outPath, JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote ${outPath} — ${vectors.length} vectors (JS self-check passed)`);

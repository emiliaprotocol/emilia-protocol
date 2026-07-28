// SPDX-License-Identifier: Apache-2.0
//
// Generates conformance/vectors/status.v1.json from the shipped EP-STATUS
// implementation. These vectors are the portable, protocol-independent test
// suite for the question draft-schrock-ep-revocation-statement-00 explicitly
// defers: "A relying party that needs to establish that no revocation is known
// as of time T MUST obtain separately authenticated status evidence and apply a
// relying-party-selected freshness bound."
//
// Nothing here requires an EMILIA receipt. A status target is a generic
// (type, id, digest, usage) tuple, so any protocol with a signed artifact and a
// content digest can bind to it. That is the whole point: an author whose draft
// says "revocation is left to local policy" can run these vectors against their
// own implementation without adopting anything of ours.
//
// Run: node conformance/generate-status-vectors.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import {
  buildRevokerAuthorityCertificate,
  buildStatusArtifact,
} from '../lib/revocation/status.js';
import {
  verifyStatusArtifact,
  verifyRevokerAuthorityCertificate,
  statusArtifactDigest,
} from '../packages/verify/status.js';

const b64u = (b) => Buffer.from(b).toString('base64url');
const spki = (k) => b64u(k.export({ type: 'spki', format: 'der' }));

// Deterministic keys so the emitted vectors are byte-stable across runs.
const seedKey = (seed) => {
  const sk = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      crypto.createHash('sha256').update(seed).digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return { privateKey: sk, publicKey: crypto.createPublicKey(sk) };
};

const signerFor = (pair, keyId) => ({
  algorithm: 'Ed25519',
  keyId,
  async sign(bytes) {
    return crypto.sign(null, Buffer.from(bytes), pair.privateKey);
  },
});

const AUTHORITY = seedKey('ep-status-vectors/authority');
const REVOKER = seedKey('ep-status-vectors/revoker');
const IMPOSTOR = seedKey('ep-status-vectors/impostor');

const AUTHORITY_KEY_ID = 'authority-key-1';
const PIN = Object.freeze({
  authority_domain: 'status.example',
  authority_id: 'authority:example',
  key_id: AUTHORITY_KEY_ID,
  public_key: spki(AUTHORITY.publicKey),
});

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-01T01:00:00.000Z';
const T2 = '2026-01-01T02:00:00.000Z';
const T_EXPIRY = '2027-01-01T00:00:00.000Z';

// A generic target. `digest` is the content digest of whatever artifact the
// adopting protocol is reasoning about. Nothing EMILIA-specific.
const TARGET = Object.freeze({
  type: 'receipt',
  id: 'urn:example:artifact:7f3a',
  digest: `sha256:${'a'.repeat(64)}`,
  usage: 'authorization',
});

const OTHER_TARGET = Object.freeze({
  ...TARGET,
  id: 'urn:example:artifact:0000',
  digest: `sha256:${'b'.repeat(64)}`,
});

const authoritySigner = signerFor(AUTHORITY, AUTHORITY_KEY_ID);

const vectors = [];
const add = (v) => vectors.push(v);

async function main() {
  // ── The revoker authority certificate: who may revoke, over what scope ──
  const cert = await buildRevokerAuthorityCertificate({
    certificateId: 'cert-1',
    authorityPin: PIN,
    revokerId: 'revoker:ops',
    revokerPublicKey: spki(REVOKER.publicKey),
    scope: {
      allowed_target_types: ['receipt', 'commit'],
      allowed_usages: ['authorization', 'execution'],
    },
    issuedAt: T0,
    expiresAt: T_EXPIRY,
    signer: authoritySigner,
  });

  // A certificate whose scope excludes 'delegation', used for the scope refusal.
  const narrowCert = await buildRevokerAuthorityCertificate({
    certificateId: 'cert-narrow',
    authorityPin: PIN,
    revokerId: 'revoker:narrow',
    revokerPublicKey: spki(REVOKER.publicKey),
    scope: { allowed_target_types: ['commit'], allowed_usages: ['execution'] },
    issuedAt: T0,
    expiresAt: T_EXPIRY,
    signer: authoritySigner,
  });

  add({
    id: 'authority-certificate-verifies',
    kind: 'revoker_authority',
    description:
      'A signed revoker authority certificate verifies under the pinned authority key. This is the artifact answering "was this party entitled to revoke", which the revocation-statement draft assigns to relying-party pinning policy and does not itself carry.',
    certificate: cert,
    authority_pin: PIN,
    now: T1,
    expect: { valid: true },
  });

  add({
    id: 'authority-certificate-wrong-pin-refused',
    kind: 'revoker_authority',
    description:
      'The same certificate under a different pinned authority key is refused. Attribution is not authority.',
    certificate: cert,
    authority_pin: { ...PIN, public_key: spki(IMPOSTOR.publicKey) },
    now: T1,
    expect: { valid: false, reason_contains: 'revoker_authority' },
  });

  add({
    id: 'authority-certificate-outside-validity-refused',
    kind: 'revoker_authority',
    description:
      'A certificate evaluated after expires_at is refused rather than silently accepted.',
    certificate: cert,
    authority_pin: PIN,
    now: '2027-06-01T00:00:00.000Z',
    expect: { valid: false, reason_contains: 'not_valid_at_time' },
  });

  // ── The status head chain: the negative answer with a freshness bound ──
  const head1 = await buildStatusArtifact({
    authorityPin: PIN,
    certificate: cert,
    target: TARGET,
    status: 'not_revoked',
    issuedAt: T0,
    nextUpdate: T1,
    signer: signerFor(REVOKER, cert.revoker_key.key_id),
  });

  add({
    id: 'status-current-not-revoked',
    kind: 'status',
    description:
      'A signed head asserts not_revoked with an explicit next_update. This is the separately authenticated status evidence the revocation-statement draft requires and does not define.',
    target: TARGET,
    status: head1,
    certificate: cert,
    authority_pin: PIN,
    now: T0,
    expect: { outcome: 'current_not_revoked', valid: true },
  });

  add({
    id: 'status-stale-is-indeterminate-not-negative',
    kind: 'status',
    description:
      'Evaluated past next_update, the same head does not become a negative answer. It becomes indeterminate. Absence of fresh evidence is never proof of non-revocation.',
    target: TARGET,
    status: head1,
    certificate: cert,
    authority_pin: PIN,
    now: T2,
    expect: { outcome: 'indeterminate' },
  });

  add({
    id: 'status-target-mismatch-refused',
    kind: 'status',
    description:
      'A head for one target must not answer for another. Binds (type, id, digest, usage).',
    target: OTHER_TARGET,
    status: head1,
    certificate: cert,
    authority_pin: PIN,
    now: T0,
    expect: { valid: false },
  });

  // Terminal revocation, chained to the previous head.
  const head2 = await buildStatusArtifact({
    authorityPin: PIN,
    certificate: cert,
    target: TARGET,
    status: 'revoked',
    issuedAt: T1,
    nextUpdate: null,
    previousStatus: head1,
    signer: signerFor(REVOKER, cert.revoker_key.key_id),
  });

  add({
    id: 'status-revoked-is-terminal',
    kind: 'status',
    description:
      'A revoked head carries no next_update and does not expire. Passage of time cannot turn REVOKED back into acceptable.',
    target: TARGET,
    status: head2,
    certificate: cert,
    authority_pin: PIN,
    previous_status: head1,
    now: '2030-01-01T00:00:00.000Z',
    expect: { outcome: 'revoked', valid: true },
  });

  add({
    id: 'status-rollback-refused',
    kind: 'status',
    description:
      'Replaying the earlier not_revoked head against an accepted later head is refused. The chain is append-only: sequence must advance and previous_status_digest must match.',
    target: TARGET,
    status: head1,
    certificate: cert,
    authority_pin: PIN,
    previous_status: head2,
    now: T1,
    expect: { valid: false, reason_contains: 'sequence' },
  });

  // Scope violation: a delegation target under a certificate limited to commit.
  let scopeRefusal = null;
  try {
    await buildStatusArtifact({
      authorityPin: PIN,
      certificate: narrowCert,
      target: { ...TARGET, type: 'delegation', usage: 'delegation' },
      status: 'revoked',
      issuedAt: T1,
      nextUpdate: null,
      signer: signerFor(REVOKER, narrowCert.revoker_key.key_id),
    });
  } catch (err) {
    scopeRefusal = String(err && err.message ? err.message : err);
  }
  add({
    id: 'status-outside-revoker-scope-refused',
    kind: 'issuance_refusal',
    description:
      'A revoker whose certificate scope excludes this target type cannot mint a status head for it. Scope is enforced at issuance, not left to the reader.',
    refusal: scopeRefusal,
    expect: { refused: true },
  });

  // Signature tamper.
  const tampered = JSON.parse(JSON.stringify(head1));
  tampered.status = 'revoked';
  add({
    id: 'status-tampered-signature-refused',
    kind: 'status',
    description:
      'Flipping the status field after signing fails signature verification. The state is inside the signed payload.',
    target: TARGET,
    status: tampered,
    certificate: cert,
    authority_pin: PIN,
    now: T0,
    expect: { valid: false, reason_contains: 'signature' },
  });

  // ── The joint: a foreign artifact kind, registered by the relying party ──
  // AP2 mandates, ORPRG permits, intent tokens and capabilities are not EMILIA
  // artifacts and are not in the core three types. Under a pinned registry they
  // bind here anyway; with no registry pinned they are still refused.
  const FOREIGN_REGISTRY = { types: ['mandate'], usages: ['settlement'] };
  const FOREIGN_TARGET = Object.freeze({
    type: 'mandate',
    id: 'urn:example:mandate:44b1',
    digest: `sha256:${'c'.repeat(64)}`,
    usage: 'settlement',
  });

  const foreignCert = await buildRevokerAuthorityCertificate({
    certificateId: 'cert-foreign',
    authorityPin: PIN,
    revokerId: 'revoker:mandates',
    revokerPublicKey: spki(REVOKER.publicKey),
    scope: { allowed_target_types: ['mandate'], allowed_usages: ['settlement'] },
    issuedAt: T0,
    expiresAt: T_EXPIRY,
    signer: authoritySigner,
    targetRegistry: FOREIGN_REGISTRY,
  });

  const foreignHead = await buildStatusArtifact({
    authorityPin: PIN,
    certificate: foreignCert,
    target: FOREIGN_TARGET,
    status: 'not_revoked',
    issuedAt: T0,
    nextUpdate: T1,
    signer: signerFor(REVOKER, foreignCert.revoker_key.key_id),
    targetRegistry: FOREIGN_REGISTRY,
  });

  add({
    id: 'foreign-registered-type-accepted-under-pinned-registry',
    kind: 'status',
    description:
      'A non-EMILIA artifact kind ("mandate"/"settlement") mints and verifies end to end when the relying party pins a registry containing it. This is the extension path: an author binds their own artifact kind without adopting EMILIA receipts and without waiting for a new revision of this specification.',
    target: FOREIGN_TARGET,
    status: foreignHead,
    certificate: foreignCert,
    authority_pin: PIN,
    target_registry: FOREIGN_REGISTRY,
    now: T0,
    expect: { outcome: 'current_not_revoked', valid: true },
  });

  add({
    id: 'foreign-type-refused-without-pinned-registry',
    kind: 'status',
    description:
      'The exact same signed head is refused when no registry is pinned. Extension is a configured, auditable act by the relying party, never a verifier widening its own vocabulary. The default stays fail-closed and conformant with the published core set.',
    target: FOREIGN_TARGET,
    status: foreignHead,
    certificate: foreignCert,
    authority_pin: PIN,
    now: T0,
    expect: { outcome: 'indeterminate' },
  });

  add({
    id: 'status-missing-evidence-is-indeterminate',
    kind: 'status',
    description:
      'No status artifact at all yields indeterminate, never current_not_revoked. This is the single most important refusal in the suite: a relying party with no evidence has learned nothing, not good news.',
    target: TARGET,
    status: null,
    certificate: cert,
    authority_pin: PIN,
    now: T0,
    expect: { outcome: 'indeterminate' },
  });

  // ── Self-check every vector against the shipped verifier ──
  let checked = 0;
  for (const v of vectors) {
    if (v.kind === 'issuance_refusal') {
      if (!v.refusal) throw new Error(`${v.id}: expected an issuance refusal, got none`);
      checked += 1;
      continue;
    }
    const opts = {
      authorityPin: v.authority_pin,
      certificate: v.certificate,
      now: v.now,
      ...(v.target_registry ? { targetRegistry: v.target_registry } : {}),
      ...(v.previous_status ? { previousStatus: v.previous_status } : {}),
    };
    const got =
      v.kind === 'revoker_authority'
        ? verifyRevokerAuthorityCertificate(v.certificate, {
            authorityPin: v.authority_pin,
            now: v.now,
            ...(v.target_registry ? { targetRegistry: v.target_registry } : {}),
          })
        : verifyStatusArtifact(v.target, v.status, opts);

    if (typeof v.expect.valid === 'boolean' && got.valid !== v.expect.valid) {
      throw new Error(`${v.id}: expected valid=${v.expect.valid}, got ${got.valid} (${got.reasons.join(', ')})`);
    }
    if (v.expect.outcome && got.outcome !== v.expect.outcome) {
      throw new Error(`${v.id}: expected outcome=${v.expect.outcome}, got ${got.outcome} (${got.reasons.join(', ')})`);
    }
    if (v.expect.reason_contains) {
      const hit = got.reasons.some((r) => r.includes(v.expect.reason_contains));
      if (!hit) throw new Error(`${v.id}: expected a reason containing "${v.expect.reason_contains}", got [${got.reasons.join(', ')}]`);
    }
    v.observed = { outcome: got.outcome, valid: got.valid, reasons: got.reasons };
    checked += 1;
  }

  const suite = {
    suite_note:
      'EP-STATUS-v1 conformance vectors. Protocol-independent: a status target is a generic (type, id, digest, usage) tuple, so any specification with a signed artifact and a content digest can bind to it without adopting EMILIA receipts. Covers the freshness-bounded negative answer, the revoker authority certificate, append-only chaining, and the indeterminate outcome.',
    version: 'EP-STATUS-v1',
    generated_by: 'conformance/generate-status-vectors.mjs',
    authority_pin: PIN,
    vectors,
  };

  writeFileSync(
    'conformance/vectors/status.v1.json',
    `${JSON.stringify(suite, null, 2)}\n`,
  );
  console.log(`STATUS VECTORS: wrote ${vectors.length} vectors, ${checked} self-checked against the shipped verifier`);
  console.log(`  head1 digest: ${statusArtifactDigest(head1)}`);
}

main().catch((err) => {
  console.error('STATUS VECTORS: FAIL');
  console.error(err);
  process.exit(1);
});

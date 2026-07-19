// SPDX-License-Identifier: Apache-2.0
// The surface-binding join demo with a structured WinMagic-LIT possession row.
// Evidence bytes = 2-byte length prefix + canonicalized JSON payload + 64-byte
// Ed25519 signature by the Live Key over that payload. The payload carries:
//
//   1. version + profile id   - the verify library knows how to parse; condition
//                               claims are a declaration BY REFERENCE to the
//                               profile, not a list of internals.
//   2. key id                 - hash of the DER-encoded SPKI key the RP pinned at
//                               registration. Check #3 is a LOOKUP, not a chain
//                               walk. No cert.
//   3. condition claims       - phase-table style; only what can honestly be
//                               claimed. Mint inputs need no runtime assertion:
//                               the signature existing is the proof they held.
//   4. ceremony binding       - hash of the PRE-SURFACE action draft (the action
//                               minus approval_surface, avoiding circularity)
//                               plus an RP-issued nonce the verifier compares
//                               against its own expected value. Kills replay
//                               of yesterday's genuine evidence across ceremonies.
//   5. timestamp              - the RP applies its own staleness window.
//
//   node examples/surface-binding-join/run-lit.mjs
//
// LIT side supplies: producePresentation (device, private key),
// verifyPresentation (relying party, pinned PUBLIC keys). EP is unchanged:
// it only ever hashes the evidence bytes and joins by digest equality.

import crypto from 'node:crypto';
import { issueFromKeyBundle, generateIssuerKeyBundle, formatLogKeyId, policyHash, canonicalize } from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import { bindSurfaceInto, verifySurfaceBinding, SURFACE_BINDING_VERSION } from '../../packages/verify/surface-binding.js';
import { buildRelianceGapReport } from '../../packages/verify/reliance-gap.js';

const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// ── LIT implementation (what WinMagic supplies) ─────────────────────────────

const LIT_PRESENTATION_VERSION = 1;
const LIT_PROFILE_ID = 'winmagic-lit:profile-x@v1';
const SIGNATURE_LENGTH = 64; // Ed25519

// The WinMagic-LIT device key pair (the Live Key). In production this is
// provisioned on the device; the PRIVATE key never leaves it, and the
// DER-encoded SPKI public key (or its hash) is pinned by RPs at registration.
const litDeviceKeys = crypto.generateKeyPairSync('ed25519');

// 2. Key identifier: hash of the DER-encoded SPKI key. What the RP pins; a lookup key.
const litKeyId = (publicKey) =>
  `sha256:${sha256hex(publicKey.export({ type: 'spki', format: 'der' }))}`;

// Hash of the PRE-SURFACE action draft: the action WITHOUT approval_surface.
// (approval_surface will carry the digest of THESE evidence bytes, so hashing
// the final action would be circular. Hashing the draft avoids it.)
const actionDraftHash = (draft) => {
  const { approval_surface, ...preSurface } = draft;
  return `sha256:${sha256hex(Buffer.from(canonicalize(preSurface), 'utf8'))}`;
};

// Device 2, ceremony time: build payload items 1-5, sign over them with the
// Live Key. Evidence bytes = <2-byte payload length><payload JSON><signature>.
function producePresentation(privateKey, publicKey, { actionDraft, nonce, now }) {
  const payload = Buffer.from(canonicalize({
    // 1. version + profile id: claims below are a declaration by reference to
    //    the profile; the recipe stays deployment config, nothing TPM-specific
    //    travels in the blob.
    presentation_version: LIT_PRESENTATION_VERSION,
    profile_id: LIT_PROFILE_ID,
    // 2. key identifier: pinned-key lookup, not a chain walk.
    key_id: litKeyId(publicKey),
    // 3. condition claims, phase-table style. Only what the phase table says
    //    can honestly be claimed. Mint inputs need no runtime assertion; the
    //    signature existing is the proof they held.
    condition_claims: ['user-verified-at-mint', 'posture-at-build', 'checksum'],
    // 4. binding + freshness: THIS ceremony, not just these bytes. Hash of the
    //    pre-surface action draft plus the RP-issued challenge nonce (relayed
    //    to the device by the approval app; checked by the RP on verify).
    ceremony_binding: { action_draft_hash: actionDraftHash(actionDraft), nonce },
    // 5. timestamp: the RP applies its own staleness window.
    presented_at: now,
  }), 'utf8');
  const signature = crypto.sign(null, payload, privateKey); // over items 1-5
  const lengthPrefix = Buffer.from([payload.length >> 8, payload.length & 0xff]);
  return Buffer.concat([lengthPrefix, payload, signature]);
}

// Relying party: verify the presentation under PINNED public keys.
// This is the ONLY place the LIT public keys appear.
function verifyPresentation(evidenceBytes, { pinnedKeys, actionInFront, expectedNonce, now, maxAgeMs }) {
  // Framing.
  if (evidenceBytes.length < 2 + SIGNATURE_LENGTH) {
    return { valid: false, reason: 'malformed_presentation' };
  }
  const payloadLength = (evidenceBytes[0] << 8) | evidenceBytes[1];
  if (evidenceBytes.length !== 2 + payloadLength + SIGNATURE_LENGTH) {
    return { valid: false, reason: 'malformed_presentation' };
  }
  const payload = evidenceBytes.subarray(2, 2 + payloadLength);
  const signature = evidenceBytes.subarray(2 + payloadLength);

  let claims;
  try { claims = JSON.parse(payload.toString('utf8')); }
  catch { return { valid: false, reason: 'payload_unparseable' }; }

  // 1. Version + profile: do we know how to parse and price these claims?
  if (claims.presentation_version !== LIT_PRESENTATION_VERSION || claims.profile_id !== LIT_PROFILE_ID) {
    return { valid: false, reason: 'unknown_version_or_profile' };
  }

  // 2. Key id: a LOOKUP against keys pinned at registration. No chain walk.
  const publicKey = pinnedKeys.get(claims.key_id);
  if (!publicKey) return { valid: false, reason: 'key_id_not_pinned' };

  // Signature by the Live Key over items 1-5 closes it.
  if (!crypto.verify(null, payload, publicKey, signature)) {
    return { valid: false, reason: 'signature_invalid' };
  }

  // 4. Ceremony binding: the evidence must reference the action in front of us
  //    (minus approval_surface) AND echo the nonce WE issued for this ceremony.
  //    Replay across ceremonies dies here.
  if (claims.ceremony_binding?.action_draft_hash !== actionDraftHash(actionInFront)) {
    return { valid: false, reason: 'ceremony_binding_mismatch' };
  }
  if (claims.ceremony_binding?.nonce !== expectedNonce) {
    return { valid: false, reason: 'nonce_mismatch' };
  }

  // 5. Freshness under the RP's own staleness window.
  const ageMs = /** @type {any} */ (new Date(now)) - /** @type {any} */ (new Date(claims.presented_at));
  if (!(ageMs >= 0 && ageMs <= maxAgeMs)) {
    return { valid: false, reason: 'presentation_stale' };
  }

  return { valid: true, claims };
}

// ── Ceremony (Device 2) ──────────────────────────────────────────────────────

// 0. The exact action draft exists FIRST: the presentation must reference it.
const policy = { policy_id: 'ep:policy:lit-demo@v1', rule: 'named human approves the exact action before it runs' };
const actionDraft = {
  ep_version: '1.0',
  action_type: 'demo.lit.commit',
  organization_id: 'org-lit-demo',
  target: { system: 'lit.demo', resource: 'txn/0001' },
  parameters: { irreversible: true, note: 'LIT-signed possession row demo' },
  initiator: 'ep:entity:demo-agent',
  policy_id: policy.policy_id,
  requested_at: '2026-07-10T22:00:05Z',
};

// 1. LIT produces the possession-row evidence, bound to THIS ceremony. Opaque to EP.
// The nonce is a challenge ISSUED BY THE RELYING PARTY for this ceremony and
// relayed to the device by the approval app; the RP checks the echo on verify.
const ceremonyNonce = crypto.randomBytes(16).toString('hex');
const possessionEvidence = producePresentation(litDeviceKeys.privateKey, litDeviceKeys.publicKey, {
  actionDraft,
  nonce: ceremonyNonce,
  now: '2026-07-10T22:00:06Z',
});
console.log('LIT evidence bytes:', possessionEvidence.length, 'total (2 length +', possessionEvidence.length - 2 - SIGNATURE_LENGTH, 'payload +', SIGNATURE_LENGTH, 'signature)');

// 2. The binding: an opaque digest of that evidence, placed in the SIGNED action.
const binding = {
  '@version': SURFACE_BINDING_VERSION,
  surface_kind: 'winmagic-lit',
  attestation_digest: `sha256:${sha256hex(possessionEvidence)}`,
  verifier_hint: 'verifyPresentation under pinned WinMagic-LIT public keys',
};

const { action } = bindSurfaceInto(actionDraft, binding);

// 3. Authorization row: a named human signs the exact action (surface reference included).
const keys = generateIssuerKeyBundle({
  approverId: 'ep:approver:demo-operator',
  approverKeyId: 'ep:key:demo-operator#1',
  logKeyId: formatLogKeyId('lit-demo'),
});
const { receipt, verification } = await issueFromKeyBundle({ keys, action, policy });

// ── Relying party: four checks, all local ────────────────────────────────────

// The RP pinned the LIT public key at registration, keyed by key id (in
// production: from WinMagic's published key manifest). Plus the RP's own clock
// and staleness window for check #5.
const rpPinnedLitKeys = new Map([[litKeyId(litDeviceKeys.publicKey), litDeviceKeys.publicKey]]);
const rpVerifyContext = (actionInFront) => ({
  pinnedKeys: rpPinnedLitKeys,
  actionInFront,
  expectedNonce: ceremonyNonce, // the challenge the RP issued for this ceremony
  now: '2026-07-10T22:01:00Z',
  maxAgeMs: 5 * 60 * 1000,
});

console.log('\n=== RP check 1: authorization row (EP receipt) ===');
const r = verifyTrustReceipt(/** @type {Record<string, unknown>} */ (/** @type {unknown} */ (receipt)), { approverKeys: verification.approver_keys, logPublicKey: verification.log_public_key });
console.log('receipt valid:', r.valid);

console.log('\n=== RP check 2: the join (digest equality) ===');
const sb = verifySurfaceBinding(receipt, possessionEvidence);
console.log('present:', sb.checks.present, '| digest_match:', sb.checks.digest_match, '| surface_kind:', sb.binding?.surface_kind);

console.log('\n=== RP check 3: LIT possession row (LIT verifier, pinned public key) ===');
const pv = verifyPresentation(possessionEvidence, rpVerifyContext(receipt.action));
console.log('presentation valid:', pv.valid, '| profile:', pv.claims?.profile_id, '| conditions:', pv.claims?.condition_claims?.join(', '));

console.log('\n=== RP check 4: reliance verdict under the RP\'s pinned profile ===');
const profile = {
  '@type': 'EP-RELIANCE-PROFILE-v1',
  profile_id: 'ep:profile:lit-demo@v1',
  party: 'relying party (demo)',
  description: 'accepts the demo issuer key and the demo policy hash; requires a receipt',
  required_assurance: 'signed',
  required_authority: false,
  accepted_registry_keys: [],
  accepted_issuer_keys: [verification.log_public_key],
  accepted_policy_hashes: [policyHash(policy)],
  required_evidence: ['receipt'],
};
const packet = {
  evaluated_at: '2026-07-10T22:01:00Z',
  action: { ...receipt.action, action_hash: receipt.action_hash },
  evidence: [{ type: 'receipt', artifact: receipt }],
  context: { approver_keys: verification.approver_keys, log_public_key: verification.log_public_key },
};
const green = buildRelianceGapReport(packet, profile, {});
console.log('kernel verdict:', green.kernel_verdict);

const allGreen = r.valid && sb.checks.digest_match && pv.valid && green.kernel_verdict === 'rely';
console.log('\n>>> EXECUTE?', allGreen ? 'yes: all four checks passed' : 'NO');

// ── Refusals ─────────────────────────────────────────────────────────────────

console.log('\n=== Refusal (a): tampered payload byte, original signature ===');
const tampered = Buffer.from(possessionEvidence);
tampered[2] ^= 0x01; // flip a bit in the payload
const sbT = verifySurfaceBinding(receipt, tampered);
const pvT = verifyPresentation(tampered, rpVerifyContext(receipt.action));
console.log('join digest_match:', sbT.checks.digest_match, '| reason:', sbT.reason);
console.log('LIT verifier:', pvT.valid, '| reason:', pvT.reason);

console.log('\n=== Refusal (b): rogue device, identical payload signed by an unpinned key ===');
const rogueKeys = crypto.generateKeyPairSync('ed25519');
const rogueEvidence = producePresentation(rogueKeys.privateKey, rogueKeys.publicKey, {
  actionDraft,
  nonce: ceremonyNonce,
  now: '2026-07-10T22:00:06Z',
});
const pvR = verifyPresentation(rogueEvidence, rpVerifyContext(receipt.action));
const sbR = verifySurfaceBinding(receipt, rogueEvidence);
console.log('LIT verifier:', pvR.valid, '| reason:', pvR.reason);
console.log('join digest_match:', sbR.checks.digest_match, '(different key id + signature => different digest)');

console.log('\n=== Refusal (c): replay, yesterday\'s GENUINE evidence baked into a NEW action draft ===');
// The attacker takes the genuine evidence bytes and binds them into a different
// action. The join PASSES (the digest honestly matches those bytes); only the
// ceremony binding inside the signed payload catches it: the evidence references
// the ORIGINAL pre-surface draft, not the action now in front of the RP.
const replayDraft = { ...actionDraft, target: { system: 'lit.demo', resource: 'txn/0002' } };
const { action: replayAction } = bindSurfaceInto(replayDraft, {
  '@version': SURFACE_BINDING_VERSION,
  surface_kind: 'winmagic-lit',
  attestation_digest: `sha256:${sha256hex(possessionEvidence)}`,
});
const { receipt: replayReceipt } = await issueFromKeyBundle({ keys, action: replayAction, policy });
const sbP = verifySurfaceBinding(replayReceipt, possessionEvidence);
const pvP = verifyPresentation(possessionEvidence, rpVerifyContext(replayReceipt.action));
console.log('join digest_match:', sbP.checks.digest_match, '(the bytes ARE the bound bytes)');
console.log('LIT verifier:', pvP.valid, '| reason:', pvP.reason);

console.log('\nRows joined by digest equality; the LIT verifier alone judges the possession row,');
console.log('and the ceremony binding pins the evidence to one exact action draft.');

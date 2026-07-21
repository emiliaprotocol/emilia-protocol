// SPDX-License-Identifier: Apache-2.0
// Generator for the Class-A device-signoff conformance vectors (EP-SIGNOFF-v1):
// a WebAuthn ECDSA P-256 assertion bound to a canonicalized authorization
// context. Adversarial battery structured on the verifier failure taxonomy
// (cf. S. Bu, secdispatch 2026-06): structural, cryptographic, action-binding,
// operation/audience, lifecycle/UV. Run: node generate-signoffs.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';

const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v);

// One canonical $82,000 authorization context.
function baseContext() {
  return {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: crypto.createHash('sha256').update(canon({ amount: 82000, currency: 'USD', target: 'wire/8841' }), 'utf8').digest('hex'),
    policy: 'policy_default_large_payment_release',
    nonce: 'sig_' + crypto.randomBytes(16).toString('hex'),
    approver: 'ep:approver:jchen', initiator: 'ent_agent_7',
    issued_at: '2026-06-11T00:00:00.000Z', expires_at: '2026-06-11T00:05:00.000Z',
  };
}

// Build a real assertion. opts let us bend exactly one thing per vector.
/**
 * @param {{
 *   tamperContextAfterSign?: Record<string, string>|null,
 *   flags?: number,
 *   type?: string,
 *   rpId?: string,
 *   origin?: string,
 *   duplicateChallenge?: boolean,
 *   invalidUtf8?: boolean,
 *   paddedClientData?: boolean,
 *   wrongKey?: boolean,
 *   malformSig?: boolean,
 * }} [opts]
 */
function makeSignoff({
  tamperContextAfterSign = null,
  flags = 0x05,
  type = 'webauthn.get',
  rpId = 'emiliaprotocol.ai',
  origin = 'https://www.emiliaprotocol.ai',
  duplicateChallenge = false,
  invalidUtf8 = false,
  paddedClientData = false,
  wrongKey = false,
  malformSig = false,
}: {
  tamperContextAfterSign?: Record<string, string> | null;
  flags?: number;
  type?: string;
  rpId?: string;
  origin?: string;
  duplicateChallenge?: boolean;
  invalidUtf8?: boolean;
  paddedClientData?: boolean;
  wrongKey?: boolean;
  malformSig?: boolean;
} = {}) {
  const signer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const verifierKey = wrongKey ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey : signer.publicKey;
  const context = baseContext();
  const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
  const clientDataText = duplicateChallenge
    ? `{"type":${JSON.stringify(type)},"challenge":"attacker-controlled","challenge":${JSON.stringify(challenge)},"origin":${JSON.stringify(origin)}}`
    : JSON.stringify({ type, challenge, origin });
  const clientData = invalidUtf8
    ? Buffer.concat([
      Buffer.from(`{"type":${JSON.stringify(type)},"challenge":${JSON.stringify(challenge)},"origin":"`, 'utf8'),
      Buffer.from([0xc3, 0x28]),
      Buffer.from('"}', 'utf8'),
    ])
    : Buffer.from(clientDataText, 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId, 'utf8').digest(),
    Buffer.from([flags]),
    Buffer.from([0, 0, 0, 9]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  let signature = crypto.sign('sha256', signed, signer.privateKey).toString('base64url');
  if (malformSig) signature = Buffer.from('not-a-valid-ecdsa-signature').toString('base64url');
  // tamper the *delivered* context after the signature was made over the original challenge
  const deliveredContext = tamperContextAfterSign ? { ...context, ...(tamperContextAfterSign as any) } : context;
  return {
    signoff: {
      '@type': 'ep.signoff',
      context: deliveredContext,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url') + (paddedClientData ? '=' : ''),
        signature,
      },
    },
    approver_public_key: verifierKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    rp_id: rpId === 'emiliaprotocol.ai' ? 'emiliaprotocol.ai' : 'emiliaprotocol.ai', // verifier always expects the real RP
    allowed_origins: ['https://www.emiliaprotocol.ai'],
  };
}

const V: any[] = [];
const add = (id, description, failure_class, expectValid, built) =>
  V.push({ id, description, failure_class, expect: { valid: expectValid }, rp_id: built.rp_id, allowed_origins: built.allowed_origins, approver_public_key: built.approver_public_key, signoff: built.signoff });

add('accept_valid', 'A genuine Class-A device assertion over the exact action', 'accept', true, makeSignoff());
add('reject_structural_ceremony_type', 'clientData.type is webauthn.create (a registration), not webauthn.get (an assertion)', 'structural', false, makeSignoff({ type: 'webauthn.create' }));
add('reject_crypto_wrong_key', 'Signature verifies, but against the wrong approver public key', 'cryptographic', false, makeSignoff({ wrongKey: true }));
add('reject_crypto_malformed_sig', 'Signature value is not a valid ECDSA signature', 'cryptographic', false, makeSignoff({ malformSig: true }));
add('reject_action_binding_hash', 'The action_hash in the delivered context differs from what was signed — challenge no longer binds', 'action-binding', false, makeSignoff({ tamperContextAfterSign: { action_hash: 'f'.repeat(64) } }));
add('reject_action_binding_nonce', 'The nonce (consumption key) was altered after signing — challenge no longer binds', 'action-binding', false, makeSignoff({ tamperContextAfterSign: { nonce: 'sig_' + 'e'.repeat(32) } }));
add('reject_audience_wrong_rp', 'The assertion was scoped to a different relying party than expected', 'operation/audience', false, makeSignoff({ rpId: 'evil.example' }));
add('reject_audience_wrong_origin', 'The assertion came from an origin outside the relying party allowlist', 'operation/audience', false, makeSignoff({ origin: 'https://evil.emiliaprotocol.ai' }));
add('reject_parser_duplicate_challenge', 'Signed clientDataJSON contains duplicate challenge members and is therefore ambiguous', 'structural', false, makeSignoff({ duplicateChallenge: true }));
add('reject_parser_invalid_utf8', 'Signed clientDataJSON contains malformed UTF-8 and must not be replacement-decoded', 'structural', false, makeSignoff({ invalidUtf8: true }));
add('reject_encoding_padded_client_data', 'clientDataJSON uses a padded alias instead of canonical unpadded base64url', 'structural', false, makeSignoff({ paddedClientData: true }));
add('reject_lifecycle_uv_absent', 'User-verification flag unset — no biometric/PIN; insufficient assurance for Class A', 'lifecycle/UV', false, makeSignoff({ flags: 0x01 }));
add('reject_lifecycle_up_absent', 'User-presence flag unset — no human was present at the authenticator', 'lifecycle/UV', false, makeSignoff({ flags: 0x04 }));

const out = {
  suite: 'EP-SIGNOFF-v1',
  profile: 'Class A — device-bound WebAuthn keys (ECDSA P-256)',
  vectors_version: '1.0.0',
  description: 'Adversarial conformance vectors for the EMILIA Protocol Class-A human device signoff: a WebAuthn assertion whose challenge is the SHA-256 of the JCS-canonicalized authorization context. An EP-SIGNOFF-v1 conformant verifier MUST return expect.valid for every vector.',
  scope_note: 'These exercise the OFFLINE assertion verifier (cryptographic, action-binding, audience, lifecycle/UV). Replay / one-time consumption and enrollment-active are SERVER-STATE checks (the nonce is the global consumption key) and are out of scope for offline assertion vectors. failure_class follows the verifier taxonomy discussed on secdispatch (S. Bu, 2026-06).',
  count: V.length,
  vectors: V,
};
writeFileSync(new URL('./signoffs.v1.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote signoffs.v1.json — ${V.length} vectors (${V.filter(v => v.expect.valid).length} accept, ${V.filter(v => !v.expect.valid).length} reject)`);

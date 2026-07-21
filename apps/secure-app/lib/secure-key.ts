/**
 * EP Secure App — device key + biometric gate.
 *
 * Production path: the named human's signing key lives in the device secure
 * enclave / passkey store, and the OS produces the WebAuthn assertion after a
 * Face ID / biometric ceremony. Enrollment registers the public key with EP
 * (second-party attestation by an org admin).
 *
 * This module provides the biometric gate (expo-local-authentication) and key
 * persistence (expo-secure-store). For Expo Go / demo where a hardware passkey
 * is unavailable, it falls back to a software P-256 key (@noble/curves) — the
 * same "simulated secure element" posture as the web /try page. The fallback is
 * clearly a DEMO key, never represented as enclave-backed.
 *
 * @license Apache-2.0
 */

import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

const DEMO_KEY_ITEM = 'ep_secure_app_demo_priv';

type BiometricResult =
  | { ok: true; reason: undefined }
  | { ok: false; reason: string };

type WebAuthnAssertion = {
  authenticator_data: string;
  client_data_json: string;
  signature: string;
};

/** Require a biometric (Face ID / fingerprint) ceremony. Returns true on success. */
export async function requireBiometric(promptMessage: string = 'Approve this action'): Promise<BiometricResult> {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const enrolled = await LocalAuthentication.isEnrolledAsync();
  if (!hasHardware || !enrolled) {
    // No biometric configured — on a real deployment this blocks signing.
    return { ok: false, reason: 'no_biometric_enrolled' };
  }
  const res = await LocalAuthentication.authenticateAsync({ promptMessage, disableDeviceFallback: false });
  if (res.success) return { ok: true, reason: undefined };
  return { ok: false, reason: 'error' in res ? res.error : 'denied' };
}

/** Get-or-create the demo software signing key (Expo Go / no-passkey path). */
async function getDemoKey(): Promise<Uint8Array> {
  let hex = await SecureStore.getItemAsync(DEMO_KEY_ITEM);
  if (!hex) {
    hex = Buffer.from(p256.utils.randomPrivateKey()).toString('hex');
    await SecureStore.setItemAsync(DEMO_KEY_ITEM, hex, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

/** The enrolled public key (uncompressed P-256 point, hex) to register with EP. */
export async function getEnrolledPublicKeyHex(): Promise<string> {
  const priv = await getDemoKey();
  return Buffer.from(p256.getPublicKey(priv, false)).toString('hex');
}

/**
 * Sign a WebAuthn challenge with the device key after a biometric ceremony,
 * returning the assertion fields the EP verifier expects.
 *
 * @param challenge - base64url challenge from ep-signoff.challengeFromContext
 * @param opts - rpId and origin for WebAuthn assertion
 */
export async function signChallenge(
  challenge: string,
  { rpId, origin }: { rpId: string; origin: string }
): Promise<WebAuthnAssertion> {
  const gate = await requireBiometric('Approve and sign this action');
  if (!gate.ok) throw new Error(`biometric_failed:${gate.reason || 'denied'}`);

  const priv = await getDemoKey();
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }), 'utf8');
  const rpIdHash = sha256(new TextEncoder().encode(rpId));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = 0x05; // UP | UV
  // signCount 0 (bytes 33..36 already zero)

  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(sha256(clientDataJSON), authData.length);
  const sig = p256.sign(sha256(signedData), priv); // returns Signature
  const der = sig.toDERRawBytes();

  const b64u = (b: any): string => Buffer.from(b).toString('base64url');
  return {
    authenticator_data: b64u(authData),
    client_data_json: b64u(clientDataJSON),
    signature: b64u(der),
  };
}

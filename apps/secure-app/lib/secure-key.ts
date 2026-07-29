/**
 * EP Secure App — explicit exportable software-key mode.
 *
 * `expo-secure-store` protects the serialized key at rest, but the key is
 * generated and used in JavaScript and is therefore exportable. This module
 * never calls it Secure Enclave-backed, never labels it Class A, and refuses
 * every policy that requires hardware-attested provenance.
 *
 * @license Apache-2.0
 */

import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import {
  SOFTWARE_KEY_PROVENANCE,
  assertSoftwareSignerAllowed,
  authenticateForPolicy,
} from './security-boundary.mjs';

const SOFTWARE_KEY_ITEM = 'ep_secure_app_software_exportable_p256_v1';

export interface SigningPolicy {
  requiredKeyProvenance: 'software_allowed' | 'hardware_attested_required';
  userVerification: 'biometric_only' | 'biometric_or_device_passcode';
}

export interface WebAuthnShapedEvidence {
  authenticator_data: string;
  client_data_json: string;
  signature: string;
}

export interface SoftwareSignResult {
  webauthn: WebAuthnShapedEvidence;
  signer: {
    key_provenance: typeof SOFTWARE_KEY_PROVENANCE;
    assurance_authority: 'server_enrollment_required';
    user_verification_policy: SigningPolicy['userVerification'];
    user_verification_method: 'biometric' | 'device_owner_authentication';
    authenticator_flags_asserted: false;
  };
}

async function getSoftwareKey(): Promise<Uint8Array> {
  let hex = await SecureStore.getItemAsync(SOFTWARE_KEY_ITEM);
  if (!hex) {
    hex = Buffer.from(p256.utils.randomPrivateKey()).toString('hex');
    await SecureStore.setItemAsync(SOFTWARE_KEY_ITEM, hex, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  }
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('software_key_corrupt');
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

/** Public key for local software-mode diagnostics; it is not an enrollment. */
export async function getSoftwarePublicKeyHex(): Promise<string> {
  const privateKey = await getSoftwareKey();
  return Buffer.from(p256.getPublicKey(privateKey, false)).toString('hex');
}

/**
 * Produce local WebAuthn-shaped evidence with an exportable software key.
 *
 * The authenticator flags are deliberately zero: a separate Expo local-auth
 * prompt is not a platform authenticator assertion and cannot honestly set
 * WebAuthn UP/UV bits. The result is useful only for local crypto diagnostics;
 * the Class-A verifier must reject it and no live-submit function accepts it.
 */
export async function signChallengeWithSoftwareKey(
  challenge: string,
  {
    rpId,
    origin,
    policy,
  }: { rpId: string; origin: string; policy: SigningPolicy }
): Promise<SoftwareSignResult> {
  const normalizedPolicy = assertSoftwareSignerAllowed(policy) as SigningPolicy;
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)
      || !/^[A-Za-z0-9.-]{1,253}$/.test(rpId)
      || origin !== `https://${rpId}`) {
    throw new Error('invalid_software_signing_context');
  }

  const gate = await authenticateForPolicy(
    LocalAuthentication,
    normalizedPolicy,
    'Authorize this local software-key signature'
  );
  if (!gate.ok) throw new Error(`user_verification_failed:${gate.reason || 'denied'}`);
  const verificationMethod = gate.method === 'biometric'
    ? 'biometric'
    : gate.method === 'device_owner_authentication'
      ? 'device_owner_authentication'
      : null;
  if (!verificationMethod) throw new Error('user_verification_method_unrecognized');

  const privateKey = await getSoftwareKey();
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }), 'utf8');
  const rpIdHash = sha256(new TextEncoder().encode(rpId));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = 0x00; // No authenticator-bound UP or UV claim.

  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(sha256(clientDataJSON), authData.length);
  const signature = p256.sign(sha256(signedData), privateKey).toDERRawBytes();
  const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

  return {
    webauthn: {
      authenticator_data: b64u(authData),
      client_data_json: b64u(clientDataJSON),
      signature: b64u(signature),
    },
    signer: {
      key_provenance: SOFTWARE_KEY_PROVENANCE,
      assurance_authority: 'server_enrollment_required',
      user_verification_policy: normalizedPolicy.userVerification,
      user_verification_method: verificationMethod,
      authenticator_flags_asserted: false,
    },
  };
}

// SPDX-License-Identifier: Apache-2.0
/**
 * EP platform-attestation — a narrow, zero-dependency consumer profile for a
 * signed JSON EAT carried as compact JWS.
 *
 * Scope is intentionally small. This verifier consumes an attestation result
 * in the RFC 9334 relying-party role and uses RFC 9711 EAT/JWT claims where
 * they fit (`eat_nonce`, `eat_profile`, integer `iat`, and `measres`). It does
 * NOT appraise raw hardware evidence, validate arbitrary EAT profiles, or prove
 * that a TEE exists. The relying party pins the result signer, profile,
 * audience, nonce, action digest, freshness policy, and acceptable build
 * measurements. A successful result means only that the exact pinned signer
 * vouched for those exact claims under this closed profile.
 *
 * No trust material is accepted from the token or evidence wrapper. The JWS
 * protected header is closed and may contain only `alg`, `kid`, and `typ`.
 */
import crypto, { type KeyObject } from 'node:crypto';

import { strictJsonGate } from './strict-json.js';

type Obj = Record<string, any>;

export const EP_PLATFORM_ATTESTATION_VERSION = 'EP-PLATFORM-ATTESTATION-v1';
export const EP_PLATFORM_ATTESTATION_PROFILE = 'tag:emiliaprotocol.ai,2026:platform-attestation/eat-jwt/v1';
export const EP_PLATFORM_ATTESTATION_COMPONENT = 'ep-platform-attestation';

const MAX_TOKEN_BYTES = 32 * 1024;
const MAX_HEADER_BYTES = 2 * 1024;
const MAX_PAYLOAD_BYTES = 24 * 1024;
const MAX_KEY_BYTES = 1024;
const MAX_REFERENCE_MEASUREMENTS = 64;
const MAX_ATTESTATION_AGE_SECONDS = 86_400;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

export interface PlatformAttestationOptions {
  trustedAttesters: Record<string, Record<string, string>>;
  expectedProfile: string;
  expectedAudience: string;
  expectedNonce: string;
  expectedActionDigest: string;
  referenceMeasurements: string[];
  verificationTime: string;
  maxAgeSeconds: number;
}

export interface PlatformAttestationResult {
  valid: boolean;
  action_digest: string | null;
  detail: {
    reason: string | null;
    profile?: string;
    issuer?: string;
    key_id?: string;
    build_measurement?: string;
    profile_alignment?: 'RFC9334-attestation-result/RFC9711-EAT-JWT';
    hardware_verified?: false;
  };
}

function plainRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function exactKeys(value: Obj, expected: readonly string[]): boolean {
  try {
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
  } catch {
    return false;
  }
}

function fail(reason: string): PlatformAttestationResult {
  return { valid: false, action_digest: null, detail: { reason } };
}

function decodeBase64url(segment: unknown, maxBytes: number): Buffer | null {
  if (typeof segment !== 'string' || !BASE64URL.test(segment)) return null;
  try {
    const bytes = Buffer.from(segment, 'base64url');
    if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString('base64url') !== segment) return null;
    return bytes;
  } catch {
    return null;
  }
}

function decodeStrictJson(segment: string, maxBytes: number): { value: Obj | null; syntaxValid: boolean } {
  const bytes = decodeBase64url(segment, maxBytes);
  if (!bytes) return { value: null, syntaxValid: false };
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!strictJsonGate(text).ok) return { value: null, syntaxValid: false };
    const value = JSON.parse(text);
    return { value: plainRecord(value) ? value : null, syntaxValid: true };
  } catch {
    return { value: null, syntaxValid: false };
  }
}

function strictUtcInstantMs(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_UTC);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second] = match;
  const base = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return NaN;
  const normalized = new Date(parsed).toISOString().slice(0, 19);
  return normalized === base ? parsed : NaN;
}

function validExpectedNonce(value: unknown): value is string {
  return typeof value === 'string'
    && Buffer.byteLength(value, 'utf8') >= 8
    && Buffer.byteLength(value, 'utf8') <= 88;
}

function referenceSet(value: unknown): Set<string> | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REFERENCE_MEASUREMENTS) return null;
  const result = new Set<string>();
  for (const measurement of value) {
    if (typeof measurement !== 'string' || !SHA256.test(measurement) || result.has(measurement)) return null;
    result.add(measurement);
  }
  return result;
}

function loadPinnedEd25519Key(value: unknown): KeyObject | null {
  const der = decodeBase64url(value, MAX_KEY_BYTES);
  if (!der) return null;
  try {
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function parseBuildMeasurement(value: unknown): string | null {
  if (!Array.isArray(value) || value.length !== 1) return null;
  const group = value[0];
  if (!Array.isArray(group) || group.length !== 2 || group[0] !== 'ep-build') return null;
  const results = group[1];
  if (!Array.isArray(results) || results.length !== 1) return null;
  const result = results[0];
  if (!Array.isArray(result) || result.length !== 2
      || typeof result[0] !== 'string' || !SHA256.test(result[0])
      || result[1] !== 'success') return null;
  return result[0];
}

function verifyPlatformAttestationInternal(
  evidence: unknown,
  options: PlatformAttestationOptions,
): PlatformAttestationResult {
  if (!plainRecord(evidence)
      || !exactKeys(evidence, ['@version', 'token'])
      || evidence['@version'] !== EP_PLATFORM_ATTESTATION_VERSION
      || typeof evidence.token !== 'string'
      || Buffer.byteLength(evidence.token, 'utf8') > MAX_TOKEN_BYTES) {
    return fail('evidence_shape_invalid');
  }
  if (!plainRecord(options)) return fail('relying_party_policy_invalid');

  const verificationTimeMs = strictUtcInstantMs(options.verificationTime);
  const references = referenceSet(options.referenceMeasurements);
  if (!plainRecord(options.trustedAttesters)
      || options.expectedProfile !== EP_PLATFORM_ATTESTATION_PROFILE
      || typeof options.expectedAudience !== 'string' || options.expectedAudience.length === 0 || options.expectedAudience.length > 2048
      || !validExpectedNonce(options.expectedNonce)
      || typeof options.expectedActionDigest !== 'string' || !SHA256.test(options.expectedActionDigest)
      || !references
      || !Number.isFinite(verificationTimeMs)
      || !Number.isSafeInteger(options.maxAgeSeconds)
      || options.maxAgeSeconds < 0
      || options.maxAgeSeconds > MAX_ATTESTATION_AGE_SECONDS) {
    return fail('relying_party_policy_invalid');
  }

  const segments = evidence.token.split('.');
  if (segments.length !== 3 || segments.some((segment: string) => !segment)) return fail('token_format_invalid');
  const [headerSegment, payloadSegment, signatureSegment] = segments;

  const decodedHeader = decodeStrictJson(headerSegment, MAX_HEADER_BYTES);
  if (!decodedHeader.syntaxValid) return fail('protected_header_json_invalid');
  const header = decodedHeader.value;
  if (!header || !exactKeys(header, ['alg', 'kid', 'typ'])
      || header.alg !== 'EdDSA' || header.typ !== 'eat+jwt'
      || typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 256) {
    return fail('protected_header_invalid');
  }

  const decodedPayload = decodeStrictJson(payloadSegment, MAX_PAYLOAD_BYTES);
  if (!decodedPayload.syntaxValid) return fail('payload_json_invalid');
  const payload = decodedPayload.value;
  if (!payload || !exactKeys(payload, [
    'iss', 'aud', 'iat', 'exp', 'eat_nonce', 'eat_profile', 'measres', 'ep_action_digest',
  ])) return fail('payload_shape_invalid');

  if (typeof payload.iss !== 'string' || payload.iss.length === 0 || payload.iss.length > 2048
      || typeof payload.aud !== 'string' || payload.aud.length === 0 || payload.aud.length > 2048
      || !validExpectedNonce(payload.eat_nonce)
      || typeof payload.eat_profile !== 'string' || payload.eat_profile.length === 0 || payload.eat_profile.length > 2048
      || typeof payload.ep_action_digest !== 'string' || !SHA256.test(payload.ep_action_digest)) {
    return fail('payload_claims_invalid');
  }
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.exp <= payload.iat) {
    return fail('time_claims_invalid');
  }

  const trustedIssuer = Object.prototype.hasOwnProperty.call(options.trustedAttesters, payload.iss)
    ? options.trustedAttesters[payload.iss] : null;
  if (!plainRecord(trustedIssuer) || !Object.prototype.hasOwnProperty.call(trustedIssuer, header.kid)) {
    return fail('attester_untrusted');
  }
  const pinnedKey = loadPinnedEd25519Key(trustedIssuer[header.kid]);
  if (!pinnedKey) return fail('attester_key_invalid');

  const signature = decodeBase64url(signatureSegment, 64);
  if (!signature || signature.length !== 64) return fail('signature_invalid');
  let signatureValid = false;
  try {
    signatureValid = crypto.verify(
      null,
      Buffer.from(`${headerSegment}.${payloadSegment}`, 'ascii'),
      pinnedKey,
      signature,
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return fail('signature_invalid');

  if (payload.eat_profile !== options.expectedProfile) return fail('profile_mismatch');
  if (payload.aud !== options.expectedAudience) return fail('audience_mismatch');
  if (payload.eat_nonce !== options.expectedNonce) return fail('nonce_mismatch');
  if (payload.ep_action_digest !== options.expectedActionDigest) return fail('action_digest_mismatch');

  const buildMeasurement = parseBuildMeasurement(payload.measres);
  if (!buildMeasurement) return fail('measurement_result_invalid');
  if (!references.has(buildMeasurement)) return fail('measurement_untrusted');

  if (payload.iat * 1000 > verificationTimeMs) return fail('token_from_future');
  if (verificationTimeMs >= payload.exp * 1000) return fail('token_expired');
  if (verificationTimeMs - payload.iat * 1000 > options.maxAgeSeconds * 1000) return fail('token_too_old');

  return {
    valid: true,
    action_digest: payload.ep_action_digest,
    detail: {
      reason: null,
      profile: payload.eat_profile,
      issuer: payload.iss,
      key_id: header.kid,
      build_measurement: buildMeasurement,
      profile_alignment: 'RFC9334-attestation-result/RFC9711-EAT-JWT',
      // This profile consumes a signed appraisal result. It deliberately does
      // not claim to independently verify hardware or generic EAT evidence.
      hardware_verified: false,
    },
  };
}

/**
 * Verify one EP platform-attestation component. This is a fail-closed boundary:
 * malformed objects, hostile accessors, invalid policy, or crypto errors all
 * return a denial result and never escape as an exception.
 */
export function verifyPlatformAttestation(
  evidence: unknown,
  options: PlatformAttestationOptions,
): PlatformAttestationResult {
  try {
    return verifyPlatformAttestationInternal(evidence, options);
  } catch {
    return fail('unexpected_verification_error');
  }
}

// SPDX-License-Identifier: Apache-2.0
/**
 * Profile-neutral authorization-artifact hook for AADP compositions.
 *
 * The hook records what an AADP deployment natively verified. It is evidence,
 * not an AADP approval, permit, obligation, provider key, or authorization
 * decision. The EP helper below is one profile that derives the hook from a
 * verified Authorization Bundle and a relying-party-pinned action mapping.
 */
import {
  verifyAuthorizationBundle,
  type AuthorizationBundleVerificationOptions,
} from './authorization-bundle.js';
import { canonicalizeAeb, digestAeb, type AebDigest } from './aeb-adapter-contract.js';

export const AADP_AUTHORIZATION_ARTIFACT_VERSION =
  'AADP-AUTHORIZATION-ARTIFACT-v1';
export const AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE =
  'EP-AADP-AUTHORIZATION-ARTIFACT-v1';

export interface AadpAuthorizationArtifact {
  profile: typeof AADP_AUTHORIZATION_ARTIFACT_VERSION;
  artifact_profile: string;
  artifact_digest: AebDigest;
  verification_outcome: 'verified' | 'not_satisfying' | 'not_reachable';
  action_mapping_profile: string;
  action_digest: AebDigest;
}

export type AadpAuthorizationArtifactMatchVerdict =
  | 'MATCH'
  | 'MISMATCH'
  | 'INDETERMINATE';

export interface AadpAuthorizationArtifactMatchResult {
  verdict: AadpAuthorizationArtifactMatchVerdict;
  artifact: AadpAuthorizationArtifact | null;
  reason: string | null;
}

export interface AadpAction {
  action_type: string;
  params: Record<string, unknown>;
}

export interface DeriveAadpEpAuthorizationArtifactInput {
  bundle: unknown;
  artifactReferenceDigest?: AebDigest;
  aadpAction: unknown;
  actionMappingProfile: string;
  mapAction: (action: AadpAction) => unknown;
  bundleOptions: Omit<AuthorizationBundleVerificationOptions, 'expectedAction'>;
}

export interface AadpEpAuthorizationArtifactResult {
  verdict: 'VERIFIED' | 'REFUSE' | 'INDETERMINATE';
  artifact: AadpAuthorizationArtifact | null;
  mapped_action: unknown | null;
  authorization_decision: false;
  reasons: string[];
}

type Obj = Record<string, unknown>;

const ARTIFACT_KEYS = new Set([
  'profile',
  'artifact_profile',
  'artifact_digest',
  'verification_outcome',
  'action_mapping_profile',
  'action_digest',
]);
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function dataRecord(value: unknown): Obj | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) return null;
    const record: Obj = {};
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      record[key] = descriptor.value;
    }
    return record;
  } catch {
    return null;
  }
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function absoluteUri(value: unknown): value is string {
  if (!nonEmptyString(value)) return false;
  try {
    return new URL(value).protocol.length > 1;
  } catch {
    return false;
  }
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function parseAadpAction(value: unknown): AadpAction | null {
  const record = dataRecord(value);
  if (!record
      || Object.keys(record).length !== 2
      || !Object.hasOwn(record, 'action_type')
      || !Object.hasOwn(record, 'params')
      || !nonEmptyString(record.action_type)) return null;
  const params = dataRecord(record.params);
  if (!params) return null;
  try {
    return {
      action_type: record.action_type,
      params: JSON.parse(canonicalizeAeb(params)) as Record<string, unknown>,
    };
  } catch {
    return null;
  }
}

/** Return a safe normalized copy of the closed, profile-neutral hook. */
export function parseAadpAuthorizationArtifact(
  value: unknown,
): AadpAuthorizationArtifact | null {
  const record = dataRecord(value);
  if (!record
      || Object.keys(record).length !== ARTIFACT_KEYS.size
      || !Object.keys(record).every((key) => ARTIFACT_KEYS.has(key))
      || record.profile !== AADP_AUTHORIZATION_ARTIFACT_VERSION
      || !nonEmptyString(record.artifact_profile)
      || !validDigest(record.artifact_digest)
      || !['verified', 'not_satisfying', 'not_reachable'].includes(record.verification_outcome as string)
      || !absoluteUri(record.action_mapping_profile)
      || !validDigest(record.action_digest)) return null;
  return {
    profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
    artifact_profile: record.artifact_profile,
    artifact_digest: record.artifact_digest,
    verification_outcome: record.verification_outcome as AadpAuthorizationArtifact['verification_outcome'],
    action_mapping_profile: record.action_mapping_profile,
    action_digest: record.action_digest,
  };
}

/**
 * Compare a presented AADP hook with one independently derived by the PDP.
 * Missing native verification is indeterminate. Malformed or unequal
 * presenter input is a hard mismatch.
 */
export function matchAadpAuthorizationArtifact(
  presented: unknown,
  expected: unknown,
): AadpAuthorizationArtifactMatchResult {
  const actual = parseAadpAuthorizationArtifact(presented);
  if (!actual) {
    return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_malformed' };
  }
  const derived = parseAadpAuthorizationArtifact(expected);
  if (!derived) {
    return {
      verdict: 'INDETERMINATE',
      artifact: null,
      reason: 'native_authorization_artifact_unavailable',
    };
  }
  try {
    if (canonicalizeAeb(actual) !== canonicalizeAeb(derived)) {
      return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_mismatch' };
    }
  } catch {
    return { verdict: 'MISMATCH', artifact: null, reason: 'authorization_artifact_malformed' };
  }
  return { verdict: 'MATCH', artifact: derived, reason: null };
}

function safeDigest(value: unknown): AebDigest | null {
  try { return digestAeb(value); } catch { return null; }
}

function buildArtifact(
  input: DeriveAadpEpAuthorizationArtifactInput,
  actionDigest: AebDigest,
  artifactDigest: AebDigest | null,
  verificationOutcome: AadpAuthorizationArtifact['verification_outcome'],
): AadpAuthorizationArtifact | null {
  if (artifactDigest === null || !absoluteUri(input.actionMappingProfile)) return null;
  return {
    profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
    artifact_profile: AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
    artifact_digest: artifactDigest,
    verification_outcome: verificationOutcome,
    action_mapping_profile: input.actionMappingProfile,
    action_digest: actionDigest,
  };
}

function unavailable(
  reason: string,
  artifact: AadpAuthorizationArtifact | null = null,
): AadpEpAuthorizationArtifactResult {
  return {
    verdict: 'INDETERMINATE',
    artifact,
    mapped_action: null,
    authorization_decision: false,
    reasons: [reason],
  };
}

/**
 * Derive the generic AADP hook from an EP Authorization Bundle.
 *
 * `mapAction` and `actionMappingProfile` are relying-party configuration. They
 * are never read from the presenter. The underlying Bundle verifier still
 * requires pinned approver keys, a local audience, current policy, a fresh
 * authorization instance, and every other native EP verification input.
 */
export function deriveAadpEpAuthorizationArtifact(
  input: DeriveAadpEpAuthorizationArtifactInput,
): AadpEpAuthorizationArtifactResult {
  try {
    const action = parseAadpAction(input?.aadpAction);
    if (!action) {
      return {
        verdict: 'REFUSE',
        artifact: null,
        mapped_action: null,
        authorization_decision: false,
        reasons: ['aadp_action_malformed'],
      };
    }
    const aadpActionDigest = digestAeb(action);
    const referencedArtifactDigest = safeDigest(input.bundle)
      ?? (validDigest(input.artifactReferenceDigest) ? input.artifactReferenceDigest : null);
    if (!absoluteUri(input?.actionMappingProfile)
        || typeof input?.mapAction !== 'function') {
      return unavailable(
        'aadp_action_mapping_unavailable',
        buildArtifact(input, aadpActionDigest, referencedArtifactDigest, 'not_reachable'),
      );
    }

    let mappedAction: unknown;
    try {
      mappedAction = input.mapAction(structuredClone(action));
    } catch {
      return unavailable(
        'aadp_action_mapping_unavailable',
        buildArtifact(input, aadpActionDigest, referencedArtifactDigest, 'not_reachable'),
      );
    }
    const mappedRecord = dataRecord(mappedAction);
    if (!mappedRecord) {
      return unavailable(
        'aadp_action_mapping_unavailable',
        buildArtifact(input, aadpActionDigest, referencedArtifactDigest, 'not_reachable'),
      );
    }

    const verification = verifyAuthorizationBundle(input.bundle, {
      ...input.bundleOptions,
      expectedAction: mappedRecord,
    });
    if (verification.verdict !== 'SATISFIED' || verification.bundle_digest === null) {
      const verificationOutcome = verification.verdict === 'REFUSE'
        ? 'not_satisfying'
        : 'not_reachable';
      return {
        verdict: verification.verdict === 'REFUSE' ? 'REFUSE' : 'INDETERMINATE',
        artifact: buildArtifact(
          input,
          aadpActionDigest,
          verification.bundle_digest ?? referencedArtifactDigest,
          verificationOutcome,
        ),
        mapped_action: mappedRecord,
        authorization_decision: false,
        reasons: verification.reasons,
      };
    }

    return {
      verdict: 'VERIFIED',
      artifact: {
        profile: AADP_AUTHORIZATION_ARTIFACT_VERSION,
        artifact_profile: AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
        artifact_digest: verification.bundle_digest,
        verification_outcome: 'verified',
        action_mapping_profile: input.actionMappingProfile,
        action_digest: aadpActionDigest,
      },
      mapped_action: mappedRecord,
      authorization_decision: false,
      reasons: [],
    };
  } catch {
    return unavailable('native_authorization_artifact_unavailable');
  }
}

/** Derive the native EP hook and compare it to a presenter-supplied AADP hook. */
export function verifyAadpEpAuthorizationArtifact(
  presented: unknown,
  input: DeriveAadpEpAuthorizationArtifactInput,
): AadpEpAuthorizationArtifactResult {
  const derived = deriveAadpEpAuthorizationArtifact(input);
  if (derived.verdict !== 'VERIFIED') return derived;
  const matched = matchAadpAuthorizationArtifact(presented, derived.artifact);
  if (matched.verdict === 'MATCH') return derived;
  return {
    verdict: matched.verdict === 'MISMATCH' ? 'REFUSE' : 'INDETERMINATE',
    artifact: null,
    mapped_action: derived.mapped_action,
    authorization_decision: false,
    reasons: [matched.reason ?? 'authorization_artifact_mismatch'],
  };
}

export default Object.freeze({
  AADP_AUTHORIZATION_ARTIFACT_VERSION,
  AADP_EP_AUTHORIZATION_ARTIFACT_PROFILE,
  parseAadpAuthorizationArtifact,
  matchAadpAuthorizationArtifact,
  deriveAadpEpAuthorizationArtifact,
  verifyAadpEpAuthorizationArtifact,
});

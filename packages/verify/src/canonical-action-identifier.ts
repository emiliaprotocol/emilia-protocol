// SPDX-License-Identifier: Apache-2.0
/**
 * Canonical Action Identifier scheme boundary.
 *
 * New identifiers use the `canactid` URI scheme, provisionally registered by
 * IANA. Provisional registration is not IETF endorsement. Historical CAID-04
 * signed artifacts remain byte-immutable and are available only through the
 * explicitly selected legacy profile below. Callers must never translate a
 * signed `caid:` value into `canactid:` because the identifier is part of the
 * signed material.
 */

export const CANACTID_V1_PROFILE = 'canactid-v1' as const;
export const LEGACY_CAID_V04_PROFILE = 'legacy-caid-v04' as const;

export type CanonicalActionIdentifierProfile =
  | typeof CANACTID_V1_PROFILE
  | typeof LEGACY_CAID_V04_PROFILE;

const ACTION_TYPE = '([a-z][a-z0-9-]*(?:\\.[a-z][a-z0-9-]*)*\\.[1-9][0-9]*)';
const CANONICALIZATION = '([a-z0-9]+(?:-[a-z0-9]+)*)';
const DIGEST = '([A-Za-z0-9_-]{43})';

export const CANACTID_V1_PATTERN = new RegExp(
  `^canactid:1:${ACTION_TYPE}:${CANONICALIZATION}:${DIGEST}$`,
);

export const LEGACY_CAID_V04_PATTERN = new RegExp(
  `^caid:1:${ACTION_TYPE}:${CANONICALIZATION}:${DIGEST}$`,
);

export interface ParsedCanonicalActionIdentifier {
  profile: CanonicalActionIdentifierProfile;
  scheme: 'canactid' | 'caid';
  version: 1;
  action_type: string;
  canonicalization: string;
  digest: string;
}

function patternFor(profile: CanonicalActionIdentifierProfile): RegExp {
  return profile === LEGACY_CAID_V04_PROFILE
    ? LEGACY_CAID_V04_PATTERN
    : CANACTID_V1_PATTERN;
}

export function isCanonicalActionIdentifier(value: unknown): value is string {
  return typeof value === 'string' && CANACTID_V1_PATTERN.test(value);
}

export function isLegacyCaidV04(value: unknown): value is string {
  return typeof value === 'string' && LEGACY_CAID_V04_PATTERN.test(value);
}

export function parseCanonicalActionIdentifier(
  value: unknown,
  profile: CanonicalActionIdentifierProfile = CANACTID_V1_PROFILE,
): ParsedCanonicalActionIdentifier | null {
  if (typeof value !== 'string') return null;
  const match = patternFor(profile).exec(value);
  if (!match) return null;
  return Object.freeze({
    profile,
    scheme: profile === LEGACY_CAID_V04_PROFILE ? 'caid' : 'canactid',
    version: 1 as const,
    action_type: match[1],
    canonicalization: match[2],
    digest: match[3],
  });
}

export function canonicalActionIdentifierMatchesActionType(
  value: unknown,
  actionType: string,
  profile: CanonicalActionIdentifierProfile = CANACTID_V1_PROFILE,
): boolean {
  const parsed = parseCanonicalActionIdentifier(value, profile);
  return parsed !== null && parsed.action_type === actionType;
}

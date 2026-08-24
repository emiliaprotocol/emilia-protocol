// SPDX-License-Identifier: Apache-2.0

import {
  inspectAssuranceRecordIntegrity,
  type AssuranceRecord,
} from '@emilia-protocol/verify/claim-assurance';

import referenceRecordJson from '../public/assurance/records/sha256-dbf1f303f1b6e58aec00b3fec1f782e2853fd9ab9601d9325c7e7014091f2985.json';

export const CLAIM_ASSURANCE_REFERENCE_RECORD_ID =
  'sha256:dbf1f303f1b6e58aec00b3fec1f782e2853fd9ab9601d9325c7e7014091f2985' as const;

export const CLAIM_ASSURANCE_REFERENCE_API_PATH =
  `/api/v1/assurance/records/${encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID)}` as const;

export const CLAIM_ASSURANCE_REFERENCE_PAGE_PATH =
  `/assurance/records/${encodeURIComponent(CLAIM_ASSURANCE_REFERENCE_RECORD_ID)}` as const;

function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return Object.freeze(value);
}

const referenceRecord = deepFreeze(
  referenceRecordJson as unknown as AssuranceRecord,
);
const integrity = inspectAssuranceRecordIntegrity(referenceRecord, {
  expected_record_digest: CLAIM_ASSURANCE_REFERENCE_RECORD_ID,
});

if (!integrity.integrity_valid
    || referenceRecord.record_digest !== CLAIM_ASSURANCE_REFERENCE_RECORD_ID
    || referenceRecord.authorizes_action !== false) {
  throw new Error('invalid committed Claim Assurance reference record');
}

/** Exact lookup for the one committed synthetic record. No enumeration exists. */
export function getClaimAssuranceReferenceRecord(
  recordId: string,
): Readonly<AssuranceRecord> | null {
  let normalizedRecordId: string;
  try {
    normalizedRecordId = decodeURIComponent(recordId);
  } catch {
    return null;
  }
  return normalizedRecordId === CLAIM_ASSURANCE_REFERENCE_RECORD_ID ? referenceRecord : null;
}

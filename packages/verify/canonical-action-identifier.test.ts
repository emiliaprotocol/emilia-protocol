// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CANACTID_V1_PROFILE,
  LEGACY_CAID_V04_PROFILE,
  canonicalActionIdentifierMatchesActionType,
  isCanonicalActionIdentifier,
  isLegacyCaidV04,
  parseCanonicalActionIdentifier,
} from './src/canonical-action-identifier.js';

const DIGEST = 'A'.repeat(43);
const CURRENT = `canactid:1:payment.release.1:jcs-sha256:${DIGEST}`;
const LEGACY = `caid:1:payment.release.1:jcs-sha256:${DIGEST}`;

test('current identifier validation accepts only the canactid scheme', () => {
  assert.equal(isCanonicalActionIdentifier(CURRENT), true);
  assert.equal(isCanonicalActionIdentifier(LEGACY), false);
  assert.equal(isCanonicalActionIdentifier(`canactid:1:payment.release.1:jcs-sha256:${'A'.repeat(42)}`), false);
});

test('legacy CAID validation is an explicit separate profile', () => {
  assert.equal(isLegacyCaidV04(LEGACY), true);
  assert.equal(isLegacyCaidV04(CURRENT), false);
  assert.equal(parseCanonicalActionIdentifier(LEGACY), null);
  assert.deepEqual(parseCanonicalActionIdentifier(LEGACY, LEGACY_CAID_V04_PROFILE), {
    profile: LEGACY_CAID_V04_PROFILE,
    scheme: 'caid',
    version: 1,
    action_type: 'payment.release.1',
    canonicalization: 'jcs-sha256',
    digest: DIGEST,
  });
});

test('parsing and action-type matching preserve the scheme and exact action type', () => {
  assert.deepEqual(parseCanonicalActionIdentifier(CURRENT), {
    profile: CANACTID_V1_PROFILE,
    scheme: 'canactid',
    version: 1,
    action_type: 'payment.release.1',
    canonicalization: 'jcs-sha256',
    digest: DIGEST,
  });
  assert.equal(canonicalActionIdentifierMatchesActionType(CURRENT, 'payment.release.1'), true);
  assert.equal(canonicalActionIdentifierMatchesActionType(CURRENT, 'payment.release.10'), false);
  assert.equal(canonicalActionIdentifierMatchesActionType(LEGACY, 'payment.release.1'), false);
  assert.equal(
    canonicalActionIdentifierMatchesActionType(LEGACY, 'payment.release.1', LEGACY_CAID_V04_PROFILE),
    true,
  );
});

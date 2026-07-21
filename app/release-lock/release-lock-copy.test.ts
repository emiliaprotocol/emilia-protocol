// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

function readLocal(relativePath) {
  return readFileSync(
    fileURLToPath(new URL(relativePath, import.meta.url)),
    'utf8',
  );
}

const productCopy = [
  readLocal('./new/ReleaseLockNew.tsx'),
  readLocal('./ReleaseLockTerms.tsx'),
  readLocal('./[lockId]/ReleaseLockExperience.tsx'),
  readLocal('./[lockId]/mirror/ActionMirrorExperience.tsx'),
].join('\n');

const normalizedCopy = productCopy.replace(/\s+/g, ' ');

describe('Release Lock claims and ceremony copy', () => {
  it('states the narrow boundary and separates the two authority events', () => {
    expect(normalizedCopy).toContain(
      'two separately enrolled passkey credentials approving the same exact immutable action version',
    );
    expect(normalizedCopy).toContain('CO_ACCEPTED is not payment authority.');
    expect(normalizedCopy).toContain(
      'Only DRAW_RELEASE can make this custodian instruction eligible.',
    );
    expect(normalizedCopy).toContain(
      'Any material amendment changes both action digests and invalidates CO_ACCEPTED',
    );
    expect(normalizedCopy).toContain('Release Lock does not hold funds, judge work');
    expect(normalizedCopy).toContain('does not prove comprehension');
    expect(normalizedCopy).toContain('does not prove comprehension, biometric identity');
    expect(normalizedCopy).toContain(
      'Production also requires distinct subjects under one pinned external authority',
    );
    expect(normalizedCopy).not.toContain(
      'Each person keeps one separately enrolled seat',
    );
  });

  it('does not introduce camera, video, or liveness as a V1 factor', () => {
    expect(productCopy).not.toMatch(/\bgetUserMedia\b/i);
    expect(productCopy).not.toMatch(/\bcamera\b/i);
    expect(productCopy).not.toMatch(/\bvideo\b/i);
    expect(productCopy).not.toMatch(/\bliveness\b/i);
  });
});

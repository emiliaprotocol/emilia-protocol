// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const DIGEST = 'A'.repeat(43);
const CURRENT = `canactid:1:payment.release.1:jcs-sha256:${DIGEST}`;
const LEGACY = `caid:1:payment.release.1:jcs-sha256:${DIGEST}`;

function schema(name: string): any {
  return JSON.parse(readFileSync(
    new URL(`../public/schemas/${name}`, import.meta.url),
    'utf8',
  ));
}

describe('public current-profile schemas use the provisionally registered canactid scheme', () => {
  const patterns = [
    schema('discovery-permit-binding-v1.schema.json').properties.caid.pattern,
    schema('ep-action-evidence-packet.schema.json').$defs.caid.pattern,
    schema('ep-reliance-program.schema.json').$defs.caid.pattern,
  ];

  for (const pattern of patterns) {
    it(`accepts current and rejects legacy for ${pattern}`, () => {
      const matcher = new RegExp(pattern);
      expect(matcher.test(CURRENT)).toBe(true);
      expect(matcher.test(LEGACY)).toBe(false);
    });
  }
});

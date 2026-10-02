// SPDX-License-Identifier: Apache-2.0
//
// The repository's own code uses the @xmldom/xmldom 0.9 line, while packages
// that declare only ^0.8 keep their own nested 0.8 copy through the nested
// "overrides" pins in package.json. These tests hold that topology: no global
// override forces one line onto every consumer, and every installed copy
// satisfies the range its dependent declares.

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const XMLDOM = '@xmldom/xmldom';
const PACKAGE = JSON.parse(readFileSync('package.json', 'utf8'));
const LOCK_PACKAGES: Record<string, any> = JSON.parse(readFileSync('package-lock.json', 'utf8')).packages;
const DIRECT_PIN: string = PACKAGE.dependencies[XMLDOM];
const NESTED_PINS: Array<[string, string]> = Object.entries(PACKAGE.overrides ?? {})
  .filter(([, value]) => value !== null && typeof value === 'object' && XMLDOM in (value as object))
  .map(([consumer, value]) => [consumer, (value as Record<string, string>)[XMLDOM]]);

/** Node's nearest-node_modules lookup, applied to package-lock.json paths. */
function resolveInLock(fromPath: string, name: string): string | undefined {
  let base = fromPath;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
    if (LOCK_PACKAGES[candidate]) return candidate;
    if (!base) return undefined;
    const parent = base.lastIndexOf('/node_modules/');
    base = parent === -1 ? '' : base.slice(0, parent);
  }
}

/** For a caret/tilde/exact 0.x range, the release line it admits (e.g. "0.8."). */
function zeroMinorLine(range: string): string | null {
  const match = /^[\^~]?0\.(\d+)\b/.exec(range.trim());
  return match ? `0.${match[1]}.` : null;
}

describe('@xmldom/xmldom dual-version topology', () => {
  it('pins the direct dependency exactly and declares no global override', () => {
    expect(DIRECT_PIN).toMatch(/^0\.9\.\d+$/);
    expect(PACKAGE.overrides?.[XMLDOM]).toBeUndefined();
    expect(NESTED_PINS.map(([consumer]) => consumer).sort()).toEqual([
      '@node-saml/node-saml',
      'mammoth',
      'xml-crypto',
      'xml-encryption',
    ]);
    for (const [, pin] of NESTED_PINS) expect(pin).toMatch(/^0\.8\.\d+$/);
  });

  it('resolves the root copy to the direct pin and each 0.8-only consumer to its nested pin', () => {
    expect(LOCK_PACKAGES[`node_modules/${XMLDOM}`]?.version).toBe(DIRECT_PIN);
    for (const [consumer, pin] of NESTED_PINS) {
      const installs = Object.keys(LOCK_PACKAGES).filter((entry) => entry.endsWith(`node_modules/${consumer}`));
      expect(installs.length, consumer).toBeGreaterThan(0);
      for (const install of installs) {
        const resolved = resolveInLock(install, XMLDOM);
        expect(resolved, install).toBe(`${install}/node_modules/${XMLDOM}`);
        expect(LOCK_PACKAGES[resolved!].version, install).toBe(pin);
      }
    }
  });

  it('gives every locked dependent an xmldom copy inside the release line it declares', () => {
    const dependents = Object.entries(LOCK_PACKAGES).filter(
      ([entry, meta]) => entry !== '' && meta?.dependencies?.[XMLDOM],
    );
    expect(dependents.length).toBeGreaterThan(0);
    for (const [entry, meta] of dependents) {
      const line = zeroMinorLine(meta.dependencies[XMLDOM]);
      const resolved = resolveInLock(entry, XMLDOM);
      expect(resolved, entry).toBeDefined();
      if (line) expect(LOCK_PACKAGES[resolved!].version.startsWith(line), `${entry} -> ${resolved}`).toBe(true);
    }
  });

  it('loads 0.9 from the repository root and 0.8 from each installed consumer', () => {
    const rootRequire = createRequire(path.resolve('package.json'));
    expect(rootRequire(`${XMLDOM}/package.json`).version).toBe(DIRECT_PIN);
    for (const [consumer, pin] of NESTED_PINS) {
      const consumerRequire = createRequire(rootRequire.resolve(`${consumer}/package.json`));
      expect(consumerRequire(`${XMLDOM}/package.json`).version, consumer).toBe(pin);
    }
  });
});

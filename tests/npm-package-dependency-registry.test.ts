// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  assertInternalDependenciesPublished,
  collectInternalRegistryDependencies,
} from '../scripts/check-npm-package-dependencies.mjs';

describe('npm internal dependency registry guard', () => {
  it('checks Gate against the exact verifier version declared for publication', () => {
    const metadata = JSON.parse(readFileSync('packages/gate/package.json', 'utf8'));
    const requested: string[] = [];
    const dependencies = assertInternalDependenciesPublished(metadata, (spec: string) => {
      requested.push(spec);
      return true;
    });

    expect(requested).toContain('@emilia-protocol/verify@3.15.0');
    expect(dependencies.map(({ spec }) => spec)).toContain('@emilia-protocol/verify@3.15.0');
  });

  it('covers dependencies, optional dependencies, and peer dependencies', () => {
    const dependencies = collectInternalRegistryDependencies({
      name: '@emilia-protocol/example',
      dependencies: { '@emilia-protocol/verify': '3.15.0' },
      optionalDependencies: { '@emilia-protocol/optional': '^1.2.3' },
      peerDependencies: { '@emilia-protocol/peer': '>=2.0.0 <3.0.0' },
    });

    expect(dependencies.map(({ spec }) => spec)).toEqual([
      '@emilia-protocol/optional@^1.2.3',
      '@emilia-protocol/peer@>=2.0.0 <3.0.0',
      '@emilia-protocol/verify@3.15.0',
    ]);
  });

  it('fails closed when any declared internal dependency does not resolve', () => {
    expect(() => assertInternalDependenciesPublished(
      {
        name: '@emilia-protocol/gate',
        dependencies: {
          '@emilia-protocol/require-receipt': '0.7.0',
          '@emilia-protocol/verify': '3.15.0',
        },
      },
      (spec: string) => spec !== '@emilia-protocol/verify@3.15.0',
    )).toThrow(/@emilia-protocol\/verify@3\.15\.0 \(dependencies\)/);
  });
});

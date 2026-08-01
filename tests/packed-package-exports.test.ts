// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import {
  packageTargets,
  typedPackageSpecifiers,
} from '../scripts/check-packed-package-exports.mts';

describe('packed package export classification', () => {
  it('imports executable exports and reads declared SQL, JSON, and WASM assets', () => {
    expect(packageTargets('@example/package', {
      exports: {
        '.': { import: './index.js', types: './index.d.ts' },
        './schema.sql': './assets/schema.sql',
        './vectors.json': './assets/vectors.json',
        './verifier.wasm': './assets/verifier.wasm',
      },
    })).toEqual([
      { specifier: '@example/package', kind: 'module' },
      { specifier: '@example/package/schema.sql', kind: 'asset' },
      { specifier: '@example/package/vectors.json', kind: 'asset' },
      { specifier: '@example/package/verifier.wasm', kind: 'asset' },
    ]);
  });

  it('refuses exports without a runtime target or with an unreviewed asset type', () => {
    expect(() => packageTargets('@example/package', {
      exports: { './types-only': { types: './types-only.d.ts' } },
    })).toThrow(/has no closed import target/);

    expect(() => packageTargets('@example/package', {
      exports: { './stylesheet': './assets/style.css' },
    })).toThrow(/has unsupported target/);
  });

  it('enumerates every public typed entry for a strict packed-consumer check', () => {
    expect(typedPackageSpecifiers('@example/package', {
      exports: {
        '.': { import: './index.js', types: './index.d.ts' },
        './typed': { import: './typed.js', types: './typed.d.ts' },
        './runtime-only': { import: './runtime.js' },
        './package.json': './package.json',
      },
    })).toEqual([
      '@example/package',
      '@example/package/typed',
    ]);
  });
});

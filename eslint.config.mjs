// ESLint v9 flat config for emilia-protocol (Next.js 15 + ESLint 9).
//
// Bridges `next/core-web-vitals` (still legacy-format under the hood) via
// FlatCompat so we can drop `.eslintrc.json` and the
// `ESLINT_USE_FLAT_CONFIG=false` workaround in lint-staged. When
// eslint-config-next ships a native flat preset, switch to it directly.

import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { FlatCompat } from '@eslint/eslintrc';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({ baseDirectory: __dirname });

export default [
  // Global ignores — flat config replaces .eslintrc `ignorePatterns`.
  // node_modules/ is implicit in flat config and does not need listing.
  {
    ignores: [
      '.next/**',
      'out/**',
      'coverage/**',
      'dist/**',
      'build/**',
      'packages/**',
      'sdks/**',
      'scripts/**',
      'tests/**',
      'e2e/**',
      'conformance/**',
      'supabase/**',
      'formal/**',
      'infrastructure/**',
      'create-ep-app/**',
      'public/embed.js',
    ],
  },

  // Bridge legacy Next.js preset.
  ...compat.extends('next/core-web-vitals'),

  // Project-local rule overrides.
  {
    rules: {
      'react/no-unescaped-entities': 'off',
      'react-hooks/exhaustive-deps': 'warn',
      '@next/next/no-img-element': 'warn',
      '@next/next/no-html-link-for-pages': 'warn',
      '@next/next/no-page-custom-font': 'warn',
      'jsx-a11y/alt-text': 'warn',
    },
  },
];

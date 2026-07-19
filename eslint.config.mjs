// ESLint v9 flat config for emilia-protocol (Next.js 15+ / ESLint 9+).
//
// eslint-config-next v16 ships native flat-config exports, so we import
// `core-web-vitals` directly and spread it into the array. Previously we
// used FlatCompat to bridge the legacy preset; that shim is no longer
// needed and produced confusing stack traces under v16.

import nextCoreWebVitals from 'eslint-config-next/core-web-vitals';
import noRawAuthEntity from './eslint-rules/no-raw-auth-entity.mjs';

const config = [
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
      'examples/**',
      'bench/**',
      'tests/**',
      'e2e/**',
      'conformance/**',
      'supabase/**',
      'formal/**',
      'ml/**',
      'infrastructure/**',
      'create-ep-app/**',
      'public/embed.js',
    ],
  },

  // Native flat preset from eslint-config-next v16+.
  ...nextCoreWebVitals,

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

  // Security boundary: authenticated entity rows are not caller identities.
  // Keep this rule scoped to runtime code so tests and documentation can show
  // the bad shape when they are explicitly exercising the regression guard.
  {
    files: ['app/**/*.js', 'app/**/*.jsx', 'lib/**/*.js', 'lib/**/*.mjs'],
    ignores: ['lib/**/*.test.js', 'lib/**/*.test.jsx', 'lib/**/*.test.mjs'],
    plugins: {
      'ep-security': {
        rules: { 'no-raw-auth-entity': noRawAuthEntity },
      },
    },
    rules: {
      'ep-security/no-raw-auth-entity': 'error',
    },
  },
];

export default config;

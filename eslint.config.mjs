// ESLint v9 flat config for emilia-protocol (Next.js 15+ / ESLint 9+).
//
// eslint-config-next v16 ships native flat-config exports, so we import
// `core-web-vitals` directly and spread it into the array. Previously we
// used FlatCompat to bridge the legacy preset; that shim is no longer
// needed and produced confusing stack traces under v16.

import nextCoreWebVitals from 'eslint-config-next/core-web-vitals';

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
];

import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname),
    },
  },
  test: {
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      include: ['lib/**/*.js'],
      exclude: [
        'lib/supabase.js',   // infrastructure adapter — tested via integration
        'lib/env.js',        // thin env wrapper
        '**/*.test.js',
      ],
      thresholds: {
        // Locked 2026-04-02 after full audit remediation. Never lower — ratchet up only.
        statements: 95,
        functions: 97,
        branches: 90,
        lines: 97,
      },
    },
  },
});

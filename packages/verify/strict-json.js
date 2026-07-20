// SPDX-License-Identifier: Apache-2.0
// Compatibility re-export: packages/verify/strict-json.js moved to TypeScript
// (src/strict-json.ts, compiled to dist/strict-json.js). This shim keeps the
// pre-migration relative-import path (`../verify/strict-json.js`) working for
// every existing consumer across the repo without touching each call site.
export * from './dist/strict-json.js';

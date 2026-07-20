// SPDX-License-Identifier: Apache-2.0
// Compatibility re-export: packages/verify/web.js moved to TypeScript
// (src/web.ts, compiled to dist/web.js). This shim keeps the pre-migration
// relative-import path (`../verify/web.js`) working for every existing
// consumer across the repo without touching each call site.
export * from './dist/web.js';

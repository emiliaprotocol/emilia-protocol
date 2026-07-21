// SPDX-License-Identifier: Apache-2.0
//
// Type-only stub for 'viem', wired in via tsconfig.json "paths". viem
// re-exports "ox"'s ABI-generic machinery, and resolving its real types
// against lib/blockchain.ts's usage hits ox's own known "type instantiation
// is excessively deep" limit under `next build`'s type-check. This affects
// TypeScript's type resolution only -- webpack/Next's dependency tracer
// still resolves and bundles the real installed package at build time and
// runtime, since "paths" is not consulted for real node_modules bundling.
// lib/blockchain.ts is the only file in this repo that imports viem
// (verified by repo-wide grep); every call site there already types its own
// inputs/outputs explicitly, so this stub only needs to keep destructuring
// and `await import(...)` assignable, not model viem's real API surface.
declare module 'viem' {
  const value: any;
  export = value;
}

// Generated from issuer.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Trust Receipt issuer — emits I-D Section 6.2 authorization receipts.
 * @license Apache-2.0
 *
 * SINGLE SOURCE OF TRUTH: packages/issue/index.js (the published
 * @emilia-protocol/issue package). This module re-exports it so the in-repo
 * issuer and the npm package are the same bytes by construction — no drift, no
 * second copy to keep in sync. The package emits the §6.2 receipt shape that
 * @emilia-protocol/verify's verifyTrustReceipt() accepts 7/7 (§6.3) using only
 * node:crypto, with no EP backend.
 *
 * Why re-export here rather than vendor a copy (cf. lib/verify-web.js, which is
 * a byte-pinned vendored copy with a drift test): the browser verifier must be
 * independently bundleable into the Next.js client, so it needs its own file.
 * This issuer is consumed only by Node test code (tests/trust-receipt-issuer.test.js)
 * and never bundled client-side, so a plain ESM re-export is the cleaner,
 * drift-proof arrangement. The production mint path is the canonical writer
 * behind POST /api/v1/trust-receipts and does not import this module.
 *
 * Stable exports (unchanged): issueTrustReceipt, assembleTrustReceipt,
 * buildContexts, collectSignoffs, merkleProof, canonicalize, actionHash,
 * contextDigest.
 */
export { issueTrustReceipt, assembleTrustReceipt, buildContexts, collectSignoffs, merkleProof, canonicalize, actionHash, contextDigest, } from '../../packages/issue/index.js';

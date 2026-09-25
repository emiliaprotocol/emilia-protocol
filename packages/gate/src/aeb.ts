// SPDX-License-Identifier: Apache-2.0
/**
 * Stable AEB consequence-admission surface.
 *
 * The verifier determines whether the native evidence matches the protected
 * action. The consequence boundary separately applies local authorization,
 * reserves native replay identities and the exact-action in-flight fence, owns
 * provider entry, and reconciles an uncertain result.
 */
export * from './aeb-consumption-store.js';
export * from './consequence-boundary.js';

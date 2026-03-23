/**
 * Shared cryptographic utilities.
 *
 * Single canonical SHA-256 implementation for the entire codebase.
 * All lib/ modules should import from here instead of inlining
 * their own createHash('sha256') calls.
 *
 * @license Apache-2.0
 */

import { createHash } from 'crypto';

/**
 * Compute SHA-256 hash of a string.
 * @param {string} data — input to hash
 * @returns {string} hex-encoded SHA-256 hash
 */
export function sha256(data) {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

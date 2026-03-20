/**
 * EP Handshake — Claim normalization.
 *
 * Pure functions that normalize raw presentations into internal format.
 *
 * @license Apache-2.0
 */

import { sha256 } from './invariants.js';

/**
 * Compute a presentation hash from presentation data.
 */
export function computePresentationHash(data) {
  return sha256(
    typeof data === 'string' ? data : JSON.stringify(data),
  );
}

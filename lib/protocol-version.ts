/**
 * EP Protocol Version
 * 
 * Included in every trust evaluation output so consumers know
 * which protocol version produced the result.
 * 
 * Update this when:
 *   - Scoring weights change
 *   - Policy semantics change  
 *   - Context key schema changes
 *   - Provenance tiers change
 *   - Establishment rules change
 * 
 * @license Apache-2.0
 */

export const EP_PROTOCOL_VERSION = {
  spec: '1.1',
  scoring_model: 'v2',
  weight_model: 'behavioral-first-four-factor',
  hash_algorithm: 'SHA-256',
  receipt_version: 1,
};

export const EP_VERSION_STRING = 'EP/1.1-v2';

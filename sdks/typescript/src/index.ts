/**
 * EMILIA Protocol TypeScript SDK.
 *
 * The package root intentionally re-exports the single supported client
 * implementation. Keeping the entry point as a barrel prevents the public
 * package contract from drifting away from the client exercised by the SDK
 * tests and documented in the README.
 *
 * @license Apache-2.0
 */

export { EPClient } from './client.js';
export * from './types.js';

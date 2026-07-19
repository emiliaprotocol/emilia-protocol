/**
 * EP envelope — public entrypoint with built-in profiles registered.
 *
 * @license Apache-2.0
 *
 * `import { verifyEnvelope } from 'lib/envelope'` gives you the verifier with the
 * six built-in profiles already registered. Importing './profiles.js' for its
 * registration side effect MUST come before re-exporting the core.
 */
import './profiles.js';

export {
  EP_ENVELOPE_VERSION,
  registerProfile,
  getProfile,
  listProfiles,
  verifyEnvelope,
  migrate,
  isWellFormedProfileUrn,
  isVendorProfileUrn,
  isLosslessMigration,
} from './envelope.js';
export { BUILTIN_PROFILES } from './profiles.js';

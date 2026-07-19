/**
 * Built-in EP profile registrations — the additive profiles, wrapped as
 * EP-ENVELOPE-v1 plugins.
 *
 * @license Apache-2.0
 *
 * Each plugin's validateBody() adapts the uniform envelope to the profile's
 * existing (bespoke) verifier and returns its { valid, checks, errors }. The
 * inner verifiers are unchanged and already fail closed (unpinned-key rejection,
 * etc.); the envelope adds the shared pipeline + the PluginCannotWeaken
 * composition on top. Descriptor metadata comes from descriptors.js (the single
 * registry source). This is the template a THIRD PARTY copies to register their
 * own profile in the `urn:ep:profile:x-<vendor>:*` space without touching core.
 *
 * Importing this module registers the built-ins as a side effect.
 */

import { registerProfile } from './envelope.js';
import { DESCRIPTOR_BY_URN, PROFILE_DESCRIPTORS } from './descriptors.js';
import { verifyRevocation } from '../revocation/revocation.js';
import { verifyEyeSet } from '../eye/eye-set.js';
import { verifyExecutionIntegrity } from '../execution/integrity.js';
import { verifyDisplayAttestation } from '../wysiwys/render.js';
import { verifyProvenanceOffline } from '../provenance/chain.js';
import { verifyResolutionReceipt } from '../../packages/verify/resolution.js';

const d = (urn) => DESCRIPTOR_BY_URN[urn];

// urn:ep:profile:revocation:v1 — payload = the EP-REVOCATION-v1 statement; the
// target the relying party holds + the pinned revoker keys come from opts.
registerProfile('urn:ep:profile:revocation:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:revocation:v1'),
  validateBody: (env, opts = {}) =>
    verifyRevocation(opts.target, env.payload, { revokerKeys: opts.revokerKeys, maxAgeSeconds: opts.maxAgeSeconds, now: opts.now }),
}));

// urn:ep:profile:eye-set:v1 — payload = { set: "<JWS-compact SET>" }.
registerProfile('urn:ep:profile:eye-set:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:eye-set:v1'),
  validateBody: (env, opts = {}) => {
    const setCompact = typeof env.payload?.set === 'string' ? env.payload.set : null;
    if (!setCompact) {
      return { valid: false, checks: { payload_shape: false }, errors: ['eye-set envelope payload must be { set: "<JWS compact>" }'] };
    }
    return verifyEyeSet(setCompact, { pinnedKeys: opts.pinnedKeys, audience: opts.audience, requireFresh: opts.requireFresh, maxAgeSec: opts.maxAgeSec, now: opts.now });
  },
}));

// urn:ep:profile:execution-integrity:v1 — payload = the attestation.
registerProfile('urn:ep:profile:execution-integrity:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:execution-integrity:v1'),
  validateBody: (env, opts = {}) => {
    const receipt = opts.receipt || (opts.approvedActionHash ? { action_hash: opts.approvedActionHash } : {});
    return verifyExecutionIntegrity(env.payload, receipt, { executorKeys: opts.executorKeys, reversibilityAsserted: opts.reversibilityAsserted });
  },
}));

// urn:ep:profile:wysiwys:v1 — payload = the display attestation.
registerProfile('urn:ep:profile:wysiwys:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:wysiwys:v1'),
  validateBody: (env, opts = {}) =>
    verifyDisplayAttestation(opts.action, env.payload, { displaySignerKeys: opts.displaySignerKeys, requireDisplayAttestation: opts.requireDisplayAttestation, requireSignedAttestation: opts.requireSignedAttestation }),
}));

// urn:ep:profile:provenance-chain:v1 — payload = the provenance bundle.
registerProfile('urn:ep:profile:provenance-chain:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:provenance-chain:v1'),
  validateBody: (env, opts = {}) => verifyProvenanceOffline(env.payload, /** @type {any} */ (opts)),
}));

// urn:ep:profile:resolution:v1 — payload = an EP-RESOLUTION-v1 artifact. The
// exact source envelope, expected action, RP ID, and role-pinned principal keys
// remain relying-party inputs; the envelope cannot self-assert any of them.
registerProfile('urn:ep:profile:resolution:v1', /** @type {any} */ ({
  descriptor: d('urn:ep:profile:resolution:v1'),
  validateBody: (env, opts = {}) => verifyResolutionReceipt(env.payload, {
    bindingMoment: opts.bindingMoment,
    expectedActionHash: opts.expectedActionHash,
    expectedNonce: opts.expectedNonce,
    expectedInitiator: opts.expectedInitiator,
    evaluationTime: opts.evaluationTime,
    principalKeys: opts.principalKeys,
    rpId: opts.rpId,
    allowedOrigins: opts.allowedOrigins,
  }),
}));

export const BUILTIN_PROFILES = Object.freeze(PROFILE_DESCRIPTORS.map((x) => x.profile));

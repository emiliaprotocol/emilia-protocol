// SPDX-License-Identifier: Apache-2.0
/**
 * Stable decision-plane name for the credential-free remote actuator client.
 *
 * The implementation remains in github-app.ts until the checked-in standalone
 * companion manifest can be changed by its owning lane. That legacy filename
 * contains no provider adapter or provider credential handling.
 */
export {
  CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION,
  CONSEQUENCE_ACTUATOR_RESPONSE_VERSION,
  consequenceActuatorTargetDigest,
  createConsequenceActuatorClient,
} from './github-app.js';

export interface ConsequenceActuatorEnvelopeBinding {
  action_digest: string;
  attempt_id: string;
  caid: string;
  expires_at: string;
  idempotency_key: string;
  nonce: string;
  operation: string;
  provider_account_id: string;
  target_digest: string;
  tenant_id: string;
}

/**
 * EP Anomaly Detection
 *
 * Reference detectors for the most directly exploitable patterns in EP's
 * threat model. Pure functions — wire into any observability pipeline.
 *
 * See docs/OBSERVABILITY.md for an operator runbook.
 *
 * @license Apache-2.0
 */

export {
  detectAll,
  detectBindingBurst,
  detectGlobalBindingBurst,
  detectAbandonedSignoffs,
  detectPolicyChurn,
  detectAuthorityChurn,
  detectDelegationDepth,
  ANOMALY_THRESHOLDS,
} from './detectors.js';

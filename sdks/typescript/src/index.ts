/**
 * EMILIA Protocol TypeScript SDK
 *
 * Portable trust for machine counterparties.
 *
 * @example
 * ```typescript
 * import { EPClient } from '@emilia-protocol/sdk';
 *
 * const ep = new EPClient({ apiKey: process.env.EP_API_KEY });
 * const profile = await ep.trustProfile('merchant-xyz');
 * ```
 *
 * @license Apache-2.0
 */

export { EPClient } from './client.js';
export { EPError } from './types.js';

export type {
  // Enumerations
  EntityType,
  AgentBehavior,
  TransactionType,
  TrustPolicy,
  TrustDecision,
  DisputeReason,
  DisputeStatus,
  TrustDomain,
  ReportType,
  ConfidenceTier,

  // Input/config types
  TrustContext,
  ReceiptClaims,
  SubmitReceiptInput,
  EPClientOptions,

  // Sub-structures
  BehavioralProfile,
  SignalProfile,
  ProvenanceProfile,
  TrustProfile,
  DisputeSummary,
  AnomalyAlert,

  // Primary response types
  EntityTrustProfile,
  TrustEvaluation,
  Receipt,
  SubmitReceiptResult,
  EntitySearchResult,
  Dispute,
  LeaderboardEntry,
  TrustGateResult,
  DelegationRecord,
  DomainScore,
  DomainScoreResult,
  InstallPreflightResult,
  Principal,
  PrincipalLookupResult,
  LineageResult,
  BatchReceiptResult,
  ConfirmReceiptResult,
  TrustPolicyDefinition,
  EPStats,
} from './types.js';

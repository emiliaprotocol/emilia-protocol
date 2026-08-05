// SPDX-License-Identifier: Apache-2.0

export type AuthorityFilter = 'all' | 'review' | 'pass-through' | 'blind-spot';
export type AuthorityDisposition = 'review_required' | 'pass_through_proposal' | 'visibility_gap';
export type AuthorityConfidence = 'high' | 'medium' | 'low' | 'not_available';
export type AuthorityIcon = 'wire' | 'deploy' | 'delete' | 'summarize' | 'unknown';

export interface AuthorityAction {
  id: string;
  name: string;
  selector: string;
  description: string;
  icon: AuthorityIcon;
  category: string;
  assurance: string;
  authoritySource: string;
  exactFields: string[];
  disposition: AuthorityDisposition;
  confidence: AuthorityConfidence;
  blindSpots: string[];
}

export interface DemoStep {
  id: string;
  label: string;
  detail: string;
}

export const AUTHORITY_ACTIONS: AuthorityAction[] = [
  {
    id: 'wire-transfer',
    name: 'Release wire transfer',
    selector: 'releaseWire',
    description: 'Moves funds to an externally controlled beneficiary account.',
    icon: 'wire',
    category: 'money_movement.release',
    assurance: 'Proposed receipt · class_a',
    authoritySource: 'Not established by static scan — owner review required',
    exactFields: ['action_type', 'amount_usd', 'currency', 'payment_instruction_id', 'beneficiary_account_hash'],
    disposition: 'review_required',
    confidence: 'medium',
    blindSpots: [
      'Direct provider API paths and alternative payment rails are not visible in this declaration.',
      'Whether production credentials are isolated behind Gate is not established by a scan.',
    ],
  },
  {
    id: 'production-deploy',
    name: 'Deploy to production',
    selector: 'deployToProduction',
    description: 'Changes production code and runtime state across a customer-facing service.',
    icon: 'deploy',
    category: 'production.deploy',
    assurance: 'Proposed receipt · quorum',
    authoritySource: 'Not established by static scan — owner review required',
    exactFields: ['action_type', 'repo', 'commit_sha', 'environment', 'artifact_digest'],
    disposition: 'review_required',
    confidence: 'medium',
    blindSpots: [
      'Out-of-band cloud-console changes and unmediated CI credentials are not visible here.',
      'A generated wrapper does not establish complete mediation at the production actuator.',
    ],
  },
  {
    id: 'delete-customer',
    name: 'Delete customer record',
    selector: 'deleteCustomer',
    description: 'Irreversibly removes a customer record and associated application data.',
    icon: 'delete',
    category: 'records.delete',
    assurance: 'Proposed receipt · class_a',
    authoritySource: 'Not established by static scan — owner review required',
    exactFields: ['action_type', 'record_type', 'record_id', 'before_state_hash'],
    disposition: 'review_required',
    confidence: 'medium',
    blindSpots: [
      'Direct database access, retention jobs, and downstream replicas are not represented.',
      'The scanner cannot establish that every deletion path reaches the same boundary.',
    ],
  },
  {
    id: 'get-account-balance',
    name: 'Get account balance',
    selector: 'getAccountBalance',
    description: 'Return the current balance for a declared account.',
    icon: 'summarize',
    category: 'No category match',
    assurance: 'No receipt assurance class proposed',
    authoritySource: 'Not established by static scan — owner review required',
    exactFields: [],
    disposition: 'pass_through_proposal',
    confidence: 'low',
    blindSpots: [
      'Argument values and downstream handler behavior require owner review.',
      'Read-only hints are advisory and do not replace inspection of the supplied handler.',
    ],
  },
  {
    id: 'unknown-runtime',
    name: 'Runtime-registered surface not observed',
    selector: 'not observed',
    description: 'A static declaration cannot enumerate tools registered only at runtime.',
    icon: 'unknown',
    category: 'Visibility gap',
    assurance: 'Not available',
    authoritySource: 'Unknown — owner input required',
    exactFields: [],
    disposition: 'visibility_gap',
    confidence: 'not_available',
    blindSpots: [
      'Runtime-registered tools are not present in the supplied declaration.',
      'No consequence or pass-through judgment can be made until the operation surface is visible.',
    ],
  },
];

export const DEMO_STEPS: DemoStep[] = [
  {
    id: 'proposal',
    label: 'Scan proposal',
    detail: 'The synthetic declaration produced a proposed disposition and named its blind spots.',
  },
  {
    id: 'review',
    label: 'Human review',
    detail: 'A fictional owner accepts the material fields and required authority for this demonstration.',
  },
  {
    id: 'refusal',
    label: 'Synthetic refusal',
    detail: 'A local mock call without authorization is refused before its supplied handler runs.',
  },
  {
    id: 'approval',
    label: 'Exact-action approval',
    detail: 'A synthetic approval artifact binds the selected action and exact field values.',
  },
  {
    id: 'execution',
    label: 'One-time execution',
    detail: 'In-memory demo authority is consumed once. No external provider or production system is touched.',
  },
  {
    id: 'evidence',
    label: 'Portable evidence',
    detail: 'A synthetic evidence packet records the bounded demo result without claiming production enforcement.',
  },
];

export function filterAuthorityActions(
  actions: AuthorityAction[],
  filter: AuthorityFilter,
): AuthorityAction[] {
  if (filter === 'review') return actions.filter((action) => action.disposition === 'review_required');
  if (filter === 'pass-through') {
    return actions.filter((action) => action.disposition === 'pass_through_proposal');
  }
  if (filter === 'blind-spot') return actions.filter((action) => action.blindSpots.length > 0);
  return actions;
}

export function canRunSyntheticPath(action: AuthorityAction): boolean {
  return action.disposition === 'review_required';
}

export function visibleAuthorityActionCount(actions: AuthorityAction[]): number {
  return actions.filter((action) => action.disposition !== 'visibility_gap').length;
}

export function nextDemoStep(current: number): number {
  return Math.min(current + 1, DEMO_STEPS.length - 1);
}

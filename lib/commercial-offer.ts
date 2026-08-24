// SPDX-License-Identifier: Apache-2.0

/**
 * The public commercial offer. Buyer-facing pages and emails import this file
 * so price, duration, scope, and rollout posture cannot drift independently.
 */
/**
 * The single fixed-scope pilot offered from every public conversion path.
 * Commercial terms are selected by this server-owned identifier; intake
 * callers cannot override them or manufacture a second public offer.
 */
export const PROTECTED_WORKFLOW_PILOT = Object.freeze({
  id: 'protected_workflow_pilot_v1',
  name: 'Protected-workflow pilot',
  priceUsd: 25_000,
  priceLabel: '$25,000',
  shortPriceLabel: '$25K',
  durationDays: 90,
  durationLabel: '90 days',
  workflowCount: 1,
  workflowLabel: '1 assessed consequence boundary',
  firstProfileLabel: 'Finance operations vendor bank-detail change or payment release',
  safetyRuleLabel: 'No accepted exact-action authority and required evidence, no provider entry',
  eligibilityLabel: 'Other consequential workflows remain eligible',
  rolloutLabel: 'Synthetic, read-only, sandbox, or shadow validation only; any production activation is a separately scoped Gate Implementation',
});

export const GATE_QUALIFICATION = Object.freeze({
  name: 'Gate Qualification v2',
  profileLabel: 'public experimental implementation profile',
  scopeLabel: 'one exact measured candidate and assignment',
  outcomeLabel: 'portable, time-bounded qualification from accepted evaluation evidence',
  boundaryLine: 'Qualification travels. Authorization stays local. Gate controls the consequence.',
  disclaimer: 'Qualification is not authorization, certification, deployment evidence, or proof of a successful effect.',
});

export const GATE_IMPLEMENTATION = Object.freeze({
  name: 'Gate Implementation',
  priceLabel: '$150K-$250K',
  scopeLabel: 'one prospective consequence boundary',
  valueMetric: 'protected workflow',
  outcomeLabel: 'customer acceptance packet for one separately scoped production Gate binding and evidence operation',
});

export const PRODUCTION_GATE = Object.freeze({
  name: 'Operated Gate',
  priceLabel: '$250K-$500K / year',
  valueMetric: 'protected workflow',
  scopeLabel: 'deployment-specific quote by protected workflow and operating boundary',
  availabilityLabel: 'Scoped after implementation acceptance; not a generally available live service',
  quoteDimensions: ['protected workflows', 'deployment boundary', 'evidence retention', 'integrations', 'service level'],
});

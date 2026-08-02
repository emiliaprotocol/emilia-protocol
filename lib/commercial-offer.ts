// SPDX-License-Identifier: Apache-2.0

/**
 * The public commercial offer. Buyer-facing pages and emails import this file
 * so price, duration, scope, and rollout posture cannot drift independently.
 */
export const MANAGED_PILOT = Object.freeze({
  name: 'EMILIA Signal Diagnostic',
  priceUsd: 25_000,
  priceLabel: '$25,000',
  shortPriceLabel: '$25K',
  durationDays: 60,
  durationLabel: '60 days',
  workflowCount: 1,
  workflowLabel: '1 read-only workflow diagnostic',
  rolloutLabel: 'Synthetic first; governed export only after approval',
});

/**
 * Fixed-scope design-partner offer for buyers graduating from the public
 * Arena into one real consequence boundary. Commercial terms are selected by
 * this server-owned identifier; intake callers cannot override them.
 */
export const FINANCIAL_AUTHORITY_DESIGN_PARTNER = Object.freeze({
  id: 'financial_authority_design_partner_v1',
  name: 'Financial Authority design-partner pilot',
  priceUsd: 25_000,
  priceLabel: '$25,000',
  shortPriceLabel: '$25K',
  durationDays: 90,
  durationLabel: '90 days',
  workflowCount: 1,
  workflowLabel: '1 protected workflow',
  providerRailCount: 1,
  providerRailLabel: '1 provider rail',
  rolloutLabel: 'Synthetic validation first; production access only through a buyer-approved boundary',
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
  outcomeLabel: 'production-ready Gate binding and evidence operations',
});

export const PRODUCTION_GATE = Object.freeze({
  name: 'Operated Gate',
  priceLabel: '$250K-$500K / year',
  valueMetric: 'protected workflow',
  scopeLabel: 'deployment-specific quote by protected workflow and operating boundary',
  availabilityLabel: 'Scoped after implementation acceptance; not a generally available live service',
  quoteDimensions: ['protected workflows', 'deployment boundary', 'evidence retention', 'integrations', 'service level'],
});

// SPDX-License-Identifier: Apache-2.0

/**
 * The public commercial offer. Buyer-facing pages and emails import this file
 * so price, duration, scope, and rollout posture cannot drift independently.
 */
export const MANAGED_PILOT = Object.freeze({
  name: 'Amelia I Diagnostic',
  priceUsd: 25_000,
  priceLabel: '$25,000',
  shortPriceLabel: '$25K',
  durationDays: 60,
  durationLabel: '60 days',
  workflowCount: 1,
  workflowLabel: '1 read-only workflow diagnostic',
  rolloutLabel: 'Synthetic first; governed export only after approval',
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
  quoteDimensions: ['protected workflows', 'deployment boundary', 'evidence retention', 'integrations', 'service level'],
});

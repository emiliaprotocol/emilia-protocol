// SPDX-License-Identifier: Apache-2.0

/**
 * The public commercial offer. Buyer-facing pages and emails import this file
 * so price, duration, scope, and rollout posture cannot drift independently.
 */
export const MANAGED_PILOT = Object.freeze({
  name: 'Managed Gate Pilot',
  priceUsd: 25_000,
  priceLabel: '$25,000',
  shortPriceLabel: '$25K',
  durationDays: 60,
  durationLabel: '60 days',
  workflowCount: 1,
  workflowLabel: '1 protected workflow',
  rolloutLabel: 'Observe first; enforce only after customer approval',
});

export const PRODUCTION_GATE = Object.freeze({
  name: 'Production Gate',
  priceLabel: 'Annual contract',
  valueMetric: 'protected workflow',
  quoteDimensions: ['protected workflows', 'deployment boundary', 'evidence retention', 'integrations', 'service level'],
});

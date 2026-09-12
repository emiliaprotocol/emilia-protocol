// SPDX-License-Identifier: Apache-2.0

/** Public offer only. This does not create an order, entitlement or qualification. */
export const MARKETPLACE_GATE_OFFER = Object.freeze({
  id: 'marketplace_gate_setup_v1',
  name: 'Gate setup and support',
  status: 'QUOTE_REQUIRED' as const,
  checkoutEnabled: false,
  price: null,
  scope: 'One agreed action in one supported tool integration.',
  included: [
    'Review the action, its owner and the limits it needs.',
    'Help connect Gate to the path that holds the execution credentials.',
    'Test refusal and recovery for the agreed environment.',
    'Document what is covered, what is excluded and who operates it.',
  ],
  exclusions: 'No certification, insurance, guaranteed outcome or automatic production activation.',
});

export const GATE_QUOTE_EMAIL = 'team@emiliaprotocol.ai';

// Only a static, non-sensitive brief is embedded. Scan data, API keys and private
// repository URLs must never be copied into a query string or attached automatically.
export const GATE_QUOTE_MAILTO = `mailto:${GATE_QUOTE_EMAIL}?subject=${encodeURIComponent('Gate setup: scope and quote')}&body=${encodeURIComponent(
  'Hi EMILIA,\n\nI would like help setting up Gate for one agent action.\n\nThe job I want the agent to do:\nThe tool or business system it uses:\nThe action I want to control:\nThe person responsible for it:\n\nPlease confirm the supported integration, scope, price and support terms before any work or charge.\n\nI will share private configuration through an agreed channel, not in this email.',
)}`;

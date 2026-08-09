// SPDX-License-Identifier: Apache-2.0
//
// Watch It Refuse — deterministic action classification.
//
// Maps a user's free-text description of a consequential agent action onto one
// of the demo archetypes, each backed by a REAL action type from the CAID
// reference registry (caid/registry/action-types.json). Classification is
// plain keyword heuristics: no model calls, no network, same input -> same
// archetype -> same canonical action object -> same CAID.
//
// The action objects built here are SYNTHETIC DEMO OBJECTS. Field values that
// the registry requires as digests are real sha256 digests computed over
// clearly-labeled demo inputs derived from the user's text, so the CAID
// computation is the real registry-conformant computation over honest demo
// content — never a fabricated identifier.

import crypto from 'node:crypto';

export type WirArchetype =
  | 'payment'
  | 'destructive'
  | 'communication'
  | 'deployment'
  | 'physical'
  | 'generic';

export const WIR_ARCHETYPES: readonly WirArchetype[] = Object.freeze([
  'payment', 'destructive', 'communication', 'deployment', 'physical', 'generic',
]);

/** Registry action type backing each archetype (all from caid/registry/action-types.json). */
export const WIR_ACTION_TYPES: Readonly<Record<WirArchetype, string>> = Object.freeze({
  payment: 'wire.transfer.1',
  destructive: 'dataset.delete.1',
  communication: 'email.send.external.1',
  deployment: 'release.deploy.prod.1',
  // No dedicated physical-actuation type exists in the registry; a governed
  // tool invocation (tool.call.1) is the honest representation for both the
  // physical archetype and the generic consequential fallback.
  physical: 'tool.call.1',
  generic: 'tool.call.1',
});

export const WIR_ARCHETYPE_LABELS: Readonly<Record<WirArchetype, string>> = Object.freeze({
  payment: 'Irreversible money movement',
  destructive: 'Destructive data operation',
  communication: 'Outbound external communication',
  deployment: 'Production deployment',
  physical: 'Physical actuation (governed tool call)',
  generic: 'Consequential action (governed tool call)',
});

export const MAX_ACTION_TEXT_CHARS = 280;

const PAYMENT_RE = /\b(wire|transfer|pay(?:ment|out)?|refund|remit|invoice|disburse|withdraw|deposit)\b|[$€£]\s?\d/i;
const DESTRUCTIVE_RE = /\b(delete|drop|destroy|erase|wipe|truncate|purge|nuke|rm\s+-rf|remove)\b/i;
const DEPLOY_RE = /\b(deploy|rollout|roll\s?out|release|ship(?:ping)?\s+to|push(?:ing)?\s+to\s+prod|go\s+live|cutover)\b/i;
const COMMUNICATION_RE = /\b(email|e-mail|send\b.*\b(message|note|letter)|dm|text\s+(him|her|them|the)|post|tweet|publish|announce|resignation|reply|newsletter|press\s+release)\b/i;
const PHYSICAL_RE = /\b(unlock|lock|open\s+the|close\s+the|start\s+the|stop\s+the|shut\s*(?:down|off)|turn\s+(?:on|off)|actuate|dispense|robot|drone|valve|door|gate\b|thermostat|machine|pump|motor|conveyor|centrifuge)\b/i;

/**
 * Deterministic archetype classification. Precedence is fixed and documented:
 * payment > destructive > deployment > communication > physical > generic.
 * (e.g. "wire $40k" is payment even though "send" also reads as communication.)
 */
export function classifyActionText(text: string): WirArchetype {
  if (PAYMENT_RE.test(text)) return 'payment';
  if (DESTRUCTIVE_RE.test(text)) return 'destructive';
  if (DEPLOY_RE.test(text)) return 'deployment';
  if (COMMUNICATION_RE.test(text)) return 'communication';
  if (PHYSICAL_RE.test(text)) return 'physical';
  return 'generic';
}

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/** "sha256:<hex>" digest over a namespaced demo input string. */
function demoDigest(label: string, text: string): string {
  return `sha256:${sha256Hex(`demo.watch-it-refuse:${label}:${text}`)}`;
}

/**
 * Parse the first monetary amount in the text into a CAID amount-string.
 * "$40k" -> "40000", "$1.5m" -> "1500000", "$250" -> "250". Deterministic;
 * falls back to "10000" when no amount is present.
 */
export function parseAmount(text: string): string {
  const m = /(\d[\d,]*(?:\.\d+)?)\s*(k|m|bn|b|thousand|million|billion)?\b/i.exec(text);
  if (!m) return '10000';
  const base = Number(m[1].replace(/,/g, ''));
  if (!Number.isFinite(base) || base <= 0) return '10000';
  const unit = (m[2] || '').toLowerCase();
  const multiplier = unit === 'k' || unit === 'thousand' ? 1_000
    : unit === 'm' || unit === 'million' ? 1_000_000
      : unit === 'b' || unit === 'bn' || unit === 'billion' ? 1_000_000_000
        : 1;
  const value = base * multiplier;
  if (!Number.isFinite(value) || value <= 0 || value > 1_000_000_000_000) return '10000';
  // CAID amount-string: integer or decimal, no trailing junk.
  return Number.isInteger(value) ? String(value) : value.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
}

function slugToken(text: string, fallback: string): string {
  const token = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return token || fallback;
}

/**
 * Build the registry-conformant canonical action object for the archetype.
 * Every field the registry marks required is present and type-valid; digest
 * fields are real sha256 digests over namespaced demo inputs derived from the
 * user's text, so identical text yields an identical CAID.
 */
export function buildActionObject(archetype: WirArchetype, text: string): Record<string, unknown> {
  const actionType = WIR_ACTION_TYPES[archetype];
  switch (archetype) {
    case 'payment':
      return {
        action_type: actionType,
        amount: parseAmount(text),
        currency: 'USD',
        debtor_account: demoDigest('debtor-account', 'DEMO-OPERATING-ACCOUNT'),
        creditor_account: demoDigest('creditor-account', text),
        creditor_agent_bic: 'EMILDEMOXXX',
        end_to_end_id: `WIR-DEMO-${sha256Hex(text).slice(0, 12).toUpperCase()}`,
      };
    case 'destructive':
      return {
        action_type: actionType,
        dataset_id: slugToken(text, 'demo-dataset'),
        store: 'demo.watch-it-refuse.store',
        snapshot_before_delete: false,
      };
    case 'communication':
      return {
        action_type: actionType,
        recipients_digest: demoDigest('recipients', text),
        recipient_count: 1,
        subject: text.slice(0, 120),
        body_digest: demoDigest('body', text),
      };
    case 'deployment':
      return {
        action_type: actionType,
        service: slugToken(text, 'demo-service'),
        environment: 'prod',
        artifact_digest: demoDigest('artifact', text),
        source_ref: sha256Hex(`demo.watch-it-refuse:source-ref:${text}`).slice(0, 40),
      };
    case 'physical':
      return {
        action_type: actionType,
        target: 'local',
        tool: 'demo.watch-it-refuse.actuator',
        args: { instruction: text },
      };
    case 'generic':
    default:
      return {
        action_type: actionType,
        target: 'local',
        tool: 'demo.watch-it-refuse.consequential-action',
        args: { instruction: text },
      };
  }
}

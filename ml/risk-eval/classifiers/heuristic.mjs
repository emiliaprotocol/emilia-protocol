// SPDX-License-Identifier: Apache-2.0
// Lightweight ADVISORY risk classifier — deterministic, no LLM, no network.
//
// This is the shippable, verifiable half of the ML risk layer (docs/ml/
// risk-classifier.md). It is NOT a fine-tuned model; it is a deterministic
// feature/lexical/near-duplicate detector that catches the perimeter cases the
// exact-match rule engine (lib/guard-policies.js) misses:
//   - renamed money-destination fields   (payout_destination, payee_account…)
//   - novel destructive action types     (delete_production_database…)
//   - prompt-injected / adversarial intent buried in free-form reasoning
//   - free-form money-movement described in prose, with no known type/fields
//
// CONTRACT (the one rule, docs/ml/risk-classifier.md):
//   * ADVISORY. The verified engine still decides. This layer may only RAISE the
//     tier (allow → allow_with_signoff); it NEVER lowers one, never turns a
//     deny/allow_with_signoff into allow, never decides alone.
//   * FALLS BACK to the deterministic rules on uncertainty (no signal fired ⇒
//     return the engine's decision verbatim).
// The output carries `advisory` evidence (fired signals + injection_suspected)
// for the Trust Receipt; the escalation itself is a fail-safe, human-in-loop
// signal, never an autonomous block.

import { evaluateGuardPolicy, GUARD_ACTION_TYPES, GUARD_DECISIONS } from '../../../lib/guard-policies.js';

// ── Lexicons ────────────────────────────────────────────────────────────────
// Kept small, explicit, and auditable on purpose. A fine-tuned model
// generalizes these; this detector encodes the high-signal tokens by hand so a
// reviewer can see exactly why any action escalated (STAGING.md covers the gap).

// Strong money-destination tokens. A CHANGED-FIELD name containing any of these
// is a near-duplicate of a real money-destination field even when its exact
// name is not in the engine's list. "address" is deliberately absent — a bare
// mailing_address must NOT look like money movement (the engine already gates
// benefit address routing separately).
const MONEY_FIELD_TOKENS = Object.freeze([
  'bank', 'account', 'acct', 'routing', 'iban', 'swift', 'bic', 'aba',
  'beneficiary', 'payout', 'payee', 'wallet', 'ach', 'remittance', 'disburse',
]);

// Money-MOVEMENT verbs and asset nouns for free-form intent. A verb + an asset
// noun (or a currency amount) in prose signals money movement the taxonomy has
// no type for.
const MONEY_MOVE_VERBS = Object.freeze([
  'wire', 'transfer', 'send', 'remit', 'disburse', 'withdraw', 'move', 'route',
  'pay', 'payout', 'transmit', 'forward', 'settle',
]);
const MONEY_ASSET_NOUNS = Object.freeze([
  'funds', 'fund', 'money', 'cash', 'treasury', 'wallet', 'balance', 'payment',
  'crypto', 'btc', 'eth', 'usdc', 'usdt', 'stablecoin', 'account', 'wire',
]);

// Destructive/irreversible action verbs. On an action type the engine does NOT
// know (novel), any of these makes it a high-impact escalation candidate.
const DESTRUCTIVE_VERBS = Object.freeze([
  'delete', 'drop', 'destroy', 'wipe', 'purge', 'erase', 'truncate',
  'terminate', 'deprovision', 'decommission', 'revoke', 'disable', 'shutdown',
  'shut', 'remove', 'kill', 'nuke', 'reset', 'rotate', 'exfiltrate', 'exfil',
]);

// Prompt-injection / adversarial-intent phrases. Matched against the RAW joined
// free-form text (order-sensitive), not tokens.
const INJECTION_PHRASES = Object.freeze([
  'ignore previous instructions', 'ignore prior instructions',
  'ignore all previous', 'ignore the above', 'disregard previous',
  'disregard prior', 'disregard all previous', 'disregard the above',
  'override your instructions', 'override previous', 'forget previous',
  'before anyone notices', 'before anyone sees', 'without anyone knowing',
  'do not tell', "don't tell", 'without confirmation', 'without approval',
  'bypass the', 'bypass approval', 'no need to ask', 'do not ask',
  "don't ask", 'act as if', 'you are now',
]);

// The action-type vocabulary the engine actually reasons about. An action type
// OUTSIDE this set is "novel" — the taxonomy has no rule for it.
const KNOWN_ACTION_TYPES = Object.freeze(new Set(Object.values(GUARD_ACTION_TYPES)));

// ── Feature extraction ────────────────────────────────────────────────────

/** Split any string into lowercase alphanumeric tokens. */
function tokenize(s) {
  return String(s || '').toLowerCase().split(/[^a-z0-9$]+/i).filter(Boolean);
}

/**
 * Collect the free-form text an action carries: agent reasoning, description,
 * request text, and any string-valued context fields. This is where injected
 * intent and prose money-movement live — invisible to field/taxonomy rules.
 */
function collectFreeText(input) {
  const parts = [];
  const push = (v) => { if (typeof v === 'string' && v.trim()) parts.push(v); };
  push(input?.description);
  push(input?.request);
  push(input?.reason);
  const ctx = input?.context;
  if (ctx && typeof ctx === 'object') {
    for (const v of Object.values(ctx)) push(v);
  }
  return parts.join('  ').toLowerCase();
}

/**
 * Deterministic advisory feature extractor. Pure — no I/O. Returns the fired
 * signals and a coarse injection flag. Exported for the self-test.
 */
export function extractSignals(input) {
  const signals = [];
  const changedFields = Array.isArray(input?.targetChangedFields) ? input.targetChangedFields : [];
  const fieldTokens = new Set(changedFields.flatMap(tokenize));
  const actionType = String(input?.actionType || '');
  const actionTokens = new Set(tokenize(actionType));
  const freeText = collectFreeText(input);
  const freeTokens = new Set(tokenize(freeText));

  // (1) Renamed / near-duplicate money-destination field.
  const moneyFieldHit = [...fieldTokens].find((t) => MONEY_FIELD_TOKENS.includes(t))
    // "payout_destination"-style: a destination that is about paying out funds.
    || (fieldTokens.has('destination')
        && [...fieldTokens].some((t) => ['pay', 'payout', 'fund', 'funds', 'money', 'wire'].includes(t))
        ? 'destination' : undefined);
  if (moneyFieldHit) {
    signals.push({ code: 'money_field_rename', detail: `changed field resembles a money-destination field (token "${moneyFieldHit}")` });
  }

  // (2) Novel destructive action type (not in the engine's taxonomy).
  if (actionType && !KNOWN_ACTION_TYPES.has(actionType)) {
    const verb = [...actionTokens].find((t) => DESTRUCTIVE_VERBS.includes(t));
    if (verb) {
      signals.push({ code: 'novel_destructive_action', detail: `unknown action type "${actionType}" carries destructive verb "${verb}"` });
    }
  }

  // (3) Prompt-injection / adversarial intent in free-form text.
  const injectionPhrase = INJECTION_PHRASES.find((p) => freeText.includes(p));
  const injectionSuspected = Boolean(injectionPhrase);
  if (injectionPhrase) {
    signals.push({ code: 'prompt_injection', detail: `adversarial phrase "${injectionPhrase}" in free-form text` });
  }

  // (4) Free-form money movement in prose (verb + asset noun, or a currency
  //     amount). Catches exfil/wire intent with no known action type or field.
  const moveVerb = [...freeTokens].find((t) => MONEY_MOVE_VERBS.includes(t));
  const assetNoun = [...freeTokens].find((t) => MONEY_ASSET_NOUNS.includes(t));
  const currencyAmount = /\$\s?\d|\b\d[\d,]*\s?(usd|dollars|eur|gbp|btc|eth)\b/i.test(freeText);
  if (moveVerb && (assetNoun || currencyAmount)) {
    signals.push({ code: 'freeform_money_movement', detail: `prose money movement: verb "${moveVerb}"${assetNoun ? ` + asset "${assetNoun}"` : ' + currency amount'}` });
  }

  return { signals, injectionSuspected };
}

// ── Advisory classifier ─────────────────────────────────────────────────────

/**
 * Classify an action. Runs the verified engine, then applies the deterministic
 * advisory layer as a RAISE-ONLY overlay. Async to match the classify()
 * contract the harness/other classifiers use.
 *
 * @param {object} input - the shape evaluateGuardPolicy accepts.
 * @returns {Promise<{decision:string, signoffRequired:boolean, reasons:string[],
 *   advisory:{signals:string[], injection_suspected:boolean, raised:boolean}}>}
 */
export async function classify(input) {
  const base = evaluateGuardPolicy(input);
  const { signals, injectionSuspected } = extractSignals(input);

  const advisory = {
    signals: signals.map((s) => s.code),
    injection_suspected: injectionSuspected,
    raised: false,
  };

  // RAISE-ONLY: the advisory layer may escalate a bare ALLOW to signoff. It
  // never touches a decision the engine already gated (deny / signoff) — that
  // is the "never lower, fall back to rules on uncertainty" contract. With no
  // signal, `base` is returned verbatim.
  if (base.decision === GUARD_DECISIONS.ALLOW && signals.length > 0) {
    return {
      decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
      signoffRequired: true,
      requiredAssurance: 'A', // advisory escalation is high-risk perimeter by nature
      reasons: [
        'Advisory risk classifier escalated this action to human signoff (perimeter signal the deterministic rules do not cover).',
        ...signals.map((s) => `advisory: ${s.code} — ${s.detail}`),
        ...(base.reasons || []),
      ],
      advisory: { ...advisory, raised: true },
    };
  }

  return { ...base, advisory };
}

/**
 * EP-COVERAGE-RUBRIC-v1 — the citable rubric for the Agent Authorization
 * Coverage register.
 *
 * The seven consequential-action categories are NOT redefined here. They are
 * derived from the shipped enforcement manifest in `packages/scan/risk-packs.js`
 * so that the register can never drift from what the Gate actually enforces.
 *
 * A note on why this file exists separately from the register itself: the rubric
 * is designed to be cited on its own. Someone writing about agent authorization
 * should be able to adopt the seven categories and the verdict vocabulary
 * without adopting, endorsing, or even mentioning any implementation. That is
 * deliberate. The rubric is the shared vocabulary; the register is one
 * application of it.
 */

import { HIGH_RISK_ACTION_PACKS } from '../scan/risk-packs.js';

export const RUBRIC_VERSION = 'EP-COVERAGE-RUBRIC-v1';

/**
 * Verdict vocabulary.
 *
 * Every verdict is a statement about a PUBLISHED DECLARATION on a given date.
 * None of them is a statement about runtime behaviour. This distinction is the
 * whole basis on which the register is defensible: a target whose runtime does
 * require human approval, but whose published declaration does not say so, is
 * accurately described by DECLARATION_SILENT. The sentence stays true either
 * way, and the target can change it by publishing.
 */
export const VERDICTS = Object.freeze({
  NO_CONSEQUENTIAL_ACTION_DECLARED: {
    id: 'NO_CONSEQUENTIAL_ACTION_DECLARED',
    sentence:
      'As published on {date}, this declaration does not advertise a capability in any of the seven consequential-action categories.',
    is_finding: false,
  },
  DECLARED_AUTHORIZATION: {
    id: 'DECLARED_AUTHORIZATION',
    sentence:
      'As published on {date}, this declaration advertises {categories} and states a human-authorization precondition.',
    is_finding: false,
  },
  DECLARATION_SILENT: {
    id: 'DECLARATION_SILENT',
    sentence:
      'As published on {date}, this declaration advertises {categories} and states no human-authorization precondition.',
    is_finding: true,
  },
  INDETERMINATE: {
    id: 'INDETERMINATE',
    sentence:
      'As published on {date}, this declaration could not be classified against the rubric and is recorded as indeterminate.',
    is_finding: false,
  },
});

/**
 * Phrases that, present in a declaration, constitute a declared human
 * authorization precondition. Deliberately generous: a target gets the benefit
 * of any reasonable reading, because a false DECLARATION_SILENT costs more than
 * a missed finding.
 */
export const AUTHORIZATION_PHRASES = Object.freeze([
  'human approval',
  'human-approval',
  'human in the loop',
  'human-in-the-loop',
  'requires approval',
  'approval required',
  'requires confirmation',
  'confirmation required',
  'requires authorization',
  'authorization required',
  'manual approval',
  'user must approve',
  'user confirmation',
  'explicit consent',
  'dual control',
  'two-person',
  'four-eyes',
  'authorization receipt',
  'signoff',
  'sign-off',
]);

/**
 * Registry-declaration keyword sets per category.
 *
 * IMPORTANT SCOPE LIMIT, and it must survive into every published edition: the
 * shipped risk packs match on exact tool names at a tool-call chokepoint. A
 * public registry record carries only a name, a title, and a prose
 * description. So these keyword sets classify ADVERTISED CAPABILITY, which is a
 * strictly weaker signal than a tool-level scan. The register says so on every
 * page. It is not a vulnerability finding and it is not a runtime claim.
 */
const CATEGORY_KEYWORDS = Object.freeze({
  // Tightened to capability phrasings. Bare 'payment', 'stripe', 'transaction',
  // 'checkout' and 'billing' matched a merchant DIRECTORY and an API-test tool
  // that merely named Stripe as a profile: three false positives out of four on
  // the first live sample. A tool that talks about payments is not a tool that
  // moves money.
  'money_movement.release': [
    'send payment', 'make payment', 'process payment', 'release payment',
    'initiate payment', 'payment infrastructure', 'send a payment', 'pay an invoice',
    'wire transfer', 'transfer funds', 'send money', 'send funds', 'move funds',
    'payout', 'disburse', 'issue refund', 'charge a card', 'charge cards',
    'execute trade', 'place an order',
  ],
  'money_movement.bank_details_change': [
    'bank account', 'bank details', 'beneficiary', 'payee', 'payroll',
    'account number', 'routing number', 'update payment method',
  ],
  // Bare 'production' was removed: it is an environment noun, not a capability.
  // "Read-only access to production logs" is not a deploy capability, and on the
  // first live sample that single word produced two false positives out of six.
  'production.deploy': [
    'deploy', 'deployment', 'redeploy', 'release to prod', 'rollout', 'roll out',
    'provision', 'terraform apply', 'helm install', 'kubectl apply',
    'infrastructure as code', 'ship to production', 'push to production',
  ],
  // Deliberately mutation-shaped. An earlier draft matched bare 'api key',
  // 'credential', 'admin' and 'privilege'; on the first live 200-row sample that
  // produced a 15.6% category driven almost entirely by one vendor's boilerplate
  // phrase "no API keys", which is a NEGATION of the capability. Mentioning a
  // credential is not declaring the power to change who holds one.
  'permissions.admin_change': [
    'grant access', 'revoke access', 'grant permission', 'change permission',
    'manage permission', 'modify permission', 'assign role', 'role assignment',
    'iam policy', 'access control list', 'add user', 'remove user',
    'escalate privilege', 'rotate credential', 'rotate api key', 'issue api key',
  ],
  // Bare 'export' matched a screenplay tool's file export. Bulk/data qualifiers
  // are what make it a consequential capability.
  'data.bulk_export': [
    'data export', 'bulk export', 'export all', 'export data', 'csv export',
    'bulk download', 'download all', 'database dump', 'dump the database',
    'extract all', 'exfiltrat', 'full backup',
  ],
  'records.delete': [
    'delete', 'remove records', 'purge', 'drop table', 'truncate', 'erase',
    'destroy', 'hard delete', 'wipe',
  ],
  'regulated.decision_override': [
    'prior authorization', 'claim denial', 'medical necessity', 'eligibility determination',
    'underwriting decision', 'benefit determination', 'adjudicat', 'override decision',
  ],
});

/**
 * Phrases that NEGATE a capability claim. A declaration saying "no API keys" or
 * "without deploying" is advertising the absence of the thing, and scoring it as
 * a finding is the single fastest way to lose the register's credibility. When
 * one of these immediately precedes a matched keyword, the match is discarded.
 *
 * Learned the hard way: the first live sample scored eight servers as
 * permission-change capabilities on the strength of the phrase "no API keys".
 */
export const NEGATION_PREFIXES = Object.freeze([
  'no ', 'not ', 'never ', 'without ', 'no more ', 'zero ', 'avoid ', 'avoids ',
  'eliminates ', 'eliminate ', 'removes the need for ', 'instead of ', 'rather than ',
  'free of ', 'free from ', "doesn't need ", 'does not need ', "doesn't require ",
  'does not require ', 'no need for ',
]);

/**
 * A declaration that describes itself as read-only cannot be advertising a
 * mutation capability. Checked against the WHOLE declaration rather than as a
 * local negation prefix, because the qualifier usually sits far from the matched
 * word: "Read-only access to Auralogs production logs" was scored as a deploy
 * capability on the first live sample.
 *
 * regulated.decision_override is exempt: a determination can be rendered by a
 * system that describes its data access as read-only.
 */
export const READ_ONLY_MARKERS = Object.freeze([
  'read-only', 'read only', 'readonly', 'query-only', 'query only',
  'no write', 'without writing', 'observability only', 'analytics only',
]);

export const READ_ONLY_EXEMPT_CATEGORIES = Object.freeze(['regulated.decision_override']);

/** The seven categories, derived from the shipped enforcement manifest. */
export const CATEGORIES = Object.freeze(
  HIGH_RISK_ACTION_PACKS.map((pack) =>
    Object.freeze({
      id: pack.id,
      label: pack.label,
      action_type: pack.action_type,
      risk: pack.risk,
      assurance_class: pack.assurance_class,
      why: pack.why,
      keywords: Object.freeze(CATEGORY_KEYWORDS[pack.id] ?? []),
    }),
  ),
);

export function categoryById(id) {
  return CATEGORIES.find((c) => c.id === id) ?? null;
}

/**
 * Categories with no keyword set would silently never match, which would
 * understate coverage without anyone noticing. Surface that as a defect rather
 * than letting it degrade quietly.
 */
export function rubricIntegrityProblems() {
  return CATEGORIES.filter((c) => c.keywords.length === 0).map(
    (c) => `category ${c.id} has no registry-declaration keyword set and can never match`,
  );
}

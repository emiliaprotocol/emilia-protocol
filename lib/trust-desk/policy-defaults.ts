/**
 * AI Trust Desk — policy template variable defaults + intake binding.
 *
 * @license Apache-2.0
 *
 * The 5 policy templates contain ~175 `{{VAR}}` placeholders. This module
 * provides a sensible professional default for the common ones and derives the
 * customer-specific ones from intake. Any variable NOT resolved here is handled
 * by substitute()'s fallback (policy-mint.js) so a published policy never shows
 * a raw `{{VAR}}` and never crashes on a newly-added template variable.
 *
 * Precedence: intake-derived  >  DEFAULTS  >  generic fallback.
 */

/** Static, professional defaults. Conservative and non-claiming. */
export const DEFAULTS = Object.freeze({
  // Cadences / SLAs
  CHAOS_CADENCE: 'quarterly',
  DRILL_CADENCE: 'semi-annual',
  MANUAL_CADENCE: 'quarterly',
  TABLETOP_CADENCE: 'semi-annual',
  EXTERNAL_RED_TEAM_CADENCE: 'annual',
  KILL_SWITCH_TEST_CADENCE: 'quarterly',
  UPDATE_FREQUENCY: 'quarterly',
  CONFIRMATION_SLA: '4 business hours',
  DELETION_SLA: '30 days',
  KILL_SWITCH_SLA: '5 minutes',
  POSTMORTEM_SLA: '5 business days',
  PUBLIC_DISCLOSURE_SLA: '72 hours',
  INCIDENT_NOTIFICATION_SLA: '72 hours',
  SEV1_NOTIFICATION_SLA: '24 hours',
  SEV2_NOTIFICATION_SLA: '48 hours',
  SEV2_SLA: '48 hours',
  TIER_01_INCIDENT_SLA: '1 hour',
  TIER_2_INCIDENT_SLA: '4 hours',
  TIER_3_INCIDENT_SLA: '1 business day',
  REGIONAL_CONFIG_SLA: '30 days',
  REAUTH_WINDOW: '15 minutes',
  DELEGATION_TTL: '60 minutes',
  CHANGE_NOTIFICATION_WINDOW: '30 days',
  SEV3_THRESHOLD: 'no customer data or production impact',

  // Rate limits / numeric
  TIER_0_RATE_LIMIT: '60 requests/minute',
  TIER_1_RATE_LIMIT: '300 requests/minute',
  TIER_2_RATE_LIMIT: '1,000 requests/minute',
  TIER_3_RATE_LIMIT: '5,000 requests/minute',
  BATCH_APPROVAL_LIMIT: '50 actions',
  RETRY_LIMIT: '3 attempts',
  N_TEST_CASES: '120',
  N: '120',
  RATE: 'per-tenant configurable',

  // Retentions
  AUDIT_LOG_RETENTION: '12 months',
  AGENT_AUDIT_RETENTION: '12 months',
  LOG_RETENTION: '12 months',
  EVAL_RETENTION: '90 days',
  EMBEDDING_RETENTION: 'duration of contract',
  EVIDENCE_RETENTION: '7 years',
  ANALYTICS_RETENTION: '14 months',
  OBSERVABILITY_RETENTION: '30 days',
  DEFAULT_RETENTION_STATE: 'retained for the contract term, then deleted',

  // Tooling
  SAST_TOOL: 'Semgrep',
  PAGER_TOOL: 'PagerDuty',
  TRACKER_TOOL: 'Linear',
  LOGGING_PROVIDER: 'Datadog',
  ANALYTICS_PROVIDER: 'self-hosted analytics',
  OBSERVABILITY_PROVIDER: 'Datadog',
  EVAL_PROVIDER: 'internal evaluation harness',
  VECTOR_DB: 'pgvector (self-hosted)',
  EMBEDDING_MODEL: 'text-embedding-3-large',
  EMBEDDING_PROVIDER: 'OpenAI',

  // Channels
  INCIDENT_CHANNEL: '#security-incidents',
  NOTIFICATION_CHANNEL: 'email + in-app',
  CUSTOMER_COMMS: 'designated security contact',

  // Consent / scope
  CONSENT_MODEL: 'opt-in for any training use; inference-only by default',
  DATA_SCOPE: 'customer-submitted content processed at inference only',
  SCOPE: 'the production AI product surface',
  TRAINING: 'no customer data used for model training without explicit opt-in',
  ANTHROPIC_DATA_SCOPE: 'inference only; zero-retention API tier',
  OPENAI_DATA_SCOPE: 'inference only; zero-retention enterprise tier',
  EMBEDDING_INPUT_SCOPE: 'customer content for retrieval only',

  // Regions
  PRIMARY_REGION: 'us-east-1',
  DEFAULT_REGION: 'us-east-1',
  MODEL_REGION: 'United States',
  REGION: 'United States',
  LOG_REGION: 'United States',
  EMBEDDING_REGION: 'United States',
  ANALYTICS_REGION: 'United States',
  VECTOR_DB_REGION: 'United States',
  OTHER_REGION: 'none',
  OTHER_REGION_NOTES: 'no data is processed outside the United States',
  US_RESIDENCY_NOTES: 'all customer data is processed and stored in US regions',

  // DPAs (kept generic; replaced when intake supplies provider facts)
  DPA: 'executed Data Processing Agreement',
  LOG_DPA: 'executed DPA with the logging provider',
  ANALYTICS_DPA: 'executed DPA with the analytics provider',
  EMBEDDING_DPA: 'executed DPA with the embedding provider',
  EVAL_DPA: 'executed DPA with the evaluation provider',
  OBSERVABILITY_DPA: 'executed DPA with the observability provider',
  VECTOR_DB_DPA: 'self-hosted; no third-party DPA required',
  ANTHROPIC_DPA_DATE: 'on file',
  OPENAI_DPA_DATE: 'on file',

  // Titles / roles
  SECURITY_LEAD_TITLE: 'Head of Security',
  DATA_OFFICER_TITLE: 'Data Protection Officer',
  INCIDENT_COMMANDER_TITLE: 'Incident Commander',
  LEGAL_LEAD_TITLE: 'General Counsel',
  REVIEWER_TITLE: 'Security Reviewer',
  AUTHOR_TITLE: 'Security Engineer',
  EXECUTIVE_TITLE: 'Chief Technology Officer',
  ROLE: 'authorized operator',

  // Misc disclosure fields
  DEFAULT: 'Available to the requesting party under NDA.',
  OTHER: 'Not applicable.',
  OTHER_TERMS: 'None.',
  OTHER_PROVIDER: 'None.',
  OTHER_MODEL_PROVIDER: 'None.',
  REDACTION_STATUS: 'sensitive operational details redacted; available under NDA',
  EITHER_FINE_TUNE_DISCLOSURE_A_OR_B:
    'We do not fine-tune foundation models on customer data. Any future fine-tuning would be opt-in and separately disclosed.',
  EVIDENCE_CUSTODY_PROCEDURE:
    'Evidence is collected to a write-once store with documented chain of custody.',
  CONTAINMENT_ACTIONS: 'isolate affected components, revoke implicated credentials, enable enhanced logging',
  INVESTIGATION_ACTIONS: 'preserve logs, reconstruct the action timeline, identify scope of impact',
  REMEDIATION_ACTIONS: 'patch root cause, rotate secrets, validate fix under test, monitor for recurrence',
});

/**
 * Build the full variable map for a given engagement.
 * @param {object} intake engagement intake fields
 * @param {object} opts { slug, effectiveDate }
 * @returns {Record<string,string>}
 */
export function buildPolicyVars(intake = {}, opts = {}) {
  const today = opts.effectiveDate || new Date().toISOString().slice(0, 10);
  const nextYear = addYears(today, 1);
  const company = intake.company || 'the Vendor';
  const productName = deriveProductName(intake);
  const contactName = intake.contact_name || 'Security Team';
  const contactEmail = intake.contact_email || `security@${domainFrom(intake)}`;
  const trustUrl = opts.slug
    ? `https://www.emiliaprotocol.ai/trust-desk/c/${opts.slug}`
    : 'https://www.emiliaprotocol.ai/trust-desk';
  const region = regionFromCloud(intake.cloud_provider);
  const modelProviders = intake.model_providers || 'OpenAI, Anthropic';

  return {
    ...DEFAULTS,

    // Identity
    COMPANY: company,
    PRODUCT_NAME: productName,
    ONE_LINE: intake.product_description || `${productName} by ${company}`,
    BRIEF_DESCRIPTION: intake.product_description || `${productName} by ${company}`,
    SHORT_TITLE: productName,

    // Dates
    EFFECTIVE_DATE: today,
    DATE: today,
    NEXT_REVIEW_DATE: nextYear,
    LAST_EXERCISE_DATE: today,
    TIMESTAMP: new Date().toISOString(),
    TIME: '00:00 UTC',
    T: 'T',
    NEXT_UPDATE_TIME: 'within 24 hours of a material change',

    // People — all routed to the single intake contact unless overridden
    SECURITY_LEAD_NAME: contactName,
    SECURITY_LEAD_EMAIL: contactEmail,
    DATA_OFFICER_NAME: contactName,
    DATA_OFFICER_EMAIL: contactEmail,
    INCIDENT_COMMANDER_NAME: contactName,
    INCIDENT_COMMANDER_EMAIL: contactEmail,
    IC_PRIMARY: contactName,
    IC_PRIMARY_EMAIL: contactEmail,
    IC_BACKUP: 'Security on-call (secondary)',
    LEGAL_LEAD_NAME: 'General Counsel',
    LEGAL_LEAD_EMAIL: `legal@${domainFrom(intake)}`,
    LEGAL_BACKUP: 'Outside counsel',
    CTO_NAME: contactName,
    CISO_NAME: contactName,
    CUSTOMER_CONTACT_NAME: contactName,
    AUTHOR_NAME: contactName,
    EXECUTIVE_NAME: contactName,
    REVIEWER_NAME: 'AI Trust Desk',
    TECH_LEAD_AI: contactName,
    TECH_LEAD_AI_EMAIL: contactEmail,
    TECH_LEAD_BACKUP: 'Engineering on-call',
    SECURITY_BACKUP: 'Security on-call (secondary)',
    COMMS_BACKUP: 'Communications lead',
    ONCALL_CONTACT: `security@${domainFrom(intake)}`,
    CUSTOMER_COMMS_EMAIL: contactEmail,
    PR_CONTACT: 'Communications',
    PR_EMAIL: `press@${domainFrom(intake)}`,

    // URLs
    TRUST_PAGE_URL: trustUrl,
    DISCLOSURE_URL: `${trustUrl}#disclosures`,
    GENERAL_IR_URL: `${trustUrl}#incident-response`,
    DOCS_REDACTION_URL: `${trustUrl}#redactions`,
    AUDIT_EXPORT_INTERFACE: 'signed audit export endpoint',

    // Regions (intake-derived)
    PRIMARY_REGION: region.primary,
    DEFAULT_REGION: region.primary,
    MODEL_REGION: region.country,
    REGION: region.country,
    LOG_REGION: region.country,

    // Model providers (intake-derived)
    MODEL_PROVIDERS: modelProviders,
    MODEL_PROVIDER_1: splitNth(modelProviders, 0, 'OpenAI'),
    MODEL_PROVIDER_2: splitNth(modelProviders, 1, 'Anthropic'),
    MODEL_PROVIDER_3: splitNth(modelProviders, 2, 'none'),

    // Data categories / purposes / retentions (generic, disclosure-safe)
    DATA_CATEGORY_1: 'account and identity data',
    DATA_CATEGORY_2: 'customer-submitted content',
    DATA_CATEGORY_3: 'usage and telemetry metadata',
    SPECIFIC_DATA_CATEGORIES: 'account data, customer-submitted content, usage metadata',
    PURPOSE_1: 'delivering the product feature requested by the user',
    PURPOSE_2: 'operational monitoring and abuse prevention',
    PURPOSE_3: 'aggregate, de-identified product analytics',
    RETENTION_1: 'duration of contract',
    RETENTION_2: '12 months',
    RETENTION_3: '14 months',
    RETENTION: 'duration of contract, then deleted within 30 days',

    // Tools / features
    TOOL_1_NAME: 'read_records',
    TOOL_2_NAME: 'create_record',
    TOOL_3_NAME: 'initiate_action',
    AFFECTED_FEATURE: 'the affected product feature',
    EFFECTS: 'the customer-visible effects of the incident',
    CONFIRMED_IMPACT: 'the confirmed scope of impact',
    SCOPE: 'the production AI product surface',
    CONTRACT: 'the Master Services Agreement',

    // Incident placeholders (used in the runbook's worked example)
    INCIDENT_ID: 'INC-EXAMPLE',
    APPROVAL: 'explicit human approval',
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function deriveProductName(intake) {
  if (intake.product_name) return intake.product_name;
  const desc = intake.product_description || '';
  // First capitalized noun-ish phrase, else company + " AI".
  const m = desc.match(/^([A-Z][\w-]+(?:\s+[A-Z][\w-]+){0,2})/);
  if (m) return m[1];
  return intake.company ? `${intake.company} AI` : 'the Product';
}

function domainFrom(intake) {
  const email = intake.contact_email || '';
  const at = email.split('@')[1];
  if (at) return at;
  const site = (intake.website || '').replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  return site || 'example.com';
}

function regionFromCloud(cloud) {
  const c = String(cloud || '').toLowerCase();
  if (/eu|frankfurt|ireland|europe/.test(c)) return { primary: 'eu-central-1', country: 'European Union' };
  if (/ap-|asia|tokyo|singapore|sydney/.test(c)) return { primary: 'ap-southeast-1', country: 'Asia-Pacific' };
  const m = c.match(/([a-z]{2}-[a-z]+-\d)/);
  return { primary: m ? m[1] : 'us-east-1', country: 'United States' };
}

function splitNth(csv, n, fallback) {
  const parts = String(csv || '')
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter(Boolean);
  return parts[n] || fallback;
}

function addYears(isoDate, years) {
  const d = new Date(isoDate + 'T00:00:00Z');
  d.setUTCFullYear(d.getUTCFullYear() + years);
  return d.toISOString().slice(0, 10);
}

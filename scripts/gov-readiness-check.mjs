#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Static government-readiness guardrail.
//
// This is not a FedRAMP authorization. It is a CI-enforceable posture check for
// the code and migration bundle: tenant-bound writes, strict verifier defaults,
// key-custody abstraction, append-only security events, readiness docs, and
// incident drill hooks.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getActiveCryptoProfile, assertProfileSatisfied, CRYPTO_PROFILE_IDS } from '../lib/crypto/profile.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

function exists(rel) {
  return fs.existsSync(path.join(ROOT, rel));
}

function collect(dir, pattern, acc = []) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) return acc;
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === '.git') continue;
    const rel = path.join(dir, entry.name);
    if (entry.isDirectory()) collect(rel, pattern, acc);
    else if (pattern.test(entry.name)) acc.push(rel);
  }
  return acc;
}

const checks = [];

function check(name, fn) {
  try {
    const detail = fn();
    checks.push({ name, ok: true, detail });
  } catch (e) {
    checks.push({ name, ok: false, detail: e.message });
  }
}

function requireContains(rel, needle, message = `${rel} missing ${needle}`) {
  const src = read(rel);
  if (!src.includes(needle)) throw new Error(message);
}

check('tenant-bound v1 writes require authenticated org binding', () => {
  const files = [
    'app/api/v1/trust-receipts/route.js',
    'app/api/v1/approvers/webauthn/register-options/route.js',
    'app/api/v1/approvers/webauthn/register-verify/route.js',
    'lib/guard-adapter.js',
  ];
  const missing = files.filter((f) => !read(f).includes('requireBound: true'));
  if (missing.length) throw new Error(`missing requireBound:true in ${missing.join(', ')}`);
  requireContains('supabase/migrations/101_entity_organization_binding.sql', 'organization_id');
  return `${files.length} authenticated surfaces checked`;
});

check('approver enrollment requires an explicit capability', () => {
  requireContains('lib/approver-enrollment-auth.js', "APPROVER_ENROLL_PERMISSION = 'approver.enroll'");
  for (const rel of [
    'app/api/v1/approvers/webauthn/register-options/route.js',
    'app/api/v1/approvers/webauthn/register-verify/route.js',
  ]) requireContains(rel, 'hasApproverEnrollmentPermission');
  return 'both WebAuthn enrollment phases require approver.enroll or admin';
});

check('async Gate providers cannot bypass a guarded action', () => {
  const gate = read('packages/gate/index.js');
  for (const needle of [
    '? await opts.selector(...args)',
    '? await opts.receipt(...args)',
    '? await opts.observedAction(...args)',
  ]) {
    if (!gate.includes(needle)) throw new Error(`packages/gate/index.js missing ${needle}`);
  }
  return 'guard resolves async selector, receipt, and observed-action providers before check';
});

check('strict production verifier refuses inline issuer keys', () => {
  // Inline-key acceptance is demo-only. Non-demo guarded endpoints require
  // pinned issuer keys even outside gov-strict mode.
  requireContains('lib/gov-receipt-verifier.js', 'allowInlineKey: false');
  requireContains('lib/gov-receipt-verifier.js', 'trustedIssuerKeys.length === 0');
  requireContains('app/api/v1/guarded/route.js', 'verifyReceiptForProduction');
  requireContains('app/api/v1/guarded/route.js', 'assertGovVerifierReady');
  return 'production verifier pins trusted issuer keys on non-demo guarded endpoints';
});

check('inline/self-signed receipt acceptance is demo-only', () => {
  const runtimeFiles = collect('app/api', /\.js$/);
  const offenders = [];
  for (const rel of runtimeFiles) {
    const src = read(rel);
    if (!src.includes('allowInlineKey: true')) continue;
    if (!rel.startsWith('app/api/demo/')) offenders.push(rel);
  }
  if (offenders.length) throw new Error(`allowInlineKey:true outside demo routes: ${offenders.join(', ')}`);
  return 'no non-demo API route accepts inline keys';
});

check('security event ledger is append-only and hash-chained', () => {
  requireContains('supabase/migrations/110_security_events_hash_chain.sql', 'CREATE TABLE IF NOT EXISTS security_events');
  requireContains('supabase/migrations/110_security_events_hash_chain.sql', 'prevent_security_event_mutation');
  requireContains('supabase/migrations/110_security_events_hash_chain.sql', 'event_hash TEXT NOT NULL UNIQUE');
  requireContains('supabase/migrations/110_security_events_hash_chain.sql', 'idx_security_events_single_child_per_parent');
  requireContains('lib/security-events.js', "error.code !== '23505'");
  requireContains('lib/security-events.js', 'verifySecurityEventChain');
  requireContains('lib/write-guard.js', "'security_events'");
  return 'security_events migration + runtime verifier present';
});

check('gov-strict mode requires durable rate limiting for write surfaces', () => {
  requireContains('lib/env.js', 'getRateLimitConfig');
  requireContains('lib/rate-limit.js', 'durable_rate_limit_required');
  requireContains('lib/rate-limit.js', 'FAIL_CLOSED_CATEGORIES');
  requireContains('.env.example', 'EP_REQUIRE_DURABLE_RATE_LIMIT');
  return 'write/admin categories fail closed without durable rate limiter when required';
});

check('SAML ACS fails closed when replay protection is unavailable', () => {
  requireContains('app/api/sso/saml/acs/route.js', 'saml_replay_cache_unavailable');
  requireContains('app/api/sso/saml/acs/route.js', 'failing closed');
  requireContains('supabase/migrations/103_saml_consumed_assertions.sql', 'saml_consumed_assertions');
  return 'SAML replay cache is a gate, not best-effort logging';
});

check('key custody abstraction rejects local keys in gov/prod mode', () => {
  requireContains('lib/key-custody.js', 'assertProductionKeyCustody');
  requireContains('lib/key-custody.js', "mode === 'local-dev'");
  requireContains('lib/key-custody.js', 'createExternalCustodySigner');
  requireContains('lib/env.js', 'getKeyCustodyConfig');
  requireContains('.env.example', 'EP_SECRET_KEY');
  return 'KMS/HSM custody interface present';
});

check('crypto profile is declared and fail-closed', () => {
  // The profile registry exists and refuses unknown/out-of-boundary algorithms.
  requireContains('lib/crypto/profile.js', 'assertAlgAllowed');
  requireContains('lib/crypto/profile.js', 'unknown_crypto_profile');
  // If THIS environment declares a profile, it must be satisfiable. A fips
  // profile that isn't backed by a validated-module custody signer (kms/hsm) is
  // not truly at its boundary → not ready. getActiveCryptoProfile throws
  // (fail closed) on an unrecognized EP_CRYPTO_PROFILE.
  if (process.env.EP_CRYPTO_PROFILE) {
    const profile = getActiveCryptoProfile();
    const sat = assertProfileSatisfied({ custodyMode: process.env.EP_KEY_CUSTODY_MODE });
    if (!sat.ok) throw new Error(sat.reasons.join('; '));
    return `crypto profile "${profile.id}" declared and satisfied`;
  }
  return `crypto profile module present (default; profiles: ${CRYPTO_PROFILE_IDS.join('/')})`;
});

check('incident drill is runnable', () => {
  requireContains('scripts/drills/key-compromise-drill.mjs', 'runKeyCompromiseDrill');
  const pkg = JSON.parse(read('package.json'));
  if (!pkg.scripts?.['gov:drill:key-compromise']) throw new Error('package.json missing gov:drill:key-compromise');
  return 'key compromise drill script wired';
});

check('government readiness docs packet exists', () => {
  const required = [
    'docs/gov-readiness/README.md',
    'docs/gov-readiness/GOV_DEPLOYMENT_MODES.md',
    'docs/gov-readiness/BOUNDARY.md',
    'docs/gov-readiness/KEY_CUSTODY.md',
    'docs/gov-readiness/AUDIT_LOG_RETENTION.md',
    'docs/gov-readiness/INCIDENT_RESPONSE.md',
    'docs/gov-readiness/RLS_AND_TENANCY.md',
    'docs/gov-readiness/PENTEST_SCOPE.md',
    'docs/gov-readiness/SECURITY_DECISION_RECORD.md',
  ];
  const missing = required.filter((f) => !exists(f));
  if (missing.length) throw new Error(`missing docs: ${missing.join(', ')}`);
  return `${required.length} docs present`;
});

check('gov readiness npm script is wired', () => {
  const pkg = JSON.parse(read('package.json'));
  if (pkg.scripts?.['gov:check'] !== 'node scripts/gov-readiness-check.mjs') {
    throw new Error('package.json missing gov:check script');
  }
  return 'npm run gov:check available';
});

const failed = checks.filter((c) => !c.ok);
console.log('Government Readiness Static Check');
console.log('='.repeat(42));
for (const c of checks) {
  console.log(`${c.ok ? '[ok]' : '[fail]'} ${c.name}`);
  if (!c.ok) console.log(`  ${c.detail}`);
}
console.log('='.repeat(42));
if (failed.length) {
  console.error(`FAILED: ${failed.length} readiness check(s) failed.`);
  process.exit(1);
}
console.log(`PASSED: ${checks.length} readiness checks.`);

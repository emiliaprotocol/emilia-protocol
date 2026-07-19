// SPDX-License-Identifier: Apache-2.0
import { Buffer } from 'node:buffer';
import { importPKCS8 } from 'jose';
import { createClient } from '@supabase/supabase-js';
import { getMobileConfig } from '../lib/mobile/config.js';

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const pass = (message) => console.log(`PASS  ${message}`);
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
  pass(message);
};

const config = getMobileConfig({ env: process.env, production: true });
assert(config.iosBundleId === 'ai.emiliaprotocol.approver', 'permanent iOS identity is pinned');
assert(config.androidPackageName === 'ai.emiliaprotocol.approver', 'permanent Android identity is pinned');
assert(config.appleTeamId === '5M2Z48UQQY', 'Apple team identity is pinned');
assert(config.rpId === 'www.emiliaprotocol.ai', 'WebAuthn relying-party identity is pinned');
assert(config.profileId === 'emilia.high-assurance.mobile.v1', 'high-assurance mobile profile is pinned');
assert(config.appleEnvironment === 'production', 'App Attest production environment is selected');
assert(config.appleAllowedValidationCategories.length > 0, 'App Attest validation categories are pinned');
assert(config.appleAllowedBundleVersions.length > 0, 'App Attest bundle versions are pinned');
assert(config.androidConfigured, 'Android package key and Play signing certificate are pinned');
assert(config.androidSigningCertificateSha256Hex.length === 64, 'canonical Android signing certificate is normalized');
assert(config.androidKeyHashes.every((value) => /^[A-Za-z0-9_-]{43}$/.test(value)), 'Android package key pins are valid SHA-256 values');
assert(config.androidCertificateDigests.every((value) => /^[A-Za-z0-9_-]{43}={0,2}$/.test(value)), 'Play certificate pins are valid SHA-256 values');
assert(config.androidKeyHashes.length === 1
  && config.androidCertificateDigests.length === 1
  && config.androidAssetLinksFingerprints.length === 1,
'one Android signing certificate feeds WebAuthn, Play Integrity, and Digital Asset Links');
assert(config.androidAllowedVersionCodes.length > 0, 'Play version codes are pinned');
assert(config.androidMinimumSdkVersion >= 33, 'Play strong-integrity SDK floor is enforced');
assert(config.androidRequirePlayProtect === true, 'Play Protect verdict is required');

const encodedAccount = required('GOOGLE_PLAY_SERVICE_ACCOUNT_JSON');
const accountText = encodedAccount.startsWith('{')
  ? encodedAccount
  : Buffer.from(encodedAccount, 'base64').toString('utf8');
const account = JSON.parse(accountText);
assert(typeof account.client_email === 'string' && account.client_email.includes('@'),
  'Google Play Integrity service-account identity is parseable');
assert(typeof account.private_key === 'string' && account.private_key.includes('PRIVATE KEY'),
  'Google Play Integrity private key is present');
await importPKCS8(account.private_key, 'RS256');
pass('Google Play Integrity private key is cryptographically parseable');

const assetLinkPins = config.androidAssetLinksFingerprints;

const supabase = createClient(
  required('NEXT_PUBLIC_SUPABASE_URL'),
  required('SUPABASE_SERVICE_ROLE_KEY'),
  { auth: { persistSession: false, autoRefreshToken: false } },
);
const nonexistentSessionId = '00000000-0000-0000-0000-000000000000';
const readinessNow = new Date().toISOString();

for (const [table, columns] of [
  ['mobile_kv_state', 'state_key,state_value'],
  ['mobile_pairings', 'code_hash,allowed_apps'],
  ['mobile_sessions', 'session_id,device_key_id,revoked_at'],
  ['mobile_enrollments', 'device_key_id,attestation_key_id,platform_public_key,sign_count'],
  ['mobile_counters', 'counter_key,counter_value'],
  ['mobile_audit_records', 'record_id,record_hash'],
  ['mobile_evidence_records', 'record_id,record'],
  ['mobile_actions', 'action_reference,presentation,decision_evidence'],
  ['mobile_action_challenges', 'challenge_id,session_id'],
]) {
  const { error } = await supabase.from(table).select(columns).limit(1);
  if (error) throw new Error(`${table} is unavailable: ${error.code || error.message}`);
  pass(`${table} is available to the service role`);
}

const directWrite = await supabase
  .from('mobile_sessions')
  .update({ last_used_at: readinessNow })
  .eq('session_id', nonexistentSessionId);
assert(
  directWrite.error?.code === '42501' || /permission denied/i.test(directWrite.error?.message || ''),
  'service role cannot mutate mobile trust tables directly',
);

const invalidStateInsert = await supabase.rpc('mobile_state_add_if_absent', {
  p_state_key: null,
  p_state_value: null,
});
assert(!invalidStateInsert.error && invalidStateInsert.data === false,
  'mobile state insertion RPC exists and refuses malformed input');

const invalidStateTransition = await supabase.rpc('mobile_state_compare_and_set', {
  p_state_key: null,
  p_expected: null,
  p_replacement: null,
  p_now: readinessNow,
});
assert(!invalidStateTransition.error && invalidStateTransition.data === false,
  'mobile state transition RPC exists and refuses malformed input');

const invalidPairing = await supabase.rpc('create_mobile_pairing', {
  p_code_hash: null,
  p_entity_ref: null,
  p_approver_id: null,
  p_profile_id: null,
  p_allowed_apps: {},
  p_expires_at: readinessNow,
  p_session_expires_at: readinessNow,
  p_now: readinessNow,
});
assert(!invalidPairing.error && invalidPairing.data === false,
  'mobile pairing RPC exists and refuses malformed input');

const invalidTouch = await supabase.rpc('touch_mobile_session', {
  p_session_id: nonexistentSessionId,
  p_token_hash: '0'.repeat(64),
  p_now: readinessNow,
});
assert(!invalidTouch.error && invalidTouch.data === false,
  'mobile session touch RPC exists and refuses an unknown session');

const invalidDemoAction = await supabase.rpc('create_mobile_demo_action', {
  p_action_reference: null,
  p_entity_ref: null,
  p_approver_id: null,
  p_initiator_id: null,
  p_action: {},
  p_presentation: {},
  p_policy: {},
  p_policy_id: null,
  p_expires_at: readinessNow,
  p_now: readinessNow,
});
assert(!invalidDemoAction.error && invalidDemoAction.data === false,
  'mobile demo action RPC exists and refuses malformed input');

const validPresentation = await supabase.rpc('mobile_presentation_is_valid', {
  p_value: {
    '@version': 'EP-MOBILE-PRESENTATION-v1',
    title: 'Readiness check',
    summary: 'Validate the deployed closed presentation schema.',
    risk: 'none',
    consequence: '',
    material_fields: { check: 'non-mutating' },
  },
});
assert(!validPresentation.error && validPresentation.data === true,
  'versioned closed mobile presentation schema is deployed');
const hiddenPresentation = await supabase.rpc('mobile_presentation_is_valid', {
  p_value: {
    '@version': 'EP-MOBILE-PRESENTATION-v1',
    title: 'Readiness check',
    summary: 'Validate the deployed closed presentation schema.',
    risk: 'none',
    consequence: '',
    material_fields: { hidden: { nested: true } },
  },
});
assert(!hiddenPresentation.error && hiddenPresentation.data === false,
  'deployed presentation schema refuses nested unseen fields');

const invalidEvidence = await supabase.rpc('append_mobile_evidence_record', {
  p_entity_ref: null,
  p_expected_hash: null,
  p_record: {},
  p_canonical_body: '{}',
});
assert(!invalidEvidence.error && invalidEvidence.data === false, 'portable evidence RPC exists and refuses malformed input');

const invalidCommit = await supabase.rpc('commit_mobile_action_decision', {
  p_entity_ref: '__mobile_readiness_nonexistent__',
  p_session_id: nonexistentSessionId,
  p_challenge_id: '__mobile_readiness_nonexistent__',
  p_action_hash: `sha256:${'0'.repeat(64)}`,
  p_decision: 'approved',
  p_verdict: 'verified',
  p_decision_evidence: {
    context: {
      action_hash: `sha256:${'0'.repeat(64)}`,
      decision: 'approved',
      approver: '__mobile_readiness_nonexistent__',
    },
    signoff: { key_class: 'A', context_hash: `sha256:${'0'.repeat(64)}` },
  },
  p_expected_hash: null,
  p_record: {},
  p_canonical_body: '{}',
  p_now: readinessNow,
});
assert(!invalidCommit.error && invalidCommit.data?.ok === false,
  'atomic action/evidence RPC exists and refuses malformed input');

const invalidRevocation = await supabase.rpc('revoke_mobile_session', {
  p_entity_ref: '__mobile_readiness_nonexistent__',
  p_session_id: nonexistentSessionId,
  p_now: readinessNow,
});
assert(!invalidRevocation.error && invalidRevocation.data === false, 'atomic session revocation RPC exists and refuses an unknown session');

const fetchJson = async (path) => {
  const response = await fetch(new URL(path, `${config.iosOrigin}/`), { redirect: 'manual' });
  if (response.status !== 200) throw new Error(`${path} returned HTTP ${response.status}`);
  const type = response.headers.get('content-type') || '';
  if (!type.includes('application/json')) throw new Error(`${path} is not JSON`);
  return response.json();
};

const apple = await fetchJson('/.well-known/apple-app-site-association');
const appleId = `${config.appleTeamId}.${config.iosBundleId}`;
assert(apple?.applinks?.details?.some((item) => item?.appIDs?.includes(appleId)), 'AASA serves the permanent Apple application identifier');

const android = await fetchJson('/.well-known/assetlinks.json');
const target = Array.isArray(android)
  ? android.find((item) => item?.target?.package_name === config.androidPackageName)
  : null;
assert(Boolean(target), 'Digital Asset Links serves the permanent Android package');
const servedPins = target.target.sha256_cert_fingerprints || [];
assert(servedPins.length === 1 && servedPins[0] === assetLinkPins[0],
  'Digital Asset Links serves exactly the canonical Android signing certificate');

console.log('MOBILE PRODUCTION READINESS: PASS');

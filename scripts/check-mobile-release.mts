// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root: string = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(root, path), 'utf8');
const contains = (path: string, value: RegExp, message: string): void => {
  assert.match(read(path), value, `${path}: ${message}`);
};

const identity: string = 'ai.emiliaprotocol.approver';
const host: string = 'www.emiliaprotocol.ai';

contains('examples/mobile-government/ios/project.yml', new RegExp(`PRODUCT_BUNDLE_IDENTIFIER: ${identity.replaceAll('.', '\\.')}`), 'permanent bundle identity drifted');
contains('examples/mobile-government/ios/project.yml', /DEVELOPMENT_TEAM: 5M2Z48UQQY/, 'Apple team identity drifted');
contains('examples/mobile-government/ios/project.yml', /APP_ATTEST_ENVIRONMENT: production/, 'release App Attest is not production');
contains('examples/mobile-government/ios/GovernmentApproval.entitlements', new RegExp(`applinks:${host.replaceAll('.', '\\.')}`), 'universal link entitlement missing');
contains('examples/mobile-government/ios/GovernmentApproval.entitlements', /devicecheck\.appattest-environment/, 'App Attest entitlement missing');
contains('examples/mobile-government/ios/Sources/PrivacyInfo.xcprivacy', /NSPrivacyTracking[\s\S]*<false\/>/, 'tracking declaration must remain false');
contains('examples/mobile-government/ios/Sources/SecureSessionStore.swift', /kSecAttrAccessibleWhenUnlockedThisDeviceOnly/, 'session secret is not device-only Keychain data');
contains('examples/mobile-government/ios/Sources/ApprovalViewModel.swift', /UIScreen\.main\.isCaptured/, 'screen-capture refusal is missing');
contains('examples/mobile-government/ios/Sources/ApprovalView.swift', /scenePhase != \.active \|\| model\.screenCaptureDetected/, 'protected iOS content is not hidden from inactive/captured surfaces');
contains('examples/mobile-government/ios/Sources/ApprovalView.swift', /reviewRisk[\s\S]*reviewSummary[\s\S]*presentationVersion[\s\S]*materialFields[\s\S]*consequence/, 'iOS review does not render the complete versioned presentation');
contains('examples/mobile-government/ios/Sources/ApprovalViewModel.swift', /validatePresentation\(\s*challenge\.presentation,\s*for:\s*challenge\.action\s*\)/, 'iOS signs without first closing the presentation schema against the exact action');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /NoRedirectSessionDelegate/, 'iOS redirects are not refused');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /maximumResponseBytes = 1_048_576/, 'iOS response ceiling is missing');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /https:\/\/www\.emiliaprotocol\.ai\/api\//, 'iOS production API identity is not pinned');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /expectedDecision: challenge\.authorizationContext\.decision[\s\S]*result\.decision == expectedDecision/, 'iOS ceremony recovery is not bound to the reviewed decision');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /catch APIError\.transport[\s\S]{0,500}recoverCeremonyResult\([\s\S]{0,160}challengeID: challenge\.challengeID/, 'iOS does not recover a possibly committed ceremony after a lost POST response');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /recoverCeremonyResult[\s\S]*v1\/mobile\/ceremonies\/[\s\S]*outcomeUnknown/, 'iOS does not close an unresolved recovery lookup as outcome unknown');
assert.doesNotMatch(read('examples/mobile-government/ios/Sources/MobileAPI.swift'), /Nothing was authorized/, 'iOS makes an unsafe non-commit claim after transport failure');

contains('sdks/kotlin-mobile/sample/build.gradle.kts', new RegExp(`applicationId = "${identity.replaceAll('.', '\\.')}"`), 'permanent package identity drifted');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /minSdk = 33/, 'production sample no longer matches the server integrity floor');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /verifyProductionIdentity/, 'release signing gate is missing');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /enableV1Signing = false/, 'legacy APK v1 signing must remain disabled');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /EMILIA_RELEASE_BUILD_NUMBER/, 'store build number is not release-bound');
contains('sdks/kotlin-mobile/sample/src/main/AndroidManifest.xml', /android:allowBackup="false"/, 'Android backup must remain disabled');
contains('sdks/kotlin-mobile/sample/src/main/AndroidManifest.xml', /android:usesCleartextTraffic="false"/, 'cleartext traffic must remain disabled');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MainActivity.kt', /WindowManager\.LayoutParams\.FLAG_SECURE/, 'production screen-capture defense is missing');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MainActivity.kt', /decodeAndValidate[\s\S]*validatePresentation\(value\.presentation,\s*value\.action\)/, 'Android signs without first closing the presentation schema against the exact action');
contains('sdks/kotlin-mobile/src/main/kotlin/ai/emiliaprotocol/mobile/AndroidProviders.kt', /SHA256withECDSA[\s\S]*KeyPairGenerator\.getInstance\(KeyProperties\.KEY_ALGORITHM_EC, ANDROID_KEY_STORE\)/, 'Android ceremony proof is not backed by a non-exportable Keystore signing key');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/SecureSessionStore.kt', /AndroidKeyStore/, 'session secret is not Android Keystore protected');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /PRODUCTION_BASE_URL = "https:\/\/www\.emiliaprotocol\.ai\/api\/"/, 'Android production API identity is not pinned');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /challenge\.authorizationContext\.decision[\s\S]*result\.decision != expectedDecision/, 'Android ceremony recovery is not bound to the reviewed decision');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /catch \(_:\s*MobileApiException\.Transport\)[\s\S]{0,400}recoverCeremonyResult\([\s\S]{0,120}challenge\.challengeId,[\s\S]{0,80}expectedDecision/, 'Android does not recover a possibly committed ceremony after a lost POST response');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /recoverCeremonyResult[\s\S]*v1\/mobile\/ceremonies\/[\s\S]*OutcomeUnknown/, 'Android does not close an unresolved recovery lookup as outcome unknown');
assert.doesNotMatch(read('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt'), /Nothing was authorized/, 'Android makes an unsafe non-commit claim after transport failure');

contains('app/.well-known/apple-app-site-association/route.js', new RegExp(`5M2Z48UQQY\\.${identity.replaceAll('.', '\\.')}`), 'Apple association identity drifted');
contains('app/.well-known/assetlinks.json/route.js', new RegExp(identity.replaceAll('.', '\\.')), 'Android association identity drifted');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function revoke_mobile_session/, 'atomic credential revocation is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function revoke_mobile_session\(text, uuid, timestamptz\) from anon, authenticated, public/, 'revocation RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /alter table mobile_sessions enable row level security/, 'mobile session RLS is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function append_mobile_evidence_record/, 'portable evidence atomic append is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function append_mobile_evidence_record\(text, text, jsonb, text\) from anon, authenticated, public/, 'portable evidence RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function commit_mobile_action_decision\([\s\S]*p_canonical_body text[\s\S]*returns jsonb/, 'action and evidence are not committed through the atomic RPC');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /p_decision_evidence jsonb/, 'terminal decision RPC does not accept portable decision evidence');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /insert into mobile_evidence_records\([\s\S]*return jsonb_build_object\('ok', true\)/, 'terminal action transaction does not append portable evidence');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function commit_mobile_action_decision\(text, uuid, text, text, text, text, jsonb, text, jsonb, text, timestamptz\)/, 'atomic action/evidence RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /mobile_presentation_is_valid[\s\S]*EP-MOBILE-PRESENTATION-v1[\s\S]*jsonb_typeof\(field\.value\) <> 'string'/, 'database presentation schema is not closed against unseen nested fields');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /insert into mobile_counters\(counter_key, counter_value\)[\s\S]*p_enrollment ->> 'sign_count'/, 'registration counter baseline is not seeded in the enrollment transaction');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /session_id uuid not null references mobile_sessions[\s\S]*p_record ->> 'session_id' is distinct from p_session_id::text[\s\S]*reason', 'session_inactive'/, 'terminal decisions are not transactionally bound to an active mobile session');
contains('supabase/migrations/20260720181619_mobile_action_continuity.sql', /create or replace function mobile_action_decision_identity_guard\([\s\S]*action_caid[\s\S]*action_digest/, 'terminal decisions are not bound to the exact CAID revision');
contains('supabase/migrations/20260720181619_mobile_action_continuity.sql', /create or replace function consume_mobile_action\([\s\S]*consumption_nonce[\s\S]*already_consumed/, 'single-consumption and replay refusal are missing');
contains('supabase/migrations/20260720181619_mobile_action_continuity.sql', /create or replace function consume_mobile_action\([\s\S]*target\.expires_at <= p_now[\s\S]*reason', 'expired'/, 'expired authorization can still be consumed');
contains('supabase/migrations/20260720181619_mobile_action_continuity.sql', /create or replace function mark_mobile_action_indeterminate\([\s\S]*retry_safe', false/, 'provider timeout does not burn blind retry');
contains('supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql', /primary key \(entity_ref, operation_id\)/, 'operation identifiers remain globally squattable across tenants');
contains('supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql', /create or replace function consume_mobile_action\([\s\S]*insert into mobile_action_operations\([\s\S]*executor_key\.key_id/, 'consumption does not freeze the intended executor key');
contains('supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql', /create or replace function reconcile_mobile_action_operation\([\s\S]*for share[\s\S]*executor_key_not_active[\s\S]*provider_evidence = p_provider_evidence/, 'authenticated reconciliation is not transactionally key-bound with retained evidence');
contains('supabase/migrations/20260720193917_mobile_action_continuity_hardening.sql', /where entity_ref = p_entity_ref and operation_id = p_operation_id/, 'operation transitions are not tenant scoped');
contains('supabase/migrations/20260720181619_mobile_action_continuity.sql', /create or replace function list_mobile_action_continuity\([\s\S]*left join mobile_action_groups[\s\S]*action\.group_id is null/, 'continuity snapshot hides legacy mobile actions');
contains('supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql', /alter function append_mobile_audit_event\(text, jsonb\)[\s\S]*set search_path = extensions, public, pg_temp/, 'mobile audit hashing cannot resolve Supabase pgcrypto safely');
contains('supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql', /alter function append_mobile_evidence_record\(text, text, jsonb, text\)[\s\S]*set search_path = extensions, public, pg_temp/, 'mobile evidence hashing cannot resolve Supabase pgcrypto safely');
contains('supabase/migrations/20260720182147_mobile_pgcrypto_schema_pin.sql', /alter function commit_mobile_action_decision\([\s\S]*set search_path = extensions, public, pg_temp/, 'atomic mobile decision hashing cannot resolve Supabase pgcrypto safely');
contains('supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql', /revoke all on function mobile_action_challenge_identity\(\)[\s\S]*from public, anon, authenticated/, 'challenge identity trigger is exposed as a public RPC');
contains('supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql', /revoke all on function mobile_action_decision_identity_guard\(\)[\s\S]*from public, anon, authenticated/, 'decision identity trigger is exposed as a public RPC');
contains('supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql', /revoke all on function mobile_action_decision_projection\(\)[\s\S]*from public, anon, authenticated/, 'decision projection trigger is exposed as a public RPC');
contains('supabase/migrations/20260720182519_mobile_action_advisor_hardening.sql', /create index if not exists mobile_action_challenges_group_revision_idx[\s\S]*entity_ref, group_id, revision/, 'challenge continuity foreign key lacks a covering index');
contains('mobile/spec/ep-mobile-v1.schema.json', /EP-MOBILE-CHALLENGE-v2[\s\S]*action_reference[\s\S]*action_caid[\s\S]*action_digest/, 'mobile schema does not require the signed Action Lock');
contains('packages/mobile/package.json', /"action-identity\.js"/, 'published mobile package omits its CAID Action Lock implementation');
contains('scripts/check-mobile-production.mjs', /service role cannot mutate mobile trust tables directly[\s\S]*p_session_id: nonexistentSessionId/, 'production readiness does not test the read-only service role and session-bound terminal RPC');
contains('scripts/check-mobile-production.mjs', /mobile_presentation_is_valid[\s\S]*p_decision_evidence:/, 'production readiness is stale relative to the current mobile RPC and presentation schema');
contains('scripts/check-mobile-production.mjs', /create_mobile_demo_action_v2[\s\S]*mark_mobile_action_indeterminate[\s\S]*reconcile_mobile_action_operation[\s\S]*list_mobile_action_continuity/, 'production readiness omits the durable continuity RPCs');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on mobile_kv_state,[\s\S]*from anon, authenticated/, 'public database grants were not revoked');
for (const rpc of [
  'mobile_state_add_if_absent',
  'mobile_state_compare_and_set',
  'create_mobile_pairing',
  'touch_mobile_session',
  'create_mobile_demo_action',
]) {
  contains('supabase/migrations/20260715180000_mobile_production_platform.sql', new RegExp(`create or replace function ${rpc}\\(`), `${rpc} write boundary is missing`);
}
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke insert, update, delete, truncate, references, trigger on mobile_kv_state,[\s\S]*from service_role/, 'service role can bypass the mobile RPC write boundary');
contains('lib/write-guard.ts', /'mobile_kv_state',[\s\S]*'mobile_action_challenges'/, 'native approval tables are not runtime write-guarded');
for (const path of [
  'app/api/v1/mobile/pairings/route.ts',
  'app/api/v1/mobile/pairings/exchange/route.ts',
  'app/api/v1/mobile/inbox/route.ts',
  'app/api/v1/mobile/session/route.ts',
  'app/api/v1/mobile/ceremonies/[challengeId]/route.ts',
  'app/api/v1/mobile/demo/actions/route.ts',
  'app/api/v1/mobile/history/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/passport/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/withdraw/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/consume/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/outcomes/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/alignments/route.ts',
  'app/api/v1/mobile/actions/[actionReference]/supersede/route.ts',
  'app/api/v1/mobile/executors/route.ts',
  'lib/mobile/runtime.ts',
] as const) {
  contains(path, /getGuardedClient/, 'mobile runtime bypasses the guarded database client');
  assert.doesNotMatch(read(path), /\bgetServiceClient\b/, `${path}: unrestricted service client is forbidden`);
}
contains('lib/rate-limit.ts', /mobile_runtime_ip[\s\S]*mobile_write/, 'mobile runtime throttles are missing');
contains('lib/mobile/runtime.ts', /session:\$\{runtime\.session\.session_id\}[\s\S]*mobile_write/, 'paired ceremonies are not session-rate-limited');
contains('.github/workflows/mobile-signed-release.yml', /EMILIA_ANDROID_CERTIFICATE_SHA256_HEX/, 'signed Android identity is not compared with its server pin');
contains('.github/workflows/mobile-signed-release.yml', /MOBILE_ANDROID_SIGNING_CERT_SHA256[\s\S]*check-mobile-signing-identity\.mjs[\s\S]*AAB_CERT_SHA256/, 'APK and AAB signing identities are not cross-checked against one canonical certificate');
contains('.github/workflows/mobile-signed-release.yml', /get-task-allow/, 'signed iOS archive is not checked for debugger entitlement');
contains('.github/workflows/mobile-signed-release.yml', /github\.repository == 'emiliaprotocol\/emilia-protocol'[\s\S]*github\.ref == 'refs\/heads\/main'/, 'signed mobile release is not restricted to the canonical repository main branch');
contains('.github/workflows/mobile-signed-release.yml', /actions\/checkout@[a-f0-9]+[\s\S]{0,120}ref: \$\{\{ github\.sha \}\}/, 'signed mobile release checkout is not pinned to the approved workflow commit');
const signedReleaseWorkflow: string = read('.github/workflows/mobile-signed-release.yml');
assert.equal(
  [...signedReleaseWorkflow.matchAll(/actions\/checkout@[a-f0-9]+[\s\S]{0,120}?ref: \$\{\{ github\.sha \}\}/g)].length,
  3,
  'every signed mobile release checkout must use the approved workflow commit',
);

const signingCheck: string = resolve(root, 'scripts/check-mobile-signing-identity.mjs');
const certificateHex: string = '05'.repeat(32);
const certificateFingerprint: string = (certificateHex.toUpperCase().match(/../g) as RegExpMatchArray).join(':');
execFileSync(process.execPath, [signingCheck, certificateHex, certificateFingerprint, 'fixture'], { stdio: 'pipe' });
assert.throws(
  () => execFileSync(process.execPath, [signingCheck, certificateHex, '06'.repeat(32), 'fixture'], { stdio: 'pipe' }),
  /Command failed/,
  'signing identity mismatch must fail the release check',
);

for (const path of [
  'examples/mobile-government/README.md',
  'examples/mobile-government/ios/README.md',
  'sdks/kotlin-mobile/README.md',
]) {
  assert.doesNotMatch(read(path), /example\.gov/, `${path}: stale example identity remains`);
}

console.log('mobile release invariants: OK');

// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(resolve(root, path), 'utf8');
const contains = (path, value, message) => {
  assert.match(read(path), value, `${path}: ${message}`);
};

const identity = 'ai.emiliaprotocol.approver';
const host = 'www.emiliaprotocol.ai';

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
contains('examples/mobile-government/ios/Sources/ApprovalViewModel.swift', /validatePresentation\(challenge\.presentation\)/, 'iOS signs without first closing the presentation schema');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /NoRedirectSessionDelegate/, 'iOS redirects are not refused');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /maximumResponseBytes = 1_048_576/, 'iOS response ceiling is missing');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /https:\/\/www\.emiliaprotocol\.ai\/api\//, 'iOS production API identity is not pinned');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /catch APIError\.transport[\s\S]{0,400}recoverCeremonyResult\(challengeID: challenge\.challengeID\)/, 'iOS does not recover a possibly committed ceremony after a lost POST response');
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
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MainActivity.kt', /decodeAndValidate[\s\S]*validatePresentation\(value\.presentation\)/, 'Android signs without first closing the presentation schema');
contains('sdks/kotlin-mobile/src/main/kotlin/ai/emiliaprotocol/mobile/AndroidProviders.kt', /SHA256withECDSA[\s\S]*KeyPairGenerator\.getInstance\(KeyProperties\.KEY_ALGORITHM_EC, ANDROID_KEY_STORE\)/, 'Android ceremony proof is not backed by a non-exportable Keystore signing key');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/SecureSessionStore.kt', /AndroidKeyStore/, 'session secret is not Android Keystore protected');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /PRODUCTION_BASE_URL = "https:\/\/www\.emiliaprotocol\.ai\/api\/"/, 'Android production API identity is not pinned');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /catch \(_:\s*MobileApiException\.Transport\)[\s\S]{0,400}recoverCeremonyResult\(challenge\.challengeId\)/, 'Android does not recover a possibly committed ceremony after a lost POST response');
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
contains('scripts/check-mobile-production.mjs', /service role cannot mutate mobile trust tables directly[\s\S]*p_session_id: nonexistentSessionId/, 'production readiness does not test the read-only service role and session-bound terminal RPC');
contains('scripts/check-mobile-production.mjs', /mobile_presentation_is_valid[\s\S]*p_decision_evidence:/, 'production readiness is stale relative to the current mobile RPC and presentation schema');
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
contains('lib/write-guard.js', /'mobile_kv_state',[\s\S]*'mobile_action_challenges'/, 'native approval tables are not runtime write-guarded');
for (const path of [
  'app/api/v1/mobile/pairings/route.js',
  'app/api/v1/mobile/pairings/exchange/route.js',
  'app/api/v1/mobile/inbox/route.js',
  'app/api/v1/mobile/session/route.js',
  'app/api/v1/mobile/ceremonies/[challengeId]/route.js',
  'app/api/v1/mobile/demo/actions/route.js',
  'lib/mobile/runtime.js',
]) {
  contains(path, /getGuardedClient/, 'mobile runtime bypasses the guarded database client');
  assert.doesNotMatch(read(path), /\bgetServiceClient\b/, `${path}: unrestricted service client is forbidden`);
}
contains('lib/rate-limit.js', /mobile_runtime_ip[\s\S]*mobile_write/, 'mobile runtime throttles are missing');
contains('lib/mobile/runtime.js', /session:\$\{runtime\.session\.session_id\}[\s\S]*mobile_write/, 'paired ceremonies are not session-rate-limited');
contains('.github/workflows/mobile-signed-release.yml', /EMILIA_ANDROID_CERTIFICATE_SHA256_HEX/, 'signed Android identity is not compared with its server pin');
contains('.github/workflows/mobile-signed-release.yml', /MOBILE_ANDROID_SIGNING_CERT_SHA256[\s\S]*check-mobile-signing-identity\.mjs[\s\S]*AAB_CERT_SHA256/, 'APK and AAB signing identities are not cross-checked against one canonical certificate');
contains('.github/workflows/mobile-signed-release.yml', /get-task-allow/, 'signed iOS archive is not checked for debugger entitlement');
contains('.github/workflows/mobile-signed-release.yml', /github\.repository == 'emiliaprotocol\/emilia-protocol'[\s\S]*github\.ref == 'refs\/heads\/main'/, 'signed mobile release is not restricted to the canonical repository main branch');
contains('.github/workflows/mobile-signed-release.yml', /actions\/checkout@[a-f0-9]+[\s\S]{0,120}ref: \$\{\{ github\.sha \}\}/, 'signed mobile release checkout is not pinned to the approved workflow commit');
const signedReleaseWorkflow = read('.github/workflows/mobile-signed-release.yml');
assert.equal(
  [...signedReleaseWorkflow.matchAll(/actions\/checkout@[a-f0-9]+[\s\S]{0,120}?ref: \$\{\{ github\.sha \}\}/g)].length,
  3,
  'every signed mobile release checkout must use the approved workflow commit',
);

const signingCheck = resolve(root, 'scripts/check-mobile-signing-identity.mjs');
const certificateHex = '05'.repeat(32);
const certificateFingerprint = certificateHex.toUpperCase().match(/../g).join(':');
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

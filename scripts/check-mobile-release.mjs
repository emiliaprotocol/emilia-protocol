// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
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
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /NoRedirectSessionDelegate/, 'iOS redirects are not refused');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /maximumResponseBytes = 1_048_576/, 'iOS response ceiling is missing');
contains('examples/mobile-government/ios/Sources/MobileAPI.swift', /https:\/\/www\.emiliaprotocol\.ai\/api\//, 'iOS production API identity is not pinned');

contains('sdks/kotlin-mobile/sample/build.gradle.kts', new RegExp(`applicationId = "${identity.replaceAll('.', '\\.')}"`), 'permanent package identity drifted');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /minSdk = 33/, 'production sample no longer matches the server integrity floor');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /verifyProductionIdentity/, 'release signing gate is missing');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /enableV1Signing = false/, 'legacy APK v1 signing must remain disabled');
contains('sdks/kotlin-mobile/sample/build.gradle.kts', /EMILIA_RELEASE_BUILD_NUMBER/, 'store build number is not release-bound');
contains('sdks/kotlin-mobile/sample/src/main/AndroidManifest.xml', /android:allowBackup="false"/, 'Android backup must remain disabled');
contains('sdks/kotlin-mobile/sample/src/main/AndroidManifest.xml', /android:usesCleartextTraffic="false"/, 'cleartext traffic must remain disabled');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MainActivity.kt', /WindowManager\.LayoutParams\.FLAG_SECURE/, 'production screen-capture defense is missing');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/SecureSessionStore.kt', /AndroidKeyStore/, 'session secret is not Android Keystore protected');
contains('sdks/kotlin-mobile/sample/src/main/kotlin/ai/emiliaprotocol/approver/MobileApi.kt', /PRODUCTION_BASE_URL = "https:\/\/www\.emiliaprotocol\.ai\/api\/"/, 'Android production API identity is not pinned');

contains('app/.well-known/apple-app-site-association/route.js', new RegExp(`5M2Z48UQQY\\.${identity.replaceAll('.', '\\.')}`), 'Apple association identity drifted');
contains('app/.well-known/assetlinks.json/route.js', new RegExp(identity.replaceAll('.', '\\.')), 'Android association identity drifted');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function revoke_mobile_session/, 'atomic credential revocation is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function revoke_mobile_session\(text, uuid, timestamptz\) from anon, authenticated, public/, 'revocation RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /alter table mobile_sessions enable row level security/, 'mobile session RLS is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function append_mobile_evidence_record/, 'portable evidence atomic append is missing');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function append_mobile_evidence_record\(text, text, jsonb, text\) from anon, authenticated, public/, 'portable evidence RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /create or replace function commit_mobile_action_decision\([\s\S]*p_canonical_body text[\s\S]*returns jsonb/, 'action and evidence are not committed through the atomic RPC');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /insert into mobile_evidence_records\([\s\S]*return jsonb_build_object\('ok', true\)/, 'terminal action transaction does not append portable evidence');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /revoke all on function commit_mobile_action_decision\(text, uuid, text, text, text, text, text, jsonb, text, timestamptz\)/, 'atomic action/evidence RPC is publicly executable');
contains('supabase/migrations/20260715180000_mobile_production_platform.sql', /session_id uuid not null references mobile_sessions[\s\S]*p_record ->> 'session_id' <> p_session_id::text[\s\S]*reason', 'session_inactive'/, 'terminal decisions are not transactionally bound to an active mobile session');
contains('scripts/check-mobile-production.mjs', /service role cannot mutate mobile trust tables directly[\s\S]*p_session_id: nonexistentSessionId/, 'production readiness does not test the read-only service role and session-bound terminal RPC');
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
  'app/api/v1/mobile/demo/actions/route.js',
  'lib/mobile/runtime.js',
]) {
  contains(path, /getGuardedClient/, 'mobile runtime bypasses the guarded database client');
  assert.doesNotMatch(read(path), /\bgetServiceClient\b/, `${path}: unrestricted service client is forbidden`);
}
contains('lib/rate-limit.js', /mobile_runtime_ip[\s\S]*mobile_write/, 'mobile runtime throttles are missing');
contains('lib/mobile/runtime.js', /session:\$\{runtime\.session\.session_id\}[\s\S]*mobile_write/, 'paired ceremonies are not session-rate-limited');
contains('.github/workflows/mobile-signed-release.yml', /EMILIA_ANDROID_CERTIFICATE_SHA256_HEX/, 'signed Android identity is not compared with its server pin');
contains('.github/workflows/mobile-signed-release.yml', /get-task-allow/, 'signed iOS archive is not checked for debugger entitlement');

for (const path of [
  'examples/mobile-government/README.md',
  'examples/mobile-government/ios/README.md',
  'sdks/kotlin-mobile/README.md',
]) {
  assert.doesNotMatch(read(path), /example\.gov/, `${path}: stale example identity remains`);
}

console.log('mobile release invariants: OK');

#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Refuse accidental reintroduction of the obsolete CAID-04 `caid:1:` wire
// spelling on current surfaces. Historical packets, immutable evidence, old
// migrations, and explicit legacy-refusal boundaries remain byte-preserved.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const ALLOWED_PREFIXES = [
  'caid/conformance/history/',
  'examples/external-verification/',
  'standards/archive/',
  'standards/posted/',
  'standards/profiles/NEXT-WIMSE-CAID-SCOPE-00/',
  'standards/profiles/NEXT-WIMSE-CAID-SCOPE-01/',
  'standards/staged/NEXT-AEC-06/',
  'standards/staged/NEXT-AEC-07/',
  'standards/staged/NEXT-CAID-02/',
  'standards/staged/NEXT-CAID-03/',
  'standards/staged/NEXT-CAID-04/',
];

const ALLOWED_EXACT = new Set([
  'caid/README.md',
  'caid/impl/js/caid.mjs',
  'caid/impl/python/caid.py',
  'docs/CANACTID-MIGRATION.md',
  'examples/ccs/vectors.reference.json',
  'packages/gate/canonical-action-identifier.test.js',
  'packages/gate/canonical-action-identifier.test.ts',
  'packages/mcp-guard/canactid-metadata.test.mjs',
  'packages/require-receipt/canactid-selector.test.js',
  'packages/verify/canonical-action-identifier.test.js',
  'packages/verify/canonical-action-identifier.test.ts',
  'packages/verify/dist/canonical-action-identifier.js',
  'packages/verify/src/canonical-action-identifier.ts',
  'lib/mobile/action-continuity.js',
  'lib/mobile/action-continuity.ts',
  'packages/verify/vendor/caid.mjs',
  'scripts/check-caid-02.mjs',
  'scripts/check-caid-03.mjs',
  'scripts/check-caid-04.mjs',
  'scripts/check-aec-08.mjs',
  'scripts/check-canactid-boundary.mjs',
  'scripts/test-mobile-migration.sh',
  'sdks/kotlin-mobile/src/test/kotlin/ai/emiliaprotocol/mobile/ActionContinuityTest.kt',
  'sdks/swift-mobile/Tests/EmiliaMobileTests/EmiliaMobileTests.swift',
  'standards/profiles/NEXT-WIMSE-CAID-SCOPE-02/generate-vectors.mjs',
  'standards/profiles/NEXT-WIMSE-CAID-SCOPE-02/validate.mjs',
  'standards/profiles/NEXT-WIMSE-CAID-SCOPE-02/vectors.json',
  'standards/staged/NEXT-CAID-05/validate.mjs',
  'standards/staged/RENDERS/draft-schrock-ep-authorization-evidence-chain-05.html',
  'standards/staged/RENDERS/draft-schrock-ep-authorization-evidence-chain-05.txt',
  'standards/staged/RENDERS/draft-schrock-ep-bounded-execution-program-00.html',
  'standards/staged/RENDERS/draft-schrock-ep-bounded-execution-program-00.txt',
  'standards/staged/UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-05.xml',
  'standards/staged/UPLOAD-THIS/draft-schrock-ep-bounded-execution-program-00.xml',
  'supabase/migrations/20260720181619_mobile_action_continuity.sql',
  'supabase/migrations/20260721163000_trust_program_store.sql',
  'supabase/migrations/20260721171500_ep_approval_acquisition.sql',
  'supabase/migrations/20260728210700_open_exposure_ledger.sql',
  'supabase/migrations/20260802120000_arena_synthetic_allowance.sql',
  'supabase/migrations/20261005090000_canactid_scheme_transition.sql',
  'tests/canactid-database-cutover.test.ts',
  'tests/canactid-public-schema-boundary.test.ts',
  'tests/mobile-action-continuity-migration.sql',
]);

const OASNT_NAMESPACE_FILES = new Set([
  'docs/standards-engagement/OASNT-CAID-AEB-COMPOSITION.md',
  'packages/verify/aeb-oasnt-adapter.test.js',
  'packages/verify/aeb-oasnt-adapter.test.ts',
  'packages/verify/dist/aeb-oasnt-adapter.js',
  'packages/verify/src/aeb-oasnt-adapter.ts',
]);

function repositoryFiles() {
  const output = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { encoding: 'utf8' },
  );
  return [...new Set(output.split('\0').filter(Boolean))].sort();
}

function isAllowed(file, content) {
  if (ALLOWED_PREFIXES.some((prefix) => file.startsWith(prefix))) return true;
  if (ALLOWED_EXACT.has(file)) return true;
  if (OASNT_NAMESPACE_FILES.has(file)) {
    return !content.replaceAll('oasnt:caid:1:', '').includes('caid:1:');
  }
  return false;
}

const violations = [];
for (const file of repositoryFiles()) {
  let content;
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  if (!content.includes('caid:1:') || isAllowed(file, content)) continue;
  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.includes('caid:1:')) violations.push(`${file}:${index + 1}`);
  });
}

if (violations.length > 0) {
  console.error('Current surfaces contain the obsolete CAID-04 `caid:1:` spelling:');
  violations.forEach((violation) => console.error(`- ${violation}`));
  console.error('Use `canactid:1:` for current material, or document a narrow immutable/legacy exception.');
  process.exit(1);
}

console.log('CANACTID boundary: current surfaces use `canactid:1:`; historical and explicit legacy references are isolated.');

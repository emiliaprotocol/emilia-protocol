#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generates Node-20-executable .js companions for .ts sources that are
// imported outside the ts-loader/bundler resolution path: the documented
// Action Escrow example (tested against the minimum supported Node),
// conformance/runners/run-js.mjs (exercised with zero extra tooling by
// deploy/airgap/verify-offline.sh, which the airgap-audit CI job runs on
// Node 20 by design, to prove air-gapped verification needs nothing but
// node + the repo), and apps/gate-service (ships as a BYOC Docker image
// pinned below Node's unflagged stripping threshold, and its own CI job's
// test suite runs on Node 20). Node's built-in TypeScript stripping only
// exists from 22.6 on (unflagged from 23.6), so these consumers need a real
// transpiled .js file, not the ts-loader hook's resolve-only fix. Using
// transpileModule (syntactic type-stripping only, no cross-file semantic
// checking) rather than a full tsc program build is deliberate: these files
// type-check fine under this repo's loose per-tier tsconfigs, but test/
// directories are excluded from every tier's checkJs/typecheck coverage, so
// apps/gate-service/test/helpers.ts in particular has never actually been
// verified against strict-null-checks and isn't worth blocking a Node-20
// compatibility shim on.
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), '..');
const SCRIPT_NAME = 'scripts/build-standalone-runtimes.mjs';

const TARGETS = [
  'lib/integrations/action-escrow/procore-change-order.ts',
  'lib/integrations/action-escrow/acrobat-sign.ts',
  'lib/integrations/action-escrow/bounded-fetch.ts',
  'lib/integrations/action-escrow/licensed-custodian.ts',
  'lib/authority/authority-doc.ts',
  'lib/authority/document-proof-join.ts',
  'lib/authority/proof.ts',
  'lib/canonical-json.ts',
  'lib/evidence/admissibility.ts',
  'lib/evidence/effect-predicates.ts',
  'lib/evidence/evidence-graph.ts',
  'lib/aml/screening.ts',
  'lib/aml/watchlist.ts',
  'lib/auth-projections.ts',
  'lib/canonical-writer.ts',
  'lib/crypto.ts',
  'lib/crypto/profile.ts',
  'lib/demo-receipt.ts',
  'lib/env.ts',
  'lib/envelope/descriptors.ts',
  'lib/guard-policies.ts',
  'lib/handshake/invariants.ts',
  'lib/key-custody.ts',
  'lib/logger.ts',
  'lib/mobile/config.ts',
  'lib/rules-engine.ts',
  'lib/siem.ts',
  'lib/supabase.ts',
  'lib/trust-desk/answerer.ts',
  'lib/trust-desk/classifier.ts',
  'lib/trust-desk/customers.ts',
  'lib/trust-desk/ep-receipt.ts',
  'lib/trust-desk/extractor.ts',
  'lib/trust-desk/hash.ts',
  'lib/trust-desk/ids.ts',
  'lib/trust-desk/llm.ts',
  'lib/trust-desk/minter.ts',
  'lib/trust-desk/notify.ts',
  'lib/trust-desk/page-store.ts',
  'lib/trust-desk/page-verify.ts',
  'lib/trust-desk/pipeline.ts',
  'lib/trust-desk/policy-defaults.ts',
  'lib/trust-desk/policy-mint.ts',
  'lib/trust-desk/signing.ts',
  'lib/trust-desk/store-supabase.ts',
  'lib/trust-desk/store.ts',
  'lib/trust-desk/templates-index.ts',
  'lib/trust-desk/verifier.ts',
  'lib/authority/enforcement.ts',
  'lib/authority/registry-head.ts',
  'lib/authority/resolver.ts',
  'lib/authority/store.ts',
  'lib/cbor-encode.ts',
  'lib/evidence/policy-packs.ts',
  'lib/frontier/model-to-matter.ts',
  'lib/grace/curtailment.ts',
  'lib/grace/mobile-grid.ts',
  'lib/grace/reference-adapters.ts',
  'lib/grace/reference-scenario.ts',
  'lib/ncpdp/privacy.ts',
  'lib/ncpdp/rx-reliance.ts',
  'lib/negotiate/evidence-challenge.ts',
  'lib/provenance/chain.ts',
  'lib/scoring-v2.ts',
  'lib/scoring.ts',
  'lib/trust-receipt/issuer.ts',
  'apps/gate-service/src/auth.ts',
  'apps/gate-service/src/config.ts',
  'apps/gate-service/src/github-client.ts',
  'apps/gate-service/src/production-config.ts',
  'apps/gate-service/src/routes.ts',
  'apps/gate-service/src/runtime.ts',
  'apps/gate-service/src/server.ts',
  'apps/gate-service/test/helpers.ts',
  // scripts/ (excluding scripts/ts-loader/** -- the resolution hook itself,
  // which cannot depend on TypeScript stripping to bootstrap -- and this
  // file plus build-ts-runtime.mjs, the meta build tools that produce these
  // companions and so must stay directly Node-executable themselves).
  'scripts/_schema-introspect.mts',
  'scripts/airgap-keys.mts',
  'scripts/assemble-conformance-case.mts',
  'scripts/build-clean-room-kit.mts',
  'scripts/build-ep-registry.mts',
  'scripts/build-soc2-evidence-pdf.mts',
  'scripts/build-standards-observatory.mts',
  'scripts/check-admissibility-registry.mts',
  'scripts/check-authority-claims.mts',
  'scripts/check-conformance-doc-counts.mts',
  'scripts/check-demo-key-isolation.ts',
  'scripts/check-docs-secrets.ts',
  'scripts/check-frozen-clean-room.mts',
  'scripts/check-language-governance.ts',
  'scripts/check-license-headers.ts',
  'scripts/check-mobile-production.mts',
  'scripts/check-mobile-release.mts',
  'scripts/check-mobile-signing-identity.mts',
  'scripts/check-outcome-authority-formal.mts',
  'scripts/check-preprint-sync.mts',
  'scripts/check-protocol-discipline.ts',
  'scripts/check-public-conformance-claims.mts',
  'scripts/check-release-chain.mts',
  'scripts/check-runtime-bridge.mts',
  'scripts/check-write-discipline.ts',
  'scripts/create-ep-profile.mts',
  'scripts/db-contract-audit.mts',
  'scripts/db-contract.manifest.mts',
  'scripts/db-contract.mts',
  'scripts/demo-rules-engine-shadow.ts',
  'scripts/differential-hostility.mts',
  'scripts/drills/failover-drill.ts',
  'scripts/drills/key-compromise-drill.mts',
  'scripts/e2e-offline-verify.mts',
  'scripts/emilia-gate.mts',
  'scripts/evaluate-external-implementation.mts',
  'scripts/gen-python-fixture.mts',
  'scripts/generate-conformance-manifest.mts',
  'scripts/generate-llm-context.mts',
  'scripts/generate-proof-metrics.mts',
  'scripts/generate-proof-stats.mts',
  'scripts/gov-readiness-check.mts',
  'scripts/import-standards-recon.mts',
  'scripts/key-inventory.mts',
  'scripts/lib/standards-text.mts',
  'scripts/migrate-to-logger.ts',
  'scripts/migration-reconcile.mts',
  'scripts/mobile-live-demo.mts',
  'scripts/passport-demo.mts',
  'scripts/pin-action-shas.ts',
  'scripts/purge-serialized-entities.mts',
  'scripts/python-artifact-integrity.mts',
  'scripts/realdevice-setup.mts',
  'scripts/reconcile-load-test.ts',
  'scripts/refresh-standards-observatory.mts',
  'scripts/render-pdf.mts',
  'scripts/replay-protocol.ts',
  'scripts/require-release-approval.mts',
  'scripts/run-package-suites.mts',
  'scripts/schema-security-audit.mts',
  'scripts/seed-entities.ts',
  'scripts/stripe-setup.mts',
  'scripts/td-run.mts',
  'scripts/td-verify.mts',
  'scripts/test-clean-room-intake.mts',
  'scripts/typecheck-strict.mts',
  'scripts/verify-clean-room-submission.mts',
  'scripts/verify-demo-receipt.ts',
  'scripts/verify-reproducible-package.mts',
  'scripts/verify-reproducible-wheel.mts',
  'scripts/verify-security-case.mts',
].map((relativeSource) => {
  const sourcePath = resolve(repositoryRoot, relativeSource);
  const runtimePath = sourcePath.replace(/\.mts$/, '.mjs').replace(/\.ts$/, '.js');
  const basename = relativeSource.split('/').pop();
  return {
    relativeSource,
    sourcePath,
    runtimePath,
    // The eslint-disable makes generated output lint-exempt as a unit: the
    // .ts source is what gets linted, and transpileModule can drop detached
    // block comments (a source's own /* eslint-disable */ pragma among them).
    banner: `// Generated from ${basename} by ${SCRIPT_NAME}. Do not edit.\n/* eslint-disable */\n`,
  };
});

async function renderRuntime({ sourcePath, banner }) {
  const source = await readFile(sourcePath, 'utf8');
  const result = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      newLine: ts.NewLineKind.LineFeed,
      removeComments: false,
      sourceMap: false,
      inlineSourceMap: false,
      inlineSources: false,
      verbatimModuleSyntax: true,
    },
    fileName: sourcePath,
    reportDiagnostics: true,
  });
  const errors = (result.diagnostics ?? []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  if (errors.length > 0) {
    throw new Error(ts.formatDiagnostics(errors, {
      getCanonicalFileName: (fileName) => fileName,
      getCurrentDirectory: () => repositoryRoot,
      getNewLine: () => '\n',
    }));
  }
  // Some CLI scripts have a `#!/usr/bin/env node` shebang before the license
  // header; it must stay the first line for direct execution, so the banner
  // is inserted after the header either way, not necessarily at offset 0.
  // Headers themselves vary (`// SPDX-License-Identifier: Apache-2.0` line
  // comment vs. a JSDoc `@license Apache-2.0` block) -- both are legitimate,
  // pre-existing conventions in this repo, so this only checks that transpiling
  // didn't silently drop the license notice, not one exact literal form.
  const shebangMatch = result.outputText.match(/^#!.*\n/);
  const afterShebang = shebangMatch ? result.outputText.slice(shebangMatch[0].length) : result.outputText;
  // Only enforce preservation when the source actually had a license header
  // to begin with -- a handful of these scripts never carried one.
  if (/Apache-2\.0/.test(source) && !/Apache-2\.0/.test(afterShebang.slice(0, 1000))) {
    throw new Error(`${sourcePath} must retain its Apache-2.0 header`);
  }
  const spdxLine = '// SPDX-License-Identifier: Apache-2.0\n';
  if (result.outputText.includes(spdxLine)) {
    return result.outputText.replace(spdxLine, `${spdxLine}${banner}`);
  }
  // No SPDX line comment to anchor on (e.g. a JSDoc @license block instead):
  // insert the banner right after the shebang, or at the very top otherwise.
  return shebangMatch
    ? `${shebangMatch[0]}${banner}${afterShebang}`
    : `${banner}${result.outputText}`;
}

export async function buildStandaloneRuntimes({ check = false } = {}) {
  for (const target of TARGETS) {
    const expected = await renderRuntime(target);
    if (check) {
      let actual = null;
      try {
        actual = await readFile(target.runtimePath, 'utf8');
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
      if (actual !== expected) {
        throw new Error(
          `${target.relativeSource} Node 20 runtime is missing or stale; run npm run build:standalone-runtimes`,
        );
      }
      continue;
    }
    await writeFile(target.runtimePath, expected, 'utf8');
  }
  process.stdout.write(
    `STANDALONE RUNTIMES: ${check ? 'synchronized' : 'generated'} (${TARGETS.length})\n`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await buildStandaloneRuntimes({ check: process.argv.includes('--check') });
}

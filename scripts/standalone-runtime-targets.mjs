// SPDX-License-Identifier: Apache-2.0
//
// Single source of truth for the Node-20 standalone-runtime companion set.
// Side-effect-free on purpose: vitest.config.js imports it (to alias each
// generated companion back to its .ts/.mts source and exclude companions from
// coverage), and scripts/build-standalone-runtimes.mjs imports it to generate
// and sync the companions. Keep it free of top-level await and of any import
// beyond the list itself so config bundlers can load it in any module format.

export const STANDALONE_RUNTIME_SOURCES = [
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
  'lib/mobile/action-continuity.ts',
  'lib/mobile/store.ts',
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
  'lib/revocation/status.ts',
  'lib/scoring-v2.ts',
  'lib/scoring.ts',
  // (lib/strict-json.js is deliberately NOT here: it is a vendored,
  // byte-identical copy of packages/verify/dist/strict-json.js, pinned by
  // tests/verify-web-consistency.test.js -- same for lib/verify-web.js.
  // Neither is a companion target and neither converts to .ts.)
  'lib/trust-receipt/issuer.ts',
  'apps/gate-service/src/auth.ts',
  'apps/gate-service/src/config.ts',
  'apps/gate-service/src/github-client.ts',
  'apps/gate-service/src/production-config.ts',
  'apps/gate-service/src/routes.ts',
  'apps/gate-service/src/runtime.ts',
  'apps/gate-service/src/server.ts',
  'apps/gate-service/test/helpers.ts',
  'apps/consequence-control-service/src/routes.ts',
  'apps/consequence-control-service/src/runtime.ts',
  'apps/consequence-control-service/src/github-app.ts',
  'apps/consequence-control-service/src/production-config.ts',
  'apps/consequence-control-service/src/server.ts',
  'apps/secure-app/lib/ep-signoff.ts',
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
  'scripts/check-formal-runtime-traces.mts',
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
  'scripts/check-repository-boundary.ts',
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
];

/**
 * Trees whose EVERY .ts/.mts source gets a companion automatically: these
 * directories are executed by bare `node` in Node-20 CI jobs (or discovered
 * by `node --test`, which on Node 20 only finds .test.js/.test.mjs), so each
 * converted source needs a generated runtime twin without a manual list
 * entry per file. Scanned by companionSources() below.
 */
export const COMPANION_DIR_GLOBS = [
  'examples',
  'conformance',
  'witness',
  'fuzz',
  'attestation',
  'load-tests',
  'bench',
  'mcp-server',
  'cli',
  'integrations',
  'actions',
  'receipt-required-pr-kit',
  // ('formal' is deliberately NOT scanned: the bounded-model and runner .mjs
  // bytes are themselves the recorded proof subject -- the checked-in
  // formal/results summaries pin their exact SHA-256, so those files stay
  // byte-stable handwritten JS, like conformance vectors.)
  'ml',
  'create-ep-app',
  'eslint-rules',
];

/**
 * Package-internal test trees: run via `node --test` on Node 20 in the
 * per-package CI jobs; .test.ts sources need .test.js companions so
 * discovery keeps finding them.
 */
export const COMPANION_PACKAGE_TEST_GLOBS = ['packages'];

function scanTree(fs, dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
    const full = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      scanTree(fs, full, out);
    } else if (/\.m?ts$/.test(entry.name) && !entry.name.endsWith('.d.ts') && !entry.name.endsWith('.d.mts')) {
      out.push(full);
    }
  }
}

/**
 * Full companion source list: the explicit entries above plus every .ts/.mts
 * source under COMPANION_DIR_GLOBS, plus every *.test.ts / *.test.mts under
 * COMPANION_PACKAGE_TEST_GLOBS. Takes the fs module and repo root as
 * arguments so this module itself stays import-side-effect free for config
 * bundlers.
 */
export function companionSources(fs, repoRoot) {
  const out = [...STANDALONE_RUNTIME_SOURCES];
  const seen = new Set(out);
  const scanned = [];
  for (const dir of COMPANION_DIR_GLOBS) scanTree(fs, `${repoRoot}/${dir}`, scanned);
  for (const abs of scanned) {
    const rel = abs.slice(repoRoot.length + 1);
    if (!seen.has(rel)) { seen.add(rel); out.push(rel); }
  }
  const pkgScanned = [];
  for (const dir of COMPANION_PACKAGE_TEST_GLOBS) scanTree(fs, `${repoRoot}/${dir}`, pkgScanned);
  for (const abs of pkgScanned) {
    const rel = abs.slice(repoRoot.length + 1);
    if (!/\.test\.m?ts$/.test(rel)) continue;
    if (!seen.has(rel)) { seen.add(rel); out.push(rel); }
  }
  return out;
}

/** Repo-relative generated-companion paths for the full scanned set. */
export function companionRuntimePaths(fs, repoRoot) {
  return companionSources(fs, repoRoot).map(
    (source) => source.replace(/\.mts$/, '.mjs').replace(/\.ts$/, '.js'),
  );
}

/** Repo-relative generated-companion paths (.ts -> .js, .mts -> .mjs) for
 * the explicit list only; prefer companionRuntimePaths(fs, root). */
export const COMPANION_RUNTIME_PATHS = STANDALONE_RUNTIME_SOURCES.map(
  (source) => source.replace(/\.mts$/, '.mjs').replace(/\.ts$/, '.js'),
);

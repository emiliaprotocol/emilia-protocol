/**
 * The LIVE reproducible-build link for the attestation chain.
 *
 * Wraps the repository's existing deterministic packager
 * (scripts/verify-reproducible-package.mjs, `npm run release:verify:reproducible`)
 * as the `rebuild` function verifyBuildAttestation() expects. The packager builds
 * the artifact TWICE from a canonicalized input and refuses if the bytes differ,
 * so the sha256 it returns is a determinism-proven binary hash.
 *
 * BOUNDARY (honest): this rebuilds the package as it exists in the CURRENT
 * worktree. It does NOT itself check out an arbitrary historical commit — that is
 * the job of the build harness (git checkout <commit> && npm ci) that runs this.
 * When invoked as the rebuild link, the caller is responsible for having the
 * pinned source.commit checked out; verifyBuildAttestation compares the resulting
 * hash to the record's claimed binary hash, which is where "binary == build of
 * source" is actually enforced.
 *
 * @license Apache-2.0
 */

import { verifyReproduciblePackage } from '../scripts/verify-reproducible-package.mjs';

/**
 * A rebuild function suitable for verifyBuildAttestation({ rebuild }).
 * @param {{ commit: string, package_path: string }} source
 * @returns {{ sha256: string, filename: string, bytes: number }}
 */
export function reproducibleRebuild(source) {
  const result = verifyReproduciblePackage(source.package_path);
  return { sha256: result.sha256, filename: result.filename, bytes: result.bytes };
}

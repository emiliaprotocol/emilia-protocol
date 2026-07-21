#!/usr/bin/env node
// Generated from verify-cli.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP build-attestation CLI.
 *
 *   node attestation/verify-cli.mjs emit <package_path>
 *       Reproducibly builds <package_path> from the current worktree, assembles a
 *       single-leaf EP-BUILD-ATTESTATION-v1 record for HEAD, prints it as JSON.
 *
 *   node attestation/verify-cli.mjs verify <record.json> [--rebuild]
 *       Verifies a record offline (leaf binding + log inclusion). With --rebuild,
 *       also runs the live reproducible build and enforces binary == build of
 *       source. The live rebuild refuses unless the CURRENT worktree is clean
 *       and HEAD exactly equals the pinned commit.
 *
 *   node attestation/verify-cli.mjs demo <package_path>
 *       End-to-end: builds twice (determinism proof), assembles a record, verifies
 *       the full software chain with the live rebuild link, prints the result.
 *
 * @license Apache-2.0
 */
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { verifyBuildAttestation } from './build-attestation.js';
import { assembleRecord } from './merkle-log.js';
import { reproducibleRebuild } from './reproducible-rebuild.mjs';
function headCommit() {
    return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}
function emit(packagePath) {
    const commit = headCommit();
    const built = reproducibleRebuild({ commit, package_path: packagePath });
    return assembleRecord({ commit, package_path: packagePath }, { filename: built.filename, sha256: built.sha256, bytes: built.bytes });
}
function main() {
    const [cmd, arg, ...rest] = process.argv.slice(2);
    if (cmd === 'emit') {
        if (!arg)
            throw new Error('usage: emit <package_path>');
        process.stdout.write(JSON.stringify(emit(arg), null, 2) + '\n');
        return;
    }
    if (cmd === 'verify') {
        if (!arg)
            throw new Error('usage: verify <record.json> [--rebuild]');
        const record = JSON.parse(fs.readFileSync(arg, 'utf8'));
        const opts = rest.includes('--rebuild') ? { rebuild: reproducibleRebuild } : {};
        const result = verifyBuildAttestation(record, opts);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
        process.exit(result.valid ? 0 : 1);
    }
    if (cmd === 'demo') {
        const packagePath = arg || 'packages/verify';
        const commit = headCommit();
        // Determinism proof: build twice, show identical hashes.
        const a = reproducibleRebuild({ commit, package_path: packagePath });
        const b = reproducibleRebuild({ commit, package_path: packagePath });
        const record = assembleRecord({ commit, package_path: packagePath }, { filename: a.filename, sha256: a.sha256, bytes: a.bytes });
        const result = verifyBuildAttestation(record, { rebuild: reproducibleRebuild });
        process.stdout.write(JSON.stringify({
            determinism_proof: { build_1_sha256: a.sha256, build_2_sha256: b.sha256, identical: a.sha256 === b.sha256 },
            record,
            verification: result,
        }, null, 2) + '\n');
        process.exit(result.valid && result.complete && a.sha256 === b.sha256 ? 0 : 1);
    }
    throw new Error('usage: emit|verify|demo');
}
main();

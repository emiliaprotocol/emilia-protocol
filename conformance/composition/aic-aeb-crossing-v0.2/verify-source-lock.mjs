// SPDX-License-Identifier: Apache-2.0
// Generated from verify-source-lock.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const SOURCE_LOCK_BYTES = readFileSync(new URL('./source-lock.json', import.meta.url));
const SOURCE_LOCK = JSON.parse(SOURCE_LOCK_BYTES.toString('utf8'));
function sha256(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
const GITHUB_REPOSITORY_PATTERN = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/;
const GIT_REVISION_PATTERN = /^[0-9a-f]{40}$/;
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function inspectedRepository(sourceLock, repositoryUrl, revision) {
    const repositories = sourceLock?.varwof?.repositories;
    if (!Array.isArray(repositories)) {
        throw new Error('source lock Varwof repositories must be an array');
    }
    const matches = repositories.filter((entry) => (entry?.repository === repositoryUrl && entry?.revision === revision));
    if (matches.length !== 1) {
        throw new Error(`source lock inspection scope must match one pinned repository revision: ${repositoryUrl}@${revision}`);
    }
    return matches[0];
}
function assertInspectedPath(repository, path) {
    if (!Array.isArray(repository?.inspected_files)
        || !repository.inspected_files.some((entry) => entry?.path === path)) {
        throw new Error(`source lock inspection claim references an unpinned path: ${path}`);
    }
}
export function assertAicInspectionBoundary(sourceLock = SOURCE_LOCK) {
    const inspection = sourceLock?.inspection;
    if (!isRecord(inspection) || !isRecord(inspection.scope)) {
        throw new Error('source lock inspection boundary is missing');
    }
    const { repository, revision } = inspection.scope;
    if (repository !== 'https://github.com/varwof/gateway-core'
        || typeof revision !== 'string'
        || !GIT_REVISION_PATTERN.test(revision)) {
        throw new Error('source lock inspection scope must pin the gateway-core revision');
    }
    const pinnedRepository = inspectedRepository(sourceLock, repository, revision);
    const bearer = inspection.gateway_bearer_bridge;
    if (!isRecord(bearer) || bearer.path !== 'jwt.go') {
        throw new Error('source lock bearer-bridge inspection is missing');
    }
    assertInspectedPath(pinnedRepository, bearer.path);
    if (bearer.gateway_module_manifest_path !== 'go.mod'
        || bearer.gateway_types_module_version !== 'v0.4.0'
        || bearer.gateway_types_module_revision
            !== '76f725ffc375ae7fda1f0255ea3e12a0074f6c4c') {
        throw new Error('source lock bearer-bridge module resolution changed');
    }
    assertInspectedPath(pinnedRepository, bearer.gateway_module_manifest_path);
    const resolvedTypes = inspectedRepository(sourceLock, 'https://github.com/varwof/types', bearer.gateway_types_module_revision);
    if (resolvedTypes.resolved_module_version !== bearer.gateway_types_module_version
        || resolvedTypes.consumed_by
            !== `${repository}@${revision}`) {
        throw new Error('source lock bearer-bridge dependency resolution changed');
    }
    assertInspectedPath(resolvedTypes, 'aicjwt/validate.go');
    assertInspectedPath(resolvedTypes, 'aicjwt/keyhash.go');
    const requiredBearerFacts = {
        verify_bearer_returns_synthesized_certificate: true,
        verify_bearer_returns_outer_claims: true,
        verify_bearer_sets_expected_audience: false,
        verify_bearer_sets_request_capability: false,
        verify_bearer_sets_principal_material: false,
        verify_bearer_sets_presenter_key: false,
        synthesized_certificate_sets_raw_der: false,
        synthesized_certificate_sets_raw_spki: false,
        synthesized_certificate_sets_public_key: false,
        authenticated_original_carrier_provenance_returned: false,
        non_test_verify_bearer_call_sites_observed: false,
        jwt_mapping_requires_original_compact_token: true,
        local_mapping_derives_compact_token_audience: true,
        local_mapping_derives_presented_jwk_thumbprint: true,
        local_mapping_proves_presenter_key_possession: false,
        separate_authenticated_capability_evaluation_required: true,
        synthesized_certificate_admissible_to_native_x509_mapping: false,
    };
    for (const [name, expected] of Object.entries(requiredBearerFacts)) {
        if (bearer[name] !== expected) {
            throw new Error(`source lock bearer-bridge inspection fact changed: ${name}`);
        }
    }
    const bundle = inspection.native_x509_bundle;
    if (!isRecord(bundle) || bundle.path !== 'credential_bundle.go') {
        throw new Error('source lock native-X.509 inspection is missing');
    }
    assertInspectedPath(pinnedRepository, bundle.path);
    const requiredBundleFacts = {
        requires_nonempty_agent_and_principal_chains: true,
        enforces_distinct_agent_and_principal_leaf_der: false,
        compares_principal_key_hash_to_principal_certificate_spki: true,
        local_mapping_requires_exact_certificate_der: true,
        local_mapping_requires_distinct_agent_and_principal_der: true,
    };
    for (const [name, expected] of Object.entries(requiredBundleFacts)) {
        if (bundle[name] !== expected) {
            throw new Error(`source lock native-X.509 inspection fact changed: ${name}`);
        }
    }
    if (bundle.principal_spki_hash_algorithm !== 'sha-256') {
        throw new Error('source lock native-X.509 SPKI algorithm changed');
    }
    const wiring = inspection.upstream_wiring;
    if (!isRecord(wiring)
        || wiring.cross_process_authenticated_provenance_wrapper_required !== true
        || wiring.deployed_wiring_verified !== false) {
        throw new Error('source lock upstream wiring boundary changed');
    }
}
export function assertAicRawRepositoryFileUrl(repositoryUrl, revision, inspectedPath, rawUrl) {
    const repositoryMatch = GITHUB_REPOSITORY_PATTERN.exec(repositoryUrl);
    if (!repositoryMatch) {
        throw new Error(`source lock repository must be an exact https://github.com/{owner}/{name} URL: ${repositoryUrl}`);
    }
    if (!GIT_REVISION_PATTERN.test(revision)) {
        throw new Error(`source lock revision must be an exact lowercase 40-hex commit: ${revision}`);
    }
    const pathSegments = inspectedPath.split('/');
    if (inspectedPath.length === 0
        || inspectedPath.startsWith('/')
        || inspectedPath.endsWith('/')
        || inspectedPath.includes('\\')
        || inspectedPath.includes('?')
        || inspectedPath.includes('#')
        || inspectedPath.includes('%')
        || pathSegments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
        throw new Error(`source lock inspected path must be a safe relative POSIX path: ${inspectedPath}`);
    }
    const [, owner, repository] = repositoryMatch;
    const expectedRawUrl = `https://raw.githubusercontent.com/${owner}/${repository}/${revision}/${inspectedPath}`;
    let parsedRawUrl;
    try {
        parsedRawUrl = new URL(rawUrl);
    }
    catch {
        throw new Error(`source lock raw URL is invalid: ${rawUrl}`);
    }
    if (rawUrl !== expectedRawUrl
        || parsedRawUrl.href !== rawUrl
        || parsedRawUrl.protocol !== 'https:'
        || parsedRawUrl.hostname !== 'raw.githubusercontent.com'
        || parsedRawUrl.username !== ''
        || parsedRawUrl.password !== ''
        || parsedRawUrl.port !== ''
        || parsedRawUrl.search !== ''
        || parsedRawUrl.hash !== '') {
        throw new Error(`source lock raw URL does not match declared repository, revision, and path: expected ${expectedRawUrl}, got ${rawUrl}`);
    }
}
export async function verifyAicSourceLock(fetchBytes = async (url) => {
    const response = await fetch(url, {
        headers: { accept: 'application/octet-stream, text/plain;q=0.9, */*;q=0.1' },
        redirect: 'error',
    });
    if (!response.ok)
        throw new Error(`source fetch failed: ${response.status} ${url}`);
    return new Uint8Array(await response.arrayBuffer());
}) {
    assertAicInspectionBoundary();
    const sources = [
        ...SOURCE_LOCK.drafts.map((entry) => ({
            name: entry.name,
            url: entry.url,
            expected_sha256: entry.sha256,
        })),
        ...SOURCE_LOCK.varwof.repositories.flatMap((repository) => (repository.inspected_files.map((entry) => {
            assertAicRawRepositoryFileUrl(repository.repository, repository.revision, entry.path, entry.url);
            return {
                name: `${repository.repository}@${repository.revision}:${entry.path}`,
                url: entry.url,
                expected_sha256: entry.sha256,
            };
        }))),
    ];
    const verified = [];
    for (const source of sources) {
        const bytes = await fetchBytes(source.url);
        const actual = sha256(bytes);
        if (actual !== source.expected_sha256) {
            throw new Error(`source lock mismatch for ${source.name}: expected ${source.expected_sha256}, got ${actual}`);
        }
        verified.push({
            name: source.name,
            url: source.url,
            sha256: actual,
            bytes: bytes.byteLength,
            verified: true,
        });
    }
    return {
        profile: 'AIC-AEB-CROSSING-SOURCE-LOCK-VERIFICATION-v1',
        source_lock_file_sha256: `sha256:${sha256(SOURCE_LOCK_BYTES)}`,
        sources: verified,
        passed: true,
    };
}
async function main() {
    process.stdout.write(`${JSON.stringify(await verifyAicSourceLock(), null, 2)}\n`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    await main();
}

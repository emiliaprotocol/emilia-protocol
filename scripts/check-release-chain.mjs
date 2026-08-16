#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from check-release-chain.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'release/release-packages.v1.json';
const WORKFLOW_DIR = '.github/workflows';
const REPOSITORY_URL = 'https://github.com/emiliaprotocol/emilia-protocol.git';
const SKIP_DIRS = new Set(['.git', '.next', '.venv', 'node_modules', 'release-artifacts']);
const CANONICAL_SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const RELEASE_ACTION_REFS = Object.freeze({
    checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    setupJava: 'actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961',
    attest: 'actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d',
    pypiPublish: 'pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33',
});
export function isCanonicalNpmRepositoryUrl(value) {
    if (typeof value !== 'string')
        return false;
    return value === REPOSITORY_URL || value === `git+${REPOSITORY_URL}`;
}
function walkFiles(root, directory = root, files = []) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (entry.isSymbolicLink())
            continue;
        const absolute = path.join(directory, entry.name);
        const relative = path.relative(root, absolute).split(path.sep).join('/');
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.stryker-') || relative.startsWith('conformance/clean-room/frozen-v1/'))
                continue;
            walkFiles(root, absolute, files);
        }
        else if (entry.isFile() && (entry.name === 'package.json'
            || entry.name === 'pyproject.toml'
            || entry.name === 'go.mod')) {
            files.push(absolute);
        }
    }
    return files;
}
function pythonProjectName(text, source) {
    const marker = text.search(/^\[project\]\s*$/m);
    if (marker < 0)
        throw new Error(`${source} has no [project] table`);
    const remainder = text.slice(marker).replace(/^\[project\]\s*\n?/m, '');
    const nextTable = remainder.search(/^\[/m);
    const section = nextTable >= 0 ? remainder.slice(0, nextTable) : remainder;
    const name = section.match(/^name\s*=\s*["']([^"']+)["']\s*$/m)?.[1];
    if (!name)
        throw new Error(`${source} has no parseable [project].name`);
    return name;
}
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
export function discoverReleaseSurfaces(root = ROOT) {
    const surfaces = [];
    for (const absolute of walkFiles(root)) {
        const relativeFile = path.relative(root, absolute).split(path.sep).join('/');
        const packagePath = path.posix.dirname(relativeFile) === '.' ? '.' : path.posix.dirname(relativeFile);
        if (absolute.endsWith('package.json')) {
            const metadata = JSON.parse(fs.readFileSync(absolute, 'utf8'));
            if (metadata.private === true || typeof metadata.name !== 'string')
                continue;
            surfaces.push({ ecosystem: 'npm', package: metadata.name, path: packagePath });
        }
        else if (absolute.endsWith('pyproject.toml')) {
            const text = fs.readFileSync(absolute, 'utf8');
            surfaces.push({ ecosystem: 'pypi', package: pythonProjectName(text, relativeFile), path: packagePath });
        }
        else {
            const goMod = fs.readFileSync(absolute, 'utf8');
            const module = goMod.match(/^module\s+(\S+)\s*$/m)?.[1];
            const releasePath = path.join(path.dirname(absolute), 'go-release.json');
            if (!module || !fs.existsSync(releasePath)) {
                throw new Error(`${relativeFile} is missing an explicit go-release.json classification`);
            }
            const metadata = JSON.parse(fs.readFileSync(releasePath, 'utf8'));
            if (metadata['@version'] !== 'EP-GO-MODULE-RELEASE-v1'
                || metadata.module !== module
                || !new RegExp(`^module\\s+${escapeRegExp(metadata.module)}\\s*$`, 'm').test(goMod)) {
                throw new Error(`${relativeFile} is not bound to its Go module release classification`);
            }
            if (metadata.private === true) {
                if (typeof metadata.reason !== 'string' || metadata.reason.trim().length < 20
                    || metadata.version !== undefined || metadata.tag !== undefined) {
                    throw new Error(`${relativeFile} has a malformed private Go module classification`);
                }
                continue;
            }
            if (typeof metadata.version !== 'string' || typeof metadata.tag !== 'string') {
                throw new Error(`${relativeFile} has no public Go release identity`);
            }
            surfaces.push({ ecosystem: 'go', package: metadata.module, path: packagePath });
        }
    }
    return surfaces.sort((a, b) => `${a.ecosystem}:${a.package}`.localeCompare(`${b.ecosystem}:${b.package}`));
}
function requireText(text, needles, label) {
    const missing = needles.filter((needle) => !text.includes(needle));
    if (missing.length)
        throw new Error(`${label} is missing release controls: ${missing.join(', ')}`);
}
function requireBefore(text, earlier, later, label) {
    const earlierIndex = text.indexOf(earlier);
    const laterIndex = text.indexOf(later);
    if (earlierIndex < 0 || laterIndex < 0 || earlierIndex >= laterIndex) {
        throw new Error(`${label} must run ${earlier} before ${later}`);
    }
}
function requireOnlyActionRef(text, expected, label) {
    const action = expected.slice(0, expected.lastIndexOf('@'));
    const actionPattern = new RegExp(`${escapeRegExp(action)}@[^\\s#"']+`, 'gu');
    const refs = text.match(actionPattern) ?? [];
    if (refs.length === 0 || refs.some((ref) => ref !== expected)) {
        throw new Error(`${label} must use only ${expected}`);
    }
}
function forbidCredentialInjection(text, label) {
    if (/^\s*(?:NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|PYPI_API_TOKEN)\s*:/m.test(text)
        || /^\s*password\s*:/m.test(text)) {
        throw new Error(`${label} injects a long-lived publication credential`);
    }
}
export function validateTlaSecurityCaseWorkflowText(text, label, evidenceCommand = 'npm run security-case:emit') {
    requireText(text, [
        'TLA2TOOLS_JAR: ${{ github.workspace }}/tla2tools.jar',
        RELEASE_ACTION_REFS.setupJava,
        'distribution: temurin',
        "java-version: '17'",
        'TLA_VERSION: v1.7.4',
        'TLA_SHA256: 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88',
        '"https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"',
        'echo "${TLA_SHA256}  tla2tools.jar" | sha256sum -c -',
    ], `${label} TLA+ execution guard`);
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.setupJava, `${label} Java setup action`);
    requireBefore(text, RELEASE_ACTION_REFS.setupJava, evidenceCommand, `${label} Java 17 guard`);
    requireBefore(text, 'echo "${TLA_SHA256}  tla2tools.jar" | sha256sum -c -', evidenceCommand, `${label} TLA+ checksum guard`);
    return true;
}
function validateManualPublisher(text, label, { direct, commitBound = false, protectedPublisher = false, }) {
    if (/^[ \t]{2}push:/m.test(text))
        throw new Error(`${label} publishes from an automatic push trigger`);
    requireText(text, [
        'workflow_dispatch:',
        'release_tag:',
        'confirmation:',
        'environment: registry-publishing-approval',
    ], label);
    const workflow = YAML.parse(text);
    const publish = workflow?.jobs?.publish;
    const approval = workflow?.jobs?.approval;
    const dependencies = Array.isArray(publish?.needs) ? publish.needs : [publish?.needs];
    const publishIsProtected = publish?.environment === 'registry-publishing-approval';
    const approvalIsProtected = dependencies.includes('approval')
        && approval?.environment === 'registry-publishing-approval'
        && Object.keys(approval?.permissions ?? {}).length === 0;
    if (protectedPublisher) {
        if (!publishIsProtected || publish?.permissions?.['id-token'] !== 'write') {
            throw new Error(`${label} does not put the OIDC publisher inside the protected approval environment`);
        }
        if (approval) {
            throw new Error(`${label} uses a detached approval job instead of protecting the publisher`);
        }
        if (publish?.uses || !Array.isArray(publish?.steps)) {
            throw new Error(`${label} protected publisher must execute its release steps in the environment job`);
        }
    }
    else if (!publishIsProtected && !approvalIsProtected) {
        throw new Error(`${label} does not bind publication to the protected approval environment`);
    }
    if (direct) {
        requireText(text, [
            'fetch-depth: 0',
            'persist-credentials: false',
            'scripts/require-release-approval.mjs',
            '--allowed-actor FutureEnterprises',
            'concurrency:',
            'cancel-in-progress: false',
        ], label);
        if (commitBound) {
            requireText(text, [
                'ref: ${{ github.sha }}',
                '--expected-commit "$GITHUB_SHA"',
                '--expected-ref "$GITHUB_REF"',
            ], label);
        }
    }
}
export function validateReusableNpmWorkflowText(text) {
    requireText(text, [
        'environment: registry-publishing-approval',
        'npm run check:security-case',
        'npm run conformance:manifest:check',
        'verify-reproducible-package.mjs',
        'run: npm test',
        'actions/upload-artifact@',
        'actions/download-artifact@',
        'artifact-ids: ${{ needs.build.outputs.release_artifact_id }}',
        RELEASE_ACTION_REFS.attest,
        'subject-path: ${{ steps.validate.outputs.tarball }}',
        'npm publish "./${TESTED_TARBALL#./}" --access public --provenance --ignore-scripts',
        'cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"',
        'ref: ${{ github.sha }}',
        'persist-credentials: false',
        'scripts/require-release-approval.mjs',
        '--allowed-actor FutureEnterprises',
        '--expected-commit "$GITHUB_SHA"',
        '--expected-ref "$GITHUB_REF"',
        '--package-json "$PACKAGE_DIR/package.json"',
        'package_json_sha256',
        'tarball package/package.json bytes differ from approved source package.json',
        'duplicate npm tarball path',
        'npm tarball links are forbidden',
        'unexpected release artifact inventory',
        'duplicate release artifact path',
        'release artifact path escapes extraction root',
        'release artifact symlink is forbidden',
        'dependency-pins.json',
        'internal dependency unavailable from npm',
        'git ls-remote --exit-code https://github.com/emiliaprotocol/emilia-protocol.git',
        'already exists; refusing to publish',
        'response.status !== 404',
        'node scripts/check-npm-package-dependencies.mjs --install-pinned "$PACKAGE_DIR"',
        'group: registry-publish-${{ inputs.package_name }}',
    ], 'reusable npm workflow');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.checkout, 'reusable npm workflow checkout action');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.attest, 'reusable npm workflow attestation action');
    if (text.includes('ref: ${{ inputs.release_tag }}')
        || text.includes('already exists; continuing to mandatory byte verification')
        || /\bgit ls-remote\b[^\n]*(?:\borigin\b|remote\.origin|git config)/u.test(text)) {
        throw new Error('reusable npm workflow follows mutable release input or treats an existing version as success');
    }
    const workflow = YAML.parse(text);
    const jobs = workflow?.jobs ?? {};
    const build = jobs.build;
    const publisher = jobs.publisher;
    if (JSON.stringify(Object.keys(jobs)) !== JSON.stringify(['build', 'publisher'])) {
        throw new Error('reusable npm workflow must contain only unprivileged build and protected publisher jobs');
    }
    const permissions = workflow?.permissions ?? {};
    const expectedPermissions = { contents: 'read' };
    if (JSON.stringify(permissions) !== JSON.stringify(expectedPermissions)) {
        throw new Error('reusable npm workflow grants OIDC outside the protected publisher');
    }
    if (build?.environment !== undefined
        || JSON.stringify(build?.permissions ?? {}) !== JSON.stringify({ contents: 'read' })
        || !Array.isArray(build?.steps)
        || build.steps.some((step) => step.uses?.startsWith('actions/attest@'))) {
        throw new Error('reusable npm build job is not unprivileged');
    }
    if (publisher?.needs !== 'build'
        || publisher?.environment !== 'registry-publishing-approval'
        || JSON.stringify(publisher?.permissions ?? {}) !== JSON.stringify({
            contents: 'read',
            'id-token': 'write',
            attestations: 'write',
        })
        || !Array.isArray(publisher?.steps)
        || publisher.steps.some((step) => step.uses?.startsWith('actions/checkout@'))
        || publisher.steps.some((step) => typeof step.run === 'string'
            && (step.run.includes('scripts/')
                || /\bnpm (?:test|run|ci|install|exec)\b/u.test(step.run)))) {
        throw new Error('reusable npm publisher is not an inert protected OIDC job');
    }
    const download = publisher.steps.find((step) => /^actions\/download-artifact@[0-9a-f]{40}$/u.test(step.uses ?? ''));
    if (download?.with?.['artifact-ids'] !== '${{ needs.build.outputs.release_artifact_id }}'
        || download?.with?.name !== undefined) {
        throw new Error('reusable npm publisher does not download the immutable exact artifact ID');
    }
    requireBefore(text, 'scripts/require-release-approval.mjs', 'run: npm test', 'reusable npm workflow');
    requireBefore(text, 'git ls-remote --exit-code https://github.com/emiliaprotocol/emilia-protocol.git', 'npm publish "./${TESTED_TARBALL#./}" --access public --provenance --ignore-scripts', 'reusable npm remote ref guard');
    validateTlaSecurityCaseWorkflowText(text, 'reusable npm workflow', 'npm run check:security-case');
    forbidCredentialInjection(text, 'reusable npm workflow');
    return true;
}
export function validateReusableNpmCallerText(text, label) {
    if (/^[ \t]{2}push:/m.test(text))
        throw new Error(`${label} publishes from an automatic push trigger`);
    requireText(text, [
        'workflow_dispatch:',
        'release_tag:',
        'confirmation:',
        'uses: ./.github/workflows/_publish-npm-package.yml',
    ], label);
    const workflow = YAML.parse(text);
    const jobs = workflow?.jobs ?? {};
    if (JSON.stringify(Object.keys(jobs)) !== JSON.stringify(['publish'])) {
        throw new Error(`${label} must delegate only to the protected reusable publisher`);
    }
    const publish = jobs.publish;
    if (publish?.uses !== './.github/workflows/_publish-npm-package.yml'
        || publish?.needs !== undefined
        || publish?.environment !== undefined) {
        throw new Error(`${label} uses a detached or caller-side approval instead of the reusable protected publisher`);
    }
    const expectedPermissions = {
        contents: 'read',
        'id-token': 'write',
        attestations: 'write',
    };
    if (JSON.stringify(publish?.permissions ?? {}) !== JSON.stringify(expectedPermissions)) {
        throw new Error(`${label} does not grant the reusable publisher its exact OIDC permissions`);
    }
    return true;
}
export function validateReusablePypiWorkflowText(text) {
    requireText(text, [
        'environment: registry-publishing-approval',
        'npm run security-case:emit',
        'npm run conformance:manifest',
        'verify-reproducible-wheel.mjs',
        'python -m pytest',
        RELEASE_ACTION_REFS.attest,
        'subject-path: ${{ steps.build.outputs.wheel }}',
        'subject-path: ${{ steps.build.outputs.sdist }}',
        RELEASE_ACTION_REFS.pypiPublish,
        'cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"',
        'cmp "${{ steps.build.outputs.sdist }}" "$REGISTRY_SDIST"',
        'scripts/require-release-approval.mjs',
        'group: registry-publish-pypi-${{ inputs.package_name }}',
    ], 'reusable PyPI workflow');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.checkout, 'reusable PyPI workflow checkout action');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.attest, 'reusable PyPI workflow attestation action');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.pypiPublish, 'reusable PyPI workflow publish action');
    const workflow = YAML.parse(text);
    const publish = workflow?.jobs?.publish;
    if (JSON.stringify(Object.keys(workflow?.jobs ?? {})) !== JSON.stringify(['publish'])
        || publish?.environment !== 'registry-publishing-approval'
        || publish?.permissions?.['id-token'] !== 'write') {
        throw new Error('reusable PyPI workflow does not put its OIDC publisher inside the protected approval environment');
    }
    validateTlaSecurityCaseWorkflowText(text, 'reusable PyPI workflow');
    forbidCredentialInjection(text, 'reusable PyPI workflow');
    return true;
}
export function validateGoTagWorkflowText(text) {
    requireText(text, [
        'workflow_dispatch:',
        'release_tag:',
        'confirmation:',
        'environment: registry-publishing-approval',
        'ref: ${{ github.sha }}',
        'fetch-depth: 0',
        'persist-credentials: false',
        'scripts/require-release-approval.mjs',
        '--unpublished-tag',
        '--allowed-actor FutureEnterprises',
        '--tag-prefix packages/go-verify/v',
        '--expected-commit "$GITHUB_SHA"',
        'go-version-file: packages/go-verify/go.mod',
        'go vet ./...',
        'go test ./...',
        'npm run security-case:emit',
        'npm run conformance:manifest',
        RELEASE_ACTION_REFS.attest,
        'github.rest.git.createRef',
        "context.ref !== 'refs/heads/main'",
        "includes.includes('refs/tags/packages/go-verify/v*')",
        "rules.has('deletion') && rules.has('update')",
        'GOPROXY: https://proxy.golang.org',
        'go mod download -json',
        'p.Origin?.[key]',
        'p.GoModSum',
        'diff -ru packages/go-verify "$PROXY_DIR"',
        'release-artifacts/go-verify-proxy.zip',
    ], 'Go tag workflow');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.checkout, 'Go tag workflow checkout action');
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.attest, 'Go tag workflow attestation action');
    let workflow;
    try {
        workflow = YAML.parse(text);
    }
    catch (error) {
        throw new Error(`Go tag workflow is not valid YAML: ${error.message}`);
    }
    const triggers = workflow?.on;
    if (!triggers || typeof triggers !== 'object'
        || JSON.stringify(Object.keys(triggers).sort()) !== JSON.stringify(['workflow_dispatch'])) {
        throw new Error('Go tag workflow must be manual-dispatch only');
    }
    const jobs = workflow.jobs || {};
    const preflight = jobs.preflight;
    const approval = jobs.approval;
    const createTag = jobs.create_tag;
    const verifyProxy = jobs.verify_proxy;
    if (!preflight || !approval || !createTag || !verifyProxy) {
        throw new Error('Go tag workflow must separate preflight, approval, tag creation, and proxy verification');
    }
    const needs = (job, dependency) => {
        const value = job?.needs;
        return Array.isArray(value) ? value.includes(dependency) : value === dependency;
    };
    if (preflight.permissions?.contents !== 'read' || preflight.permissions?.['id-token'] !== 'write'
        || preflight.permissions?.attestations !== 'write') {
        throw new Error('Go preflight must have read-only source plus attestation permissions');
    }
    if (!needs(approval, 'preflight') || approval.environment !== 'registry-publishing-approval'
        || Object.keys(approval.permissions || {}).length !== 0) {
        throw new Error('Go release approval must follow preflight and hold no token permissions');
    }
    if (!needs(createTag, 'preflight') || !needs(createTag, 'approval')
        || createTag.permissions?.contents !== 'write'
        || Object.keys(createTag.permissions || {}).some((key) => key !== 'contents')) {
        throw new Error('Go tag creation must be the isolated contents-write job after approval');
    }
    const createSteps = createTag.steps || [];
    if (createSteps.length !== 1 || createSteps.some((step) => step.run || !/^actions\/github-script@[0-9a-f]{40}$/.test(step.uses || ''))) {
        throw new Error('Go tag creation may run only a commit-pinned GitHub API action, never repository code');
    }
    if (!needs(verifyProxy, 'preflight') || !needs(verifyProxy, 'create_tag')
        || verifyProxy.permissions?.contents !== 'read'
        || verifyProxy.permissions?.['id-token'] !== 'write'
        || verifyProxy.permissions?.attestations !== 'write') {
        throw new Error('Go proxy verification must be read-only and follow exact tag creation');
    }
    for (const [jobName, job] of Object.entries(jobs)) {
        if (jobName !== 'create_tag' && job.permissions?.contents === 'write') {
            throw new Error(`Go release job ${jobName} may not hold contents write permission`);
        }
    }
    for (const job of [preflight, verifyProxy]) {
        const checkout = (job.steps || []).find((step) => /^actions\/checkout@[0-9a-f]{40}$/.test(step.uses || ''));
        if (!checkout || checkout.with?.ref !== '${{ github.sha }}' || checkout.with?.['persist-credentials'] !== false) {
            throw new Error('Go release code execution must check out the dispatched SHA without persisted credentials');
        }
    }
    for (const job of Object.values(jobs)) {
        for (const step of job.steps || []) {
            const artifactName = step.with?.name;
            if (typeof artifactName === 'string' && (artifactName.includes('inputs.release_tag') || artifactName.includes('/'))) {
                throw new Error('Go release artifact names must be slash-free and version-derived');
            }
        }
    }
    if (/\bgit\s+(?:push|tag)\b/.test(text)) {
        throw new Error('Go release workflow may not grant repository code a Git write primitive');
    }
    validateTlaSecurityCaseWorkflowText(text, 'Go tag workflow');
    forbidCredentialInjection(text, 'Go tag workflow');
    return true;
}
export function validateCredentialRotationGuideText(text) {
    const normalized = text.replace(/\s+/g, ' ');
    requireText(normalized, [
        'A local or CI write token is not a supported fallback.',
        'Do not create a replacement publish token.',
        "npm config delete //registry.npmjs.org/:_authToken --location=user",
        'A broken OIDC relationship must fail closed.',
    ], 'credential rotation guide');
    if (/Create a fresh[^\n]*Access Token/i.test(text)
        || /_authToken=NEW_TOKEN/i.test(text)
        || /New granular token created/i.test(text)) {
        throw new Error('credential rotation guide reintroduces a publication-token fallback');
    }
    return true;
}
export function validateNpmDirect(text, label) {
    return validateReusableNpmCallerText(text, label);
}
export function validateGateNpmWorkflowText(text, label = 'publish-gate.yml') {
    return validateReusableNpmCallerText(text, label);
}
export function validatePypiDirect(text, label) {
    requireText(text, [
        'npm run security-case:emit',
        'npm run conformance:manifest',
        'verify-reproducible-wheel.mjs',
        'python -m pytest',
        'subject-path: ${{ steps.build.outputs.wheel }}',
        'subject-path: ${{ steps.build.outputs.sdist }}',
        RELEASE_ACTION_REFS.attest,
        RELEASE_ACTION_REFS.pypiPublish,
        'cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"',
        'cmp "${{ steps.build.outputs.sdist }}" "$REGISTRY_SDIST"',
        'scripts/require-release-approval.mjs',
    ], label);
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.checkout, `${label} checkout action`);
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.attest, `${label} attestation action`);
    requireOnlyActionRef(text, RELEASE_ACTION_REFS.pypiPublish, `${label} publish action`);
    validateManualPublisher(text, label, { direct: true, protectedPublisher: true });
    validateTlaSecurityCaseWorkflowText(text, label);
    forbidCredentialInjection(text, label);
    return true;
}
function exactInput(text, key, value) {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`^\\s*${key}:\\s*['\"]?${escaped}['\"]?\\s*$`, 'm').test(text);
}
export function validateNpmLockData(metadata, lock, label) {
    const root = lock?.packages?.[''];
    if (!root || lock.lockfileVersion !== 3)
        throw new Error(`${label} is not an npm lockfile v3`);
    if (lock.name !== metadata.name || lock.version !== metadata.version
        || root.name !== metadata.name || root.version !== metadata.version) {
        throw new Error(`${label} package identity/version differs from package.json`);
    }
    for (const field of ['dependencies', 'optionalDependencies', 'devDependencies']) {
        const declared = metadata[field] ?? {};
        const locked = root[field] ?? {};
        if (JSON.stringify(declared) !== JSON.stringify(locked)) {
            throw new Error(`${label} ${field} differs from package.json`);
        }
    }
    for (const [dependency, range] of Object.entries({
        ...(metadata.dependencies ?? {}),
        ...(metadata.optionalDependencies ?? {}),
    })) {
        if (!dependency.startsWith('@emilia-protocol/'))
            continue;
        const pinnedFloor = typeof range === 'string' ? range.replace(/^[~^]/, '') : null;
        const resolved = lock.packages[`node_modules/${dependency}`]?.version;
        if (!pinnedFloor || resolved !== pinnedFloor) {
            throw new Error(`${label} does not lock ${dependency} to its declared security floor ${range}`);
        }
    }
    return true;
}
export function auditReleaseChain(root = ROOT) {
    if (fs.existsSync(path.join(root, 'scripts/publish-verify.sh'))) {
        throw new Error('direct local npm publication script is forbidden');
    }
    if (fs.existsSync(path.join(root, WORKFLOW_DIR, 'release.yml'))) {
        throw new Error('generic tag-triggered release provenance is forbidden; exact package publishers own provenance');
    }
    const pythonReadme = fs.readFileSync(path.join(root, 'packages/python-verify/README.md'), 'utf8');
    if (/\btwine\s+upload\b/.test(pythonReadme))
        throw new Error('direct local PyPI upload instructions are forbidden');
    validateCredentialRotationGuideText(fs.readFileSync(path.join(root, 'docs/operations/CREDENTIAL-ROTATION-CHECKLIST.md'), 'utf8'));
    const registryPath = path.join(root, REGISTRY);
    const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
    if (registry['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1' || !Array.isArray(registry.packages)) {
        throw new Error('release package registry is malformed');
    }
    const releaseRequirements = fs.readFileSync(path.join(root, '.github/workflow-requirements/release.in'), 'utf8');
    const hatchlingVersion = releaseRequirements.match(/^hatchling==([^\s]+)$/m)?.[1];
    if (!hatchlingVersion)
        throw new Error('release toolchain does not pin hatchling');
    const pinnedHatchling = new RegExp(`requires\\s*=\\s*\\["hatchling==${escapeRegExp(hatchlingVersion)}"\\]`);
    const reusablePath = path.join(root, WORKFLOW_DIR, '_publish-npm-package.yml');
    validateReusableNpmWorkflowText(fs.readFileSync(reusablePath, 'utf8'));
    const seenPackages = new Set();
    const seenWorkflows = new Set();
    const seenTagPrefixes = new Set();
    for (const entry of registry.packages) {
        const validTagPrefix = entry?.ecosystem === 'go'
            ? entry.tag_prefix === `${entry.path}/v`
            : /^[a-z0-9-]+-v$/.test(entry?.tag_prefix ?? '');
        if (!entry || typeof entry.package !== 'string' || typeof entry.path !== 'string'
            || typeof entry.workflow !== 'string' || typeof entry.tag_prefix !== 'string'
            || !validTagPrefix
            || !['npm_direct', 'npm_reusable', 'pypi_direct', 'pypi_reusable', 'go_tag'].includes(entry.mode)) {
            throw new Error('release registry contains a malformed entry');
        }
        if (seenPackages.has(`${entry.ecosystem}:${entry.package}`))
            throw new Error(`duplicate release package: ${entry.package}`);
        if (seenWorkflows.has(entry.workflow))
            throw new Error(`duplicate release workflow: ${entry.workflow}`);
        if (seenTagPrefixes.has(entry.tag_prefix))
            throw new Error(`duplicate release tag prefix: ${entry.tag_prefix}`);
        seenPackages.add(`${entry.ecosystem}:${entry.package}`);
        seenWorkflows.add(entry.workflow);
        seenTagPrefixes.add(entry.tag_prefix);
        const workflowPath = path.join(root, WORKFLOW_DIR, entry.workflow);
        const packagePath = path.join(root, entry.path);
        if (!fs.statSync(workflowPath).isFile() || !fs.statSync(packagePath).isDirectory())
            throw new Error(`missing release input for ${entry.package}`);
        const workflow = fs.readFileSync(workflowPath, 'utf8');
        if (entry.mode === 'npm_reusable' || entry.mode === 'npm_direct') {
            validateReusableNpmCallerText(workflow, entry.workflow);
            if (!exactInput(workflow, 'package_dir', entry.path)
                || !exactInput(workflow, 'package_name', entry.package)
                || !exactInput(workflow, 'tag_prefix', entry.tag_prefix)) {
                throw new Error(`${entry.workflow} does not bind the declared package path, name, and tag prefix`);
            }
        }
        else if (entry.mode === 'pypi_direct') {
            validatePypiDirect(workflow, entry.workflow);
        }
        else if (entry.mode === 'pypi_reusable') {
            requireText(workflow, ['uses: ./.github/workflows/_publish-pypi-package.yml'], entry.workflow);
            validateManualPublisher(workflow, entry.workflow, { direct: false });
            if (!exactInput(workflow, 'package_dir', entry.path) || !exactInput(workflow, 'package_name', entry.package)
                || !exactInput(workflow, 'tag_prefix', entry.tag_prefix)) {
                throw new Error(`${entry.workflow} does not bind the declared package path, name, and tag prefix`);
            }
        }
        else {
            validateGoTagWorkflowText(workflow);
            requireText(workflow, [entry.path, entry.package, entry.tag_prefix], entry.workflow);
        }
        if (!workflow.includes(`--tag-prefix ${entry.tag_prefix}`)
            && !entry.mode.endsWith('_reusable')
            && entry.ecosystem !== 'npm') {
            throw new Error(`${entry.workflow} does not bind release tag prefix ${entry.tag_prefix}`);
        }
        if (entry.ecosystem === 'npm') {
            const metadata = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json'), 'utf8'));
            if (metadata.name !== entry.package || !isCanonicalNpmRepositoryUrl(metadata.repository?.url)) {
                throw new Error(`${entry.package} package metadata is not bound to the EMILIA GitHub repository`);
            }
            if (typeof metadata.scripts?.test !== 'string' || !metadata.scripts.test.trim()) {
                throw new Error(`${entry.package} has no executable package test command`);
            }
            const lockPath = path.join(packagePath, 'package-lock.json');
            if (fs.existsSync(lockPath)) {
                validateNpmLockData(metadata, JSON.parse(fs.readFileSync(lockPath, 'utf8')), path.relative(root, lockPath));
            }
        }
        else if (entry.ecosystem === 'pypi') {
            const pyproject = fs.readFileSync(path.join(packagePath, 'pyproject.toml'), 'utf8');
            if (!pinnedHatchling.test(pyproject)) {
                throw new Error(`${entry.package} does not pin its Python build backend`);
            }
        }
        else if (entry.ecosystem === 'go') {
            const metadata = JSON.parse(fs.readFileSync(path.join(packagePath, 'go-release.json'), 'utf8'));
            const goMod = fs.readFileSync(path.join(packagePath, 'go.mod'), 'utf8');
            const moduleMajor = metadata.module?.match(/\/v([2-9][0-9]*)$/)?.[1];
            if (metadata['@version'] !== 'EP-GO-MODULE-RELEASE-v1'
                || metadata.module !== entry.package
                || metadata.tag !== `${entry.tag_prefix}${metadata.version}`
                || !CANONICAL_SEMVER.test(metadata.version)
                || !moduleMajor
                || !metadata.version.startsWith(`${moduleMajor}.`)
                || !goMod.includes(`module ${entry.package}`)) {
                throw new Error(`${entry.package} Go release metadata is malformed or drifted`);
            }
        }
        else {
            throw new Error(`unsupported release ecosystem: ${entry.ecosystem}`);
        }
    }
    validateReusablePypiWorkflowText(fs.readFileSync(path.join(root, WORKFLOW_DIR, '_publish-pypi-package.yml'), 'utf8'));
    const discoveredSurfaces = discoverReleaseSurfaces(root);
    const declaredSurfaces = registry.packages
        .map(({ ecosystem, package: packageName, path: packagePath }) => ({ ecosystem, package: packageName, path: packagePath }))
        .sort((a, b) => `${a.ecosystem}:${a.package}`.localeCompare(`${b.ecosystem}:${b.package}`));
    if (JSON.stringify(discoveredSurfaces) !== JSON.stringify(declaredSurfaces)) {
        throw new Error(`release surface omission/drift: declared=${JSON.stringify(declaredSurfaces)} discovered=${JSON.stringify(discoveredSurfaces)}`);
    }
    const discovered = fs.readdirSync(path.join(root, WORKFLOW_DIR))
        .filter((name) => /^publish-.*\.ya?ml$/.test(name))
        .sort();
    const declared = [...seenWorkflows].sort();
    if (JSON.stringify(discovered) !== JSON.stringify(declared)) {
        throw new Error(`release registry/workflow drift: declared=${declared.join(',')} discovered=${discovered.join(',')}`);
    }
    return {
        packages: registry.packages.length,
        npm: registry.packages.filter((entry) => entry.ecosystem === 'npm').length,
        pypi: registry.packages.filter((entry) => entry.ecosystem === 'pypi').length,
        go: registry.packages.filter((entry) => entry.ecosystem === 'go').length,
    };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const result = auditReleaseChain();
        console.log(`RELEASE CHAIN: PASS (${result.packages} packages; npm=${result.npm}; pypi=${result.pypi}; go=${result.go})`);
    }
    catch (error) {
        console.error(`RELEASE CHAIN: FAIL (${error.message})`);
        process.exitCode = 1;
    }
}

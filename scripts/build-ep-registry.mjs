#!/usr/bin/env node
// Generated from build-ep-registry.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Generate the public EP registry manifests from the single descriptor source.
 *
 * @license Apache-2.0
 *
 *   public/.well-known/ep-profiles.json   — content-addressed profile registry
 *   public/.well-known/ep-actions.json    — offline action-type vocabulary
 *
 * Each profile row is content-addressed (sha256 over its canonical descriptor)
 * so a consumer can verify the registry offline and detect tampering. EMILIA
 * hosts a MIRROR — third parties self-publish profiles in the reserved
 * `urn:ep:profile:x-<vendor>:*` space; the content hash is the integrity anchor.
 *
 * Deterministic (no timestamps) so tests/ep-registry.test.js can re-derive the
 * bytes and prove the committed manifests never drift from the descriptors.
 */
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { canonicalize } from '../packages/issue/index.js';
import { PROFILE_DESCRIPTORS, ACTION_TYPES } from '../lib/envelope/descriptors.js';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sha256 = (s) => 'sha256:' + createHash('sha256').update(s, 'utf8').digest('hex');
export function buildProfilesManifest() {
    const profiles = PROFILE_DESCRIPTORS.map((dsc) => ({ ...dsc, content_hash: sha256(canonicalize(dsc)) }));
    const registry_hash = sha256(canonicalize(profiles.map((p) => p.content_hash)));
    return {
        '@version': 'EP-REGISTRY-v1',
        wire_tag: 'EP-PROFILE-REGISTRY-v1',
        envelope: 'EP-ENVELOPE-v1',
        note: 'Content-addressed profile registry for the EP statement envelope. EMILIA hosts a mirror; profiles are self-published. Reserved private-use namespace: urn:ep:profile:x-<vendor>:*',
        spec: 'docs/EP-ENVELOPE-SPEC.md',
        registry_hash,
        profiles,
    };
}
export function buildActionsManifest() {
    return {
        '@version': 'EP-REGISTRY-v1',
        wire_tag: 'EP-ACTION-VOCABULARY-v1',
        note: 'Offline-resolvable vocabulary of consequential action types an EP profile can cover. New action types are new rows, not core changes.',
        actions: ACTION_TYPES,
    };
}
const SERIALIZE = (obj) => JSON.stringify(obj, null, 2) + '\n';
export function manifestPaths() {
    return {
        profiles: path.join(root, 'public/.well-known/ep-profiles.json'),
        actions: path.join(root, 'public/.well-known/ep-actions.json'),
    };
}
// Run as a script (not when imported by the test).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const p = manifestPaths();
    writeFileSync(p.profiles, SERIALIZE(buildProfilesManifest()));
    writeFileSync(p.actions, SERIALIZE(buildActionsManifest()));
    console.log(`wrote ${PROFILE_DESCRIPTORS.length} profiles + ${ACTION_TYPES.length} actions to public/.well-known/`);
}
export { SERIALIZE };

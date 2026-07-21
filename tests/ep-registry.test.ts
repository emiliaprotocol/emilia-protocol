// SPDX-License-Identifier: Apache-2.0
//
// EP registry conformance: the committed public manifests MUST match the
// descriptor source (no drift), every descriptor MUST be a registered profile,
// and every descriptor's vectors file MUST exist. This is what makes "profiles
// are data" enforceable instead of aspirational.

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { buildProfilesManifest, buildActionsManifest, SERIALIZE, manifestPaths } from '../scripts/build-ep-registry.mjs';
import { PROFILE_DESCRIPTORS } from '../lib/envelope/descriptors.js';
import { listProfiles, isWellFormedProfileUrn } from '../lib/envelope/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('EP registry — committed manifests never drift from descriptors', () => {
  it('public/.well-known/ep-profiles.json matches the descriptor source', () => {
    const committed = readFileSync(manifestPaths().profiles, 'utf8');
    expect(committed).toBe(SERIALIZE(buildProfilesManifest()));
  });
  it('public/.well-known/ep-actions.json matches the descriptor source', () => {
    const committed = readFileSync(manifestPaths().actions, 'utf8');
    expect(committed).toBe(SERIALIZE(buildActionsManifest()));
  });
});

describe('EP registry — profiles are real, registered, and conformance-backed', () => {
  it('every descriptor URN is well-formed and registered in the verifier', () => {
    const registered = listProfiles();
    for (const d of PROFILE_DESCRIPTORS) {
      expect(isWellFormedProfileUrn(d.profile)).toBe(true);
      expect(registered).toContain(d.profile);
    }
  });
  it('every descriptor points at a vectors file that exists', () => {
    for (const d of PROFILE_DESCRIPTORS) {
      expect(existsSync(path.join(root, d.vectors)), `${d.vectors} missing`).toBe(true);
    }
  });
  it('content hashes are present and unique per profile', () => {
    const m = buildProfilesManifest();
    const hashes = m.profiles.map((p) => p.content_hash);
    expect(hashes.every((h) => /^sha256:[0-9a-f]{64}$/.test(h))).toBe(true);
    expect(new Set(hashes).size).toBe(hashes.length);
    expect(m.registry_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

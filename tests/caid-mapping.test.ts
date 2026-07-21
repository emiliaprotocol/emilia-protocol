// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  MAPPING_VERDICTS,
  compareMappedActions,
  mappingProfileHash,
} from '../caid/impl/js/mapping.mjs';
import { runMappingVectors } from '../caid/impl/js/run-mapping-vectors.mjs';

const corpus = JSON.parse(readFileSync(new URL('../caid/conformance/mapping-vectors.json', import.meta.url), 'utf8'));
const registry = JSON.parse(readFileSync(new URL('../caid/registry/action-types.json', import.meta.url), 'utf8'));

describe('CAID Action-Mapping Profile', () => {
  it('passes every shared material-equivalence vector', () => {
    const results = runMappingVectors(corpus);
    expect(results).toHaveLength(corpus.vectors.length);
    expect(results).toHaveLength(23);
    expect(results.filter((result) => !result.pass)).toEqual([]);
  });

  it('uses the exact pinned public type definition instead of a colliding local alias', () => {
    for (const definition of corpus.definitions) {
      const registered = registry.types.find((entry) => entry.action_type === definition.action_type);
      expect(registered, definition.action_type).toBeDefined();
      expect(definition).toEqual(registered);
    }
  });

  it('fails closed when a mapping profile is not relying-party pinned', () => {
    const profile = structuredClone(corpus.profiles['ep-action-v1']);
    const side = {
      source: structuredClone(corpus.sources['ep-order']),
      profile,
      source_descriptor: structuredClone(profile.source_format),
      expected_profile_hash: mappingProfileHash(profile),
      native_verified: true,
    };
    const unpinned = structuredClone(side);
    unpinned.expected_profile_hash = '';

    const result = compareMappedActions(side, unpinned, {
      definitions: corpus.definitions,
      suite: corpus.suite,
    });

    expect(result.verdict).toBe(MAPPING_VERDICTS.indeterminate);
    expect(result.reasons).toContain('right:mapping_profile_unpinned');
  });

  it('retains the inputs needed to reproduce a successful comparison', () => {
    const buildSide = (sourceName, profileName) => {
      const profile = structuredClone(corpus.profiles[profileName]);
      return {
        source: structuredClone(corpus.sources[sourceName]),
        profile,
        source_descriptor: structuredClone(profile.source_format),
        expected_profile_hash: mappingProfileHash(profile),
        native_verified: true,
      };
    };
    const result = compareMappedActions(
      buildSide('ep-order', 'ep-action-v1'),
      buildSide('ap2-order', 'ap2-checkout-v1'),
      { definitions: corpus.definitions, suite: corpus.suite },
    );

    expect(result.verdict).toBe(MAPPING_VERDICTS.equivalent);
    for (const side of [result.left, result.right]) {
      expect(side.ok).toBe(true);
      expect(side.action).toEqual(expect.objectContaining({ action_type: 'order.place.1' }));
      expect(side.caid).toMatch(/^caid:1:order\.place\.1:jcs-sha256:/);
      expect(side.suite).toBe('jcs-sha256');
      expect(side.profile_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(side.source_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });
});

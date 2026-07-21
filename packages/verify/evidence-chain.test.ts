// SPDX-License-Identifier: Apache-2.0
// EP-AEC composition conformance — JS runner over the shared conformance/vectors/aec.json.
// The SAME vector file is run by the Python and Go ports, so all three implementations are
// proven to agree on the composition predicate (same-action binding, requirement eval,
// fail-closed). Component evidence is verified by a stub that echoes {valid, action_digest}.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { verifyAuthorizationChain, actionDigest } from './evidence-chain.js';

const here = dirname(fileURLToPath(import.meta.url));
const suite = JSON.parse(readFileSync(resolve(here, '../../conformance/vectors/aec.json'), 'utf8'));
const D = actionDigest(suite.action);
const OTHER = 'sha256:' + 'f'.repeat(64);
const subst = (x) => (x === 'SAME' ? 'sha256:' + D : x === 'OTHER' ? OTHER : x);
const stub = (ev) => ({ valid: ev.valid !== false, action_digest: ev.action_digest });
const verifiers = Object.fromEntries(suite.stub_types.map((t) => [t, stub]));

function hydrate(chain) {
  const c = JSON.parse(JSON.stringify(chain));
  if (!('action' in c)) c.action = suite.action;
  if ('action_digest' in c) c.action_digest = subst(c.action_digest);
  for (const comp of c.components || []) {
    if (comp.evidence && 'action_digest' in comp.evidence) comp.evidence.action_digest = subst(comp.evidence.action_digest);
  }
  return c;
}

for (const v of suite.vectors) {
  test(`[aec] ${v.name}`, () => {
    const requirement = v.expect_requirement_source === 'presenter'
      ? undefined
      : (v.relying_party_requirement ?? v.chain.requirement);
    const r = verifyAuthorizationChain(hydrate(v.chain), {
      verifiers,
      requirement,
      expectedActionDigest: `sha256:${D}`,
    });
    assert.equal(r.allow, v.expect_allow, `reasons: ${r.reasons.join('; ')}`);
    assert.equal(r.satisfied, v.expect_allow, `reasons: ${r.reasons.join('; ')}`);
    assert.equal(r.allow, r.satisfied, 'legacy allow alias must equal satisfied');
    if (v.expect_requirement_source) assert.equal(r.requirement_source, v.expect_requirement_source);
  });
}

test('[aec] ep-platform-attestation is reserved and cannot be replaced by a presenter verifier', () => {
  const chain = {
    '@version': 'EP-AEC-v1',
    action: suite.action,
    components: [{
      type: 'ep-platform-attestation',
      evidence: { '@version': 'EP-PLATFORM-ATTESTATION-v1', token: 'presenter-controlled' },
    }],
    requirement: 'ep-platform-attestation',
  };
  const r = verifyAuthorizationChain(chain, {
    requirement: 'ep-platform-attestation',
    expectedActionDigest: `sha256:${D}`,
    verifiers: {
      'ep-platform-attestation': () => ({ valid: true, action_digest: `sha256:${D}` }),
    },
  });
  assert.equal(r.satisfied, false);
  assert.equal(r.components[0].valid, false);
  assert.equal(r.components[0].reason, 'component evidence did not verify');
});

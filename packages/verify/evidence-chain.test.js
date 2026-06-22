// SPDX-License-Identifier: Apache-2.0
// Conformance vectors for the EP-AEC composition predicate (verifyAuthorizationChain).
// Component evidence is verified by a stub verifier that reports {valid, action_digest}
// straight from the evidence, so these vectors test the COMPOSITION LOGIC — same-action
// binding, requirement evaluation, fail-closed — independently of any component format,
// and are portable to the Python/Go ports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyAuthorizationChain, actionDigest } from './evidence-chain.js';

const ACTION = { ep_version: '1.0', action_type: 'disbursement.release', parameters: { amount: '1850000.00', payee: 'Acme' }, requested_at: '2026-02-03T17:41:09Z' };
const DIGEST = actionDigest(ACTION);
const OTHER = 'sha256:' + 'f'.repeat(64);

// Stub verifier registry: each type echoes the evidence's claimed {valid, action_digest}.
const stub = (ev) => ({ valid: ev.valid !== false, action_digest: ev.action_digest });
const opts = { verifiers: { 'policy-permit': stub, 'ep-quorum': stub, delegation: stub } };

const chain = (components, requirement) => ({ '@version': 'EP-AEC-v1', action: ACTION, action_digest: 'sha256:' + DIGEST, components, requirement });
const leg = (type, valid = true, digest = 'sha256:' + DIGEST) => ({ type, evidence: { valid, action_digest: digest } });

const cases = [
  ['ALLOW: both legs valid + same action', chain([leg('ep-quorum'), leg('policy-permit')], 'ep-quorum AND policy-permit'), true],
  ['DENY: cross-binding — permit leg binds a different action', chain([leg('ep-quorum'), leg('policy-permit', true, OTHER)], 'ep-quorum AND policy-permit'), false],
  ['DENY: required human leg missing', chain([leg('policy-permit')], 'ep-quorum AND policy-permit'), false],
  ['DENY: a leg fails to verify', chain([leg('ep-quorum', false), leg('policy-permit')], 'ep-quorum AND policy-permit'), false],
  ['DENY: unknown component type (no verifier)', chain([{ type: 'mystery', evidence: { valid: true, action_digest: 'sha256:' + DIGEST } }], 'mystery'), false],
  ['ALLOW: OR requirement satisfied by one leg', chain([leg('policy-permit')], 'ep-quorum OR policy-permit'), true],
  ['ALLOW: parenthesized requirement', chain([leg('ep-quorum'), leg('delegation')], 'ep-quorum AND (policy-permit OR delegation)'), true],
  ['DENY: declared action_digest mismatches the action', { '@version': 'EP-AEC-v1', action: ACTION, action_digest: OTHER, components: [leg('ep-quorum')], requirement: 'ep-quorum' }, false],
  ['DENY: malformed — wrong @version', { '@version': 'nope', action: ACTION, components: [leg('ep-quorum')], requirement: 'ep-quorum' }, false],
  ['DENY: malformed — empty components', chain([], 'ep-quorum'), false],
  ['DENY: malformed — missing requirement', { '@version': 'EP-AEC-v1', action: ACTION, components: [leg('ep-quorum')] }, false],
];

for (const [name, c, expectAllow] of cases) {
  test(name, () => {
    const r = verifyAuthorizationChain(c, opts);
    assert.equal(r.allow, expectAllow, `${name} → allow=${r.allow}; reasons: ${r.reasons.join('; ')}`);
  });
}

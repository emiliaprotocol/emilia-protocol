// SPDX-License-Identifier: Apache-2.0
// EP-ASSURANCE-PACKAGE-v1 — bundle + independent re-performance.
// Proves the EY-grade property: re-performance recomputes every reliance verdict
// from the packaged evidence and CATCHES a runtime that claimed `rely` over
// inadmissible evidence (drift), trusting nothing the package asserts.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  buildAssurancePackage, reperformAssurancePackage, renderAssuranceWorkpaper,
  RELIANCE_CONTROL_CATALOG, ASSURANCE_PACKAGE_VERSION,
} from '../packages/gate/reports/assurance-package.js';
import { RELIANCE_VERDICTS } from '../packages/verify/reliance.js';
import { signAuthorityProof } from '../lib/authority/proof.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l, r) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };

const logKey = ed(); const intake = ed(); const reviewer = p256();
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('d4'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
const registryPub = crypto.createPublicKey(registryKey).export({ type: 'spki', format: 'der' }).toString('base64url');
const NOW = Date.parse('2026-07-07T14:05:00.000Z');

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: crypto.sign('sha256', signedData, reviewer.privateKey).toString('base64url') };
}
function buildReceipt(nonce, amount = 40000) {
  const action = { ep_version: '1.0', action_type: 'rx.prior_auth.approve', organization_id: 'planX', target: { system: 'pbm', resource: `pa/${nonce}` }, parameters: { drug: 'SYN', ncpdp: nonce, amount, currency: 'USD' }, initiator: 'ep:entity:pa-agent', policy_id: 'ep:policy:tier4', requested_at: '2026-07-07T14:00:00Z' };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:tier4', policy_hash: 'sha256:benef', initiator: action.initiator, required_approvals: 2, issued_at: '2026-07-07T14:00:05Z', expires_at: '2026-07-07T14:15:05Z' };
  const ctx1 = { ...base, approver: 'ep:approver:intake', approver_index: 1, nonce: `${nonce}-1` };
  const ctx2 = { ...base, approver: 'ep:approver:reviewer', approver_index: 2, nonce: `${nonce}-2` };
  const d1 = sha(canon(ctx1)); const d2 = sha(canon(ctx2));
  const signoffs = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:intake#1', signed_at: '2026-07-07T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'x', key_class: 'A', approver_key_id: 'ep:key:reviewer#1', signed_at: '2026-07-07T14:04:01Z', webauthn: signA(d2) },
  ];
  const receipt = { receipt_id: `ep:receipt:${nonce}`, action, action_hash, contexts: [ctx1, ctx2], signoffs, consumption: { nonce, state: 'COMMITTED', committed_at: '2026-07-07T14:04:02Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}
const KEYS = {
  'ep:key:intake#1': { approver_id: 'ep:approver:intake', public_key: intake.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:reviewer#1': { approver_id: 'ep:approver:reviewer', public_key: reviewer.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const authority = (over = {}) => signAuthorityProof({
  authority_id: 'auth_reviewer', subject: 'ep:approver:reviewer', organization_id: 'planX', role: 'payer_medical_reviewer',
  scope: ['rx.prior_auth.approve'], limits: { max_amount_usd: 50000, currency: 'USD' },
  validity: { from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z' },
  revocation: { status: 'not_revoked', checked_at: '2026-07-07T13:59:00.000Z' },
  registry_head: 'sha256:' + '22'.repeat(32), registry_epoch: 9, policy_hash: 'sha256:benef', issued_at: '2026-07-07T13:59:00.000Z', ...over,
}, registryKey);

const PROFILE = {
  '@type': 'EP-RELIANCE-PROFILE-v1', required_assurance: 'class_a', required_authority: true, max_revocation_staleness_sec: 3600,
  accepted_registry_keys: [{ issuer_id: 'auth_reviewer', organization_id: 'planX', public_key: registryPub, min_epoch: 9, registry_head: 'sha256:' + '22'.repeat(32) }], accepted_issuer_keys: [logKey.pub],
  accepted_policy_hashes: ['sha256:benef'], required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'revocation_freshness', 'consumption_proof'],
};
const fresh = { checked_at: '2026-07-07T14:00:00.000Z' };
const baseAction = (rc, amount) => ({ action_type: 'rx.prior_auth.approve', amount, currency: 'USD', organization_id: 'planX', policy_hash: 'sha256:benef', action_hash: rc.action_hash });

function population() {
  const r1 = buildReceipt('n1', 40000); const r2 = buildReceipt('n2', 40000); const r3 = buildReceipt('n3', 90000);
  return [
    // honest admissible
    { decision_id: 'd1', action: baseAction(r1, 40000), receipt: r1, authority_proof: authority(), revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'rely' },
    // honest refusal (no authority proof) — org recorded the refusal correctly
    { decision_id: 'd2', action: baseAction(r2, 40000), receipt: r2, revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'do_not_rely_authority_missing' },
    // THE LIE: amount over the authority ceiling, but runtime CLAIMED rely
    { decision_id: 'd3', action: baseAction(r3, 90000), receipt: r3, authority_proof: authority(), revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'rely' },
  ];
}
const OPTS = { approverKeys: KEYS, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai', allowedOrigins: ['https://www.emiliaprotocol.ai'], isConsumed: () => false, now: NOW };

describe('EP-ASSURANCE-PACKAGE-v1', () => {
  it('bundles decisions into a content-addressed package', () => {
    const pkg = buildAssurancePackage(population(), { profile: PROFILE, organization: { id: 'planX' }, now: NOW });
    expect(pkg['@version']).toBe(ASSURANCE_PACKAGE_VERSION);
    expect(pkg.decisions.length).toBe(3);
    expect(pkg.package_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(pkg.exception_history.length).toBe(1); // d2 stated a refusal
  });

  it('re-performance recomputes every verdict and CATCHES the lie (drift)', () => {
    const pkg = buildAssurancePackage(population(), { profile: PROFILE, now: NOW });
    const rp = reperformAssurancePackage(pkg, OPTS);
    const byId = Object.fromEntries(rp.results.map((r) => [r.decision_id, r]));
    expect(byId.d1.recomputed_verdict).toBe('rely');
    expect(byId.d1.drift).toBe(false);
    expect(byId.d2.recomputed_verdict).toBe('do_not_rely_authority_missing');
    expect(byId.d2.drift).toBe(false);
    // The material finding: runtime claimed rely, evidence does not support it.
    expect(byId.d3.recomputed_verdict).toBe('do_not_rely_amount_exceeded');
    expect(byId.d3.drift).toBe(true);
    expect(byId.d3.drift_severity).toBe('relied_on_inadmissible_evidence');
    expect(byId.d3.control_id).toBe('RC-1');
    expect(rp.population.relied_on_inadmissible_evidence).toBe(1);
    expect(rp.population.admissible).toBe(1);
  });

  it('re-performance is deterministic (same package → same reperformance_digest)', () => {
    const pkg = buildAssurancePackage(population(), { profile: PROFILE, now: NOW });
    const a = reperformAssurancePackage(pkg, OPTS);
    const b = reperformAssurancePackage(pkg, OPTS);
    expect(a.reperformance_digest).toBe(b.reperformance_digest);
  });

  it('conclusion fields are null and the renderer refuses a filled conclusion', () => {
    const pkg = buildAssurancePackage(population(), { profile: PROFILE, now: NOW });
    const rp = reperformAssurancePackage(pkg, OPTS);
    expect(rp.conclusion).toEqual({ supportable: null, opinion: null, signed_off_by: null });
    const wp = renderAssuranceWorkpaper(rp);
    expect(wp).toContain('Conclusion: NULL by construction');
    rp.conclusion.opinion = 'unqualified';
    expect(() => renderAssuranceWorkpaper(rp)).toThrow(/conclusion fields must be null/);
  });

  it('EVERY non-rely verdict maps to exactly one control objective', () => {
    const mapped = Object.values(RELIANCE_CONTROL_CATALOG).flatMap((c) => c.verdicts);
    const mappedSet = new Set(mapped);
    expect(mapped.length).toBe(mappedSet.size); // no verdict in two controls
    for (const v of RELIANCE_VERDICTS) {
      if (v === 'rely') continue;
      expect(mappedSet.has(v)).toBe(true); // no orphan verdict
    }
  });
});

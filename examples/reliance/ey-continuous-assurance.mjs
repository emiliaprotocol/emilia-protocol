// SPDX-License-Identifier: Apache-2.0
//
// EP-ASSURANCE-PACKAGE-v1 — continuous assurance over agentic prior authorization.
//
//   node examples/reliance/ey-continuous-assurance.mjs
//
// The independent-assurer story, run offline. A payer operates automated specialty
// prior auth. Its runtime records, for each PA, the reliance verdict it acted on.
// An independent assurer takes the packaged evidence and RE-PERFORMS every verdict
// from scratch, trusting nothing the runtime claimed. It reports which PAs were
// admissible, which failed and why, and (the material finding) which the runtime
// CLAIMED it could rely on while the evidence does not support reliance.
//
// PUBLIC-SAFE: fully synthetic. No PHI. Rides beside NCPDP transactions (digest
// only). "Upload N automated actions. Reperform every reliance verdict. Show which
// were admissible, which failed, why, and whether management's control claim is
// supportable." — that is audit evidence (PCAOB AS 1105: cryptographic source,
// immutable trail, reproducible rule, direct re-performance).
import crypto from 'node:crypto';
import { buildAssurancePackage, reperformAssurancePackage, renderAssuranceWorkpaper } from '../../packages/gate/reports/assurance-package.js';
import { signAuthorityProof } from '../../lib/authority/proof.js';

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
const registryKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from('e5'.repeat(32), 'hex')]), format: 'der', type: 'pkcs8' });
// Node's crypto.createPublicKey accepts a private KeyObject at runtime (it derives
// the public key), but @types/node's overloads don't include KeyObject — cast only.
const registryPub = crypto.createPublicKey(/** @type {any} */ (registryKey)).export({ type: 'spki', format: 'der' }).toString('base64url');
const NOW = Date.parse('2026-07-07T14:05:00.000Z');

function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: crypto.sign('sha256', signedData, reviewer.privateKey).toString('base64url') };
}
function receipt(nonce, amount) {
  const action = {
    ep_version: '1.0',
    action_type: 'rx.prior_auth.approve',
    amount,
    currency: 'USD',
    organization_id: 'planX',
    policy_hash: 'sha256:benef',
    target: { system: 'pbm', resource: `pa/${nonce}` },
    parameters: { ncpdp: nonce },
    initiator: 'ep:entity:pa-agent',
    policy_id: 'ep:policy:tier4',
    requested_at: '2026-07-07T14:00:00Z',
  };
  const action_hash = `sha256:${sha(canon(action))}`;
  const base = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash, policy_id: 'ep:policy:tier4', policy_hash: 'sha256:benef', initiator: action.initiator, required_approvals: 2, issued_at: '2026-07-07T14:00:05Z', expires_at: '2026-07-07T14:15:05Z' };
  const c1 = { ...base, approver: 'ep:approver:intake', approver_index: 1, nonce: `${nonce}-1` };
  const c2 = { ...base, approver: 'ep:approver:reviewer', approver_index: 2, nonce: `${nonce}-2` };
  const d1 = sha(canon(c1)); const d2 = sha(canon(c2));
  const so = [
    { context_hash: `sha256:${d1}`, signature: crypto.sign(null, Buffer.from(d1, 'hex'), intake.privateKey).toString('base64url'), key_class: 'B', approver_key_id: 'ep:key:intake#1', signed_at: '2026-07-07T14:03:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'x', key_class: 'A', approver_key_id: 'ep:key:reviewer#1', signed_at: '2026-07-07T14:04:01Z', webauthn: signA(d2) },
  ];
  const r = { receipt_id: `ep:receipt:${nonce}`, action, action_hash, contexts: [c1, c2], signoffs: so, consumption: { nonce, state: 'COMMITTED', committed_at: '2026-07-07T14:04:02Z' } };
  const leaf = leafV2(canon(r));
  const root = pairV2(pairV2(leaf, sha('s1')), sha('s2'));
  const cp = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log#1', merkle_alg: 'EP-MERKLE-v2' };
  const sig = crypto.sign(null, crypto.createHash('sha256').update(canon(cp), 'utf8').digest(), logKey.privateKey).toString('base64url');
  r.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('s1'), position: 'right' }, { hash: sha('s2'), position: 'right' }], checkpoint: { ...cp, log_signature: sig } };
  return r;
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
const act = (r, amount) => ({ action_type: 'rx.prior_auth.approve', amount, currency: 'USD', organization_id: 'planX', policy_hash: 'sha256:benef', action_hash: r.action_hash });

// A month of automated PA decisions the payer's runtime acted on. Most are clean;
// three are not, and one of those the runtime WRONGLY recorded as reliable.
const decisions = [];
for (let i = 0; i < 8; i++) {
  const amount = 30000 + i * 100;
  const r = receipt(`ok${i}`, amount);
  decisions.push({ decision_id: `PA-ok-${i}`, action: act(r, amount), receipt: r, authority_proof: authority(), revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'rely' });
}
// honest refusal: reviewer authority expired — runtime correctly refused
{ const r = receipt('exp', 30000); decisions.push({ decision_id: 'PA-expired-auth', action: act(r, 30000), receipt: r, authority_proof: authority({ validity: { from: '2025-01-01T00:00:00.000Z', to: '2026-06-01T00:00:00.000Z' } }), revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'do_not_rely_authority_expired' }); }
// honest refusal: stale eligibility check
{
  const r = receipt('stale', 30000);
  decisions.push({
    decision_id: 'PA-stale-eligibility',
    action: act(r, 30000),
    receipt: r,
    authority_proof: authority({
      revocation: { status: 'not_revoked', checked_at: '2026-07-01T00:00:00.000Z' },
    }),
    revocation_state: { checked_at: '2026-07-01T00:00:00.000Z' },
    consumption: { consumed: false },
    stated_verdict: 'do_not_rely_stale_revocation',
  });
}
// THE FINDING: over the authority ceiling, but the runtime recorded `rely`
{ const r = receipt('over', 120000); decisions.push({ decision_id: 'PA-over-ceiling', action: act(r, 120000), receipt: r, authority_proof: authority(), revocation_state: fresh, consumption: { consumed: false }, stated_verdict: 'rely' }); }

const pkg = buildAssurancePackage(decisions, { profile: PROFILE, organization: { id: 'planX', name: 'Synthetic Health Plan' }, now: NOW });
const rp = reperformAssurancePackage(pkg, {
  approverKeys: KEYS,
  logPublicKey: logKey.pub,
  rpId: 'www.emiliaprotocol.ai',
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
  isConsumed: () => false,
  now: NOW,
});

console.log('\nContinuous assurance over agentic prior authorization (synthetic, no PHI).');
console.log(`Package: ${pkg.decisions.length} automated PA decisions | digest ${pkg.package_digest.slice(0, 16)}…\n`);
console.log(renderAssuranceWorkpaper(rp));

const finding = rp.population.relied_on_inadmissible_evidence;
console.log(`\nAssurer's evidence, not opinion: ${rp.population.admissible} admissible, ${rp.population.refused} refused, ${finding} relied on inadmissible evidence.`);
console.log(finding === 1 && rp.results.find((r) => r.decision_id === 'PA-over-ceiling')?.drift
  ? 'OK — re-performance independently caught the PA the runtime claimed it could rely on but the evidence does not support (over the reviewer authority ceiling). The auditor concludes; the tool only supports the procedure.'
  : 'FAILED — re-performance did not catch the planted finding.');
process.exit(finding === 1 ? 0 : 1);

// SPDX-License-Identifier: Apache-2.0
//
// EMILIA — live DERF demo for NCPDP WG11 SIR.
//
//   node examples/ncpdp/derf-receipt-demo.mjs           (cinematic, for screen-share / recording)
//   node examples/ncpdp/derf-receipt-demo.mjs --fast     (instant, no pacing)
//
// A self-playing terminal demo of the HumanAuthorizationReceipt: a named
// pharmacist approves ONE exact SCRIPT action, the receipt is minted over those
// bytes, and any party verifies it offline with published keys. Then a one-field
// tamper is refused, and a valid signature under an unpinned signer is shown
// VERIFIED but not ACCEPTED. Every verdict is computed by the real
// packages/verify verifier. Fully synthetic: no PHI, no network, no account.
import crypto from 'node:crypto';
import { verifyTrustReceipt } from '../../packages/verify/index.js';

const FAST = process.argv.includes('--fast');
const NOCOLOR = process.env.NO_COLOR || process.argv.includes('--no-color');
const c = (n: string) => (s: string) => (NOCOLOR ? s : `\x1b[${n}m${s}\x1b[0m`);
const dim = c('2;37'), bold = c('1'), green = c('1;32'), red = c('1;31'), amber = c('1;33'), cyan = c('1;36'), grey = c('90');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, FAST ? 0 : ms));
async function type(s: string, { d = 12, nl = true } = {}) {
  if (FAST) { process.stdout.write(s + (nl ? '\n' : '')); return; }
  for (const ch of s) { process.stdout.write(ch); await sleep(d); }
  if (nl) process.stdout.write('\n');
}
const rule = () => console.log(grey('─'.repeat(66)));
async function beat(t: string) { console.log(); rule(); await type('  ' + bold(t), { d: 8 }); rule(); await sleep(300); }

// ── canonicalization + crypto (byte-identical to the verifier) ───────────────
const canon = (v: any): string => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const leafV2 = (p: string) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(p, 'utf8')])).digest('hex');
const pairV2 = (l: string, r: string) => crypto.createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8'), Buffer.from(r, 'utf8')])).digest('hex');
const ed = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519'); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };
const p256 = () => { const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') }; };

const logKey = ed();          // the pharmacy's transparency-log key
const pharmacist = p256();    // the named human's device key (WebAuthn, Class-A)

function webauthn(digestHex: string) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const authData = Buffer.concat([crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  return { authenticator_data: authData.toString('base64url'), client_data_json: clientDataJSON.toString('base64url'), signature: crypto.sign('sha256', signedData, pharmacist.privateKey).toString('base64url') };
}

// The one exact SCRIPT action a pharmacist is about to approve (synthetic).
const action = {
  ep_version: '1.0', action_type: 'rx.renewal.response',
  target: { system: 'pharmacy.example', resource: 'rx/renewal/55019' },
  parameters: { drug: 'atorvastatin 40 mg', quantity: '90', days_supply: '90', patient_ref: 'ep:patient:synthetic-7741' },
  initiator: 'ep:agent:renewal-queue', policy_id: 'ep:policy:renewal-human-approval', requested_at: '2026-07-08T15:04:00Z',
};
const action_hash = `sha256:${sha(canon(action))}`;

function mint(a: any, ah: string) {
  const ctx = { ep_version: '1.0', context_type: 'ep.signoff.v1', action_hash: ah, policy_id: a.policy_id, policy_hash: 'sha256:' + sha('renewal-human-approval@v1'), initiator: a.initiator, required_approvals: 1, approver: 'ep:approver:pharmacist-jchen', approver_index: 1, nonce: 'n-1', issued_at: '2026-07-08T15:04:05Z', expires_at: '2026-07-08T15:19:05Z' };
  const d = sha(canon(ctx));
  const receipt: any = { receipt_id: 'ep:receipt:rx-renewal-55019', action: a, action_hash: ah, contexts: [ctx], signoffs: [{ context_hash: `sha256:${d}`, key_class: 'A', approver_key_id: 'ep:key:pharmacist-jchen#1', signed_at: '2026-07-08T15:04:06Z', webauthn: webauthn(d) }], consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: '2026-07-08T15:04:07Z' } };
  const leaf = leafV2(canon(receipt));
  const root = pairV2(leaf, sha('sibling'));
  const checkpoint = { tree_size: 2, root_hash: `sha256:${root}`, log_key_id: 'ep:log:pharmacy#1', merkle_alg: 'EP-MERKLE-v2' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canon(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}`, leaf_index: 0, inclusion_path: [{ hash: sha('sibling'), position: 'right' }], checkpoint: { ...checkpoint, log_signature } };
  return receipt;
}

// The pharmacy pins ONE approver directory + its log key. This is the whole root.
/** @type {import('../../packages/verify/index.js').TrustReceiptVerificationOptions} */
const PINNED = { approverKeys: { 'ep:key:pharmacist-jchen#1': { approver_id: 'ep:approver:pharmacist-jchen', public_key: pharmacist.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' } }, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai' };

async function main() {
  console.clear?.();
  console.log();
  await type('  ' + bold('EMILIA') + dim('   verifiable human-authorization receipt'), { d: 10 });
  await type('  ' + dim('  running code · offline · no vendor system · $0 to verify'), { d: 4 });
  await sleep(500);

  await beat('1 · THE ACTION');
  await type('  A renewal-response is worked by an ' + cyan('automated queue') + '. Before it sends,', { d: 8 });
  await type('  a named pharmacist must approve ' + bold('this exact action') + ':', { d: 8 });
  console.log();
  console.log('    ' + grey('action_type ') + action.action_type);
  console.log('    ' + grey('drug        ') + action.parameters.drug + grey('   qty ') + action.parameters.quantity + grey('   days ') + action.parameters.days_supply);
  console.log('    ' + grey('patient     ') + action.parameters.patient_ref);
  await sleep(300);
  await type('  ' + dim('canonicalized and hashed to the bytes the signature will cover:'), { d: 4 });
  console.log('    ' + amber(action_hash));
  await sleep(500);

  await beat('2 · MINT');
  await type('  Pharmacist ' + bold('J. Chen') + ' taps approve on their own device (WebAuthn).', { d: 8 });
  const receipt = mint(action, action_hash);
  await type('  A receipt is minted over ' + bold('those bytes') + ', by ' + bold('that human') + ':', { d: 8 });
  console.log();
  console.log('    ' + grey('receipt   ') + receipt.receipt_id);
  console.log('    ' + grey('signer    ') + receipt.contexts[0].approver + grey('  (Class-A device)'));
  console.log('    ' + grey('binds     ') + amber(receipt.action_hash));
  await sleep(500);

  await beat('3 · VERIFY  (offline, with published keys)');
  await type('  Any party checks it with the pharmacy\'s ' + bold('pinned') + ' key. No network:', { d: 8 });
  await sleep(200);
  const r1 = verifyTrustReceipt(receipt, PINNED as any);
  console.log();
  for (const [k, label] of [['action_hash', 'action bound to the signed bytes'], ['signoff_signatures', 'named human\'s device signature'], ['inclusion', 'transparency-log inclusion proof'], ['checkpoint_signature', 'log checkpoint signature']]) {
    console.log('    ' + (r1.checks[k as string] ? green('✓') : red('✗')) + '  ' + dim(label));
    await sleep(140);
  }
  console.log();
  await type('    ' + (r1.valid ? green(bold('VERIFIED')) : red('FAILED')) + green('  ·  ACCEPTED under the key the pharmacy pinned.'), { d: 8 });
  await type('    ' + dim('who approved this action, what exactly, and when — checkable by anyone.'), { d: 4 });
  await sleep(500);

  await beat('4 · TAMPER  (a similar action is not the same action)');
  await type('  Suppose something changes the quantity ' + red('90 → 900') + ' after approval.', { d: 8 });
  const tampered = structuredClone(receipt);
  tampered.action.parameters.quantity = '900';
  const r2 = verifyTrustReceipt(tampered, PINNED as any);
  await sleep(200);
  console.log();
  console.log('    ' + ((r2 as any).checks.action_hash ? green('✓') : red('✗')) + '  ' + dim('action bound to the signed bytes'));
  await sleep(200);
  await type('    ' + red(bold('REFUSED')) + red('  ·  the action no longer matches the bytes the pharmacist signed.'), { d: 8 });
  await type('    ' + dim('one field changed, and the receipt stops verifying. Tamper-evident.'), { d: 4 });
  await sleep(500);

  await beat('5 · VERIFIED  ≠  ACCEPTED');
  await type('  Same valid receipt, presented to a party who ' + bold('never pinned this signer') + '.', { d: 8 });
  const r3 = verifyTrustReceipt(receipt, { approverKeys: {}, logPublicKey: logKey.pub, rpId: 'www.emiliaprotocol.ai' } as any);
  await sleep(200);
  console.log();
  console.log('    ' + grey('signature bytes   ') + green('cryptographically real'));
  console.log('    ' + grey('accepted here     ') + red('no — this signer is not in your pinned root'));
  await sleep(200);
  await type('    ' + amber(bold('VERIFIED is not ACCEPTED')) + dim('. Acceptance is the relying party\'s choice,'), { d: 8 });
  await type('    ' + dim('always against keys pinned out of band. A receipt never self-certifies.'), { d: 4 });
  await sleep(500);

  console.log();
  rule();
  await type('  ' + bold('Who approved this action?  ') + green(bold('Proven.')) + dim('  Offline. Forever.'), { d: 10 });
  await type('  ' + dim('One optional element in SCRIPT. Zero burden on any receiver.'), { d: 6 });
  rule();
  console.log();

  const ok = r1.valid === true && r2.valid === false && r3.valid === false;
  if (!ok) { console.error(red('DEMO INVARIANT FAILED')); process.exit(1); }
}
main().catch((e) => { console.error(e); process.exit(1); });

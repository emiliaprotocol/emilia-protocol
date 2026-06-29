/**
 * EMILIA Gate × GitHub — the 60-second "oh shit" demo. Run: node adapters/github-demo.mjs
 *
 * An agent tries to delete a production repo. Without a receipt: refused, and the
 * GitHub API is never called. With a valid human signoff bound to THIS repo: it
 * runs and produces a reliance packet. Change the target repo after approval:
 * refused (drift). Replay the receipt: refused. Uses a fake Octokit so it runs
 * with no credentials; swap in `new Octokit({ auth })` for the real thing.
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { createGate } from '../index.js';
import { createGithubManifest, guardGithubMutation } from './github.js';

const canon = (v) => (v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const ISSUER = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
let n = 0;
const mint = (extra = {}) => {
  const payload = {
    receipt_id: `gh_${++n}`, subject: 'agent:repo-bot', issuer: 'ep:org:demo', created_at: new Date().toISOString(),
    claim: { action_type: 'github.repo.delete', owner: 'acme', repo: 'prod', outcome: 'allow_with_signoff', approver: 'ep:approver:cto', ...extra },
  };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
};

const octokit = {
  repos: { delete: async (p) => { console.log(`        !! GitHub API: repos.delete(${p.owner}/${p.repo}) EXECUTED`); return { status: 204 }; } },
};
const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [ISSUER] });
const G = (s) => `\x1b[32m${s}\x1b[0m`; const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s) => console.log(s);

async function attempt(label, params, receipt) {
  try {
    const { reliance } = await guardGithubMutation(gate, octokit, { op: 'repo.delete', params, receipt });
    line(`  ${label} -> ${G('ALLOWED')}  reliance=${reliance.verdict.toUpperCase()}`);
  } catch (e) {
    line(`  ${label} -> ${R(`REFUSED ${e.status || ''}`)} (${e.gate?.reason || e.message})`);
  }
}

line('='.repeat(66));
line('  EMILIA Gate × GitHub — agent tries to delete the production repo');
line('='.repeat(66));
await attempt('1. delete acme/prod, no receipt            ', { owner: 'acme', repo: 'prod' }, null);
const approval = mint();
await attempt('2. delete acme/prod, valid human signoff   ', { owner: 'acme', repo: 'prod' }, approval);
await attempt('3. same receipt replayed                   ', { owner: 'acme', repo: 'prod' }, approval);
const reAppro = mint();
await attempt('4. approved acme/prod, but targets staging ', { owner: 'acme', repo: 'staging' }, reAppro);
line('  ' + '-'.repeat(62));
line('  No receipt, no mutation. The GitHub API is only reached on an allowed line.');
line('='.repeat(66));

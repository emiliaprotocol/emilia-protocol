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
import { createGate, createEg1Harness } from '../index.js';
import { createGithubManifest, guardGithubMutation } from './github.js';

const action = { action_type: 'github.repo.delete', owner: 'acme', repo: 'prod' };
const harness = createEg1Harness({ action, idPrefix: 'gh' });

const executed = [];
const octokit = {
  repos: {
    delete: async (p) => {
      executed.push(`${p.owner}/${p.repo}`);
      return { status: 204 };
    },
  },
};
const gate = createGate({
  manifest: createGithubManifest(),
  trustedKeys: [harness.publicKey],
  approverKeys: harness.approverKeys,
  rpId: harness.rpId,
  allowedOrigins: harness.allowedOrigins,
  allowEphemeralStore: true,
});
const G = (s) => `\x1b[32m${s}\x1b[0m`; const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s) => console.log(s);

async function attempt(label, params, receipt) {
  const before = executed.length;
  try {
    const { reliance } = await guardGithubMutation(gate, octokit, { op: 'repo.delete', params, receipt });
    const mutation = executed.length === before + 1 ? `  GitHub API=${executed.at(-1)}` : '  GitHub API=NOT CALLED';
    line(`  ${label} -> ${G('ALLOWED')}  reliance=${reliance.verdict.toUpperCase()}${mutation}`);
  } catch (e) {
    const mutation = executed.length === before ? '  GitHub API=NOT CALLED' : '  GitHub API=CALLED';
    line(`  ${label} -> ${R(`REFUSED ${e.status || ''}`)} (${e.gate?.reason || e.message})${mutation}`);
  }
}

line('='.repeat(66));
line('  EMILIA Gate × GitHub — agent tries to delete the production repo');
line('='.repeat(66));
await attempt('1. delete acme/prod, no receipt            ', { owner: 'acme', repo: 'prod' }, null);
const approval = harness.mint({ outcome: 'allow_with_signoff' });
await attempt('2. delete acme/prod, valid human signoff   ', { owner: 'acme', repo: 'prod' }, approval);
await attempt('3. same receipt replayed                   ', { owner: 'acme', repo: 'prod' }, approval);
const reAppro = harness.mint({ outcome: 'allow_with_signoff' });
await attempt('4. approved acme/prod, but targets staging ', { owner: 'acme', repo: 'staging' }, reAppro);
line('  ' + '-'.repeat(62));
line('  No receipt, no mutation. The GitHub API is only reached on an allowed line.');
line('='.repeat(66));

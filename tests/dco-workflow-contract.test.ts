// SPDX-License-Identifier: Apache-2.0

import { execFileSync, spawnSync } from 'node:child_process';
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const source = readFileSync(resolve(ROOT, '.github/workflows/dco.yml'), 'utf8');
const workflow = YAML.parse(source);
const job = workflow.jobs.dco;
const checkout = job.steps.find(
  (step: { uses?: string }) => step.uses?.startsWith('actions/checkout@'),
);
const signoff = job.steps.find(
  (step: { name?: string }) => step.name === 'Check DCO sign-off',
);

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const AUTOPILOT = 'emilia-evidence-autopilot[bot]';
const AUTOPILOT_EMAIL = `123456+${AUTOPILOT}@users.noreply.github.com`;
const DEPENDABOT_EMAIL = '49699333+dependabot[bot]@users.noreply.github.com';

type Identity = { name: string; email: string };

/**
 * A scratch repository plus a stand-in for `gh api repos/<repo>/commits/<sha>`
 * that answers with what GitHub would report for each commit: verified,
 * verification reason, author login, committer login. Commits it does not
 * know make `gh` fail, as the API would for an unknown commit.
 */
function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'emilia-dco-contract-'));
  const repository = join(root, 'repo');
  const bin = join(root, 'bin');
  const records = join(root, 'github-commits.txt');
  mkdirSync(repository);
  mkdirSync(bin);
  writeFileSync(records, '');
  writeFileSync(join(bin, 'gh'), [
    '#!/usr/bin/env bash',
    '[[ "$1" == api && "$2" == "repos/$DCO_STUB_REPOSITORY/commits/"* ]] || exit 2',
    'sha="${2##*/}"',
    'line="$(awk -v s="$sha" \'$1 == s { $1 = ""; sub(/^ /, ""); print; exit }\' "$DCO_STUB_RECORDS")"',
    '[[ -n "$line" ]] || exit 1',
    "printf '%s\\n' \"$line\"",
    '',
  ].join('\n'));
  chmodSync(join(bin, 'gh'), 0o755);

  const git = (args: string[], env: Record<string, string> = {}) => execFileSync('git', args, {
    cwd: repository,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  }).trim();

  const commit = (
    author: Identity,
    message: string,
    options: { committer?: Identity; files?: string[] } = {},
  ): string => {
    for (const file of options.files ?? []) {
      mkdirSync(dirname(join(repository, file)), { recursive: true });
      appendFileSync(join(repository, file), `${file}\n`);
      git(['add', '--', file]);
    }
    const committer = options.committer ?? { name: 'DCO contract fixture', email: 'dco-contract@example.com' };
    git(['commit', '--quiet', '--allow-empty', '-m', message], {
      GIT_AUTHOR_NAME: author.name,
      GIT_AUTHOR_EMAIL: author.email,
      GIT_COMMITTER_NAME: committer.name,
      GIT_COMMITTER_EMAIL: committer.email,
    });
    return git(['rev-parse', 'HEAD']);
  };

  /** Records what GitHub's commits API reports for `sha`. */
  const github = (sha: string, verified: boolean, reason: string, authorLogin: string, committerLogin: string) => {
    appendFileSync(records, `${sha} ${verified} ${reason} ${authorLogin} ${committerLogin}\n`);
  };

  const dco = (base: string, head: string, env: Record<string, string> = {}) => {
    const result = spawnSync('bash', ['-euo', 'pipefail', '-c', signoff.run], {
      cwd: repository,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        DCO_STUB_REPOSITORY: REPOSITORY,
        DCO_STUB_RECORDS: records,
        REPOSITORY,
        BASE_SHA: base,
        HEAD_SHA: head,
        EVIDENCE_AUTOPILOT_BOT_LOGIN: AUTOPILOT,
        DCO_MERGE_GROUP: 'false',
        ...env,
      },
    });
    return { status: result.status, output: `${result.stdout}${result.stderr}` };
  };

  git(['init', '--quiet']);
  return { root, repository, git, commit, github, dco, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

const pat = { name: 'Pat Example', email: 'pat@example.com' };
const githubCommitter = { name: 'GitHub', email: 'noreply@github.com' };
const signed = (subject: string) => `${subject}\n\nSigned-off-by: Pat Example <pat@example.com>`;
const autopilotMessage = 'chore(evidence): regenerate\n\n[dependabot skip]\n\nEvidence-Autopilot: v1';

describe('DCO workflow contract', () => {
  it('runs checkout and the required check without a PR-author exemption', () => {
    expect(job).not.toHaveProperty('if');
    expect(checkout).not.toHaveProperty('if');
    expect(signoff).not.toHaveProperty('if');
    expect(source).not.toContain('github.event.pull_request.user.login');
  });

  it('binds every exemption to GitHub-reported identity, never to author strings', () => {
    expect(signoff.env.GH_TOKEN).toBe('${{ github.token }}');
    expect(signoff.env.REPOSITORY).toBe('${{ github.repository }}');
    expect(signoff.env.EVIDENCE_AUTOPILOT_BOT_LOGIN).toBe('${{ vars.EVIDENCE_AUTOPILOT_BOT_LOGIN }}');
    expect(signoff.env.DCO_MERGE_GROUP).toBe("${{ github.event_name == 'merge_group' }}");
    expect(signoff.run).toContain('gh api "repos/$REPOSITORY/commits/$1"');
    expect(signoff.run).toContain('.commit.verification.verified');
    expect(signoff.run).toContain('Signed-off-by: $author');
    // The old string-matched identities must not come back.
    expect(signoff.run).not.toContain(DEPENDABOT_EMAIL);
    expect(signoff.run).not.toContain('support@github.com');
    expect(signoff.run).not.toMatch(/author_name" == \*/);
  });

  it('exempts only GitHub-verified Dependabot commits and checks every human commit', () => {
    const s = sandbox();
    try {
      const base = s.commit(pat, signed('base'));
      const dependabot = s.commit({ name: 'dependabot[bot]', email: DEPENDABOT_EMAIL }, 'bump x from 1 to 2');
      s.github(dependabot, true, 'valid', 'dependabot[bot]', 'web-flow');
      expect(s.dco(base, dependabot).status).toBe(0);

      const signedHuman = s.commit(pat, signed('signed human change'));
      // A signed-off commit is accepted without consulting the API at all.
      expect(s.dco(dependabot, signedHuman).status).toBe(0);

      // Anyone can write Dependabot's name and email into a commit; GitHub
      // then resolves the author login but reports the commit unverified.
      const spoofed = s.commit({ name: 'dependabot[bot]', email: DEPENDABOT_EMAIL }, 'not really dependabot');
      s.github(spoofed, false, 'unsigned', 'dependabot[bot]', 'mallory');
      const spoofedResult = s.dco(signedHuman, spoofed);
      expect(spoofedResult.status).toBe(1);
      expect(spoofedResult.output).toContain(
        `Commit ${spoofed} is missing Signed-off-by: dependabot[bot] <${DEPENDABOT_EMAIL}>`,
      );

      // Setting the committer to GitHub <noreply@github.com> makes the API
      // resolve the committer login to web-flow, but the commit stays
      // unsigned, so the signature requirement must still refuse it.
      s.git(['checkout', '--quiet', '--detach', signedHuman]);
      const webFlowSpoof = s.commit({ name: 'dependabot[bot]', email: DEPENDABOT_EMAIL }, 'unsigned with a web-flow committer');
      s.github(webFlowSpoof, false, 'unsigned', 'dependabot[bot]', 'web-flow');
      expect(s.dco(signedHuman, webFlowSpoof).status).toBe(1);

      // Verified, but committed by a person rather than GitHub.
      s.git(['checkout', '--quiet', '--detach', signedHuman]);
      const selfSigned = s.commit({ name: 'dependabot[bot]', email: DEPENDABOT_EMAIL }, 'signed by a person');
      s.github(selfSigned, true, 'valid', 'dependabot[bot]', 'mallory');
      expect(s.dco(signedHuman, selfSigned).status).toBe(1);

      s.git(['checkout', '--quiet', '--detach', signedHuman]);
      const borrowed = s.commit({ name: 'dependabot[bot]', email: 'human@example.com' }, 'human identity cannot borrow the bot name');
      const borrowedResult = s.dco(signedHuman, borrowed);
      expect(borrowedResult.status).toBe(1);
      expect(borrowedResult.output).toContain(
        `Commit ${borrowed} is missing Signed-off-by: dependabot[bot] <human@example.com>`,
      );

      // A commit the API cannot resolve is never exempt.
      s.git(['checkout', '--quiet', '--detach', signedHuman]);
      const unknown = s.commit({ name: 'dependabot[bot]', email: DEPENDABOT_EMAIL }, 'unknown to the API');
      expect(s.dco(signedHuman, unknown).status).toBe(1);
    } finally {
      s.cleanup();
    }
  });

  it('exempts an evidence autopilot commit only on verified App identity, the trailer and derived-evidence paths', () => {
    const s = sandbox();
    try {
      const base = s.commit(pat, signed('base'), { files: ['lib/code.ts'] });
      const evidence = ['lib/proof-stats.json', 'public/.well-known/emilia-context.json'];
      const bot = { name: AUTOPILOT, email: AUTOPILOT_EMAIL };

      const genuine = s.commit(bot, autopilotMessage, { files: evidence });
      s.github(genuine, true, 'valid', AUTOPILOT, 'web-flow');
      const genuineResult = s.dco(base, genuine);
      expect(genuineResult.status).toBe(0);
      expect(genuineResult.output).toContain('GitHub-verified evidence autopilot commit');

      // GitHub may also report the bot itself as committer; still verified.
      const botCommitter = s.commit(bot, autopilotMessage, { files: evidence });
      s.github(botCommitter, true, 'valid', AUTOPILOT, AUTOPILOT);
      expect(s.dco(genuine, botCommitter).status).toBe(0);

      // The exemption is off while the repository variable is unset or
      // malformed; it is never widened to "any [bot]".
      for (const login of ['', 'emilia-evidence-autopilot', '*[bot]', 'a b[bot]']) {
        const off = s.dco(base, genuine, { EVIDENCE_AUTOPILOT_BOT_LOGIN: login });
        expect(off.status, JSON.stringify(login)).toBe(1);
        expect(off.output).toContain(`Commit ${genuine} is missing Signed-off-by: ${AUTOPILOT} <${AUTOPILOT_EMAIL}>`);
      }

      // The same verified identity changing anything else fails outright.
      const smuggled = s.commit(bot, autopilotMessage, { files: ['security/security-case.json', 'lib/code.ts'] });
      s.github(smuggled, true, 'valid', AUTOPILOT, 'web-flow');
      const smuggledResult = s.dco(botCommitter, smuggled);
      expect(smuggledResult.status).toBe(1);
      expect(smuggledResult.output).toContain(
        `Commit ${smuggled} is an evidence autopilot commit but is not single-parent or changes other paths: lib/code.ts`,
      );

      // Without the trailer a verified bot commit is an ordinary commit.
      s.git(['checkout', '--quiet', '--detach', botCommitter]);
      const noTrailer = s.commit(bot, 'chore(evidence): regenerate', { files: evidence });
      s.github(noTrailer, true, 'valid', AUTOPILOT, 'web-flow');
      expect(s.dco(botCommitter, noTrailer).status).toBe(1);
    } finally {
      s.cleanup();
    }
  });

  it('does not exempt a spoofed [bot] author carrying the autopilot trailer', () => {
    const s = sandbox();
    try {
      const base = s.commit(pat, signed('base'));
      const evidence = ['AI_CONTEXT.md', 'public/llms.txt'];
      const impostor = { name: AUTOPILOT, email: AUTOPILOT_EMAIL };
      const mallory = { name: 'mallory[bot]', email: '1+mallory[bot]@users.noreply.github.com' };
      const attempt = (identity: Identity, message: string, committer?: Identity) => {
        s.git(['checkout', '--quiet', '--detach', base]);
        return s.commit(identity, message, { files: evidence, committer });
      };
      const cases: Array<{ what: string; identity: Identity; sha: string; api: [boolean, string, string, string] }> = [
        {
          // The security review's proof: any x[bot] name and noreply email
          // with the trailer. GitHub reports it unsigned.
          what: 'arbitrary [bot] author',
          identity: mallory,
          sha: attempt(mallory, 'chore: tweak\n\nEvidence-Autopilot: v1'),
          api: [false, 'unsigned', 'mallory[bot]', '-'],
        },
        {
          what: "the App's own name and email, pushed by a person",
          identity: impostor,
          sha: attempt(impostor, autopilotMessage),
          api: [false, 'unsigned', AUTOPILOT, 'mallory'],
        },
        {
          what: "signed with the pusher's own key: verified, committed by a person",
          identity: impostor,
          sha: attempt(impostor, autopilotMessage.replace('regenerate', 'regenerate (self-signed)')),
          api: [true, 'valid', AUTOPILOT, 'mallory'],
        },
        {
          what: 'GitHub named as committer without a GitHub signature',
          identity: impostor,
          sha: attempt(impostor, autopilotMessage.replace('regenerate', 'regenerate (named GitHub)'), githubCommitter),
          api: [false, 'bad_email', AUTOPILOT, 'web-flow'],
        },
      ];
      for (const { what, identity, sha, api } of cases) {
        s.github(sha, ...api);
        const result = s.dco(base, sha);
        expect(result.status, what).toBe(1);
        expect(result.output, what).toContain(`Commit ${sha} is missing Signed-off-by: ${identity.name} <${identity.email}>`);
        expect(result.output, what).not.toContain('DCO sign-off is not required');
      }
      expect(new Set(cases.map((c) => c.sha)).size).toBe(cases.length);
    } finally {
      s.cleanup();
    }
  });

  it('on merge_group skips only first-parent merges committed by GitHub and checks everything else', () => {
    const s = sandbox();
    try {
      const base = s.commit(pat, signed('base'));
      const mergeAs = (committer: Identity, into: string, other: string, message: string) => {
        s.git(['checkout', '--quiet', '--detach', into]);
        s.git(['merge', '--quiet', '--no-ff', '-m', message, other], {
          GIT_AUTHOR_NAME: pat.name, GIT_AUTHOR_EMAIL: pat.email,
          GIT_COMMITTER_NAME: committer.name, GIT_COMMITTER_EMAIL: committer.email,
        });
        return s.git(['rev-parse', 'HEAD']);
      };

      // A clean pull request branch.
      s.git(['checkout', '--quiet', '--detach', base]);
      const cleanHead = s.commit(pat, signed('clean work'), { files: ['docs/c.md'] });

      // A pull request branch that carries an unsigned merge commit whose
      // committer claims to be GitHub (anyone can write that locally).
      s.git(['checkout', '--quiet', '--detach', base]);
      const topic = s.commit(pat, signed('topic work'), { files: ['docs/a.md'] });
      s.git(['checkout', '--quiet', '--detach', base]);
      const side = s.commit(pat, signed('side work'), { files: ['docs/b.md'] });
      const topicHead = mergeAs(githubCommitter, topic, side, 'Merge side into topic');

      const group = { DCO_MERGE_GROUP: 'true' };
      const cleanGroup = mergeAs(githubCommitter, base, cleanHead, 'Merge pull request #1');
      const cleanResult = s.dco(base, cleanGroup, group);
      expect(cleanResult.status).toBe(0);
      expect(cleanResult.output).toContain(`Commit ${cleanGroup} is a merge-queue merge commit created by GitHub`);
      // Outside a merge group the same unsigned merge commit is checked.
      expect(s.dco(base, cleanGroup).status).toBe(1);

      // The merge inside the pull request branch is not a first-parent merge
      // of the group, so it is checked and fails even though it names GitHub.
      const topicGroup = mergeAs(githubCommitter, base, topicHead, 'Merge pull request #2');
      const topicResult = s.dco(base, topicGroup, group);
      expect(topicResult.status).toBe(1);
      expect(topicResult.output).toContain(`Commit ${topicHead} is missing Signed-off-by: Pat Example <pat@example.com>`);
      expect(topicResult.output).toContain(`Commit ${topicGroup} is a merge-queue merge commit created by GitHub`);

      // A first-parent merge that GitHub did not commit is checked.
      const forgedGroup = mergeAs({ name: 'Queue', email: 'queue@example.com' }, base, cleanHead, 'Merge pull request #3');
      expect(s.dco(base, forgedGroup, group).status).toBe(1);
    } finally {
      s.cleanup();
    }
  });
});

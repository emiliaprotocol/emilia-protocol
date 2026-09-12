// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const script = path.resolve(import.meta.dirname, '../scripts/schema-pr-candidate-reconcile.mjs');
const roots: string[] = [];
const applied = '20260826130000'; const pending = '20260901190000'; const added = '20260907235809'; const privateVersion = '20260723192504';
const baseFile = `${applied}_base.sql`; const pendingFile = `${pending}_pending.sql`; const addedFile = `${added}_works_accounts.sql`;
const hash = (bytes: string) => crypto.createHash('sha256').update(bytes).digest('hex');
type Ledger = { schema_version: string; as_of: string; remote_head: string; private_remote_versions: string[];
  retroactive_pending_versions: string[]; forward_pending_versions: string[]; deployment_sequence: string[];
  requires_include_all: boolean; remote_versions: string[]; public_files: Record<string, string> };

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-schema-candidate-')); roots.push(root);
  const base = path.join(root, 'trusted-base'); const candidate = path.join(root, 'candidate-data');
  for (const checkout of [base, candidate]) {
    fs.mkdirSync(path.join(checkout, 'supabase/migrations'), { recursive: true });
    const archive = path.join(checkout, 'supabase/migration-archive/2026-07-25-history-reconciliation');
    fs.mkdirSync(archive, { recursive: true }); fs.writeFileSync(path.join(archive, 'SHA256SUMS'), '');
    fs.writeFileSync(path.join(checkout, 'supabase/migrations', baseFile), 'select 1;\n');
    fs.writeFileSync(path.join(checkout, 'supabase/migrations', pendingFile), 'select 2;\n');
    writeLedger(checkout, { schema_version: 'EP-MIGRATION-HISTORY-v1', as_of: '2026-08-26', remote_head: applied,
      private_remote_versions: [privateVersion], retroactive_pending_versions: [], forward_pending_versions: [pending],
      deployment_sequence: [pending], requires_include_all: false, remote_versions: [privateVersion, applied],
      public_files: { [baseFile]: hash('select 1;\n'), [pendingFile]: hash('select 2;\n') } });
  }
  return { root, base, candidate };
}
function readLedger(root: string): Ledger { return JSON.parse(fs.readFileSync(path.join(root, 'supabase/migration-history.v1.json'), 'utf8')); }
function writeLedger(root: string, ledger: Ledger) { fs.writeFileSync(path.join(root, 'supabase/migration-history.v1.json'), `${JSON.stringify(ledger, null, 2)}\n`); }
function addMigration(root: string, classification: 'pending' | 'remote' = 'pending') {
  fs.writeFileSync(path.join(root, 'supabase/migrations', addedFile), 'select 3;\n');
  const ledger = readLedger(root); ledger.public_files[addedFile] = hash('select 3;\n');
  if (classification === 'pending') { ledger.forward_pending_versions.push(added); ledger.deployment_sequence.push(added); }
  else {
    ledger.as_of = '2026-09-07'; ledger.remote_versions.push(added); ledger.remote_head = added;
    ledger.retroactive_pending_versions = [pending]; ledger.forward_pending_versions = []; ledger.requires_include_all = true;
  }
  writeLedger(root, ledger);
}
function run(base: string, candidate: string) {
  const result = spawnSync(process.execPath, [script, '--base-root', base, '--candidate-root', candidate], { encoding: 'utf8' });
  return { status: result.status, output: `${result.stdout || ''}${result.stderr || ''}` };
}
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });

describe('trusted-base candidate migration reconciliation', () => {
  it('accepts a helper-only candidate with unchanged migration data', () => {
    const { base, candidate } = fixture();
    expect(run(base, candidate).status).toBe(0);
  });

  it('rejects a corrupt trusted baseline instead of accepting candidate assertions over it', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(base);
    ledger.public_files[baseFile] = hash('not the trusted SQL'); writeLedger(base, ledger);
    const result = run(base, candidate);
    expect(result.status).not.toBe(0); expect(result.output).toContain('trusted base migration history is invalid');
  });

  it('accepts new pending SQL with its exact hash and deployment order', () => {
    const { base, candidate } = fixture(); addMigration(candidate);
    expect(run(base, candidate).status).toBe(0);
  });

  it('accepts correctly journaled added SQL without falsely requiring an already-applied migration to be pending', () => {
    const { base, candidate } = fixture(); addMigration(candidate, 'remote');
    const result = run(base, candidate);
    expect(result.output).not.toContain('new migration is not classified as pending');
    expect(result.status).toBe(0);
    expect(result.output).toContain('live deployment is not verified');
  });

  it('keeps pre-existing pending SQL classified as pending after a newer candidate journal head', () => {
    const { base, candidate } = fixture(); addMigration(candidate, 'remote');
    const ledger = readLedger(candidate);
    expect(ledger.retroactive_pending_versions).toEqual([pending]);
    expect(ledger.remote_versions).not.toContain(pending);
    expect(run(base, candidate).status).toBe(0);
  });

  it('rejects rewriting a confirmed base migration even when the candidate substitutes its hash', () => {
    const { base, candidate } = fixture();
    fs.writeFileSync(path.join(candidate, 'supabase/migrations', baseFile), 'select 999;\n');
    const ledger = readLedger(candidate); ledger.public_files[baseFile] = hash('select 999;\n'); writeLedger(candidate, ledger);
    expect(run(base, candidate).output).toContain(`candidate rewrites base migration: ${baseFile}`);
  });

  it('rejects deleting a confirmed base migration', () => {
    const { base, candidate } = fixture(); fs.unlinkSync(path.join(candidate, 'supabase/migrations', baseFile));
    expect(run(base, candidate).output).toContain(`candidate deletes base migration: ${baseFile}`);
  });

  it('rejects substituting only a confirmed base ledger hash', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate);
    ledger.public_files[baseFile] = hash('other bytes'); writeLedger(candidate, ledger);
    expect(run(base, candidate).status).not.toBe(0);
  });

  it('rejects demoting an existing remote version to pending while preserving its SQL bytes', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate);
    ledger.remote_versions = [privateVersion]; ledger.remote_head = privateVersion;
    ledger.forward_pending_versions = [applied, pending]; ledger.deployment_sequence = [applied, pending]; writeLedger(candidate, ledger);
    const result = run(base, candidate);
    expect(result.status).not.toBe(0); expect(result.output).toContain(`existing remote version: ${applied}`);
  });

  it('rejects deleting private remote history even when the resulting candidate ledger is internally consistent', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate);
    ledger.private_remote_versions = []; ledger.remote_versions = [applied]; writeLedger(candidate, ledger);
    const result = run(base, candidate);
    expect(result.status).not.toBe(0); expect(result.output).toContain(`existing remote version: ${privateVersion}`);
  });

  it('rejects publishing a previously private remote version by dropping its private classification', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate); const filename = `${privateVersion}_private.sql`;
    ledger.private_remote_versions = []; ledger.public_files[filename] = hash('select 0;\n'); writeLedger(candidate, ledger);
    fs.writeFileSync(path.join(candidate, 'supabase/migrations', filename), 'select 0;\n');
    const result = run(base, candidate);
    expect(result.status).not.toBe(0); expect(result.output).toContain(`existing private remote version: ${privateVersion}`);
  });

  it('rejects moving the candidate observation date behind the trusted base date', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate);
    ledger.as_of = '2026-08-25'; writeLedger(candidate, ledger);
    const result = run(base, candidate);
    expect(result.status).not.toBe(0); expect(result.output).toContain('observation date');
  });

  it.each(['duplicate remote', 'both pending and remote', 'unclassified', 'missing hash', 'wrong hash', 'bad deployment order'])(
    'rejects a new migration with %s', condition => {
      const { base, candidate } = fixture(); addMigration(candidate, 'remote'); const ledger = readLedger(candidate);
      if (condition === 'duplicate remote') ledger.remote_versions.push(added);
      if (condition === 'both pending and remote') { ledger.retroactive_pending_versions.push(added); ledger.deployment_sequence.push(added); }
      if (condition === 'unclassified') { ledger.remote_versions.pop(); ledger.remote_head = applied; ledger.retroactive_pending_versions = []; ledger.forward_pending_versions = [pending]; ledger.requires_include_all = false; }
      if (condition === 'missing hash') delete ledger.public_files[addedFile];
      if (condition === 'wrong hash') ledger.public_files[addedFile] = hash('not the submitted SQL');
      if (condition === 'bad deployment order') ledger.deployment_sequence = [];
      writeLedger(candidate, ledger); expect(run(base, candidate).status).not.toBe(0);
    },
  );

  it('rejects inconsistent pending/remote classifications on existing SQL too', () => {
    const { base, candidate } = fixture(); const ledger = readLedger(candidate);
    ledger.remote_versions.push(pending); ledger.remote_head = pending; writeLedger(candidate, ledger);
    expect(run(base, candidate).status).not.toBe(0);
  });

  it('rejects new migration symlinks and unpinned archive changes', () => {
    const { root, base, candidate } = fixture(); addMigration(candidate);
    const target = path.join(root, 'target.sql'); fs.writeFileSync(target, 'select 3;\n');
    const file = path.join(candidate, 'supabase/migrations', addedFile); fs.unlinkSync(file); fs.symlinkSync(target, file);
    expect(run(base, candidate).status).not.toBe(0);
    fs.unlinkSync(file); fs.writeFileSync(file, 'select 3;\n');
    fs.writeFileSync(path.join(candidate, 'supabase/migration-archive/2026-07-25-history-reconciliation/001_extra.sql'), 'select 1;\n');
    expect(run(base, candidate).status).not.toBe(0);
  });

  it('treats the candidate as data and does not import or run its executable files', () => {
    const { root, base, candidate } = fixture(); addMigration(candidate, 'remote');
    const marker = path.join(root, 'candidate-executed'); fs.mkdirSync(path.join(candidate, 'scripts'));
    fs.writeFileSync(path.join(candidate, 'scripts/check-migration-history.mjs'), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'executed'); throw new Error('untrusted code ran');\n`);
    fs.writeFileSync(path.join(candidate, 'package.json'), JSON.stringify({ type: 'module', scripts: { preinstall: 'exit 99' } }));
    expect(run(base, candidate).status).toBe(0); expect(fs.existsSync(marker)).toBe(false);
  });
});

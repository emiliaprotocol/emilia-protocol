// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { validateMigrationHistory } from '../scripts/check-migration-history.mjs';

const roots: string[] = [];
const hash = (value: string): string => crypto.createHash('sha256').update(value).digest('hex');

function fixture(): string {
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-migration-history-'));
  roots.push(root);
  const migrations: string = path.join(root, 'supabase/migrations');
  const archive: string = path.join(root, 'supabase/migration-archive/2026-07-25-history-reconciliation');
  fs.mkdirSync(migrations, { recursive: true });
  fs.mkdirSync(archive, { recursive: true });
  fs.writeFileSync(path.join(migrations, '001_first.sql'), 'select 1;\n');
  fs.writeFileSync(path.join(migrations, '003_pending.sql'), 'select 3;\n');
  fs.writeFileSync(path.join(archive, '001_old_alias.sql'), 'select 1;\n');
  fs.writeFileSync(
    path.join(archive, 'SHA256SUMS'),
    `${hash('select 1;\n')}  001_old_alias.sql\n`,
  );
  fs.writeFileSync(
    path.join(root, 'supabase/migration-history.v1.json'),
    `${JSON.stringify({
      schema_version: 'EP-MIGRATION-HISTORY-v1',
      as_of: '2026-07-25',
      remote_head: '002',
      private_remote_versions: ['002'],
      pending_versions: ['003'],
      remote_versions: ['001', '002'],
      public_files: {
        '001_first.sql': hash('select 1;\n'),
        '003_pending.sql': hash('select 3;\n'),
      },
    }, null, 2)}\n`,
  );
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('migration history ledger', () => {
  it('accepts public remote history plus pending migrations while keeping private history absent', () => {
    expect(validateMigrationHistory(fixture())).toEqual({
      publicFiles: 2,
      remoteVersions: 2,
      pendingVersions: 1,
      privateRemoteVersions: 1,
    });
  });

  it('rejects duplicate executable timestamps', () => {
    const root: string = fixture();
    const duplicate: string = path.join(root, 'supabase/migrations/003_duplicate.sql');
    fs.writeFileSync(duplicate, 'select 4;\n');
    const historyPath: string = path.join(root, 'supabase/migration-history.v1.json');
    const history = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
    history.public_files['003_duplicate.sql'] = hash('select 4;\n');
    fs.writeFileSync(historyPath, `${JSON.stringify(history, null, 2)}\n`);
    expect(() => validateMigrationHistory(root)).toThrow(/duplicate versions/);
  });

  it('rejects hash drift and undeclared executable files', () => {
    const root: string = fixture();
    fs.writeFileSync(path.join(root, 'supabase/migrations/001_first.sql'), 'select 9;\n');
    expect(() => validateMigrationHistory(root)).toThrow(/does not match its SHA-256 pin/);

    const extraRoot: string = fixture();
    fs.writeFileSync(path.join(extraRoot, 'supabase/migrations/004_extra.sql'), 'select 4;\n');
    expect(() => validateMigrationHistory(extraRoot)).toThrow(/cover every executable SQL migration/);
  });

  it('rejects a public copy of private history and plaintext role credentials', () => {
    const privateRoot: string = fixture();
    fs.writeFileSync(path.join(privateRoot, 'supabase/migrations/002_private.sql'), 'select 2;\n');
    const privateHistoryPath: string = path.join(privateRoot, 'supabase/migration-history.v1.json');
    const privateHistory = JSON.parse(fs.readFileSync(privateHistoryPath, 'utf8'));
    privateHistory.public_files['002_private.sql'] = hash('select 2;\n');
    fs.writeFileSync(privateHistoryPath, `${JSON.stringify(privateHistory, null, 2)}\n`);
    expect(() => validateMigrationHistory(privateRoot)).toThrow(/private remote version 002/);

    const passwordRoot: string = fixture();
    const credentialSql: string = "alter role operator login password 'do-not-commit';\n";
    fs.writeFileSync(path.join(passwordRoot, 'supabase/migrations/003_pending.sql'), credentialSql);
    const passwordHistoryPath: string = path.join(passwordRoot, 'supabase/migration-history.v1.json');
    const passwordHistory = JSON.parse(fs.readFileSync(passwordHistoryPath, 'utf8'));
    passwordHistory.public_files['003_pending.sql'] = hash(credentialSql);
    fs.writeFileSync(passwordHistoryPath, `${JSON.stringify(passwordHistory, null, 2)}\n`);
    expect(() => validateMigrationHistory(passwordRoot)).toThrow(/plaintext role password/);
  });

  it('rejects archive checksum drift', () => {
    const root: string = fixture();
    fs.writeFileSync(
      path.join(root, 'supabase/migration-archive/2026-07-25-history-reconciliation/001_old_alias.sql'),
      'select 8;\n',
    );
    expect(() => validateMigrationHistory(root)).toThrow(/does not match SHA256SUMS/);
  });
});

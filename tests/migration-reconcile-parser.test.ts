// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { maskSqlNonCode } from '../scripts/lib/sql-text.mjs';

const declaredTables = (sql: string): string[] => {
  const code = maskSqlNonCode(sql);
  return [...code.matchAll(
    /create\s+table\s+(?:if\s+not\s+exists\s+)?["']?([a-z_][a-z0-9_."]*)/gi,
  )].map((match) => match[1].toLowerCase().replace(/^public\./, ''));
};

describe('migration reconciliation SQL parser', () => {
  it('does not interpret migration documentation as a table named if', () => {
    const sql = `
      -- The next migration uses CREATE TABLE IF NOT EXISTS and then adds an index.
      CREATE TABLE IF NOT EXISTS public.real_table (id text primary key);
    `;

    expect(declaredTables(sql)).toEqual(['real_table']);
  });

  it('masks nested comments, literals, and procedural bodies', () => {
    const sql = `
      /* CREATE TABLE comment_table (id text); /* nested CREATE TABLE nested_table */ */
      SELECT 'CREATE TABLE literal_table (id text)';
      CREATE FUNCTION public.example() RETURNS void LANGUAGE plpgsql AS $body$
      BEGIN
        EXECUTE 'CREATE TABLE dynamic_table (id text)';
      END
      $body$;
      CREATE TABLE public.actual_table (id text primary key);
    `;

    expect(declaredTables(sql)).toEqual(['actual_table']);
  });

  it('preserves quoted executable identifiers', () => {
    expect(declaredTables('CREATE TABLE public."CaseSensitive" (id text);')).toEqual([
      '"casesensitive"',
    ]);
  });
});

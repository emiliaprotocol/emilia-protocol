#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { verifyCap1 } from './verify.mjs';

export async function runFile(path) {
  let document;
  try {
    document = JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    return {
      verdict: 'REFUSES',
      primary_rule: 'R0-shape',
      violations: [{
        rule: 'R0-shape',
        problems: [{
          path: '$',
          detail: `input is not readable JSON: ${error instanceof Error ? error.message : 'unknown error'}`,
        }],
      }],
    };
  }
  return verifyCap1(document);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: node run.mjs <cap-1.json>');
    process.exitCode = 2;
  } else {
    const result = await runFile(path);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.verdict === 'CONFORMS' ? 0 : 1;
  }
}

// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../..');

export interface RenderedLlmContext {
  aiContext: string;
  llms: string;
  llmsFull: string;
  machineContext: string;
}

let cached: RenderedLlmContext | undefined;

/**
 * The four LLM context artifacts as scripts/generate-llm-context.mjs renders
 * them from the current sources, written to a temporary directory.
 *
 * Tests assert on this rendering, never on the checked-in copies. Those copies
 * are volatile evidence: main regenerates them after merge
 * (.github/workflows/volatile-evidence-refresh.yml), so on a pull request they
 * may lag the sources, and whether they are current is decided by
 * `npm run check:llm-context` under the volatile-evidence policy, not by the
 * test suite. A content test that read the checked-in bytes would pass or fail
 * with that lag instead of with the generator.
 */
export function renderedLlmContext(): RenderedLlmContext {
  if (cached) return cached;
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-rendered-llm-context-'));
  try {
    execFileSync(
      process.execPath,
      [path.join(ROOT, 'scripts/generate-llm-context.mjs'), '--write', '--out-dir', outDir],
      { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    const read = (relative: string): string => fs.readFileSync(path.join(outDir, relative), 'utf8');
    cached = {
      aiContext: read('AI_CONTEXT.md'),
      llms: read('public/llms.txt'),
      llmsFull: read('public/llms-full.txt'),
      machineContext: read('public/.well-known/emilia-context.json'),
    };
    return cached;
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
}

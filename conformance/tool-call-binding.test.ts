// SPDX-License-Identifier: Apache-2.0
//
// Cross-implementation agreement on the canonical tool-call action material.
//
// WHY THIS EXISTS. Two shipped adapters produced different action digests for the same
// logical call. The TypeScript binder in packages/require-receipt (used by the LangChain,
// OpenAI-Agents and MCP-Guard adapters) canonicalized {tool, args}; the CrewAI Python
// adapter canonicalized {tool, arguments} and additionally hashed an optional selector
// that the TypeScript binder excludes. A receipt minted through one adapter could never
// verify against the other, silently, and nothing caught it because all 21 conformance
// suites covered LANGUAGE implementations and not one covered a framework adapter.
//
// Neither implementation was wrong. CAID, AEB and the receipts draft never fixed the
// member name, so both invented one. This file pins it.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

import { bindToolAction } from '../packages/require-receipt/index.js';

const ROOT = join(__dirname, '..');
const VECTOR_PATH = join(ROOT, 'conformance/vectors/tool-call-binding.v1.json');
const VECTORS = JSON.parse(readFileSync(VECTOR_PATH, 'utf8'));

describe('EP-TOOL-CALL-BINDING-v1', () => {
  it('the TypeScript binder reproduces every pinned vector', () => {
    for (const v of VECTORS.vectors) {
      expect(bindToolAction(v.tool, v.args, v.base_action), v.id).toBe(v.expected_caid);
    }
  });

  it('the CrewAI Python adapter agrees byte-for-byte with the TypeScript binder', () => {
    const script = [
      'import json, sys',
      'from emilia_crewai import bind_call_action',
      'vectors = json.load(open(sys.argv[1]))["vectors"]',
      'print(json.dumps({v["id"]: bind_call_action(v["base_action"], v["tool"], v["args"]) for v in vectors}))',
    ].join('\n');

    let raw: string;
    try {
      raw = execFileSync('python3', ['-c', script, VECTOR_PATH], {
        encoding: 'utf8',
        env: {
          ...process.env,
          PYTHONPATH: [
            join(ROOT, 'packages/crewai'),
            join(ROOT, 'packages/python-verify'),
            join(ROOT, 'packages/ep-verify-py'),
          ].join(':'),
        },
      });
    } catch (err: any) {
      // A missing or broken Python toolchain must not silently pass the one suite that
      // exists to prove two languages agree.
      throw new Error(`python adapter could not be exercised: ${err?.message ?? err}`);
    }

    const got = JSON.parse(raw);
    for (const v of VECTORS.vectors) {
      expect(got[v.id], `${v.id}: python/typescript action digest divergence`).toBe(v.expected_caid);
    }
  });

  it('the vectors discriminate: the "arguments" material must not reproduce them', () => {
    // Mutation test. Without this, the suite could pass a binder carrying the exact
    // defect it was written to catch.
    const canonical = (o: Record<string, unknown>) => JSON.stringify(o, Object.keys(o).sort());
    const brokenBinder = (tool: string, args: unknown, base: string) =>
      `${base}:sha256:${createHash('sha256').update(canonical({ tool, arguments: args })).digest('hex')}`;

    for (const v of VECTORS.vectors) {
      expect(brokenBinder(v.tool, v.args, v.base_action), v.id).not.toBe(v.expected_caid);
    }
  });
});

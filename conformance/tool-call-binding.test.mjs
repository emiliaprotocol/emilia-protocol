// SPDX-License-Identifier: Apache-2.0
//
// Cross-implementation agreement on the canonical tool-call action material.
//
//   node --test conformance/tool-call-binding.test.mjs
//
// WHY THIS EXISTS. Two shipped adapters disagreed on the action digest for the same
// logical call. The TypeScript binder in packages/require-receipt (used by the LangChain,
// OpenAI-Agents and MCP-Guard adapters) canonicalized {tool, args}; the CrewAI Python
// adapter canonicalized {tool, arguments} and additionally hashed an optional selector
// that the TypeScript binder excludes. A receipt minted through one adapter could never
// verify against the other, silently, and nothing caught it because all 21 conformance
// suites covered LANGUAGE implementations and none covered a framework adapter.
//
// Neither implementation was wrong. CAID, AEB and the receipts draft never fixed the
// member name, so both invented one. This file pins it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const VECTORS = JSON.parse(readFileSync(join(HERE, 'vectors/tool-call-binding.v1.json'), 'utf8'));

const { bindToolAction } = await import(join(ROOT, 'packages/require-receipt/index.js'));

test('TypeScript binder reproduces every pinned vector', () => {
  for (const v of VECTORS.vectors) {
    assert.equal(bindToolAction(v.tool, v.args, v.base_action), v.expected_caid, v.id);
  }
});

test('Python CrewAI adapter agrees byte-for-byte with the TypeScript binder', () => {
  const script = `
import json, sys
from emilia_crewai import bind_call_action
vectors = json.load(open(sys.argv[1]))["vectors"]
print(json.dumps({v["id"]: bind_call_action(v["base_action"], v["tool"], v["args"]) for v in vectors}))
`;
  let out;
  try {
    out = execFileSync('python3', ['-c', script, join(HERE, 'vectors/tool-call-binding.v1.json')], {
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
  } catch (err) {
    // A missing Python toolchain must not silently pass this suite.
    assert.fail(`python adapter could not be exercised: ${err.message}`);
  }
  const got = JSON.parse(out);
  for (const v of VECTORS.vectors) {
    assert.equal(got[v.id], v.expected_caid, `${v.id}: python/typescript action digest divergence`);
  }
});

test('the vectors discriminate: a renamed material member must not reproduce them', () => {
  // Mutation test. If this passes, the suite cannot detect the exact defect it exists for.
  const canonical = (o) => JSON.stringify(o, Object.keys(o).sort());
  const broken = (tool, args, base) =>
    `${base}:sha256:${createHash('sha256').update(canonical({ tool, arguments: args })).digest('hex')}`;
  let diverged = 0;
  for (const v of VECTORS.vectors) {
    if (broken(v.tool, v.args, v.base_action) !== v.expected_caid) diverged += 1;
  }
  assert.equal(diverged, VECTORS.vectors.length,
    'every vector must distinguish the "args" material from the "arguments" material');
});

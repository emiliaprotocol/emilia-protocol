#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import {
  FORMAL_RUNTIME_CONFIG,
  FORMAL_RUNTIME_INVARIANT_MAP,
} from '../packages/gate/formal-runtime-map.js';
import { RUNTIME_INVARIANTS } from '../packages/gate/runtime-monitor.js';

const config: string = readFileSync(FORMAL_RUNTIME_CONFIG, 'utf8');
const configured: Set<string> = new Set([...config.matchAll(/^INVARIANT\s+([A-Za-z0-9_]+)/gm)].map((match: RegExpExecArray) => match[1]));
const mappedFormal: Set<any> = new Set(FORMAL_RUNTIME_INVARIANT_MAP.map((item: any) => item.formal));
const mappedRuntime: Set<any> = new Set(FORMAL_RUNTIME_INVARIANT_MAP.map((item: any) => item.runtime));
const errors: string[] = [];

for (const item of FORMAL_RUNTIME_INVARIANT_MAP) {
  if (!configured.has((item as any).formal)) errors.push(`${(item as any).formal} is not declared in ${FORMAL_RUNTIME_CONFIG}`);
}
for (const invariant of Object.values(RUNTIME_INVARIANTS)) {
  if (!mappedRuntime.has(invariant)) errors.push(`${invariant} has no formal source mapping`);
}
if (mappedFormal.size !== FORMAL_RUNTIME_INVARIANT_MAP.length) errors.push('formal runtime map contains duplicate theorem names');

if (errors.length) {
  console.error('FORMAL RUNTIME BRIDGE: FAIL');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`FORMAL RUNTIME BRIDGE: PASS — ${FORMAL_RUNTIME_INVARIANT_MAP.length} runtime invariants bound to ${FORMAL_RUNTIME_CONFIG}`);

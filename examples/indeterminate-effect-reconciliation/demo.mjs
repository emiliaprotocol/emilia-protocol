#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { runIndeterminateEffectDemo } from './scenario.mts';
const result = await runIndeterminateEffectDemo();
console.log('EMILIA INDETERMINATE-EFFECT RECONCILIATION');
console.log('');
console.log(`1  PROVIDER COMMITTED     effects=${result.provider.committed_effects}`);
console.log(`2  RESPONSE LOST          ${result.first_attempt.reason}`);
console.log(`3  CAPABILITY FINALIZED   ${result.capability_operation.outcome}`);
console.log(`4  BLIND RETRY            ${result.retry.reason}`);
console.log(`5  AUTHENTICATED GET      ${result.reconciliation.outcome}`);
console.log(`6  PROVIDER EXECUTIONS    ${result.provider.execution_attempts}`);
console.log('');
console.log(JSON.stringify(result, null, 2));

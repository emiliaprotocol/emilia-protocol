#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { runSupplyChainAuthorityDemo } from './scenario.mjs';
const result = await runSupplyChainAuthorityDemo();
console.log(JSON.stringify(result, null, 2));

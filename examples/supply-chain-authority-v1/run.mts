#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { runSupplyChainAuthorityDemo } from './scenario.mjs';

const result = await runSupplyChainAuthorityDemo();
console.log(JSON.stringify(result, null, 2));

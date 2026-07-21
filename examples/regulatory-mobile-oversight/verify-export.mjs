#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from verify-export.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import fs from 'node:fs';
import { verifyRegulatoryEvidence } from './lib.mjs';
const [evidencePath, pinsPath] = process.argv.slice(2);
if (!evidencePath || !pinsPath) {
    console.error('Usage: node verify-export.mjs <evidence.json> <regulator-pins.json>');
    process.exit(2);
}
const evidence = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
const pins = JSON.parse(fs.readFileSync(pinsPath, 'utf8'));
const report = verifyRegulatoryEvidence(evidence, pins);
console.log(JSON.stringify(report, null, 2));
if (!report.valid)
    process.exitCode = 1;

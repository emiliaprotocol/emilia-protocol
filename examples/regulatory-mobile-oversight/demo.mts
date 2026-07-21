#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import {
  buildSyntheticRegulatoryDemo,
  defaultOutputDirectory,
  verifyRegulatoryEvidence,
  writeDemoArtifacts,
} from './lib.mjs';

const demo = await buildSyntheticRegulatoryDemo();
const paths = writeDemoArtifacts(demo, defaultOutputDirectory());

console.log('EMILIA regulatory mobile oversight demo');
console.log('Data: synthetic only');
console.log(`Mobile ceremony: ${demo.onlineResult.verdict}`);
console.log(`Locally checked evidence package: ${demo.offlineReport.verdict}`);
console.log(`Synthetic system-of-record update: ${demo.effect.applied ? 'applied' : 'refused'}`);
console.log(`Second presentation: ${demo.replayResult.verdict}`);
console.log(`Platform evidence in this runnable fixture: ${demo.attestationFixture}`);
console.log(`Evidence: ${paths.evidencePath}`);
console.log(`Out-of-band pins fixture: ${paths.pinsPath}`);

const tampered = structuredClone(demo.evidence);
tampered.receipt.action.units_approved = 99;
console.log(`Tampered action: ${verifyRegulatoryEvidence(tampered, demo.trustBundle).verdict}`);

const wrongPins = structuredClone(demo.trustBundle);
wrongPins.approver_keys[demo.evidence.execution_record.device_key_id as string].public_key = 'AA';
console.log(`Unpinned reviewer key: ${verifyRegulatoryEvidence(demo.evidence, wrongPins).verdict}`);

console.log('\nOffline verification recomputes the action, presentation, passkey, policy, pins, log, and joins.');
console.log('Platform attestation, atomic consumption, and durable append remain signed operator assertions.');
console.log('The package does not establish clinical correctness, licensure, comprehension, compliance, or real-world effect.');

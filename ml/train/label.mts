// SPDX-License-Identifier: Apache-2.0
// Weak-labeler: bootstrap a training set from the deterministic engine.
//
// For every action the rules already decide, evaluateGuardPolicy IS ground
// truth — emit (action -> decision) training pairs for free. Actions the rules
// default-allow but that look high-impact are flagged for HUMAN review — that
// flagged set is the "perimeter" the model has to learn. Run this on real pilot
// traffic once you have it; the sample corpus is just to demonstrate the shape.
//
//   node ml/train/label.mjs [corpus.jsonl] > train.jsonl
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateGuardPolicy } from '../../lib/guard-policies.js';
import { extractSignals } from '../risk-eval/classifiers/heuristic.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const corpusPath = process.argv[2] || path.join(HERE, 'sample-actions.jsonl');

// Crude heuristics that mark a rule-"allow" as SUSPICIOUS -> hold for a human.
// Deliberately dumb: replacing these with a real classifier is the whole point.
const SUSPICIOUS = [
  /delete|drop|wipe|destroy|terminate/i,
  /transfer|wire|withdraw|payout|exfiltrat|external wallet/i,
  /ignore (previous|prior) instructions|override|jailbreak/i,
];
/**
 * @param {object} input - the shape evaluateGuardPolicy accepts.
 * @returns {boolean}
 */
const looksSuspicious = (input) => {
  const blob = JSON.stringify(input).toLowerCase();
  return SUSPICIOUS.some((re) => re.test(blob));
};

const lines = fs.readFileSync(corpusPath, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean);
let auto = 0;
let review = 0;

for (const line of lines) {
  const input = JSON.parse(line);
  const decision = evaluateGuardPolicy(input).decision;
  const { injectionSuspected } = extractSignals(input);
  const needsReview = decision === 'allow' && looksSuspicious(input);
  const example = {
    input,
    label: needsReview ? null : decision, // null = hold for human review
    injection_suspected: injectionSuspected,
    injection_source: needsReview ? 'human_review_required' : 'deterministic_heuristic',
    source: needsReview ? 'human_review' : 'rule_oracle',
  };
  if (needsReview) review += 1; else auto += 1;
  process.stdout.write(`${JSON.stringify(example)}\n`);
}
process.stderr.write(`labeled ${lines.length}: ${auto} auto (rule oracle), ${review} flagged for human review\n`);

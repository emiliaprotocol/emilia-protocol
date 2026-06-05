// SPDX-License-Identifier: Apache-2.0
// Baseline classifier = the REAL deterministic engine (lib/guard-policies.js).
// This is the oracle for "covered" cases and the regression target. The whole
// point of the harness is to benchmark candidate models against THIS, never to
// replace it.
import { evaluateGuardPolicy } from '../../../lib/guard-policies.js';

export function classify(input) {
  const r = evaluateGuardPolicy(input);
  return { decision: r.decision, signoffRequired: r.signoffRequired, reasons: r.reasons };
}

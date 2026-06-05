// SPDX-License-Identifier: Apache-2.0
// FUTURE: the self-hosted, fine-tuned (Tinker LoRA) risk classifier.
//
// It runs INSIDE the customer's network — nothing leaves. Its output is
// ADVISORY: it may only RAISE the tier that evaluateGuardPolicy then enforces,
// never lower one, never decide alone. See docs/ml/risk-classifier.md.
//
// This is a stub until the model exists. Point EP_RISK_MODEL_URL at your
// self-hosted inference endpoint, then: node ml/risk-eval/eval.mjs tinker

const ENDPOINT = process.env.EP_RISK_MODEL_URL; // e.g. http://localhost:8000/classify

export async function classify(input) {
  if (!ENDPOINT) {
    throw new Error(
      'No model yet. Set EP_RISK_MODEL_URL to your self-hosted Tinker classifier, '
      + 'or run the baseline: node ml/risk-eval/eval.mjs',
    );
  }
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(`risk model ${res.status}`);
  // Expected model output: { tier, injection_suspected }
  const out = await res.json();
  return {
    decision: out.tier, // 'allow' | 'allow_with_signoff' | 'deny'
    signoffRequired: out.tier === 'allow_with_signoff',
    injection_suspected: out.injection_suspected,
  };
}

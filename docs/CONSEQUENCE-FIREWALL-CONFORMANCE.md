<!-- SPDX-License-Identifier: Apache-2.0 -->
# Consequence Firewall Conformance - CF-1

[![Consequence Firewall: CF-1](https://www.emiliaprotocol.ai/badges/cf-1.svg)](https://www.emiliaprotocol.ai/fire-drill/cf-1)

CF-1 is the minimum conformance bar for calling an integration a
**Consequence Firewall** for AI agents or other machine actors.

The claim is narrow:

> A consequential action cannot mutate the world unless a valid, in-scope,
> sufficiently assured, non-replayed authorization receipt passes before
> execution, and the resulting evidence can be verified offline.

CF-1 is not a vulnerability rating, fraud score, insurance warranty, or proof
that the human decision was wise. It proves that the enforcement point exists
and refuses the important failure modes.

## Required checks

An integration earns **CF-1 Enforced** only when a reproducible harness proves
all of these checks against a real guarded action:

1. **consequential_action_declared** - the action is explicitly classified as
   consequential / high risk by policy or manifest.
2. **missing_receipt_refused** - no receipt means no mutation; the gate returns
   a Receipt Required challenge before execution.
3. **wrong_authority_refused** - a receipt signed by an untrusted, revoked, or
   out-of-scope authority cannot authorize the action.
4. **weak_assurance_refused** - a lower-assurance receipt cannot satisfy a
   higher-assurance action.
5. **execution_mismatch_refused** - material execution fields from the real
   system of record must match the signed action.
6. **valid_receipt_runs_once** - a valid, in-scope, sufficiently assured receipt
   lets the action run exactly once.
7. **replay_refused** - the same receipt cannot be reused.
8. **tamper_refused** - changing any signed material field after approval
   invalidates the receipt.
9. **evidence_verifies_offline** - the allowed run emits a reliance / evidence
   packet that a third party can verify without trusting the operator's server.

## Relationship to RR-1, EG-1, and GG-1

CF-1 is the umbrella standard. The existing badges are narrower profiles:

| Profile | Scope | Relationship to CF-1 |
| --- | --- | --- |
| RR-1 | Receipt Required for one MCP / HTTP tool | Entry rail: proves missing, valid, replay, and tamper behavior |
| EG-1 | EMILIA Gate runtime harness | Reference CF-1 runtime profile: proves the firewall checks |
| GG-1 | GovGuard fraud-control profile | Government vertical profile: wrong org, wrong approver, self-approval, Class-A, replay, tamper, execution mismatch, evidence export |

An adopter can show RR-1 for a lightweight tool wrapper. A system that wants to
claim "Consequence Firewall" should earn CF-1, usually by passing EG-1 or an
equivalent vertical harness such as GG-1.

## Reference proof

The reference EMILIA Gate earns CF-1 through the EG-1 harness plus an explicit
wrong-authority negative test. The runnable EG-1 self-test proves the eight
runtime checks today:

```bash
node packages/gate/eg1.mjs   # prints "EG-1 Enforced"
```

The dedicated CF-1 harness — which additionally proves that:

- a gate trusting the wrong issuer key cannot earn the conformance claim;
- an allow-all shim fails;
- a deny-all shim fails;
- the public doc, badge, and site page stay aligned

— ships with the EMILIA Gate conformance suite.

## Badge

Add the badge only after your harness passes:

```md
[![Consequence Firewall: CF-1](https://www.emiliaprotocol.ai/badges/cf-1.svg)](https://www.emiliaprotocol.ai/fire-drill/cf-1)
```

The badge links to the public definition so anyone can see what it means and
rerun the checks. A badge without a passing harness is not CF-1.

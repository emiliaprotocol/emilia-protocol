# GRACE — Proof-of-Curtailment
### A verifiable demand-response rail for AI compute
*EMILIA Protocol · procurement & evaluation brief · 2026-06*

**GRACE is Proof-of-Curtailment for AI compute: a verifiable receipt that proves a grid-responsive
compute event was authorized, executed, measured, and settled under a pinned method.**

> COSA moves the megawatts. EMILIA proves the move was authorized and delivered.

---

## Buyer value

| Buyer | What GRACE delivers |
|-------|---------------------|
| **AI / HPC datacenter & neocloud operators** | Connect faster (prove flexible load for interconnection), get paid for verifiable curtailment, and survive audit without exposing operational logs. "Grid-responsive compute" as a procurement differentiator. |
| **Grid operators / ISOs / utilities** | Dispatch flexible compute and confirm delivery **without trusting the operator's self-reported logs**. Settlement against cryptographic proof, not attestation. |
| **Demand-response aggregators / CSPs** | A portable, tamper-evident measurement-&-verification artifact for large, fast flexible loads — higher-value DR products, fewer settlement disputes. |

GRACE **complements** existing DERMS / virtual-power-plant orchestration (it is the verifiable
authorization + settlement layer those systems lack), and is **scheduler-agnostic** on the shed side.

## The problem

Demand response is a multi-billion-dollar market, and AI datacenters are becoming its largest new
flexible load. But the record that a load actually curtailed when paid to is **self-reported and
trust-based** — baselines can be gamed, telemetry backfilled, sheds over-claimed. There is no
portable artifact a grid operator, auditor, or counterparty can verify without trusting the party
under review. That measurement-and-verification gap is the cost center GRACE removes.

## What it is — the loop

1. **Authorize.** A market-authorized party (ISO, utility, aggregator/CSP, or facility under the
   applicable tariff/program rules) issues a bounded `grid.curtailment` order; the human decision is
   captured as a device-bound named signoff — or a quorum for hard cuts.
2. **Verify & gate.** The facility controller verifies the order offline, fail-closed — posture
   changes only against a valid, in-scope, unexpired order. Spoofed/stale orders are refused.
3. **Shed.** The scheduler reduces compute (cache-first inference, deferred batch, capped GPU
   clocks), preserving life-safety / contractual lanes. Power falls.
4. **Measure.** An attested meter / smart PDU signs the power telemetry at source.
5. **Prove.** Delivered = baseline − actual, computed from the signed telemetry against a pinned
   method.
6. **Settle.** A **Proof-of-Curtailment Bundle** (order + acknowledgment + attested telemetry +
   computed kW·h) is emitted — offline-verifiable by anyone. The program pays against proof.

## Authority & baseline posture

- **Authority.** GRACE does not assume a single "government off-switch." The authorizing party is
  whoever the applicable tariff/program designates; GRACE binds that party's authorization to the
  exact, bounded, reversible event.
- **Baseline.** GRACE **does not invent the baseline — it binds the method prescribed by the
  applicable program/tariff** and pins its hash, making the method's *application* tamper-evident
  against method swaps, telemetry backfill, and input manipulation. It sits on top of the market's
  own accepted methodology.

## Demonstration (available now)

A five-minute reference demonstration on real hardware: one multi-GPU node + a smart PDU on a live
wattage graph. A market-authorized approval (device-bound) issues a "shed 700 W for 10 minutes"
order → the controller verifies it offline → the scheduler enters curtailment posture → **measured
power visibly drops** → the window expires and posture auto-reverts → a Proof-of-Curtailment Bundle
is emitted and verified offline.

**Success criteria:** a valid order sheds; a spoofed order is refused; tampered telemetry fails
verification; the bundle settles; posture auto-reverts. A runnable software reference of this loop
is already published and verifies under the production EMILIA verifier.

## Maturity & proof

- **Open standard** (Apache-2.0), not slideware — receipts verify even if the vendor disappears.
- **IETF Internet-Drafts** (authorization receipts; multi-party quorum); the `grid.curtailment`
  profile is specified as PIP-014 on top of the receipts draft.
- **Formally verified core:** 26 TLA+ safety theorems and 35 machine-checked Alloy facts (0 errors);
  85 adversarial red-team cases; 4,200+ automated tests.
- **Three independent, cross-language verifiers** (JavaScript, Python, Go) agreeing across the
  conformance suite — auditors verify a bundle against source and mathematics, not a vendor's word.
- Runnable Proof-of-Curtailment reference implementation; zero new cryptography (Ed25519 over
  RFC-8785 canonical bytes).

## Assumptions & dependencies (honest)

- Requires integration with a facility power-telemetry source. The reference starts with smart-PDU
  CSV/API; **signed-at-source / revenue-grade meter attestation is follow-on** for full
  settlement-grade deployment.
- The baseline methodology is the program's, not GRACE's; GRACE pins and protects its application.
- A first pilot requires one cooperating facility and one program/tariff context (ERCOT is the
  highest-leverage first market: most AI-datacenter construction, longest interconnection queue,
  most permissive market structure).
- EMILIA proves authorization and evidence integrity — a **necessary, not sufficient,** condition
  for trustworthy demand response; it does not by itself guarantee physical-baseline accuracy or
  market-rule compliance.

## Commercial model

Open-core. The standard, the verifier, and the receipt profile are free and open. Revenue is the
operated trust layer: the managed issuer, approver directory, transparency log, and the compliance-
evidence / settlement pipeline. The protocol is given away for ubiquity and no lock-in; the operated
infrastructure is the business.

## Next step

A scoped pilot: an **observe-mode** deployment with one facility in a target market — GRACE issues
and verifies Proof-of-Curtailment Bundles for real or simulated curtailment events alongside the
existing process, with no change to the production workflow, proving the artifact end-to-end before
any settlement reliance. From there, a single production curtailment event with a real settlement
bundle.

*Contact: team@emiliaprotocol.ai · emiliaprotocol.ai*

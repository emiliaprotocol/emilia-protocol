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

**First mover:** the wedge buyer is an **AI/HPC datacenter or neocloud operator with a DR aggregator
or utility sponsor** — the party that holds the interconnection/payment incentive *and* has a grid
counterpart to settle against. That pairing is the minimum unit for a first pilot.

## The problem

Demand response is a multi-billion-dollar market, and AI datacenters are becoming one of the largest
new flexible-load candidates. Duke University's Nicholas Institute ("Rethinking Load Growth," 2025) finds the 22
largest U.S. balancing areas could absorb **76–126 GW of new load** if it can be curtailed under ~1%
of hours — **ERCOT alone ≈ 10 GW at 0.5% curtailment**. But that headroom is only bankable if the
curtailment is *verifiable* enough for a grid operator to count it as capacity. Today the record that
a load actually curtailed when paid to is **self-reported and trust-based** — baselines can be gamed,
telemetry backfilled, sheds over-claimed. No portable artifact lets a grid operator, auditor, or
counterparty verify delivery without trusting the party under review. **That measurement-and-
verification gap — the thing standing between ~100 GW of theoretical flexibility and bankable
capacity — is what GRACE removes.**

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

## Demonstration

**Available now — runnable software reference.** The full loop is published and runs today
(`examples/grace/proof_of_curtailment.py`): it issues a `grid.curtailment` order, gates it
fail-closed, sheds, signs attested telemetry, computes delivered kW·h, emits the Proof-of-Curtailment
Bundle, and verifies the bundle under the **production EMILIA verifier** — with the adversarial paths
all refusing (tampered telemetry → INVALID; forged order → REFUSED; replay after window → REFUSED).
No new cryptography.

**Planned with a facility partner — the 5-minute hardware demonstration.** One multi-GPU node + a
smart PDU on a live wattage graph: a device-bound approval issues "shed 700 W for 10 minutes" → the
controller verifies offline → the scheduler enters curtailment posture → **measured power visibly
drops** → the window expires and posture auto-reverts → the bundle is emitted and verified offline.
**Success criteria:** valid order sheds; spoofed order refused; tampered telemetry fails; bundle
verifies for settlement review; auto-revert. (This stage requires a host facility; see Assumptions.)

## Maturity & proof

- **Open standard** (Apache-2.0), not slideware — receipts verify even if the vendor disappears.
- **IETF Internet-Drafts** (authorization receipts; multi-party quorum); the `grid.curtailment`
  profile is specified as PIP-014 on top of the receipts draft.
- **Formal verification:** 26 TLA+ invariants (TLC model checker) and 35 Alloy facts with 22
  assertions; 85 adversarial red-team cases; **5,400 automated test cases across 265 files, with every platform-applicable case required to pass**.
- **Cross-language verifiers:** JavaScript, Python, and Go reference verifiers agreeing byte-for-byte
  across the conformance suite, so auditors verify a bundle against source and mathematics, not a
  vendor's word. This is a consistency check, not a clean-room independent-implementation claim.
- **Security posture:** GRACE rejects spoofed, stale, and replayed curtailment orders as rigorously
  as it proves legitimate ones — a forged "throttle" is refused fail-closed against a pinned key, so
  adopting GRACE does not become a new attack surface on your own cluster.
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

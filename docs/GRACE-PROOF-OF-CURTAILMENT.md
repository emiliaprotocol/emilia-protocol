# GRACE — Proof-of-Curtailment
### The verifiable receipt layer for grid-responsive AI compute
*A COSA × EMILIA collaboration. Justin Kintzele (COSA) + Iman Schrock (EMILIA). Working draft — 2026-06.*

> **GRACE is Proof-of-Curtailment for AI compute: a verifiable receipt that proves a
> grid-responsive compute event was authorized, executed, measured, and settled under a pinned
> method.**

**Who it's for.** *AI datacenters:* connect faster, get paid for flexibility, survive audit.
*Grid operators / DR programs:* dispatch flexible compute without trusting self-reported logs.

---

> **The winning sentence:**
> *When the grid asks an AI datacenter to reduce load, GRACE proves who authorized it, what was
> allowed, whether the facility actually complied, and what should be paid — verifiable by anyone,
> offline, without trusting the operator's own logs.*

Not "AI traffic routing." Not "cognitive internet." Not a planetary protocol. One thing someone
will pay for: **proof of curtailment.**

---

## Why now (the macro is pulling hard)

- AI is driving datacenter electricity use from ~415 TWh in 2024 toward ~945 TWh by 2030 (IEA).
- The IEA also estimates ~20% of planned datacenter projects risk delay if grid risk isn't addressed.
- NERC is warning that large loads like datacenters are now a reliability/forecasting problem.
- ERCOT alone projects 20+ GW of newly contracted large load by 2028.
- PJM already *pays* demand-response customers to reduce load on request.

The demand exists, the money exists, and the actuator is becoming real (clusters can already shed
power through workload orchestration). The missing layer is **trustable authorization +
settlement-ready proof.** That's us.

---

## Your instinct was the seed

Justin — this started from your call, and three of your instincts were dead-on:

1. **Graceful curtailment beats a kill-switch.** A dial that degrades gracefully is the only thing
   operators will ever adopt.
2. **The human authorizes a bounded, time-boxed throttle** — "take new cognition from 80% to 20%
   until sundown," not a binary stop. You independently described EMILIA's on-the-loop model exactly.
3. **Trusted hardware belongs at the facility edge** — right again; we just found its real job.

We've put serious work into this because we think you grabbed the right thread. Here's the version
built to survive both an IETF room and a utility's procurement desk.

---

## The one reframe that unlocked everything: energy is not bandwidth

A facility's power is dominated by GPU compute and cooling; the inbound network is a rounding error
on the power bill. Marking packets or rate-limiting traffic at the perimeter doesn't move megawatts,
and it measures *nothing* about watts. What moves power is **workload scheduling** — defer jobs, cap
GPU clocks, serve from cache. The source of truth has to be a **power meter**, not the wire. That
single swap put your hardware expertise exactly where trusted hardware is genuinely needed: **the
meter, not the packet.**

---

## The loop, end to end

```
        ┌──────────────────────────── settlement $ ─────────────────────────────┐
        │                                                                        │
   1. AUTHORIZE ──▶ 2. VERIFY & GATE ──▶ 3. SHED ──▶ 4. MEASURE ──▶ 5. RECONCILE ──▶ 6. SETTLE
     (EMILIA)          (EMILIA)        (executor)   (independent       (EMILIA)        (EMILIA)
                                                     meter)
```

1. **Authorize (EMILIA).** A **market-authorized party** (ISO, utility, aggregator/CSP, or the
   facility under the applicable tariff/program rules) issues the event; its decision is captured as
   a **named-human signoff** — or a **quorum** for hard cuts (the cryptographic two-person rule) — on
   a hardware-backed device, as a bounded `grid.curtailment` order: `{facility, target_delta_kw,
   window, max_duration, protected_lanes, baseline_method_hash, telemetry_sources, expiry}`. It
   auto-expires.

2. **Verify & gate (EMILIA).** The facility controller verifies the order **offline, fail-closed**:
   posture changes *only* against a valid, unexpired, in-scope order. A spoofed or stale order is
   rejected, *and* the operator can prove it only ever acted on a legitimate one. Protects both sides.

3. **Shed (deployment-pinned executor; COSA is the reference adapter).** Only after EMILIA admits
   and consumes the exact-action authority does the executor project the target into scheduler or
   device commands. COSA can flip interactive inference to **cache-first**, **defer** batch and
   training jobs, or **cap GPU clocks** on non-critical work. Its signed acknowledgment is dispatch
   evidence; it is not authorization and does not establish the physical effect.

4. **Measure (independent attested meter).** Signed power telemetry comes from a revenue-grade meter
   or smart PDU in a separate control domain, signed at the source and Merkle-anchored so it cannot
   be backfilled or cherry-picked.

5. **Reconcile and prove (EMILIA).** EMILIA preserves the executor acknowledgment and independent
   meter statement as separate evidence, computes delivered = baseline − actual against a **pinned
   method**, and records unresolved or divergent outcomes without creating authority to retry.

6. **Settle (EMILIA).** One **Proof-of-Curtailment Bundle** — the authorization receipt + the
   operator's acknowledgment + the attested telemetry + the computed kW·h — all offline-verifiable.
   The ISO/utility pays against *proof*, not self-report. Over-claiming a shed you didn't deliver
   becomes detectable.

**EMILIA is the authority, admission, and evidence spine. COSA is a valuable executor adapter behind
that boundary.** The meter independently establishes observed effect, and GRACE composes the three
without turning any one acknowledgment into a broader claim.

---

## The baseline question, answered (it's an asset, not a hole)

The obvious challenge: "if the baseline is gameable, the proof is theater." Here's why that's
actually our strength: **GRACE does not invent the baseline — it binds the method prescribed by the
applicable program/tariff** and pins its hash. That makes the method's *application* **tamper-evident
against method swaps, telemetry backfill, and input manipulation**: change the method, fudge the
inputs, or backfill telemetry and the bundle fails verification. We don't claim the baseline is
physically perfect — we make the market's own prescribed method tamper-evident to run. We sit on top
of what the market already trusts.

---

## What we're deliberately parking (not killing)

Two of the wilder branches are interesting but would sink the pitch if we led with them:

- **Global route-cost cascades / forcing adoption by redirecting demand.** We deliberately exclude
  non-market coercion and routing-based forcing functions. Adoption comes from **payment,
  interconnection leverage, and auditability** — not from pressuring anyone's network.
- **Edge waste-heat / thermostat-as-listener.** A cool separate thesis with its own privacy,
  security, and economics problems. Keep it out of GRACE so the pitch stays clean.

---

## The demo (5 minutes, with each boundary visible)

One multi-GPU node + a smart PDU on a live wattage graph + the controller + an EMILIA verifier + a
COSA or equivalent executor adapter: grid authority Face-ID-approves "shed 700 W for 10 min" →
EMILIA verifies and admits the exact action once → the adapter projects the admitted action into
native commands → **the wattage line visibly drops** → independent readback is reconciled → the
window expires and posture auto-reverts → emit the bundle, verify offline. Then the money shots:
tamper the wattage log → verification **fails**; replay a spoofed order → **refused**.

**This isn't slideware.** A runnable reference of exactly this loop already lives at
`examples/grace/proof_of_curtailment.py` in the EP repo — it issues the order, sheds, measures via an
attested meter, emits the bundle, and verifies it under the *published* EMILIA verifier
(`EP-RECEIPT-v1`, Ed25519 over JCS bytes, **zero new crypto**) — with the tamper / forge / expire
attacks all refusing. `python3 proof_of_curtailment.py` and watch.

---

## Working model & standards alignment

- **Layers and ownership.** EMILIA owns the open authority substrate and the Gate enforcement,
  admission, consumption, and reconciliation path. COSA/J Diesel retains its scheduler, actuator,
  and integration implementation. The executor is pluggable: COSA can be a reference adapter, and
  any deployment-pinned scheduler that implements the same exact-action dispatch and evidence
  contract can occupy that role. The independent meter remains a separate trust domain.
- **Revenue (open-core, no split needed).** Both layers stay open-source; each party monetizes
  services on its own side — COSA on compute optimization, EMILIA on the managed issuer / approver
  directory / compliance-evidence + settlement pipeline. No joint entity required to start; the
  partnership is the open interface, not a cap table.
- **Standards.** `grid.curtailment` is a vertical **action-type profile** (proposed **PIP-014**) on
  top of `draft-schrock-ep-authorization-receipts` and the PIP-013 human-oversight model, registered
  in the EP profile registry (PIP-012). The Proof-of-Curtailment Bundle is documented as a GRACE
  profile that references the IETF draft normatively. Parallel engagement: Justin to grid/utility
  bodies, Iman to IETF — **cross-reference, don't compete**, so EMILIA stays *the* authorization
  layer rather than one of several.
- **Commitment (reputational, not legal).** GRACE remains a jointly authored open profile. Neither
  party ships a "GRACE-compatible" product without implementing the full authority, admission,
  executor-evidence, independent-readback, and reconciliation profile.

## Rough timeline

- **Phase 0 (now):** lock the `grid.curtailment` receipt profile + scope the demo.
- **Phase 1 (~30 days):** demo running on real hardware — one simulated curtailment event, full
  bundle emitted, offline verification + adversarial cases green.
- **Phase 2 (~90 days):** show it to three audiences — one grid/ISO contact, one datacenter operator,
  one standards contact.
- **Phase 3 (~6 months):** pilot with one real facility — production event, real settlement bundle.

## What Friday must decide

- Demo target: **700 W shed**, 10-minute window.
- Receipt profile: **`grid.curtailment`** fields locked (PIP-014 draft).
- Telemetry source: **smart PDU first**, signed revenue-grade meter next.
- Bundle contents: **order + acknowledgment + telemetry + calculation**.
- Success criteria: **valid order sheds · spoofed order fails · tampered telemetry fails ·
  auto-revert works.**

---

## The name

**GRACE — Grid-Responsive Authorized Compute Events.** Your word, and it's perfect — it's literally
graceful curtailment. The receipt inside it is **Proof-of-Curtailment**: GRACE is the event, the
receipt is the proof.

Friday: bring your actuator and facility-control view; we'll bring the authority, admission,
reconciliation, and settlement spine. The goal isn't to debate the vision — it's to lock the receipt
profile and the demo and start building. This is one of the strongest protocol-vertical fits we've
seen, and it's yours as much as ours. Let's go.

*— Iman, EMILIA Protocol*

---
*Macro figures — sources:
IEA "Energy and AI" (2025) — https://www.iea.org/reports/energy-and-ai ·
NERC 2024 Long-Term Reliability Assessment — https://www.nerc.com/pa/RAPA/ra/Reliability%20Assessments%20DL/NERC_Long%20Term%20Reliability%20Assessment_2024.pdf ·
PJM Demand Response — https://www.pjm.com/markets-and-operations/demand-response ·
ERCOT large-load interconnection projections. EMILIA proves authorization and evidence integrity —
a necessary, not sufficient, condition for trustworthy demand response.*

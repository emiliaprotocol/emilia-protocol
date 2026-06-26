# GRACE — Proof-of-Curtailment (reference demo)

**The verifiable receipt layer for grid-responsive AI compute, built for settlement.**
A COSA × EMILIA composition: COSA moves the megawatts; EMILIA proves the move was authorized and delivered.

> When the grid asks an AI datacenter to reduce load, GRACE proves *who* authorized it,
> *what* was allowed, *whether* the facility complied, and *what* should be paid — verifiable
> by anyone, offline, without trusting the operator's own logs.

## Run it

```bash
pip install emilia-verify cryptography
python3 proof_of_curtailment.py
```

No `pip`? The script falls back to the in-repo verifier at `packages/python-verify`, so a
fresh clone of this repo runs as-is.

## What it shows (7 steps, ~1 second)

1. **Authorize** — a named grid authority signs a bounded `grid.curtailment` order
   (`facility`, `target_delta_w`, `window`, `protected_lanes`, `baseline_method_hash`, `expiry`).
2. **Verify & gate** — the facility controller verifies it **offline, fail-closed**, against a
   *pinned* authority key. No valid order → no posture change.
3. **Shed** — the scheduler (COSA in production) drops compute; watts fall from baseline to target.
4. **Measure** — an **attested meter** signs the power telemetry. Distinct key from the authority
   (the same dual-key separation as COSA L5 authenticity vs EMILIA L7 authorization).
5. **Prove** — delivered kWh = baseline − actual, integrated from the *signed* samples, against a
   **pinned baseline method** (the program's own method — we pin its hash, we don't invent it).
6. **Settle** — emit a **Proof-of-Curtailment Bundle** (order + acknowledgment + attested
   telemetry + computed kWh) that anyone can verify offline. The ISO pays against proof.
7. **Adversarial** — tamper a watt reading → bundle **INVALID**; forge the order with a non-pinned
   key → **REFUSED**; replay after the window → **REFUSED**.

## What it proves — and what it doesn't

Everything verifies under the **real published EMILIA verifier** (`emilia_verify`, `EP-RECEIPT-v1`,
Ed25519 over RFC-8785 / JCS-canonical bytes) with **zero new crypto**. The receipt model is the
standard EP one; `grid.curtailment` is just an action-type profile on top of it.

EP proves the order was authorized by a pinned party, the telemetry is untampered, and the kWh
was computed from those signed samples against the pinned method. It does **not** claim the
baseline is physically perfect — baseline estimation belongs to the program/tariff. EP makes the
*application* of the market's own method **tamper-evident against method swaps, telemetry backfill,
and input manipulation**. Necessary, not sufficient.

## Where this plugs in

The shed actuator is **pluggable**: COSA is the reference backend, but any scheduler (k8s, Slurm,
Ray, or `nvidia-smi` power caps) can satisfy the same interface — *receipt in → posture change
out → attested telemetry in → bundle out*. This demo simulates the meter and the shed so it runs
on a laptop; the production demo swaps in a smart PDU on a live wattage graph and a real workload.

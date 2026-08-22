# GRACE - Proof-of-Curtailment reference circuits

**The verifiable receipt layer for grid-responsive AI compute, built for settlement.**
A COSA and EMILIA composition: the actuator moves the load; EMILIA verifies the
authorization and binds the resulting evidence.

> When the grid asks an AI datacenter to reduce load, GRACE binds *who* authorized one exact
> event, *what* was allowed, which signed execution and meter claims were accepted, and the
> deterministic result computed from those inputs. The bundle is offline-verifiable against
> pinned trust inputs. It does not prove meter truth, tariff eligibility, or payment.

## Run the mobile-to-settlement circuit

```bash
node examples/grace/live-control-room.mjs
npx vitest run tests/grace-mobile-grid.test.ts
```

This is the current end-to-end reference: two distinct Class-A mobile handshakes,
bounded execution, signed COSA reference acknowledgment, separately signed meter
evidence, an Action State `-02` Signed Statement, and one-time settlement. It also
executes replay, action-substitution, and meter-rule-smuggling attacks and requires all
three to refuse.

The browser control room at `/grace/live` uses the same implementation. Every adapter
is visibly marked as a reference simulation; no physical grid event is claimed.

## Run the original receipt vector

```bash
pip install emilia-verify cryptography
python3 proof_of_curtailment.py
```

No `pip`? The script falls back to the in-repo verifier at `packages/python-verify`, so a
fresh clone of this repo runs as-is.

## What it shows (7 steps, ~1 second)

1. **Authorize** — a named grid authority signs a bounded `grid.curtailment` order
   (`facility`, `target_delta_kw`, `window`, `baseline_method_hash`, `expiry`).
2. **Verify & gate** — the facility controller verifies it **offline, fail-closed**, against a
   *pinned* authority key. No valid order → no posture change.
3. **Shed** — a scheduler adapter drops compute; the repository currently ships a signed COSA
   reference adapter, not a production actuator integration.
4. **Measure** — an **attested meter** signs the power telemetry. Distinct key from the authority
   (the same dual-key separation as COSA L5 authenticity vs EMILIA L7 authorization).
5. **Prove** — delivered kWh = baseline − actual, integrated from the *signed* samples, against a
   **pinned baseline method** (the program's own method — we pin its hash, we don't invent it).
6. **Settlement admission** — emit a **Proof-of-Curtailment Bundle** (order + acknowledgment +
   signed telemetry + deterministic compliance result), then admit at most one invocation attempt
   to the configured settlement adapter for the entitlement key.
7. **Adversarial** — tamper a watt reading → bundle **INVALID**; forge the order with a non-pinned
   key → **REFUSED**; replay after the window → **REFUSED**.

## What it proves — and what it doesn't

Everything verifies under the **real published EMILIA verifier** (`emilia_verify`, `EP-RECEIPT-v1`,
Ed25519 over RFC-8785 / JCS-canonical bytes) with **zero new crypto**. The receipt model is the
standard EP one; `grid.curtailment` is just an action-type profile on top of it.

The verifier establishes that the configured policy accepted the human evidence, signed actuator
claim, and signed meter claim, and that the result was computed from those accepted bytes. It does
**not** establish that the baseline is economically correct, the readings are physically true, the
event qualifies under a tariff, or funds moved. Necessary, not sufficient.

## Where this plugs in

The shed actuator is **pluggable**: COSA is the first reference backend, but any scheduler (k8s, Slurm,
Ray, or `nvidia-smi` power caps) can satisfy the same interface — *receipt in → posture change
out → attested telemetry in → bundle out*. This demo simulates the meter and the shed so it runs
on a laptop. A physical claim requires a host-approved workload controller and an independently
keyed smart PDU or meter.

See `docs/GRACE-MOBILE-COSA-ACTION-STATE.md` for the exact contracts and trust boundaries.

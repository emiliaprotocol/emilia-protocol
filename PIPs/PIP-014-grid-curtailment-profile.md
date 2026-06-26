# PIP-014 — `grid.curtailment` Action-Type Profile + Proof-of-Curtailment Bundle

**Status:** Draft (GRACE vertical — COSA × EMILIA)
**Builds on:** `draft-schrock-ep-authorization-receipts` (EP-RECEIPT-v1), PIP-013 (Human-Oversight
Profile), PIP-012 (profile/envelope registry).
**Reference implementation:** `examples/grace/proof_of_curtailment.py` (runs green; verifies under
the published `emilia_verify`, zero new crypto).
**Scope note:** This profile makes curtailment evidence *tamper-evident* and *designed for
settlement*. It does not compute or warrant the baseline — that belongs to the applicable
program/tariff. Necessary, not sufficient.

---

## 1. Purpose

Define a vertical action-type, `grid.curtailment`, and a **Proof-of-Curtailment Bundle**, so a
market-authorized party can authorize a bounded, reversible compute-curtailment event and any third
party can verify — offline, without trusting the operator — *who* authorized it, *what* was allowed,
*whether* the facility complied, and *what* should be paid.

The profile reuses the standard EP receipt primitive (`EP-RECEIPT-v1`: Ed25519 over RFC-8785/JCS
canonical `payload`). No new cryptography. `grid.curtailment` registers in the EP profile registry
(PIP-012).

## 2. Roles & keys

| Role | Holds | Purpose |
|------|-------|---------|
| **Authorizing party** | Ed25519 signing key (device-bound via PIP-013 signoff; quorum for hard cuts) | Signs the curtailment **order**. Public key pinned by the controller out-of-band. |
| **Facility** | Ed25519 key | Signs the **acknowledgment** (posture entered). |
| **Attested meter** | Ed25519 key (revenue-grade meter / smart PDU, signed at source) | Signs the **telemetry**. Distinct key from the authorizer (separation of authenticity vs authorization). |

The authorizing party is whoever the tariff/program designates — ISO, utility, aggregator/CSP, or the
facility operator. Its human decision is captured as a PIP-013 named-human (or quorum) signoff.

## 3. The order — `grid.curtailment` payload

An `EP-RECEIPT-v1` whose `payload` carries:

| Field | Req | Meaning |
|-------|-----|---------|
| `action_type` | ✔ | Constant `"grid.curtailment"`. |
| `effect_class` | ✔ | `"power_reduction"`. |
| `facility` | ✔ | Target facility id (or fleet id). |
| `target_delta_kw` | ✔ | Committed reduction. (`target_delta_w` permitted for small/demo loads.) |
| `window` | ✔ | `{ not_before, not_after }` (epoch seconds or RFC 3339). |
| `expires_at` | ✔ | Hard expiry; SHOULD equal `window.not_after`. |
| `baseline_method_hash` | ✔ | `sha256:` of the program's prescribed baseline method id. Pins the method; does not define it. |
| `control_mode` | ✔ | PIP-013 value, typically `"on_the_loop"` (bounded envelope) or `"in_the_loop"`. |
| `protected_lanes` | ○ | Lanes that never shed (e.g. `["life-safety","contractual-slo"]`). |
| `telemetry_sources` | ○ | Meter ids whose attestations are accepted for settlement. |
| `approver` | ○ | Stable id of the authorizing party. |
| `max_duration` | ○ | Cap independent of the window. |

Hard cuts (large `target_delta_kw` or full-site) **MUST** use EP-QUORUM (m-of-n distinct signers).

## 4. Gate predicates (fail-closed)

The controller changes posture **only if all** hold (see `gate()` in the reference):

1. `verify_receipt(order, pinned_authority_pub).valid` — Ed25519 over canonical payload, against the
   **pinned** authority key (a forged/wrong-key order fails here).
2. `payload.action_type == "grid.curtailment"`.
3. `window.not_before <= now <= window.not_after`.
4. `now < expires_at`.

Otherwise: refuse, no posture change.

## 5. Telemetry attestation

An `EP-RECEIPT-v1` signed by the **meter** key, `payload`:

```json
{ "meter_id": "...", "unit": "watt",
  "baseline_method_hash": "sha256:...",
  "samples": [ { "t": <epoch_s>, "w": <watts> }, ... ] }
```

The signature covers the whole payload, so altering any sample breaks verification (tamper-evident).
Streaming deployments MAY add an `anchor` (Merkle proof) per EP-RECEIPT-v1; the verifier checks it
when present.

## 6. Proof-of-Curtailment Bundle

```json
{ "order": <EP-RECEIPT-v1>,            "authority_pub": "<spki-b64u>",
  "acknowledgment": <EP-RECEIPT-v1>,   "facility_pub":  "<spki-b64u>",
  "telemetry": <EP-RECEIPT-v1>,        "meter_pub":     "<spki-b64u>",
  "delivered_kwh": <number> }
```

**Verification predicates** (see `verify_bundle()` — all MUST pass):

1. `order` verifies against `authority_pub`.
2. `acknowledgment` verifies against `facility_pub`.
3. `telemetry` verifies against `meter_pub`.
4. **method pinned:** `telemetry.baseline_method_hash == order.baseline_method_hash`.
5. **arithmetic bound to evidence:** recomputing delivered kWh from the *signed* `samples`
   (trapezoidal integral of `baseline − actual` over the window) equals `delivered_kwh`.

Any failure ⇒ bundle INVALID. This is what an ISO/auditor runs, offline, with no account.

## 6a. Call order (which packages run, in sequence)

```
ISSUE  order/ack/telemetry   ──▶ emilia_verify.canonicalize()  +  Ed25519 sign
                                  (packages/python-verify · packages/verify parity)

GATE   at the facility       ──▶ emilia_verify.verify_receipt(order, authority_pub)   [fail-closed]
                                  + window / expiry / action_type predicates (§4)

MEASURE attested meter       ──▶ ISSUE(telemetry, meter_key)        (signed samples)

VERIFY  the bundle (anyone)  ──▶ verify_receipt(order,  authority_pub)
                                  verify_receipt(ack,    facility_pub)
                                  verify_receipt(telem,  meter_pub)
                                  + method-hash equality  + delivered_kwh recompute (§6)
```

Only `emilia_verify` (shipped) is invoked; the GRACE-specific glue (`gate`, `measure`,
`verify_bundle`) is in `examples/grace/proof_of_curtailment.py`. No new crypto is introduced at any
step.

## 7. Standards alignment

- `grid.curtailment` is a **profile of** `draft-schrock-ep-authorization-receipts`, registered via
  PIP-012; it does not fork the receipt spec.
- Human authorization rides PIP-013 (`control_mode`, named-human/quorum signoff).
- The Bundle is a GRACE profile that references the IETF draft normatively. Grid/utility-body
  engagement cross-references the IETF work rather than competing with it.

## 8. What's built vs. to build (honest status)

| Piece | Status |
|-------|--------|
| EP-RECEIPT-v1 issue/verify, JCS canonical, Ed25519 | **shipped** (`packages/python-verify`, `packages/verify`) |
| `grid.curtailment` order + gate, telemetry attestation, Bundle + verify, adversarial cases | **prototype** (`examples/grace/`, green) |
| `emilia verify-curtailment bundle.json` CLI subcommand | to add (on `packages/verify/cli.js`) |
| Real smart-PDU telemetry adapter (CSV/API → signed) | to add |
| Signed-at-source revenue-grade meter / HSM attestation | follow-on |
| Quorum on hard cuts wired into the order path | to add (EP-QUORUM exists) |

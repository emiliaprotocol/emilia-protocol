# EMILIA Protocol: Grid Curtailment Authorization Profile (Proof-of-Curtailment)
## draft-schrock-ep-grid-curtailment-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               28 June 2026
Expires: 30 December 2026
```

> STATUS (repo): staged I-D. Render to .xml/.txt via xml2rfc and file with the EP cluster batch.
> Derived from PIP-014; reference implementation `examples/grace/proof_of_curtailment.py` (runs green).

## Abstract

This document defines `grid.curtailment`, an EMILIA Protocol (EP) action-type profile for
authorizing and proving bounded, reversible curtailment of electrical load by autonomous or
agentic systems — the "Proof-of-Curtailment" used by the GRACE (Grid-Responsive Authorized Compute
Events) vertical. It rides the EP authorization receipt
([I-D.draft-schrock-ep-authorization-receipts]) and the human-oversight profile (PIP-013), and
introduces no new cryptography. It lets a market-authorized party issue a bounded curtailment order
that a facility verifies offline and fail-closed, and emits a settlement-grade, offline-verifiable
bundle proving who authorized the event, what was allowed, whether the facility complied, and what
should be paid. EP proves authorization and evidence integrity — a necessary, not sufficient,
condition; it does not invent the demand-response baseline.

## 1. Introduction

Demand-response markets pay large flexible loads (notably AI datacenters) to curtail, but the record
that a load actually curtailed when paid is self-reported and trust-based. This profile supplies a
portable, tamper-evident, offline-verifiable artifact for that record. It does not move power
(a scheduler does) and it does not define the baseline methodology (the program/ISO does); it binds
the authorizing party to the exact, bounded, reversible event and makes the application of the
program's prescribed baseline method un-fudgeable.

## 2. The curtailment order (action object)

An EP-RECEIPT-v1 whose action object carries: `action_type` = `"grid.curtailment"`, `effect_class` =
`"power_reduction"`, `facility`, `target_delta_kw`, `window` {`not_before`,`not_after`}, `expires_at`
(SHOULD equal `window.not_after`), `baseline_method_hash` (`sha256:` of the program's prescribed
method id — pins, does not define), `control_mode` (PIP-013, typically `on_the_loop`), and OPTIONAL
`protected_lanes`, `telemetry_sources`, `approver`, `max_duration`. Hard cuts (large `target_delta_kw`
or full-site) MUST use EP-QUORUM.

## 3. Gate predicates (fail-closed)

Posture changes only if all hold: the order verifies (Ed25519 over JCS) against the *pinned*
authority key; `action_type == "grid.curtailment"`; now within `window`; now < `expires_at`.

## 4. Telemetry attestation and the Proof-of-Curtailment Bundle

Power telemetry is signed by an attested meter (an EP-RECEIPT-v1 over `{meter_id, unit,
baseline_method_hash, samples[]}`), so any altered sample breaks verification. The bundle composes:
the order, the facility acknowledgment, the attested telemetry, and the computed `delivered_kwh`,
plus the pinning keys. Verification (all MUST pass): order verifies vs authority key; acknowledgment
vs facility key; telemetry vs meter key; `telemetry.baseline_method_hash == order.baseline_method_hash`;
recomputing delivered kWh from the signed samples equals `delivered_kwh`.

## 5. Relationship to other work

Profile of [I-D.draft-schrock-ep-authorization-receipts]; human oversight via PIP-013; long-term
preservation via EP-EVIDENCE-RECORD; transparency via SCITT/COSE (optional anchor). Composes with —
does not replace — energy market dispatch protocols (e.g. OpenADR, IEEE 2030.5), which carry the
dispatch; EP carries the authorization and proof.

## 6. Security Considerations

Over-trust is the dominant risk: a valid bundle proves authorization and telemetry integrity against
a pinned method, not that the baseline is physically correct (baseline estimation belongs to the
program). Spoofed/stale/replayed orders are refused fail-closed. Necessary, not sufficient.

## 7. IANA Considerations

Registers the `grid.curtailment` action-type in the EP action-type profile registry (PIP-012). No
other actions.

# EMILIA Protocol: Human-Oversight Profile for Autonomous and High-Risk AI Systems
## draft-schrock-ep-human-oversight-profile-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               28 June 2026
Expires: 30 December 2026
```

> STATUS (repo): public partner-triggered profile; not filed and not a filing
> candidate until a named standards or government partner validates the mapping.
> Civilian-first framing only.
> (EU AI Act Art. 14 + NIST lead; DoD 3000.09 / CCW as secondary applicability only) — leading
> the cluster's debut with defense framing is the one thing that could taint it. Derived from PIP-013.

## Abstract

Governing instruments for high-risk and autonomous AI require a human to remain meaningfully in
control of consequential actions, but none specifies an artifact that proves it — after the fact, to
a third party, without trusting the operator. This document profiles the EMILIA Protocol (EP)
authorization receipt as that verifiable human-oversight evidence layer: how to apply the receipt
primitive at authorization boundaries for human-in-the-loop and human-on-the-loop control, a small
set of OPTIONAL authorization-context conventions, and the relying-party rules that make "a human was
meaningfully in control" a verifiable artifact rather than an operator-owned log entry. It introduces
no new cryptography. It is scoped to evidence, not cognition — it proves the fact, scope, currency,
and authority of human authorization, not that the human understood or that the action was lawful or
wise. Necessary, not sufficient. Primary applicability is civilian high-risk AI; defense and
lethal-autonomy regimes are noted as secondary applicabilities.

## 1. Introduction and Motivation

The lead applicabilities are civilian: **EU AI Act Article 14** (high-risk AI effectively overseen by
natural persons who can interpret, decline, intervene, or halt — and per Art. 2(3) the Act excludes
exclusively military/defense/national-security systems, so Art. 14 is a *civilian* hook); and the
**NIST AI Risk Management Framework** (documented, auditable human oversight). The same evidence gap
recurs in secondary applicabilities — DoD Directive 3000.09's "appropriate levels of human judgment
over the use of force" and the UN CCW debate on meaningful human control — noted only to show reach,
not as the primary framing. Across all of them the unsolved problem is the evidence gap: the record
that a named human authorized *that exact* action, at the right scope, currently, under the right
authority, is a log the operator controls and could forge. EP closes it.

## 2. Control Modes and the Authorization Boundary

EP receipts are issued at *authorization boundaries*, not every machine cycle:
- **in_the_loop** — a human authorizes each discrete consequential action before it executes (one
  receipt per action; fail closed without it).
- **on_the_loop** — a human authorizes a bounded engagement envelope (action class, target/effect
  set, geofence, time window), retaining a revocation/halt authority. One receipt authorizes the
  envelope; autonomy operates only inside it, only while unrevoked and unexpired.

## 3. Authorization-Context Conventions

The receipt's authorization context MAY carry `control_mode` (in_the_loop | on_the_loop) and an
`authorization_scope` with `effect_class`, `target_set`, `geofence`, and `window` {not_before,
not_after}. These are bounds the relying party enforces; they do not expand the core guarantees.

## 4. Relying-Party (Enforcement) Rules

A relying party MUST act only on a valid receipt and MUST fail closed otherwise. For on_the_loop,
each action MUST be checked against the authorized envelope offline; out-of-envelope, expired, or
revoked actions MUST be refused. Continuous evaluation and revocation apply (the halt authority).
Higher-assurance regimes (e.g. a two-person rule) SHOULD use EP-QUORUM. Where an action executes, the
enforcement point SHOULD emit a post-execution receipt bound to the authorization
(draft-schrock-ep-enforcement-point).

## 5. What It Proves, and What It Does Not

It proves the fact, scope, currency, and authority of a named human's (or quorum's) authorization of
an exact action or bounded envelope, offline-verifiable without trusting the operator. It does not
prove the human understood, was uncoerced, or that the action was lawful, wise, or proportional.
Meaningful human control is necessary, not sufficient; EP supplies the necessary, verifiable part.

## 6. Security Considerations

Over-trust is the dominant risk: a receipt proves authorization at a stated scope, currency, and
authority — nothing more. Coercion and authorization-without-comprehension are out of scope of the
cryptographic guarantees; device-bound user verification and display-fidelity raise but do not
eliminate them.

## 7. IANA Considerations

Registers the `control_mode` values (in_the_loop, on_the_loop) in the EP profile registry; no other
IANA actions.

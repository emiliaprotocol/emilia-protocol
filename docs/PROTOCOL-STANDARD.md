# EMILIA Protocol Standard

**Version:** 1.1

## Abstract

The EMILIA Protocol defines an open, implementation-independent interface for trust-relevant evidence, trust state, trust decisions, and pre-action trust enforcement in machine-mediated systems.

EP is designed for contexts in which a system must decide whether a specific high-risk action should proceed under a specific authority context, governing policy, and transaction binding.

EP Core consists of three interoperable objects:
- Trust Receipt
- Trust Profile
- Trust Decision

EP Extensions add stronger enforcement for high-risk workflows. The most important of these is Handshake: a pre-action trust artifact that binds actor identity, authority, policy, action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow.

When policy requires named human ownership, EP can also require **Accountable Signoff** before execution.

The purpose of the protocol is not to create a universal ranking of entities. Its purpose is to make trust decisions attributable, policy-bound, contestable, and interoperable across systems that need stronger control before high-risk actions execute.

## Core objects

### Trust Receipt
Portable record of trust-relevant evidence.

### Trust Profile
Structured trust state derived from evidence.

### Trust Decision
Policy-evaluated decision with reasons and evidence.

## Extensions

### Handshake
Pre-action trust enforcement that binds:
- actor identity
- authority
- policy
- exact action context
- nonce
- expiry
- one-time consumption

### Accountable Signoff
Policy-driven human assumption of responsibility for defined high-risk actions.

### Emilia Eye
A lightweight warning layer that flags when stricter EP trust controls should apply.

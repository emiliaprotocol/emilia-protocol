# EP Core RFC

## Purpose

EP defines a portable, vendor-neutral protocol for trust evaluation and pre-action trust enforcement in high-risk workflows.

EP answers a more specific question than generic trust scoring:

> should this exact action be allowed to proceed, under this policy, by this actor, in this context?

Trust Receipt, Trust Profile, and Trust Decision remain the core interoperable objects. Handshake and Accountable Signoff provide the sharper enforcement model where systems must constrain execution, not merely describe trust state.

## Core objects

### Trust Receipt
Portable record of trust-relevant evidence.

### Trust Profile
Structured summary of trust-relevant state derived from evidence.

### Trust Decision
Policy-evaluated decision with reasons, evidence, and clear action guidance.

## Why EP Core matters

The core is small on purpose.
Everything else—Handshake, Signoff, cloud products, sector packs—depends on a stable, interoperable trust substrate below.

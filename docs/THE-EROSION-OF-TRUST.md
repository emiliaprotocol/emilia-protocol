# The Erosion of Trust

*Why humanity needs a trust protocol — and why machines need one even more.*

**Trust must never be more powerful than appeal.**

---

## We never had a true trust system

For most of human history, trust was local, embodied, and difficult to counterfeit at scale. People trusted the baker, the smith, or the merchant because proximity made memory unavoidable. A liar eventually ran out of strangers. That was never a designed system. It was an accident of small scale.

---

## The internet created trust at scale — and then captured it

Digital platforms solved the first-order problem of distance by creating reviews, ratings, and reputation systems. For a brief period, those systems worked well enough to help people make decisions about counterparties they would never meet.

Then the platforms hosting trust realized that trust itself was the control point.

When the same entity hosts trust, ranks trust, profits from transactions, and arbitrates disputes, trust becomes leverage. What looks like evaluation becomes monetized control.

---

## Machines inherit the broken trust layer

Now the next wave of decisions will not be made slowly by humans; they will be made automatically by software and AI agents. Agents will decide what to buy, what to install, which MCP server to connect to, which plugin to authorize, which seller to trust, and which machine actor to route work to.

Reviews, stars, and opaque host heuristics do not scale into that future.

Machine-mediated systems need a portable way to decide whether another principal is trustworthy enough for a given context and policy.

---

## What a trust protocol must do

A durable trust layer cannot be a popularity contest, a black-box score, or a host-specific heuristic. It must be:

- **Evidence-based** — computed from verifiable receipts and attestations, not opinions
- **Contextual** — trusted for electronics does not mean trusted for pharmaceuticals
- **Policy-driven** — evaluated against structured decision frameworks, not magic numbers
- **Challengeable** — every negative trust effect must be explainable and disputable
- **Reversible** — corrections must be possible without erasing history
- **Resilient** — designed so the quality of evidence matters more than the volume, and attacks are bounded

And once trust can influence access, routing, or conversion, it must provide due process.

---

## What EP is

**EMILIA Protocol (EP)** is a portable trust evaluation and appeals layer for counterparties, software, and machine actors.

EP computes trust from receipts and attestations rather than reviews. It produces trust profiles rather than a single number. It evaluates against policies rather than arbitrary thresholds. And it includes disputes, appeals, and append-only correction rather than silent mutation.

---

## What EP is not

EP is not a marketplace, not a payment rail, not an identity provider, and not a universal goodness score.

It is a protocol layer: a way to represent trust state, evaluate it for a declared context, challenge it when it is wrong, and preserve an auditable history of both the evidence and the correction.

---

## From commerce wedge to civilizational scope

Commerce is the first wedge because it is measurable and economically consequential. But the protocol's natural scope is larger: merchants, sellers, plugins, packages, marketplaces, MCP servers, agent tools, organizations, and machine actors generally.

The future is not a single reputation score. The future is portable, contextual, evidence-based, challengeable trust decisions across all meaningful principals in machine-mediated systems.

---

## The constitutional principle

EP must never make trust more powerful than appeal.

If trust can influence installation, access, routing, or conversion, then every negative trust effect must be explainable, challengeable, and correctable without erasing history.

---

## Seven extensions toward civilizational trust

EP as it exists today is a foundation. A complete civilizational trust layer requires seven extensions — each building on the last:

**1. Trust degradation.** What happens when the trust layer is down? Agents need specifications for graceful degradation: cached trust snapshots, staleness rules, risk-appropriate fallbacks. No infrastructure can be a single point of failure.

**2. Chain evaluation.** Real trust decisions are compositional. "Should I let this agent use this MCP server to access my data?" requires evaluating every link in the chain, not just each node independently.

**3. Transition modeling.** The most dangerous moment is not a bad actor. It is a good actor becoming bad. Ownership changes, permission escalations, provenance downgrades — these signal trust collapse before it happens.

**4. Operator accountability.** Who watches the governors? Dispute resolution operators must themselves be entities with trust profiles. Their accuracy, fairness, and response time must be measurable and challengeable.

**5. Asymmetric trust.** A human can be harmed by a machine's decision in ways the machine cannot be harmed back. Trust policies must be power-aware — the entity with more capability should carry a higher burden of proof.

**6. Trust dividends.** Honest participation needs compound incentives, not just penalties. Entities that consistently submit accurate receipts should accumulate submitter credibility that makes dishonesty economically irrational.

**7. Identity continuity.** Trust accumulation requires identity continuity. EP needs a portable identity binding interface — not a specific identity system, but a specification for cryptographic continuity across key rotations, platform migrations, and ownership transfers.

All seven require real users and real failures first — not premature engineering.

---

*EMILIA Protocol — Portable trust evaluation and appeals for counterparties, software, and machine actors.*

*emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol · Apache 2.0*

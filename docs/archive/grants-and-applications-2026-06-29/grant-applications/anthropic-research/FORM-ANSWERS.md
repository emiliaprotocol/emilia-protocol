# Anthropic External Researcher Access Program — Form Answers (as submitted)

**Status:** SUBMITTED 2026-06-13.
**Program:** Anthropic External Researcher Access Program (free Claude API credits).
**Form:** https://forms.gle/pZYC8f6qYqSKvRWn9 (reviewed first Monday of each month)
**Ask:** $10,000 in API credits, low quality-of-service.

The applicant supplies the **Organization ID** from
https://console.anthropic.com/settings/organization (account-specific; not stored here).

---

## Field answers (as submitted)

### Brief description of applicant/team (<200 words)
EMILIA Protocol is a solo-led, open-source standards effort by its founder and protocol author, Iman Schrock. Iman authored the full stack: an IETF Internet-Draft (draft-schrock-ep-authorization-receipts, at revision -01) specifying authorization receipts for high-risk AI-agent actions; formal models with 26 TLA+ properties and 22 Alloy assertions verified with zero counterexamples, re-run in CI; an 85-case red-team suite including prompt-injection containment; offline verifiers in JavaScript, Python, and Go; and zero-dependency npm packages (@emilia-protocol/verify, @emilia-protocol/issue) that issue and verify receipts locally. He is active in the IETF secdispatch discussion on authorization-evidence standards alongside the PSEA and delegation-receipt authors. Background in trust systems, cryptographic protocols, and regulated-industry software; all artifacts are Apache-2.0 and public. The expertise relevant to this request is hands-on design and formal verification of agent-authorization protocols, plus the engineering to evaluate them empirically against frontier agent models.

### Describe your research / request for free API credits (<300 words)
Topic. EMILIA Protocol produces authorization receipts: cryptographic, offline-verifiable proof that a named human approved an exact irreversible AI-agent action before it executed. Revision -01 adds an initiator escalation attestation (PIP-007) — the agent's own signed reason for escalating an action to a human, framed precisely as a claim by a party the protocol identifies but never trusts, not a window into the model. This research evaluates two properties empirically, using Claude as the agent under test: (1) containment — that prompt injection can change what an agent proposes but never yields a valid receipt for a gated action, so the absence of a receipt is a positive bypass signal; and (2) escalation calibration — whether an agent's signed escalation reasons match a policy-defined ground truth across many scenarios.

The output is an open benchmark: adversarial agent scenarios with pass/fail receipt outcomes and escalation-attestation labels, released under a permissive license for any lab to reuse. This makes agent actions accountable — when an agent acts, a receipt makes the authorizing principal provable, and its absence is evidence.

Why free API credits matter. The evaluation requires thousands of agent trials — many injection variants, many escalation scenarios, repeated rounds — against Claude models. As an unfunded solo open-source effort, that inference volume is the single binding cost; the protocol, verifiers, formal models, and harness already exist and are open. Credits convert a finished, verified protocol into measured evidence the whole field can reuse.

### Requesting more than $1000? -> Other: $10,000
Justified by the thousands-of-trials evaluation above. (Conservative fallback: $5,000.)

### Quality of service -> "I'm fine with receiving a low quality of service"
A batch eval, run overnight with retries; low QoS does not hinder it and eases approval.

### Google Scholar / GitHub profile
https://github.com/emiliaprotocol/emilia-protocol

### Additional Information (the Anthropic-specific edge)
EMILIA Protocol is open infrastructure (Apache-2.0) with a directly safety-relevant thesis for a model provider: when an agent causes harm, accountability tends to flow to the most legible party — often the model or its provider, even when a human made the consequential decision. A device-bound human authorization receipt re-attributes that: a human-directed action carries a signed record naming the authorizing principal, and an action without a receipt for a gated step is provably a bypass, not the model acting unbidden. The IETF Internet-Draft is at -01 and is in active discussion at secdispatch alongside the PSEA and delegation-receipt drafts; the escalation-attestation extension (PIP-007) is the agent-accountability research this request would evaluate. Framing in two short essays — "The Model Is the Crumple Zone" and "Why Authorization Is Not Proof" — at emiliaprotocol.ai/essays.

### Located in the United States? -> Yes

### ToS / non-confidential
Safe to accept: everything submitted is already public and Apache-2.0.

---

## Other live Anthropic paths (not this form)
- **Anthropic Fellows Program** — 4-month mentored research, stipend + compute; areas include AI control / AI security / model welfare (PIP-007 fits). Caveat: requires US/UK/Canada residence + work authorization. Bigger, higher-bar; revisit if the credits relationship goes well.
- **Economic Futures Research Awards** — $10k-$50k, empirical economic-impact research. Secondary fit only.

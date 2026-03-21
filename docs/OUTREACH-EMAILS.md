# EP Outreach Emails

## AAIF Cover Email

**To:** pr@aaif.org
**Subject:** Proposal: Working Group on Trust Before High-Risk Action in Machine-Mediated Systems

Hello AAIF team,

I'm reaching out to share a proposal for a working group focused on enforcing trust before high-risk action in machine-mediated systems.

The standards stack is getting stronger around tool access, communication, and commerce. What still appears underdefined is the trust-decision protocol: how a system evaluates whether a counterparty, plugin, MCP server, marketplace app, seller, merchant, or software component is trustworthy enough for a given context and policy.

EMILIA Protocol (EP) is the control layer between authentication and execution — an open trust-decision protocol that binds actor + authority + policy + exact action context into immutable events with replay resistance and one-time consumption. The current implementation covers trust profiles, policy evaluation, install preflight, disputes, and appeals. The goal is not to ask AAIF to adopt a product, but to offer a draft protocol and working reference implementation that could help shape a neutral standard in the open.

EP is designed to complement the rest of the stack:
- MCP for tool access
- A2A for coordination
- ACP/UCP/AP2 for commerce and payment flows
- EP for trust evaluation and appeals

The protocol is falsifiable by design — anyone can run the conformance suite to independently verify that the evaluator is producing correct results. Trust that cannot be independently verified is not trust.

I've attached the current proposal and supporting specification materials. I'd welcome the chance to discuss whether this belongs as an AAIF working group or related standards effort.

Best regards,
Iman Schrock
EMILIA Protocol
team@emiliaprotocol.ai
emiliaprotocol.ai

---

## NIST / CAISI Cover Email

**To:** CAISI team
**Subject:** Open Protocol for Trust Evaluation and Appeals in Machine-Mediated Systems

Hello CAISI team,

I'm writing to share a protocol effort that may be relevant to NIST's work on AI agents, software trust, identity, and machine-mediated decision systems.

EMILIA Protocol (EP) is the control layer between authentication and execution — an open trust-decision protocol that binds actor + authority + policy + exact action context into immutable events with replay resistance and one-time consumption. It complements identity and authorization standards by addressing a distinct question: not only who an actor is or what it is allowed to do, but whether trust has been established for a given context and policy before execution proceeds.

The current EP work includes trust profiles, context-aware policy evaluation, install preflight for software and plugins, disputes, appeals, and human escalation paths.

We believe this is relevant because systems will increasingly need to enforce trust before high-risk action — not only for agents, but also for third-party software, marketplaces, sellers, and any principal in machine-mediated systems — in a way that is explainable, challengeable, and correctable.

Critically, EP is falsifiable by design: the conformance suite and canonical test vectors allow any party to independently verify that the trust evaluator is producing correct outputs. This aligns with NIST's emphasis on transparency and auditability in AI systems.

I've attached a short proposal and supporting materials and would welcome any guidance on whether this work is relevant to CAISI or related standards discussions.

Best regards,
Iman Schrock
EMILIA Protocol
team@emiliaprotocol.ai
emiliaprotocol.ai

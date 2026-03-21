# EMILIA Protocol

EMILIA Protocol (EP) is a protocol-grade trust substrate for high-risk action enforcement.

EP does not stop at identity. It verifies whether a specific actor, operating under a specific authority context, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and durable event traceability.

**EP enforces trust before high-risk action.**

EP Core consists of three interoperable objects:
- Trust Receipt
- Trust Profile
- Trust Decision

EP Extensions add stronger enforcement where systems must control whether a specific high-risk action should proceed. The most important extension is **Handshake**, which binds actor identity, authority, policy, exact action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow.

EP can also support **Accountable Signoff** when policy requires named human ownership before execution.

The protocol is open. Managed policy, verification, signoff orchestration, monitoring, evidence tooling, and sector-specific packs are optional product layers built on top.

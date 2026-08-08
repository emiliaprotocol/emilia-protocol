Subject: AE-CHALLENGE -03: transport-neutral evidence challenge for agent protocols

Colleagues,

I would appreciate review of `draft-schrock-ae-challenge-03`:

https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/

The draft covers a narrow interoperability problem: a relying party has
refused an exact agent action because authorization evidence is missing,
stale, or unverifiable, and needs to tell the agent what can be presented on a
new attempt. The challenge is now a transport-neutral data model. It is not
authorization, a task result, or a promise that a later request will execute.

For AgentProto, I would especially value views on three remaining choices:

- Should evidence type, action profile, and presentation profile identifiers
  be absolute URIs, or protocol-local opaque identifiers?
- Which error or message carrier can preserve the complete challenge plus its
  authenticated issuer and audience without giving it result semantics?
- Is consuming the nonce after structural and action matching, but before
  evidence verification, the right common replay rule?

The HTTP binding is separate and uses RFC 9457 Problem Details. The draft also
contains an informative DMSC gateway profile, but explicitly leaves admission
ownership and cross-gateway double-admission to the handoff protocol.

This is an individual draft; no list or working-group consensus is claimed.

Best,
Iman


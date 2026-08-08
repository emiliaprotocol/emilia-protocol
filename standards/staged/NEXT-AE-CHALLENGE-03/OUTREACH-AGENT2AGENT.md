Subject: AE-CHALLENGE -03: refusal and retry semantics for missing authorization evidence

Colleagues,

I would appreciate review of `draft-schrock-ae-challenge-03`:

https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/

The case is an agent action that a relying party will not admit because the
authorization evidence is missing, stale, or unverifiable. The relying party
returns a challenge bound to its own exact action, identifies the remaining
evidence and presentation constraints, and permits a new presentation under a
fresh single-use attempt. Satisfying the challenge only triggers local policy
reevaluation; it is not authorization or task completion.

For Agent2Agent, the specific questions are:

- Should the challenge travel as an error payload, a message part, or a task
  state extension without being mistaken for an artifact or successful result?
- How should the action binding survive delegation and task rewriting when the
  receiving relying party, not the sender, owns the canonical action?
- Can a protocol expose supported presentation profiles and obtain hints while
  keeping discovery distinct from authority?

Revision -03 separates the core model from HTTP and DMSC bindings. The HTTP
binding uses 403 plus RFC 9457 `application/problem+json`; the DMSC profile
explicitly does not transfer admission ownership or prevent double admission.

This is an individual draft; no list or working-group consensus is claimed.

Best,
Iman


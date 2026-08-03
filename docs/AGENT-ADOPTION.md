# EMILIA Agent Adoption

Agent Adoption is a public, synthetic demonstration of the bounded-policy shape
that a production EMILIA Gate can enforce. It lets a person describe an agent
candidate using bounded metadata, select a server-owned job and allowance
template, and use a passkey in a user-present ceremony over the resulting
Operating Bond. No agent is connected to or executed by this launch profile.

> Draft an Operating Bond for an agent candidate, then test its synthetic limits.

## What an Operating Bond means

An Operating Bond binds these facts into one digest:

- the normalized agent candidate metadata;
- the selected synthetic job and allowance templates;
- the no-egress execution boundary; and
- the bounded validity duration that a composed synthetic trial must enforce.

The later passkey ceremony separately binds that exact bond digest to its
relying-party ID, origin, challenge, and observation time. Revocation is
append-only status, not a rewrite of the signed or digested historical bond.

The passkey evidence means that a user-present, user-verified authenticator used
the adoption-local credential for the exact context. It does not prove an
account owner, civil identity, employment, authorship, agent ownership,
comprehension, device exclusivity, or authority for later actions.

Adoption is not authorization. Every consequential action still requires its
own current, exact-action authorization and Gate admission.

## Launch profile

The public launch profile is deliberately narrow:

1. Candidate metadata is provided directly by the user. EMILIA does not fetch
   the source URL, execute imported code, ingest prompts, or collect provider
   credentials.
2. Job and allowance choices come from a closed server-owned registry.
3. The passkey credential is adoption-only. It is not inserted into the Class A
   approver registry and cannot satisfy action quorum by itself.
4. The included trial is synthetic and has no provider connector or network
   egress.
5. Publication is a separate opt-in operation and emits only an allowlisted,
   privacy-minimized projection behind an unlisted capability URL.
6. Adoption and public-share revocations are append-only. A revoked bond cannot
   be used to start another synthetic trial.
7. The browser keeps the current session capability in an HttpOnly, Secure,
   SameSite=Strict cookie until the persisted session expiry. Browser storage
   retains only the non-secret session ID. Cookie-authenticated mutations also
   require an exact same-origin `Origin` header, so a sibling subdomain cannot
   exercise the recovered capability. Recovery is same-browser convenience,
   not account recovery or cross-device identity. Possessing the passkey alone
   cannot recover the session on another browser or device.
8. Sessions and their private artifacts expire after 30 days and are removed by
   a bounded scheduled retention purge. An unlisted public projection can
   disappear sooner if the creating browser session revokes it.

The launch does not move money, hold funds, issue bank accounts, verify legal
identity, certify agents, host a marketplace, or protect execution paths that
are not connected to Gate.

## Evidence states

The product keeps its predicates separate:

- **Candidate normalized** — the bounded metadata passed the launch profile.
- **Passkey observed** — the recorded authenticator participated in a
  user-present ceremony over the exact bond context under the pinned RP ID and
  origin.
- **Synthetic trial active** — the opaque trial capability is within its
  bounded validity window and the adoption has not been revoked.
- **Synthetic decision** — the Arena allowed or refused an exact no-egress
  synthetic action under server-owned limits. This is not a Gate admission.
- **Public projection current** — the share exists and has not been withdrawn;
  this is not third-party certification or endorsement.

No state above implies another, and none is evidence that a real-world effect
occurred.

## Graduation to production

The free product is an acquisition and education surface. A production pilot
replaces the synthetic adapter with a buyer-approved Gate boundary. Provider
credentials remain inside the buyer's executor or credential broker, and Gate
must independently verify current action evidence, reserve one execution, and
refuse every bypass path before a provider call is possible.

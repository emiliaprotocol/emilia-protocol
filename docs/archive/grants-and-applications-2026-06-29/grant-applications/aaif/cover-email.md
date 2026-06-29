# AAIF — IP Red Flag / Do Not Submit EMILIA As-Is

**Status: HOLD. Do not submit EMILIA Protocol as an AAIF project proposal as-is.**

The AAIF project proposal path is not just a visibility / standards-review path.
It is a contribution path for projects that may formally join AAIF. The lifecycle
policy says accepted projects must transfer project trademarks and other project
assets to the Linux Foundation and execute project contribution documents.

- **Submit here:** <https://github.com/aaif/project-proposals/issues/new?template=project-proposal.yml>
- Lifecycle policy: <https://github.com/aaif/project-proposals/blob/main/governance/project-lifecycle-policy.md>
- How-to: <https://aaif.io/blog/how-to-submit-your-project-to-the-aaif/>
- **Do not use the working-group signup unless you are already in an AAIF member
  organization.** The form asks for "Name of Member Organization" and states
  working groups are member-only. Do not pay and do not invent a member org.

## Founder Decision

Do **not** donate:

- the EMILIA trademark;
- the `emiliaprotocol.ai` domain;
- the main repository;
- npm package names;
- governance rights over EP Core;
- commercial product names such as GovGuard / FinGuard / OpenAI Guard;
- copyright ownership beyond the Apache-2.0 license already granted.

Apache-2.0 already gives the ecosystem broad rights to use, inspect, fork, and
build on the code. Transferring the mark and project assets is a different
decision. Make that decision only with counsel, a clear carve-out, and a reason
stronger than "credibility."

## Safe Alternatives

Recommended no-money, no-donation sequence:

1. **Do not submit the AAIF project proposal for EMILIA Protocol.** That path is
   for projects willing to transfer assets if accepted.
2. **Ask for informal technical feedback instead.** Use the outreach note below
   with AAIF TC/staff contacts, member-company engineers, or conference contacts.
3. **Keep EMILIA as the company/project.** Continue publishing specs, packages,
   conformance tests, and receipts under Apache-2.0.
4. **If AAIF engagement becomes valuable later, carve out a narrow neutral
   subproject** that can safely live under foundation governance without giving
   away the EMILIA brand or business. Candidate carve-outs:
   - `authorization-receipts-conformance` — neutral test vectors and runner;
   - `ep-receipt-verifier-core` — tiny verifier core under a neutral name;
   - `agent-authorization-receipts` — standards profile only, not GovGuard or the
     EMILIA mark.
5. **Strengthen the independent case in parallel** with GovGuard pilot evidence,
   one demand-side receipt integration, one independent verifier/operator, and
   external conformance maintainers.

## Pre-submission checklist

- [x] `@emilia-protocol/verify` **1.4.0** and `@emilia-protocol/issue` **0.2.0**
      published to npm (verified 2026-06-13)
- [x] Datatracker -01 **confirmed** (verified 2026-06-13)
- [ ] Legal/IP review completed before any AAIF project proposal is filed
- [ ] Written carve-out drafted if only a neutral subproject is being contributed
- [ ] PDF regenerated only if pursuing informal review:
      `pandoc docs/AAIF-PROPOSAL-v3.md -o aaif-proposal-v3.pdf`

## If You Still Want Informal Review

Use this as an email / DM / conference follow-up to a specific person. Do not
paste it into the AAIF project proposal form unless counsel approves the asset
transfer path.

Subject: Technical feedback on authorization receipts for irreversible agent actions

> Hello —
>
> I maintain EMILIA Protocol, an open (Apache-2.0) standard for authorization
> receipt infrastructure: Eye observes risk, Guard gates before the irreversible
> write, Signoff binds a named human, Commit seals the action, and the receipt lets
> anyone verify the proof offline. IETF I-D draft-schrock-ep-authorization-receipts
> is at -01, with sibling Guard/Eye profile drafts and a zero-dependency local
> issuer (`npx @emilia-protocol/issue demo` shows the receipt loop in 60 seconds).
>
> AAIF's projects cover how agents connect, execute, and are guided; EP covers how
> their irreversible actions become provably authorized, gated, and auditable.
>
> I am not submitting EMILIA Protocol as an AAIF project at this time because the
> project lifecycle requires asset / trademark transfer if accepted. I would value
> informal technical feedback on the receipt profile, Guard / Eye drafts, and what
> a foundation-safe neutral subproject could look like, if there is one.
>
> Iman Schrock · team@emiliaprotocol.ai · emiliaprotocol.ai

Attach only if requested: `aaif-proposal-v3.pdf` (the proposal links the rest).

# STAGING: standing up three independent witness operators

Status: **STAGED, nothing deployed, nothing sent.** This closes the *code and
plan* half of audit GAP 3. The *deployment* half (real operators on independent
infrastructure) costs money and needs partners, which is the lead's call. This
file is the plan, the cost, the candidate partners, and a DRAFT outreach the lead
can send on their word.

## What is already true (verified in this kit)

- The witness EMITTER (`witness/server.mjs`) and verifier checks
  (`@emilia-protocol/verify` `witness.js`) form a closed emit/verify loop.
- The **gossip** half that was missing now exists: `detect-equivocation.mjs`.
- A real local run stands up 3 witnesses, meets quorum on an honest head, and
  **detects a simulated split view**. `equivocation-demo.mjs` and
  `equivocation.node-test.mjs` (via `node --test`) pass.

What is NOT yet true: those three witnesses are three processes on one host. The
security property only arrives when three operators run under **independent**
cloud, region, and administrative control and their views are gossiped.

## Why co-location is not enough

A witness is worth having only because its VIEW of the log is collected under
control separate from the log operator and from the other witnesses. Three
witnesses in one datacenter under one admin share one outage, one jurisdiction,
one insider. They prove the wire protocol (that is what `docker-compose.yml` is
for) and nothing about equivocation resistance. Independence is the product.

## The independence bar (target topology)

| Operator | Cloud (example) | Region (example) | Admin |
|---|---|---|---|
| op1 | AWS | us-east | Partner A |
| op2 | GCP | eu-west | Partner B |
| op3 | Hetzner / Fly / OVH | ap-southeast | Partner C |

Distinct on all three axes. Each partner generates its own key on its own host
(`node witness/generate-key.mjs`), so the private key is born where it lives and
never transits EP. EP holds only the three public records and pins them.

## Cost to stand up three operators

The service is one zero-dependency Node container, a few tens of MB of RAM, near-zero
CPU, negligible egress (a cosignature is a few hundred bytes). Per-operator
monthly compute on the smallest viable instances:

| Provider | Instance | ~Monthly |
|---|---|---|
| Hetzner | CX22 / CAX11 | ~$4.50 |
| Fly.io | shared-cpu-1x, 256MB | ~$2 to $3 |
| AWS | t4g.nano | ~$3 to $5 |
| GCP | e2-micro | ~$0 to $7 (free-tier dependent) |

- **If EP bootstraps all three itself** (a staging step, not true independence):
  roughly **$10 to $45 per month** all-in, plus TLS/DNS (Let's Encrypt is free;
  a hostname per operator if desired). This is cheap enough to run indefinitely
  as a demonstration, but it does NOT deliver independence.
- **If three partners each run their own** (the real target): EP's direct compute
  cost is approximately **$0** because each partner bears its own tiny instance.
  The real cost is coordination: recruiting operators, a one-page operator guide,
  and light monitoring that each is live. This is the intended end state.

The economics are deliberately trivial. The service was built tiny so the bar to
clear is a conversation, not a budget.

## Candidate operator partners (types, not commitments)

Ranked by fit. None contacted.

1. **Transparency-log / CT ecosystem operators.** Groups already running tlog or
   Certificate-Transparency-style infrastructure understand witnessing natively
   (the CT ecosystem invented log witnesses). Highest technical fit, lowest
   explanation cost.
2. **Academic security / systems groups.** University labs run long-lived small
   services and value being a neutral observer in a transparency system. Good for
   a jurisdiction and admin distinct from any vendor.
3. **Standards-adjacent infrastructure operators.** Participants in the same IETF
   space who already run demo endpoints and would see witnessing as aligned work.
4. **Interop-allied agent-infra projects.** Projects EP already treats as interop
   allies rather than competitors are natural second witnesses precisely because
   they are not the EP log operator.
5. **Digital-preservation and civil-society transparency orgs.** Mission-aligned
   with being an independent observer; strong on the "distinct admin" axis.

The selection rule: each operator must be an entity that does NOT operate the EP
log and does NOT share cloud, region, and admin with another witness.

## DRAFT partner-outreach message (UNSENT)

Held OUTSIDE this public repo per opsec (outreach content never lands in tracked
public paths). The drafted message was delivered to the lead directly; send it,
one message per candidate, only on the lead's explicit go.

## Go / no-go

- **Code + local proof:** done, in this branch.
- **Deploy 3 independent operators:** blocked on the lead approving spend
  (trivial) and, more importantly, on partner recruitment. Send the draft above
  only on explicit go.

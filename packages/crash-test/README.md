# @emilia-protocol/crash-test

**One command. Two acts. The whole protocol becomes obvious.**

```
npx -y @emilia-protocol/crash-test
```

### Act 1 — Authorization (at the county, today)
An AI finance agent proposes a **$2,400,000** grant disbursement to a **new** vendor
bank account. Self-approval is rejected. Synthetic Finance Director and Controller
identifiers sign the exact action with two separately generated WebAuthn-shaped
keys. The pinned two-person quorum holds and an authorization receipt is issued.

### Act 2 — Reliance (the auditor's desk, six months later)
The network is down. The EMILIA service is deleted. The database is gone. The
auditor has the receipt and a **relying-party-owned trust profile** established
out of band. The receipt verifies offline under that profile, while a forged copy
and presenter-supplied trust material are refused. The auditor gets a workpaper.

> Act 2 is the product. Act 1 is the setup.

## Scenarios — same engine, different high-risk action

The default tells the county-finance story. Two more show the same EP-QUORUM-v1
predicate gating high-risk actions in healthcare:

```
npx -y @emilia-protocol/crash-test --scenario clinical
```
A **high-alert IV medication** (heparin infusion). The agent proposes administration;
an **independent double-check** by a second qualified clinician is required (the
ISMP / Joint Commission control); the order is signed, then a forged copy with the
infusion **rate altered 10×** is rejected. The demonstration uses synthetic patient
and encounter references. Hashing real identifiers is not, by itself, HIPAA
de-identification and does not make disclosure permissible.

```
npx -y @emilia-protocol/crash-test --scenario procurement
```
A **hospital capital purchase** (a $1.85M 3T MRI from a new, off-contract vendor).
Dual control — **Department Director, then CFO** — and a forged copy with the **vendor
bank account swapped after approval** (textbook payment-redirect / BEC fraud) is
rejected, because the payee account is inside the signed action.

```
npx -y @emilia-protocol/crash-test --scenario release-authorization
```
An **autonomous effector release** in a contested, disconnected environment. An ordered
**two-person authorization** — Mission Commander, then Weapons Safety Officer — gates the
action (a requester cannot self-approve); the receipt is verified **offline, at the edge,
with EMILIA deleted**; and a forged copy with the **designated track re-pointed to a
different target after authorization** is rejected, because the exact designated track is
inside the signed action. Maps to **DoD Directive 3000.09** ("appropriate levels of human
judgment over the use of force"). Necessary, not sufficient: the demonstration
tests exact-action signature and pinned-policy enforcement. It does not establish
real-world identity, human perception, lawfulness, safety, execution, or effects.

## What you get

The run writes an **Auditor Workpaper Package** to `./emilia-workpaper/`:

- `authorization-receipt.json` — the evidence the auditor keeps.
- `relying-party-trust-profile.json` — the policy, enrolled approver keys,
  WebAuthn scope, and operator key the relying party pins independently.
- `verification-report.md` — an audit-grade determination with a single bolded
  verdict: **PRESENT AND INDEPENDENTLY VERIFIED** or **ABSENT / UNVERIFIABLE — DO
  NOT RELY** — the absence made visible, not a silent gap.

## Verify a receipt yourself (the auditor's path)

```
npx -y @emilia-protocol/crash-test verify \
  ./emilia-workpaper/authorization-receipt.json \
  --trust ./emilia-workpaper/relying-party-trust-profile.json
```

Exit code `0` = verified, `1` = do not rely, `2` = malformed or missing input.
No network, account, or API key is needed. The check rejects duplicate JSON
members, recomputes the action hash, replaces all presented policy/key material
with the relying party's pins, checks WebAuthn RP ID and origin, runs the real
**EP-QUORUM-v1** predicate, and verifies the commit under the pinned operator key.

## What it proves, and does not prove

**Proves under the supplied trust profile:** the keys enrolled for the listed
approver identifiers signed *this exact action* under the pinned policy and
WebAuthn scope; the signed timestamps satisfy the order/window rule; and the
pinned operator key signed the commit record. Altering signed fields is detected.

**Does not prove:** correct enrollment or key custody; absence of collusion or
coercion; what a person saw, understood, or intended; trusted time or current
revocation unless separately supplied; legality, safety, or wisdom; that execution
occurred; or that an effect matched or followed the authorization.

## Honesty note

The demonstration uses real ES256 WebAuthn-shaped signatures minted locally, not
hardware-backed passkeys or verified people. A production deployment must enroll
authenticators, validate attestation as policy requires, protect trust-profile
distribution, check revocation/freshness, and use separate execution/effect
evidence for execution claims. The crash test makes no network calls.

Spec: [draft-schrock-ep-quorum](https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/) ·
[draft-schrock-ep-authorization-receipts](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)

Apache-2.0

<!-- SPDX-License-Identifier: Apache-2.0 -->
# CHAP to AEB composition v1

This kit tests one bounded composition between the CHAP human-review protocol
and EMILIA's AEB evidence boundary. It is pinned to BrightbeamAI/chap commit
`9e7af2b811d3368b4afba7c6d318764959c2fd0d` and the exact source-file hashes
listed in the generated report.

Run the reference implementation:

```bash
npm run conformance:composition:chap-aeb
```

Emit a report with runner-supplied metadata:

```bash
node conformance/composition/chap-aeb-v1/run.mjs \
  --emit \
  --output /tmp/chap-aeb-report.json \
  --runner-name "Your name" \
  --runner-affiliation "Your project" \
  --runner-revision "your-source-revision" \
  --executed-at "2026-08-14T18:00:00Z"
```

The report includes text suitable for an Internet-Draft Implementation Status
section. It states that running EMILIA's code is a reproduction, not an
independent implementation.

## What the profile establishes

- A CHAP `security-signed/1.0` `decide.override` decision can be verified under
  relying-party-pinned Ed25519 roots.
- Its signature-covered `based_on_artefact` plus RFC 6902 `diff` can be applied
  and compared with the exact action at Gate.
- The resulting action can be projected into a revision-pinned CAID profile.
- The CHAP decision identity becomes a stable native replay unit for AEB.
- Signature tampering, action substitution, unsafe JSON Pointer paths, wrong
  signers, stale status, and consumed decisions fail closed.

## Deliberate limit

The current CHAP `decide.approve` shape signs `task_id`, but not the artifact it
approves. That is valid CHAP evidence, but an offline relying party cannot prove
that the approval covers the exact action at Gate. The adapter therefore
returns `INDETERMINATE`. The runner demonstrates a minimal additive extension,
`approved_artefact_digest`, inside the signed parameters. That extension is an
interop proposal, not a claim about the current CHAP specification.

A passing report does not authorize an action, execute an action, prove an
independent implementation, establish IETF adoption, or imply endorsement by
CHAP's authors.

It also does not prove completeness of the CHAP record set. Hash chaining,
signatures, and transparency inclusion establish integrity for records that
exist. They do not establish that every human decision that should have been
recorded was emitted. A deployment requiring that property must couple record
creation to the governed act or supply another independently verifiable
omission signal.

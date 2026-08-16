# WAG -00 to AEB token-issuance interoperability kit

This kit is the promised revision-pinned Workload Authorization Grant (WAG)
interoperability fixture. It verifies a WAG -00 JWT authorization grant under
a per-tenancy issuer key and maps the observed RFC 7523 token request to one
exact EMILIA CAID.

Run from the repository root:

```sh
npm run conformance:composition:wag
```

No network access, account, or external service is required. The command runs
the focused adapter suite and all 15 composition cases, then prints a
paste-ready Implementation Status paragraph.

To identify the runner in the report:

```sh
node conformance/composition/wag-aeb-v1/run.mjs \
  --runner-name "Your name" \
  --runner-affiliation "Your project" \
  --runner-revision "your-commit" \
  --executed-at "2026-08-13T20:00:00Z" \
  --output /tmp/wag-aeb-report.json
```

The report includes a paste-ready Implementation Status paragraph. Running
this kit reproduces the EMILIA reference implementation. It is not an
independent implementation, IETF adoption, certification, or employer
endorsement.

## What the kit proves

- exact WAG -00 source and source-byte pinning;
- per-tenancy issuer, `kid`, and ES256 key pinning;
- acceptance of newly seen signed subjects without per-agent registration;
- exact workload subject, audience, resource, and material Property checks;
- exact `oauth.access-token.issue.1` CAID projection;
- stable native replay identity scoped by `(iss, sub, jti)`;
- refusal of a second AEB admission using that replay identity;
- `INDETERMINATE` when current status cannot be established; and
- refusal to substitute WAG for human approval or downstream action authority.

## Honest boundary

WAG signs the JWT claims. It does not sign the RFC 8707 `resource` parameter
beside the assertion. This profile binds the resource observed by the
authorization server into the token-issuance CAID. It does not claim that the
WAG issuer signed that parameter.

WAG -00 requires a unique `jti` but does not define consumption. One-time AEB
consumption is an EMILIA composition rule, not a WAG -00 conformance claim.

# Quorum -04 validation

Local repair worktree: `.codex-emilia-technical-repair-20260906`, based on
`74a2b68b9`. Sources are uncommitted; root owns integration and publication.

- `xmllint --noout`: pass.
- Final idnits 3.1.0: no errors; one advisory `PREFER_BCP14_REF` warning.
  The standard full boilerplate and both RFC references are present.
- `xml2rfc`: TXT and HTML rendered successfully without warnings after setting the stream explicitly.
- Shared corpus `EP-QUORUM-v1`, vectors version `1.1.0`: 24/24 expected verdicts in JavaScript, Python, and Go.
- `npx vitest run tests/quorum-session.test.ts tests/quorum-web.test.ts tests/guard-quorum-template-unit.test.ts tests/quorum-org-template.test.ts`: 74/74 pass.
- `node --test packages/verify/quorum.test.js`: 9/9 pass.
- `PYTHONPATH=packages/python-verify python3 -m pytest packages/python-verify/tests/test_quorum_vectors.py -q`: 32/32 pass.
- From `packages/go-verify`, `go test ./... -run 'Quorum|RequiredAlgorithms|NonCanonicalSPKI' -count=1`: pass.
- `git diff --check` over this worker's implementation/test source files: pass. Full-worktree diff check separately reports generated HTML whitespace in other workers' packets.

## RED then GREEN evidence

- `npx vitest run tests/quorum-web.test.ts`: initial reverse-signature regression failed 6/17. Four cases accepted real signatures made in reverse over precomputed context links; two completed-proof positives were rejected. After the profile repair: 17/17 pass.
- Same command after adding policy-pin and ordered-prefix cases: 2/21 failed because a stripped policy was accepted. After expected-policy enforcement: 21/21 pass.
- `npx vitest run tests/guard-quorum-template-unit.test.ts`: 2/23 failed because ordered effective threshold used roster size instead of required=k. After the bounded template fix: 23/23 pass. The old route-suite assertion was updated to require an explicit threshold, matching the verifier.
- `npx vitest run tests/quorum-session.test.ts`: 1/11 failed because incremental admission accepted context-only strong-chain links. After the completed-proof admission check: 11/11 pass.

The reverse-order tests make genuine ECDSA signatures in IG, AO, PO order,
then present PO, AO, IG. The replacement test swaps a predecessor for another
valid signature of the same context and key, retaining valid native
signatures but invalidating the completed-proof link. Policy tests reject
profile stripping, unknown profile and threshold mutation against a trusted
exact pin. Tests do not amount to a formal proof or a hardware demonstration.

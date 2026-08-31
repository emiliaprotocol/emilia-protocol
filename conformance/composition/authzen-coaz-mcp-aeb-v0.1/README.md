<!-- SPDX-License-Identifier: Apache-2.0 -->
# AuthZEN COAZ-MCP to AEB consequence admission v0.1

This profile tests one narrow seam: an MCP `tools/call` is translated into an
AuthZEN Access Evaluation request, a local policy enforcement point records
the returned boolean, and EMILIA compiles that local observation before the
exact material action can reach consequence admission.

The profile reuses the source-pinned COAZ-MCP translation corpus in
`../coaz-translation-v0.1`, the native compiler, the signed native-verification
attestation bridge, and the checked-in AEB consequence-admission kernel. It
does not replace AuthZEN, MCP, or AEB with a new wire format. The strict local
envelope used by this profile is a compiler input, not an AuthZEN extension or
credential.

Run it from the repository root:

```sh
node --test conformance/composition/authzen-coaz-mcp-aeb-v0.1/run.node-test.mjs
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/run.mjs --check
```

To print the deterministic report:

```sh
node conformance/composition/authzen-coaz-mcp-aeb-v0.1/run.mjs
```

## What the nine cases establish

1. An exact call with a toy AuthZEN allow compiles under a pinned descriptor,
   verifier, adapter, mapping profile, and full typed action. It reaches AEB
   `ADMIT` only after the relying party's exact-action check and a local atomic
   reservation.
2. Changing the beneficiary leaves the toy PDP's decision at allow because
   that field is absent from its input tuple, but CAID and normalized-action
   checks refuse the changed action before provider entry.
3. An AuthZEN deny does not admit the action.
4. An AuthZEN allow cannot fill a required named-human authorization role and
   does not prove execution.
5. A timeout after dispatch is `INDETERMINATE`, not success or safe failure.
6. A blind retry is refused while the original operation remains unresolved.
7. Authenticated evidence bound to the same provider, operation, CAID, and
   normalized action can reconcile the outcome without re-execution.
8. A provider and action binding mismatch refuses reconciliation.
9. A changed mapping-profile pin refuses the operation before translation,
   PDP evaluation, AEB admission, or provider entry.

Every result reports native verification, relying-party acceptance,
material-action matching, evidence satisfaction, local authorization,
reservation, custody, provider outcome, observed-effect relation, retry, and
reconciliation as separate axes.

## What actually runs

The local test PEP records the AuthZEN request digest, boolean response digest,
full typed action digest, CAID, mapping-profile pin, and observation time. The
PEP harness signs an AEB native-verification attestation that names the digest
of those exact observation bytes. The compiler artifact is a strict
`{ observation, attestation }` envelope. Its adapter verifies the attestation
through the existing native bridge, recomputes the supplied observation's
digest, and requires the observation ID, time, full-action binding, and mapping
facts to agree before it calls the mapper. The native evidence digest covers
the complete presented envelope.

The compiler then checks the relying party's descriptor and profile pins,
reports semantic loss, and emits a stable native replay unit that does not
depend on the compiler's wrapper reference. It preserves the local policy
decision as an unverified policy input. Its local-authorization axis remains
`NOT_EVALUATED` and its authorization claim remains false.

That compiler report is still preflight evidence. Its reservation,
consumption, provider-entry, outcome, retry, and reconciliation axes stay
`NOT_EVALUATED` or `NOT_ESTABLISHED`. Only
`evaluateAebConsequenceCase()` advances those runtime lifecycle axes.

The focused tests also remove and substitute the native descriptor, change the
relying-party pin, change the beneficiary, require a separate named human, and
change only the compiler wrapper reference. They also mutate the supplied
observation without changing its attestation, substitute an independently
signed attestation from another observation, and exercise validly signed but
inconsistent reference, action, and mapping facts. Those cases fail closed or
retain the same replay unit as appropriate.

## Exact claim boundary

The AuthZEN Authorization API result used here is a boolean machine-policy
decision observed locally by the policy enforcement point. AuthZEN does not
sign the local observation. This reference PEP harness generates a
deterministic, public, test-only signing key so the checked-in report is
reproducible. This profile does not call the result an AuthZEN receipt,
named-human authorization, execution evidence, or AuthZEN replay token.
Single-use behavior comes from AEB's explicitly local atomic reservation
domain, not from the Authorization API or the compiler.

The `machine-policy-input` leg is a deterministic local observation compiled
through a relying-party-pinned descriptor and the existing signed native
attestation bridge. `VERIFIED` means that the local PEP attestation verified
under the pinned test key and that the supplied observation bytes match its
digest and bindings. The complete envelope is the artifact evaluated by AEB.
The descriptor's implementation digest is metadata, not a runtime
measurement. The compiler report is not a credential, does not establish
local authorization, and does not authorize provider entry. Only the
consequence kernel applies the local policy input and advances the runtime
lifecycle.

The PDP in the corpus is deliberately a toy. No deployed AuthZEN PDP,
COAZ-MCP translator, MCP gateway, or product is exercised or claimed
vulnerable. A passing report is an EMILIA reference reproduction over pinned
inputs. It is not an independent implementation, production mediation,
OpenID working-group acceptance, IETF adoption, certification, proof of
provider commitment, or proof of real-world effect.

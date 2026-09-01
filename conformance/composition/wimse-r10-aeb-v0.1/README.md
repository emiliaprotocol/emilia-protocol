<!-- SPDX-License-Identifier: Apache-2.0 -->
# WIMSE R10 native matrix and AEB host-carrier profile v0.1

This pack asks a practical question: which current delegation mechanisms can
carry the execution-time human-authorization requirement in R10, and which
parts still need a host profile or lifecycle gate?

The requirements come from the exact bytes of
`draft-reece-wimse-cross-org-delegation-02`. The comparison sources are the
current pinned Asor -00, HAMR -00, and AgentEnvelope -01 drafts, plus the
checked-in EMILIA WIMSE adapter. `matrix.json` evaluates all five rows against
ten criteria:

1. exact action;
2. target;
3. acting-for principal;
4. offline verifiability;
5. execution-time required evidence;
6. monotonic, non-droppable carriage;
7. at-most-once local admission;
8. consumption only on admission;
9. an indeterminate state; and
10. no blind retry.

The native results are intentionally strict. Asor -00 has an offline
delegation chain but no R10 evidence designation or admission lifecycle. The
`-00` revision of HAMR has a closed floor vocabulary, so `required_evidence`
is `NOT_SUPPORTED` in that revision. This is a deliberate fail-closed result,
not a missing attenuation check: recognized floor axes survive every hop,
ordered values may only tighten, equality values cannot change, and an unknown
axis rejects the link instead of being ignored or dropped. AgentEnvelope -01
has a strong action envelope and a generic legitimacy reference, but it does
not define recursive R10 carriage or the AEB admission lifecycle. The current
EMILIA WIMSE adapter binds the request and can return `INDETERMINATE`, but its
native evidence role is delegated workload, not accountable-human
authorization.

The criteria span three separate layers: who may act and under what floors;
what exact action and target are bound; and what happened once, including
admission, consumption, unresolved outcome, and retry. HAMR -00 supplies the
delegation chain and floors, while its RFC 9421 profile binds the presented
request but leaves scope semantics opaque. Section 9.2 deliberately leaves
consumed-nonce state to the verifier, and the draft does not define the third
layer.

The fifth row is different. It demonstrates one composition: a proposed host
carrier keeps a named human-authorization requirement, exact action, target,
and acting-for principal through every hop, then hands the verified inputs to
the existing AEB consequence-admission kernel. Neither HAMR nor AEB depends on
the other. This is a candidate profile, not a claim about fields in any
current native draft.

Run the focused checks from the repository root:

```sh
node --test conformance/composition/wimse-r10-aeb-v0.1/run.node-test.mjs
node conformance/composition/wimse-r10-aeb-v0.1/run.mjs --check
```

Print the deterministic report:

```sh
node conformance/composition/wimse-r10-aeb-v0.1/run.mjs
```

## What the eleven cases establish

The positive case preserves the evidence requirement through three hops,
admits once, models one provider entry, and records a normalized observation
of the requested effect. The hostile cases then prove the boundaries:

- removing or weakening the requirement refuses the chain;
- an unknown required profile fails closed;
- a changed target or acting-for principal fails before admission;
- a consumed native replay unit cannot be admitted again;
- verifier and local-policy refusals do not consume a new reliance unit;
- a timeout after dispatch remains `INDETERMINATE`; and
- a blind retry is refused while the first operation is unresolved.

`CANDIDATE-NATIVE-CARRIER.md` gives the small, format-neutral contribution
shape that the runnable row uses.

## Exact claim boundary

This is an EMILIA same-team reference reproduction over pinned public draft
bytes and pinned local code. It does not establish WIMSE adoption, Reece
endorsement, freedom to operate, independent implementation, production
mediation, remote atomicity, or exactly-once external effects. It also does
not claim that current Asor, HAMR, or AgentEnvelope drafts implement an
extension they do not define. The harness does not invoke an external
provider.

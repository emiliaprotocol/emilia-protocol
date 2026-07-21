# Platform attestation as an AEC evidence leg

`ep-platform-attestation` lets an Authorization Evidence Chain (AEC) require a
fresh, action-bound appraisal of the build that ran the Gate. It consumes a
signed attestation **result** under a relying-party-owned policy. It does not
appraise raw TPM/TEE evidence and does not establish that hardware is genuine.

The profile follows the role split in the RATS architecture:

1. A platform Attester produces implementation-specific Evidence.
2. An external Verifier appraises that Evidence against endorsements,
   reference values, and its appraisal policy.
3. The Verifier issues a signed EAT/JWT-shaped Attestation Result.
4. EMILIA, acting as the Relying Party, accepts that result only under its own
   pinned verifier key, EAT profile, audience, nonce, action digest, reference
   measurement, verification time, and maximum age.

The evidence wrapper is closed:

```json
{
  "@version": "EP-PLATFORM-ATTESTATION-v1",
  "token": "<compact signed JWT>"
}
```

The protected JWS header is limited to `alg=EdDSA`, a relying-party-resolved
`kid`, and the EAT-specific `typ=eat+jwt`. The signed payload is limited to:

- `iss` and `aud`;
- integer `iat` and `exp`;
- the RFC 9711 `eat_nonce`, `eat_profile`, and `measres` claims; and
- `ep_action_digest`, which binds the result to the exact AEC action.

This EMILIA profile intentionally narrows `eat_nonce` to one text value and
`measres` to one successful `ep-build` SHA-256 measurement. A generic EAT
processor is neither required nor implied.

## Relying-party policy

The built-in AEC verifier requires policy and keys from the verifier context:

```js
const context = {
  requirement: 'ep-platform-attestation',
  expectedAction,
  verificationTime: '2026-07-21T12:00:00Z',
  keysByType: {
    'ep-platform-attestation': {
      'https://verifier.example': {
        'verifier-key-2026-07': '<base64url Ed25519 SPKI DER>'
      }
    }
  },
  policiesByType: {
    'ep-platform-attestation': {
      expected_profile: 'tag:emiliaprotocol.ai,2026:platform-attestation/eat-jwt/v1',
      expected_audience: 'https://gate.example/authorize',
      expected_nonce: '<challenge nonce>',
      reference_measurements: ['sha256:<measured-build-digest>'],
      max_age_sec: 120
    }
  }
};
```

`ep-platform-attestation` is a reserved component name. A caller-supplied
component verifier cannot replace it with an accept-all function, and trust
keys embedded in presented evidence are rejected.

## Exact claim boundary

An accepted result means only:

> The relying party's pinned verifier key signed the exact profile, audience,
> nonce, action digest, successful build-measurement result, and freshness
> claims accepted by this closed profile.

It does not prove:

- that EMILIA independently verified a TPM, TEE, secure boot chain, firmware,
  supply chain, or physical device;
- that the external verifier's reference values or appraisal policy were
  correct or complete;
- that measured code was the only code able to affect the consequential
  action;
- that a valid measured build is free of vulnerabilities; or
- that a signed appraisal establishes human authority, outcome truth, or
  legal validity.

Those limits are why outbound material must say “consumes an RP-pinned platform
attestation result,” not “hardware-verified” or “proved to run in a TEE.”

## References

- RFC 9334, *Remote ATtestation procedureS (RATS) Architecture*
- RFC 9711, *The Entity Attestation Token (EAT)*
- RFC 9782, *Entity Attestation Token (EAT) Media Types*

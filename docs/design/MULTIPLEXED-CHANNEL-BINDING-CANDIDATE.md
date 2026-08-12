# Multiplexed channel-binding candidate (NOT IMPLEMENTED)

Status: pre-implementation design candidate for external cryptographic and TLS
review. Nothing in this note is normative, implemented, or part of a
conformance claim. The shipped
`wimse-oauth-principal-aeb-profile-v2` remains restricted to one
authentication mechanism instance per TLS connection as required by RFC 9266.

This candidate must not be implemented until an external reviewer has examined
the complete construction, state machine, TLS-termination assumptions, and
transcript definitions. A favorable review would authorize an experimental
implementation and hostile vectors, not a standards or interoperability claim.

## Security goal and limits

For multiple concurrent authentication instances on one TLS 1.3 connection,
bind one workload-signed WIMSE presentation to all of the following:

- the TLS connection observed by the relying party;
- one relying-party-issued authentication-instance nonce;
- the relying party's exact configured audience;
- the full validated CAID for the material action; and
- a non-circular digest of the native evidence artifacts.

The construction is only a current-channel binding. It does not establish
identity, delegation, human approval, authorization, admission, provider
effect, or successful execution. It is not transferable proof for a third
party because both TLS endpoints can derive the HMAC key. The workload's
asymmetric HTTP Message Signature supplies presenter authentication and covers
the channel-binding fields.

0-RTT and the TLS 1.3 early exporter are out of scope.

## Candidate construction

For private experimentation, the TLS exporter label is:

    EXPERIMENTAL-EXPORTER-EMILIA-AUTH-BINDING-v1

The label begins with `EXPERIMENTAL` because RFC 5705 permits only such labels
for private use without registration. The exporter context is the non-empty
ASCII string:

    EMILIA-WIMSE-AEB-MULTIPLEX-v1

The regular TLS 1.3 exporter, never the early exporter, derives:

    K_bind = TLS-Exporter(
      "EXPERIMENTAL-EXPORTER-EMILIA-AUTH-BINDING-v1",
      "EMILIA-WIMSE-AEB-MULTIPLEX-v1",
      32)

For each authentication attempt:

    tag = HMAC-SHA-256(K_bind, M)

The presenter carries the 16-byte instance nonce and the 32-byte tag as
canonical unpadded base64url request fields. Both fields must be covered by the
verified workload HTTP Message Signature. The relying party reconstructs `M`
from independently pinned or verified inputs. It does not trust a
presenter-supplied frame.

This construction derives one 32-byte exporter key per TLS connection and
performs one HMAC per attempted authentication. It therefore uses constant
exporter-key material per connection, but it is not constant total work or
constant total state: `n` concurrent instances require `n` HMAC evaluations
and bounded replay records for up to `n` live nonces.

## Exact digest inputs

All strings below are encoded as UTF-8. No URI, case, Unicode, or percent-
encoding normalization is performed. A value is hashed only after the profile
has validated it and selected it from relying-party-pinned state or verified
native evidence.

Define the local digest function:

    H(label, value) = SHA-256(
      ASCII(label) || 0x00 || uint32_be(len(value)) || value)

The length is the byte length of `value`, not a character count. It is
bounds-checked before allocation. These lengths are local hash-transcript
inputs, not untrusted lengths parsed from `M`.

The three 32-byte frame values are:

    audience_digest = H(
      "EMILIA-RP-AUDIENCE-v1",
      exact configured wimse_audience bytes)

    caid_digest = H(
      "EMILIA-CAID-v1",
      ASCII(full validated CAID string))

    evidence_set_digest = raw SHA-256 bytes from digestAebTyped({
      "wit": exact compact WIT string,
      "wpt": exact compact WPT string,
      "txn_token": exact compact OAuth transaction-token string,
      "spt_txn": exact compact SPT transaction-token string or null,
      "spt_intent": exact SPT intent object or null
    }, "EP-WIMSE-NATIVE-EVIDENCE-TRANSCRIPT-v1")

`evidence_set_digest` intentionally excludes the HTTP `Signature`,
`Signature-Input`, the instance nonce, the HMAC tag, and all channel-binding
request fields. Including any of those values would create a circular signing
transcript. The HTTP Message Signature separately covers the exact request,
the instance nonce, and the HMAC tag. The CAID separately commits to the
material action.

## Frame M

`M` is reconstructed as this closed 114-byte layout:

    offset  len  field
    0        1   version = 0x01
    1        1   message_type = 0x01 (presenter-to-relying-party request)
    2       16   authentication_instance_nonce
    18      32   audience_digest
    50      32   caid_digest
    82      32   evidence_set_digest
    ----
    total: 114 bytes

The verifier accepts exactly 114 bytes of locally reconstructed input. Version
1 has one closed message type. A future direction or field layout requires a
new version or a separately specified closed message type. There is no
reserved byte and no open-ended role registry in version 1.

Fixed width removes ambiguity from `M`; it does not eliminate parsing or
bounds-checking from the surrounding protocol. It also does not make variable-
length encodings inherently unsafe.

## Required state machine

The relying party, not the presenter, generates each 128-bit nonce with a
cryptographically secure random generator. The relying party stores a bounded,
expiring record that includes at least:

- the nonce;
- the TLS connection or local connection handle to which it was issued;
- the expected audience and full CAID;
- issuance and expiry times; and
- an `OPEN` or `CONSUMED` state.

The verifier must:

1. reject malformed or non-canonical nonce and tag encodings;
2. find an unexpired `OPEN` nonce issued by the relying party for the current
   connection;
3. verify and pin the native evidence, audience, and full CAID;
4. reconstruct `M` from those verified values;
5. derive `K_bind` from the current TLS connection and compare the HMAC tag in
   constant time;
6. verify that the workload HTTP Message Signature covers the nonce and tag as
   well as the profile's required request fields; and
7. atomically transition the nonce from `OPEN` to `CONSUMED`, allowing only one
   successful presentation.

Equivalent ordering may perform the atomic transition before expensive
verification only if it explicitly accepts the resulting attempt-burning
denial-of-service tradeoff. The current candidate does not make that tradeoff.

The exporter key can be cached once per connection, but nonce replay state is
still mandatory. The earlier claim that connection-local state is only the
32-byte key was incorrect.

## Key and channel lifecycle

The public RFC 9266 `EXPORTER-Channel-Binding` value is never used as a secret
key. `K_bind` is never transmitted, logged, or placed in evidence.

The candidate assumes that TLS 1.3 KeyUpdate does not change the exporter
master secret and that a new or resumed handshake produces a distinct regular
exporter value. These assumptions must be checked against each target TLS API
and included in interoperability tests. Closing a connection destroys its
exporter key and all remaining instance state.

## TLS termination and trust boundary

If the component applying AEB policy cannot obtain exporter output for the
current TLS connection from its trusted TLS termination boundary, and policy
requires this binding, the result is `INDETERMINATE`.

A reverse proxy or sidecar can participate only through an authenticated,
authorization-scoped interface that binds the exporter output to the exact
connection and request. In that deployment the proxy becomes part of the
trusted computing base. A service mesh is not automatically stronger, and no
claim is made about where high-value traffic normally terminates.

## Questions that external review must resolve

1. Is reusing one exporter-derived HMAC key with a domain-separated fixed
   transcript preferable to deriving one exporter value per instance using
   the nonce as exporter context?
2. Does the asymmetric-signature-plus-HMAC composition have any reflection,
   unknown-key-share, endpoint-confusion, or transcript-splicing weakness
   under HTTP/2 or HTTP/3 multiplexing and connection coalescing?
3. Is the proposed native-evidence transcript complete and non-circular for
   every allowed optional-field combination?
4. Is nonce consumption after cryptographic verification the right
   availability tradeoff, or must the profile define a bounded pre-verification
   claim step?
5. Which real TLS APIs expose the regular exporter and a stable connection
   handle at the relying-party enforcement point without trusting
   presenter-controlled metadata?
6. What formal or mechanized model is required before this construction can be
   called more than an experimental profile?

## Registration and publication boundary

The experimental label above is intentionally not the proposed permanent
label. If the construction survives review and interoperation, a permanent
label must be requested through the TLS Exporter Labels registry's current
Expert Review policy. Changing the label changes `K_bind`, so the permanent
label requires a new frozen vector set and explicit version transition.

No public security, performance, interoperability, or deployment claim should
be made from this note alone.

## References

- [RFC 5705, TLS exporters](https://www.rfc-editor.org/rfc/rfc5705.html)
- [RFC 8446, Section 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)
- [RFC 9266, TLS 1.3 channel bindings](https://www.rfc-editor.org/rfc/rfc9266.html)
- [RFC 9847, TLS registry updates](https://www.rfc-editor.org/rfc/rfc9847.html)

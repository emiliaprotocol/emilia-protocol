# Verify EMILIA Trust Receipt — GitHub Action

Fail a CI build unless an [EP-RECEIPT-v1](https://www.emiliaprotocol.ai/spec) Trust Receipt
verifies. Offline, zero-dependency, no API key — it runs the published
[`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify) package and
checks the Ed25519 signature (and Merkle anchor, if present) with Node's built-in `crypto`.

Put a green ✅ on every pipeline that produces or consumes a high-risk action: proof that the
action was signed off, not just logged.

## Usage

```yaml
- uses: emiliaprotocol/emilia-protocol/actions/verify-receipt@main
  with:
    receipt: ./artifacts/receipt.json
```

### With an explicit signer key (fully offline — no network)

```yaml
- uses: emiliaprotocol/emilia-protocol/actions/verify-receipt@main
  with:
    receipt: ./artifacts/receipt.json
    public-key: ${{ secrets.EP_SIGNER_PUBLIC_KEY }}   # base64url SPKI DER
```

## Inputs

| Input        | Required | Default                                                      | Description |
|--------------|----------|--------------------------------------------------------------|-------------|
| `receipt`    | yes      | —                                                            | Path to the EP-RECEIPT-v1 JSON file. |
| `public-key` | no       | _(fetched from `keys-url`)_                                  | Signer public key, base64url SPKI DER. Provide this to run fully offline. |
| `keys-url`   | no       | `https://www.emiliaprotocol.ai/.well-known/ep-keys.json`     | Key set to try when `public-key` is omitted. |
| `version`    | no       | `latest`                                                     | Version of `@emilia-protocol/verify` to install. |

## Exit codes

- `0` — receipt verified
- `1` — verification failed (signature/anchor did not check out)
- `2` — usage or configuration error

## What it does not do

This action verifies a receipt's **cryptographic integrity** — that a specific signer produced it
over the exact payload. It does not, by itself, attest that the signer is who you think they are;
pin the `public-key` (or audit `keys-url`) to bind verification to a trusted signer.

-- Migration 078: Add Ed25519 keypair columns for protocol-standard entity registration.
-- public_key: base64url-encoded SPKI DER (published via /.well-known/ep-keys.json)
-- private_key_encrypted: AES-GCM sealed base64url-encoded PKCS8 DER (legacy plaintext rows are read-compatible)
ALTER TABLE entities ADD COLUMN IF NOT EXISTS public_key text;
ALTER TABLE entities ADD COLUMN IF NOT EXISTS private_key_encrypted text;

COMMENT ON COLUMN entities.public_key IS 'Ed25519 public key (base64url SPKI DER) — discoverable at /.well-known/ep-keys.json';
COMMENT ON COLUMN entities.private_key_encrypted IS 'Ed25519 private key material sealed at rest (epenc:v1 AES-GCM over base64url PKCS8 DER). Legacy plaintext rows are read-compatible; rotate/reseal for high-assurance deployments.';

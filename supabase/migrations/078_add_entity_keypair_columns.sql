-- Migration 078: Add Ed25519 keypair columns for protocol-standard entity registration.
-- public_key: base64url-encoded SPKI DER (published via /.well-known/ep-keys.json)
-- private_key_encrypted: base64url-encoded PKCS8 DER (used for receipt signing)
ALTER TABLE entities ADD COLUMN IF NOT EXISTS public_key text;
ALTER TABLE entities ADD COLUMN IF NOT EXISTS private_key_encrypted text;

COMMENT ON COLUMN entities.public_key IS 'Ed25519 public key (base64url SPKI DER) — discoverable at /.well-known/ep-keys.json';
COMMENT ON COLUMN entities.private_key_encrypted IS 'Ed25519 private key (base64url PKCS8 DER) — used for EP-RECEIPT-v1 signing';

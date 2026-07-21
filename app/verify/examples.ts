// SPDX-License-Identifier: Apache-2.0
// Real, fully-signed example artifacts for the public /verify page. Generated
// with genuine Ed25519 (receipt) and P-256/WebAuthn (signoff) keys, so the
// in-browser verifier validates real cryptography — not a mock. Synthetic data
// (no real person/org); the keys live only here, which is the point: anyone can
// re-verify these offline.

export const EXAMPLE_RECEIPT = {
  "@version": "EP-RECEIPT-v1",
  "payload": {
    "receipt_id": "tr_demo_82k",
    "@type": "ep.trust_receipt",
    "organization_id": "org-demo",
    "action_type": "large_payment_release",
    "decision": "approved",
    "key_class": "A",
    "context": {
      "amount": 82000,
      "currency": "USD",
      "target_resource_id": "wire/8841",
      "risk_flags": [
        "new_destination",
        "after_hours"
      ],
      "change": {
        "after_bank_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      }
    },
    "issued_at": "2026-06-09T17:21:05.000Z"
  },
  "signature": {
    "algorithm": "Ed25519",
    "value": "jQhhZ-K7DmMf0_oISXOIGLuKUmq36bOeQPt1qOiiXYohpm0kjD3P9QBp2JVomwD0ZPd_fhbc0sa_yvMcsb93CQ"
  },
  "issuer_public_key": "MCowBQYDK2VwAyEAVaaaXNbqnUbffvaHL_oJgir8lwv6JINKVgzZGEMhhTM"
};

export const EXAMPLE_SIGNOFF = {
  "@type": "ep.signoff",
  "context": {
    "ep_version": "1.0",
    "context_type": "ep.signoff.v1",
    "action_hash": "aebb24348998fa136b15b27da3f9ad5b21878275350f82d11d17bd016773f2d2",
    "nonce": "sig_0d9eb593522b7426cc49eceaed8c3ab3",
    "approver": "ep:approver:jchen",
    "initiator": "ent_agent_7",
    "issued_at": "2026-06-09T17:21:05.000Z",
    "expires_at": "2026-06-09T17:26:05.000Z"
  },
  "webauthn": {
    "authenticator_data": "4OsNEivxwEn2vZAs6g8sWNWPuNWuq1bZWRCDs968rCUFAAAACQ",
    "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieC1mOFFuZFB3eXlQaDlWYVNaV0pUOXNPdkZlWmltdG9fS09HMENMUFJuTSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LmVtaWxpYXByb3RvY29sLmFpIn0",
    "signature": "MEUCIQDen5rBjE1qpx9g4Ri3dipEoqRRWGU1NCyumrS2N2ZIDAIgJLf-V7dIbjw1Ftv3p599RnnxyIkbgjvDrj9H9uFMpEg"
  },
  "approver_public_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE090Pk6OBacRwVlNvQ2_CHj8ZCGnJqE1SA63TeO2ffh1p7rEETNg03yLh5CjjWfPRaWke1wjqL5FsYTCX57T0dg",
  "rp_id": "emiliaprotocol.ai"
};

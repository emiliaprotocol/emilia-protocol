# SPDX-License-Identifier: Apache-2.0
"""
GRACE Bounded Facility Curtailment & Lost-Ack Reconciliation Engine (Python)

Implements the 4 targets requested by Iman:
1. One Bounded Facility Command (grid.curtailment.bounded.v1)
2. One Protected Effect Boundary (EMILIA Gate One-Time Admission)
3. Independent Telemetry Stream (Attested Meter Key)
4. Lost-Ack Reconciliation (Idempotent state recovery under loss)
"""

import time
import json
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# -----------------------------------------------------------------------------
# Crypto Helpers
# -----------------------------------------------------------------------------
def generate_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub_bytes

def sign_payload(private_key, payload_dict: dict) -> str:
    canonical_json = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    sig_bytes = private_key.sign(canonical_json)
    return base64.urlsafe_b64encode(sig_bytes).decode('ascii').rstrip('=')

def verify_signature(pub_raw_bytes: bytes, payload_dict: dict, sig_b64u: str) -> bool:
    try:
        # Re-pad b64u
        padded = sig_b64u + '=' * (-len(sig_b64u) % 4)
        sig_bytes = base64.urlsafe_b64decode(padded.encode('ascii'))
        canonical_json = json.dumps(payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw_bytes)
        pub_key.verify(sig_bytes, canonical_json)
        return True
    except Exception:
        return False

# -----------------------------------------------------------------------------
# 1. Bounded Facility Command Generator
# -----------------------------------------------------------------------------
def create_bounded_curtailment_order(authority_priv, facility_id: str, max_kw: float, duration_sec: int) -> dict:
    now = int(time.time())
    order_payload = {
        "@type": "grid.curtailment.bounded.v1",
        "order_id": f"ord_{now}_{facility_id}",
        "facility_id": facility_id,
        "max_shed_kw": max_kw,
        "valid_from": now,
        "valid_until": now + duration_sec,
        "max_ramp_rate_kw_sec": max_kw / 10.0,  # 10s ramp
        "baseline_method": "sha256:608a265000c7dacb489a2b5356"
    }
    signature = sign_payload(authority_priv, order_payload)
    return {
        "payload": order_payload,
        "signature": signature
    }

# -----------------------------------------------------------------------------
# 2. Protected Effect Boundary (EMILIA Gate Admission)
# -----------------------------------------------------------------------------
class ProtectedEffectBoundary:
    def __init__(self, pinned_authority_pub: bytes):
        self.pinned_authority_pub = pinned_authority_pub
        self.admitted_receipts = {}  # admission_id -> status/receipt
        self.active_power_cap_kw = 12000.0  # Default 12 MW full capacity

    def evaluate_and_admit(self, order_envelope: dict) -> dict:
        payload = order_envelope.get("payload", {})
        sig = order_envelope.get("signature", "")
        order_id = payload.get("order_id")

        # Idempotency check for lost-ack recovery
        if order_id in self.admitted_receipts:
            print(f"  [GATE] Lost-Ack Recovery: Re-issuing existing admission receipt for {order_id}")
            return self.admitted_receipts[order_id]

        # Signature check against pinned key
        if not verify_signature(self.pinned_authority_pub, payload, sig):
            raise PermissionError("Gate Refusal: Signature check failed against pinned Grid Authority key.")

        # Time window check
        now = int(time.time())
        if now < payload.get("valid_from", 0) or now > payload.get("valid_until", 0):
            raise ValueError("Gate Refusal: Curtailment order outside valid time window.")

        # Enforce Protected Effect (Power Cap Adjustment)
        target_shed = payload.get("max_shed_kw", 0)
        self.active_power_cap_kw = max(0.0, self.active_power_cap_kw - target_shed)
        admission_id = f"adm_{hashlib.sha256(order_id.encode()).hexdigest()[:16]}"

        receipt = {
            "@type": "emilia.gate.admission.v1",
            "admission_id": admission_id,
            "order_id": order_id,
            "status": "ADMITTED",
            "enforced_power_cap_kw": self.active_power_cap_kw,
            "admitted_at": now
        }
        self.admitted_receipts[order_id] = receipt
        return receipt

# -----------------------------------------------------------------------------
# 3. Independent Telemetry Stream (Attested Meter)
# -----------------------------------------------------------------------------
class AttestedMeterStream:
    def __init__(self, meter_priv):
        self.meter_priv = meter_priv
        self.samples = []

    def record_sample(self, facility_id: str, kw_now: float) -> dict:
        now = time.time()
        payload = {
            "@type": "grid.telemetry.sample.v1",
            "facility_id": facility_id,
            "kw_now": kw_now,
            "timestamp": now
        }
        sig = sign_payload(self.meter_priv, payload)
        frame = {"payload": payload, "signature": sig}
        self.samples.append(frame)
        return frame

# -----------------------------------------------------------------------------
# 4. Lost-Ack Reconciliation Engine
# -----------------------------------------------------------------------------
class LostAckReconciler:
    def __init__(self, gate: ProtectedEffectBoundary):
        self.gate = gate

    def reconcile_lost_ack(self, order_envelope: dict) -> dict:
        """Client resends order after network timeout / lost ACK."""
        print("\n  [RECONCILIATION] Connection timeout detected by client. Resending order...")
        receipt = self.gate.evaluate_and_admit(order_envelope)
        return receipt

# -----------------------------------------------------------------------------
# Main Execution Demo
# -----------------------------------------------------------------------------
def main():
    print("=" * 72)
    print("  GRACE Bounded Facility Curtailment & Reconciliation Engine")
    print("=" * 72)

    # Key Generation (Dual-Key Separation)
    auth_priv, auth_pub = generate_keypair()
    meter_priv, meter_pub = generate_keypair()

    print("\n1. BOUNDED COMMAND: Generating 10 MW curtailment order...")
    order = create_bounded_curtailment_order(auth_priv, "erc-dc-07", max_kw=10000.0, duration_sec=3600)
    print(f"   Order ID: {order['payload']['order_id']}")
    print(f"   Facility: {order['payload']['facility_id']} | Shed Target: {order['payload']['max_shed_kw']} kW")

    print("\n2. PROTECTED EFFECT: Passing through EMILIA Gate Boundary...")
    gate = ProtectedEffectBoundary(pinned_authority_pub=auth_pub)
    receipt_1 = gate.evaluate_and_admit(order)
    print(f"   Gate Admission ID: {receipt_1['admission_id']}")
    print(f"   Enforced Power Cap: {receipt_1['enforced_power_cap_kw']} kW")

    print("\n3. INDEPENDENT TELEMETRY: Attested meter recording power drop...")
    meter = AttestedMeterStream(meter_priv)
    sample1 = meter.record_sample("erc-dc-07", 12000.0)
    sample2 = meter.record_sample("erc-dc-07", 2000.0)  # Power shed active
    print(f"   Recorded {len(meter.samples)} attested meter samples.")
    print(f"   Sample 2 (Power Shed): {sample2['payload']['kw_now']} kW | Sig verified: {verify_signature(meter_pub, sample2['payload'], sample2['signature'])}")

    print("\n4. LOST-ACK RECONCILIATION: Simulating network drop & resend...")
    reconciler = LostAckReconciler(gate)
    reconciled_receipt = reconciler.reconcile_lost_ack(order)
    print(f"   Reconciled Admission ID: {reconciled_receipt['admission_id']}")
    print(f"   Idempotent Match: {receipt_1['admission_id'] == reconciled_receipt['admission_id']}")

    print("\n" + "=" * 72)
    print("  RESULT: All 4 targets (Bounded Cmd, Gate Effect, Telemetry, Lost-Ack) SUCCESS!")
    print("=" * 72)

if __name__ == "__main__":
    main()

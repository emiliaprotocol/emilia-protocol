"""
EMILIA Protocol Python Client

Portable trust evaluation and appeals for counterparties, software, and machine actors.
"""

import requests


class EmiliaClient:
    """EP client for trust profiles, policy evaluation, install preflight, disputes, and appeals."""

    def __init__(self, base_url="https://emiliaprotocol.ai", api_key=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _get(self, path):
        r = requests.get(f"{self.base_url}{path}", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def _post(self, path, body):
        r = requests.post(f"{self.base_url}{path}", json=body, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def get_trust_profile(self, entity_id):
        """Full trust profile — the canonical read surface."""
        return self._get(f"/api/trust/profile/{entity_id}")

    def evaluate_trust(self, entity_id, policy="standard", context=None):
        """Evaluate against a trust policy with optional context. Returns pass/fail with reasons."""
        return self._post("/api/trust/evaluate", {
            "entity_id": entity_id,
            "policy": policy,
            "context": context,
        })

    def install_preflight(self, entity_id, policy="standard", context=None):
        """EP-SX: Should I install this plugin/app/package? Returns allow/review/deny."""
        return self._post("/api/trust/install-preflight", {
            "entity_id": entity_id,
            "policy": policy,
            "context": context,
        })

    def submit_receipt(self, entity_id, transaction_ref, transaction_type,
                       agent_behavior=None, context=None, provenance_tier="self_attested",
                       request_bilateral=False, **signals):
        """Submit a transaction receipt. Idempotent on transaction_ref."""
        body = {
            "entity_id": entity_id,
            "transaction_ref": transaction_ref,
            "transaction_type": transaction_type,
            "agent_behavior": agent_behavior,
            "context": context,
            "provenance_tier": provenance_tier,
            "request_bilateral": request_bilateral,
        }
        body.update(signals)
        return self._post("/api/receipts/submit", body)

    def file_dispute(self, receipt_id, reason, description, evidence=None):
        """File a formal dispute against a receipt."""
        return self._post("/api/disputes/file", {
            "receipt_id": receipt_id,
            "reason": reason,
            "description": description,
            "evidence": evidence,
        })

    def report_trust_issue(self, entity_id, report_type, description, contact_email=None):
        """Report a trust issue — no auth required. Human appeal channel."""
        return self._post("/api/disputes/report", {
            "entity_id": entity_id,
            "report_type": report_type,
            "description": description,
            "contact_email": contact_email,
        })

    def get_score(self, entity_id):
        """Legacy: compatibility score only. Use get_trust_profile() instead."""
        return self._get(f"/api/score/{entity_id}")

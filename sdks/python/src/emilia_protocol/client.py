"""Synchronous, zero-dependency client for the supported EMILIA API surface."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any, Callable, Dict, List, Mapping, Optional, Union
from urllib.parse import quote, urlsplit

from ._version import __version__
from .types import (
    AttestExecutionParams,
    ConsumeTrustReceiptParams,
    ConsumeTrustReceiptResult,
    CreateTrustReceiptParams,
    ExecutionAttestation,
    GateParams,
    GateResult,
    Handshake,
    InitiateHandshakeParams,
    MutationObservationContext,
    Party,
    Presentation,
    PresentParams,
    ReceiptContext,
    RequestSignoffParams,
    RequireReceiptParams,
    RequireReceiptResult,
    RevokeResult,
    SignoffRequest,
    SignoffRequiredContext,
    TrustReceipt,
    TrustReceiptState,
    VerificationResult,
)


DEFAULT_BASE_URL = "https://emiliaprotocol.ai"
_RECEIPT_ID = re.compile(r"^tr_[a-f0-9]{32}$")
_ACTION_HASH = re.compile(r"^sha256:[a-f0-9]{64}$")


class EPError(Exception):
    """An HTTP, transport, configuration, or response-contract failure."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def _normalize_base_url(base_url: str, allow_insecure_http: bool) -> str:
    """Validate the caller-selected authority boundary for API credentials."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty absolute URL")

    candidate = base_url.strip().rstrip("/")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in candidate):
        raise ValueError("base_url must not contain control characters")

    parsed = urlsplit(candidate)
    if parsed.scheme not in ("https", "http") or not parsed.netloc or not parsed.hostname:
        raise ValueError("base_url must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query string or fragment")

    if parsed.scheme == "http" and not allow_insecure_http:
        hostname = parsed.hostname.rstrip(".").lower()
        is_loopback = hostname == "localhost" or hostname.endswith(".localhost")
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError(
                "cleartext remote base_url refused; use HTTPS or set "
                "allow_insecure_http=True explicitly"
            )

    return candidate


def _problem_code(payload: Mapping[str, Any]) -> Optional[str]:
    code = payload.get("code")
    if isinstance(code, str) and code:
        return code
    problem_type = payload.get("type")
    if isinstance(problem_type, str) and problem_type:
        return problem_type.rstrip("/").rsplit("/", 1)[-1] or None
    return None


def _problem_message(payload: Mapping[str, Any], status: int) -> str:
    for key in ("detail", "error", "title"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return "EP API error: {0}".format(status)


def _object_response(data: Any, operation: str) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise EPError(
            "{0} returned a non-object JSON response".format(operation),
            code="invalid_response",
        )
    return data


class EPClient:
    """Blocking client for handshakes, trust gate, and v1 receipt enforcement.

    The client uses only the Python standard library. Requests that can mutate
    server state are never retried automatically. ``retries`` applies only to
    GET requests, because replaying a failed POST can duplicate state.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 10,
        retries: int = 2,
        allow_insecure_http: bool = False,
    ) -> None:
        selected_url = base_url or os.environ.get("EP_BASE_URL") or DEFAULT_BASE_URL
        self._base_url = _normalize_base_url(selected_url, allow_insecure_http)
        self._api_key = api_key if api_key is not None else os.environ.get("EP_API_KEY", "")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if retries < 0:
            raise ValueError("retries must be non-negative")
        self._timeout = timeout
        self._retries = retries

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        auth: bool = False,
    ) -> Any:
        method = method.upper()
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an origin-relative API path")
        if auth and not self._api_key:
            raise EPError(
                "This endpoint requires an EMILIA API key",
                code="missing_api_key",
            )

        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "emilia-protocol-python/{0}".format(__version__),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = "Bearer {0}".format(self._api_key)

        data_bytes = (
            json.dumps(dict(body), separators=(",", ":"), allow_nan=False).encode("utf-8")
            if body is not None
            else None
        )
        retry_budget = self._retries if method in ("GET", "HEAD") else 0
        last_error: Optional[EPError] = None

        for _attempt in range(retry_budget + 1):
            request = urllib.request.Request(
                "{0}{1}".format(self._base_url, path),
                data=data_bytes,
                headers=headers,
                method=method,
            )
            try:
                # The constructor validates the caller-selected URL and refuses
                # cleartext remote credential transport unless explicitly enabled.
                with urllib.request.urlopen(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    request,
                    timeout=self._timeout,
                ) as response:
                    raw = response.read().decode("utf-8")
                    if not raw:
                        return {}
                    try:
                        return json.loads(raw)
                    except (json.JSONDecodeError, ValueError) as error:
                        raise EPError(
                            "EP API returned invalid JSON",
                            code="invalid_response",
                        ) from error
            except urllib.error.HTTPError as error:
                try:
                    raw_body = (
                        error.read().decode("utf-8", errors="replace")
                        if error.fp
                        else ""
                    )
                finally:
                    error.close()
                try:
                    parsed = json.loads(raw_body) if raw_body else {}
                except (json.JSONDecodeError, ValueError):
                    parsed = {}
                payload = parsed if isinstance(parsed, dict) else {}
                current = EPError(
                    _problem_message(payload, error.code),
                    status=error.code,
                    code=_problem_code(payload),
                )
                if error.code < 500 or retry_budget == 0:
                    raise current
                last_error = current
            except urllib.error.URLError as error:
                current = EPError(str(error.reason), code="network_error")
                if retry_budget == 0:
                    raise current
                last_error = current
            except EPError:
                raise
            except Exception as error:
                current = EPError(str(error), code="network_error")
                if retry_budget == 0:
                    raise current
                last_error = current

        if last_error is not None:
            raise last_error
        raise EPError("Unknown transport error", code="network_error")

    # ------------------------------------------------------------------
    # Handshake and trust gate
    # ------------------------------------------------------------------

    def initiate_handshake(
        self,
        mode: str,
        policy_id: str,
        parties: List[Union[Party, Mapping[str, str]]],
        binding: Optional[Mapping[str, Any]] = None,
        interaction_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        binding_ttl_ms: Optional[int] = None,
        idempotency_key: Optional[str] = None,
        action_type: Optional[str] = None,
        resource_ref: Optional[str] = None,
        intent_ref: Optional[str] = None,
    ) -> Handshake:
        normalized_parties: List[Party] = []
        for party in parties:
            if isinstance(party, Party):
                normalized_parties.append(party)
                continue
            entity_ref = party.get("entity_ref") or party.get("entityRef")
            role = party.get("role")
            normalized_parties.append(Party(str(entity_ref or ""), str(role or "")))
        params = InitiateHandshakeParams(
            mode=mode,
            policy_id=policy_id,
            parties=normalized_parties,
            payload=deepcopy(dict(payload)) if payload is not None else None,
            binding=deepcopy(dict(binding)) if binding is not None else None,
            interaction_id=interaction_id,
            binding_ttl_ms=binding_ttl_ms,
            idempotency_key=idempotency_key,
            action_type=action_type,
            resource_ref=resource_ref,
            intent_ref=intent_ref,
        )
        data = _object_response(
            self._request("POST", "/api/handshake", params.to_dict(), auth=True),
            "initiate_handshake",
        )
        return Handshake.from_dict(data)

    def get_handshake(self, handshake_id: str) -> Handshake:
        data = _object_response(
            self._request(
                "GET",
                "/api/handshake/{0}".format(quote(handshake_id, safe="")),
                auth=True,
            ),
            "get_handshake",
        )
        return Handshake.from_dict(data)

    def present(
        self,
        handshake_id: str,
        party_role: str,
        presentation_type: str,
        claims: Mapping[str, Any],
        issuer_ref: Optional[str] = None,
        issuer_proof: Optional[Mapping[str, Any]] = None,
        disclosure_mode: Optional[str] = None,
    ) -> Presentation:
        params = PresentParams(
            party_role=party_role,
            presentation_type=presentation_type,
            claims=deepcopy(dict(claims)),
            issuer_ref=issuer_ref,
            issuer_proof=deepcopy(dict(issuer_proof)) if issuer_proof is not None else None,
            disclosure_mode=disclosure_mode,
        )
        data = _object_response(
            self._request(
                "POST",
                "/api/handshake/{0}/present".format(quote(handshake_id, safe="")),
                params.to_dict(),
                auth=True,
            ),
            "present",
        )
        return Presentation.from_dict(data)

    def verify(self, handshake_id: str) -> VerificationResult:
        data = _object_response(
            self._request(
                "POST",
                "/api/handshake/{0}/verify".format(quote(handshake_id, safe="")),
                auth=True,
            ),
            "verify",
        )
        return VerificationResult.from_dict(data)

    def revoke_handshake(self, handshake_id: str, reason: str) -> RevokeResult:
        data = _object_response(
            self._request(
                "POST",
                "/api/handshake/{0}/revoke".format(quote(handshake_id, safe="")),
                {"reason": reason},
                auth=True,
            ),
            "revoke_handshake",
        )
        return RevokeResult.from_dict(data)

    def gate(
        self,
        entity_id: str,
        action: str,
        policy: str = "standard",
        value_usd: Optional[float] = None,
        delegation_id: Optional[str] = None,
        handshake_id: Optional[str] = None,
        resource_ref: Optional[str] = None,
        intent_ref: Optional[str] = None,
    ) -> GateResult:
        params = GateParams(
            entity_id=entity_id,
            action=action,
            policy=policy,
            value_usd=value_usd,
            delegation_id=delegation_id,
            handshake_id=handshake_id,
            resource_ref=resource_ref,
            intent_ref=intent_ref,
        )
        data = _object_response(
            self._request("POST", "/api/trust/gate", params.to_dict(), auth=True),
            "gate",
        )
        return GateResult.from_dict(data)

    # ------------------------------------------------------------------
    # v1 trust-receipt lifecycle
    # ------------------------------------------------------------------

    def create_trust_receipt(self, params: CreateTrustReceiptParams) -> TrustReceipt:
        data = _object_response(
            self._request(
                "POST",
                "/api/v1/trust-receipts",
                params.to_dict(),
                auth=True,
            ),
            "create_trust_receipt",
        )
        return TrustReceipt.from_dict(data)

    def get_trust_receipt(self, receipt_id: str) -> TrustReceiptState:
        data = _object_response(
            self._request(
                "GET",
                "/api/v1/trust-receipts/{0}".format(quote(receipt_id, safe="")),
                auth=True,
            ),
            "get_trust_receipt",
        )
        return TrustReceiptState.from_dict(data)

    def request_signoff(self, params: RequestSignoffParams) -> SignoffRequest:
        data = _object_response(
            self._request(
                "POST",
                "/api/v1/signoffs/request",
                params.to_dict(),
                auth=True,
            ),
            "request_signoff",
        )
        return SignoffRequest.from_dict(data)

    def consume_trust_receipt(
        self,
        receipt_id: str,
        params: ConsumeTrustReceiptParams,
    ) -> ConsumeTrustReceiptResult:
        data = _object_response(
            self._request(
                "POST",
                "/api/v1/trust-receipts/{0}/consume".format(
                    quote(receipt_id, safe="")
                ),
                params.to_dict(),
                auth=True,
            ),
            "consume_trust_receipt",
        )
        return ConsumeTrustReceiptResult.from_dict(data)

    def attest_execution(
        self,
        receipt_id: str,
        params: AttestExecutionParams,
    ) -> ExecutionAttestation:
        data = _object_response(
            self._request(
                "POST",
                "/api/v1/trust-receipts/{0}/execution".format(
                    quote(receipt_id, safe="")
                ),
                params.to_dict(),
                auth=True,
            ),
            "attest_execution",
        )
        return ExecutionAttestation.from_dict(data)

    def get_trust_receipt_evidence(self, receipt_id: str) -> Dict[str, Any]:
        return _object_response(
            self._request(
                "GET",
                "/api/v1/trust-receipts/{0}/evidence".format(
                    quote(receipt_id, safe="")
                ),
                auth=True,
            ),
            "get_trust_receipt_evidence",
        )

    @staticmethod
    def _validate_created_receipt(
        receipt: TrustReceipt,
        has_quorum_policy: bool = False,
    ) -> None:
        if not _RECEIPT_ID.fullmatch(receipt.receipt_id):
            raise EPError(
                "Receipt creation returned a missing or malformed receipt_id",
                code="invalid_receipt_response",
            )
        if not _ACTION_HASH.fullmatch(receipt.action_hash):
            raise EPError(
                "Receipt creation returned a missing or malformed action_hash",
                code="invalid_receipt_response",
            )
        if not receipt.canonical_action:
            raise EPError(
                "Receipt creation returned no canonical action",
                code="invalid_receipt_response",
            )
        if receipt.enforcement_mode != "enforce":
            raise EPError(
                "Only enforce-mode receipts can authorize require_receipt",
                status=409,
                code="receipt_not_authority",
            )
        if receipt.evidence_status != "durable":
            raise EPError(
                "Enforce-mode receipt evidence was not confirmed durable",
                status=503,
                code="evidence_not_durable",
            )
        if receipt.decision == "deny" or receipt.receipt_status == "denied":
            raise EPError(
                "EMILIA denied the action before execution",
                status=403,
                code="receipt_denied",
            )
        if receipt.signoff_required:
            valid = receipt.receipt_status == "pending_signoff" and receipt.decision in (
                "allow",
                "allow_with_signoff",
            )
        elif has_quorum_policy:
            # A caller-selected quorum is stored as an independent consume
            # condition. The creation response can remain an issued/allow
            # receipt even though the quorum ceremony is still required.
            valid = receipt.receipt_status == "issued" and receipt.decision == "allow"
        else:
            valid = receipt.receipt_status == "issued" and receipt.decision == "allow"
        if not valid:
            raise EPError(
                "Receipt creation returned a non-consumable state",
                status=409,
                code="receipt_not_consumable",
            )

    @staticmethod
    def _validate_consumption(
        receipt: TrustReceipt,
        consume: ConsumeTrustReceiptResult,
    ) -> None:
        if consume.receipt_id != receipt.receipt_id or consume.status != "consumed":
            raise EPError(
                "Receipt consumption was not confirmed",
                code="invalid_consume_response",
            )

    def require_receipt(
        self,
        params: RequireReceiptParams,
        mutate: Callable[[ReceiptContext], Any],
    ) -> RequireReceiptResult[Any]:
        """Run a mutation only after durable, one-time receipt consumption.

        A signoff callback can wait for an external human ceremony, but its
        return value is not authority. The server's consume endpoint remains the
        authoritative gate. After mutation, no execution evidence is emitted
        unless the caller supplies an independently observed action.
        """
        if not callable(mutate):
            raise TypeError("mutate must be callable")
        if params.enforcement_mode != "enforce":
            raise EPError(
                "require_receipt supports enforce mode only",
                code="enforce_mode_required",
            )

        receipt = self.create_trust_receipt(params.to_create_params())
        has_quorum_policy = params.quorum_policy is not None
        self._validate_created_receipt(receipt, has_quorum_policy)
        approved_action = deepcopy(receipt.canonical_action)

        signoff: Optional[SignoffRequest] = None
        if receipt.signoff_required or has_quorum_policy:
            if not has_quorum_policy and not params.approver_id:
                raise EPError(
                    "Receipt requires signoff; pass approver_id",
                    status=409,
                    code="missing_approver_id",
                )
            signoff = self.request_signoff(
                RequestSignoffParams(
                    receipt_id=receipt.receipt_id,
                    approver_id=params.approver_id,
                    expires_in_minutes=params.signoff_expires_in_minutes,
                    comment=params.signoff_comment,
                )
            )
            if (
                signoff.receipt_id != receipt.receipt_id
                or signoff.status != "pending"
            ):
                raise EPError(
                    "Signoff request was not confirmed",
                    code="invalid_signoff_response",
                )
            if has_quorum_policy:
                valid_signoffs = bool(signoff.signoffs) and all(
                    isinstance(item, Mapping) and bool(item.get("signoff_id"))
                    for item in signoff.signoffs
                )
                if not valid_signoffs or not signoff.quorum:
                    raise EPError(
                        "Quorum signoff requests were not confirmed",
                        code="invalid_signoff_response",
                    )
            elif not signoff.signoff_id:
                raise EPError(
                    "Signoff request was not confirmed",
                    code="invalid_signoff_response",
                )
            if params.on_signoff_required is None:
                raise EPError(
                    "Receipt requires external human signoff before execution",
                    status=409,
                    code="signoff_required",
                )
            callback_result = params.on_signoff_required(
                SignoffRequiredContext(deepcopy(receipt), deepcopy(signoff))
            )
            callback_rejected = callback_result is False or (
                isinstance(callback_result, Mapping)
                and callback_result.get("approved") is False
            )
            if callback_rejected:
                raise EPError(
                    "Human signoff was not approved",
                    status=403,
                    code="signoff_rejected",
                )

        consume = self.consume_trust_receipt(
            receipt.receipt_id,
            ConsumeTrustReceiptParams(
                action_hash=receipt.action_hash,
                executing_system=params.executing_system,
                execution_reference_id=params.execution_reference_id,
            ),
        )
        self._validate_consumption(receipt, consume)

        result = mutate(
            ReceiptContext(
                receipt=deepcopy(receipt),
                consume=deepcopy(consume),
                canonical_action=deepcopy(approved_action),
            )
        )

        lifecycle = RequireReceiptResult(
            result=result,
            receipt=receipt,
            signoff=signoff,
            consume=consume,
        )

        if params.observed_action is not None:
            try:
                observation = (
                    params.observed_action(
                        MutationObservationContext(
                            receipt=deepcopy(receipt),
                            consume=deepcopy(consume),
                            canonical_action=deepcopy(approved_action),
                            result=result,
                        )
                    )
                    if callable(params.observed_action)
                    else params.observed_action
                )
                if not isinstance(observation, Mapping) or not observation:
                    raise EPError(
                        "observed_action must be a non-empty mapping",
                        code="invalid_observed_action",
                    )
                execution_id = (
                    params.execution_id(result)
                    if callable(params.execution_id)
                    else params.execution_id
                )
                execution = self.attest_execution(
                    receipt.receipt_id,
                    AttestExecutionParams(
                        executed_action=deepcopy(approved_action),
                        observed_action=deepcopy(dict(observation)),
                        executing_system=params.executing_system,
                        execution_id=execution_id,
                    ),
                )
                if (
                    execution.receipt_id != receipt.receipt_id
                    or execution.status != "executed"
                    or execution.binding_status != "match"
                ):
                    raise EPError(
                        "Execution attestation was not confirmed as an exact match",
                        code="invalid_execution_response",
                    )
                lifecycle.execution = execution
                lifecycle.execution_status = "attested"
            except Exception as error:  # post-mutation: report uncertainty, never invite replay
                lifecycle.execution_status = "indeterminate"
                lifecycle.execution_error = str(error)
                lifecycle.do_not_retry = True
        else:
            lifecycle.execution_status = "unobserved"
            lifecycle.do_not_retry = True

        if params.fetch_evidence:
            try:
                lifecycle.evidence = self.get_trust_receipt_evidence(receipt.receipt_id)
            except Exception as error:  # execution may already have happened
                lifecycle.evidence_error = str(error)
                lifecycle.do_not_retry = True

        return lifecycle

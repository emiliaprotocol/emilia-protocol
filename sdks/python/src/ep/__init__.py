"""EMILIA Protocol — Full Python SDK.

Covers all protocol endpoints (handshake, signoff, delegation, commit)
and cloud endpoints (dashboards, analytics, audit, policy management).
Zero dependencies -- uses urllib.request (stdlib).

    from ep import EPClient

    client = EPClient(base_url="https://emiliaprotocol.ai", api_key="ep_live_...")
    policies = client.list_policies()

    # Cloud endpoints
    pending = client.cloud.get_pending_signoffs()
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote, urlencode

from .types import (
    # Core params
    AttestParams,
    Consumption,
    ConsumeParams,
    ConsumeSignoffParams,
    CreateDelegationParams,
    ExportAuditParams,
    GateParams,
    GateResult,
    Handshake,
    InitiateHandshakeParams,
    IssueChallengeParams,
    IssueCommitParams,
    Policy,
    Presentation,
    PresentParams,
    SignoffAttestation,
    SignoffChallenge,
    SignoffConsumption,
    VerificationResult,
    # New protocol responses
    RevokeResult,
    DenyResult,
    Delegation,
    DelegationVerification,
    Commit,
    CommitVerification,
    # Cloud responses
    PendingSignoffsResponse,
    SignoffQueueResponse,
    SignoffDashboard,
    SignoffAnalytics,
    EscalationResult,
    NotificationResult,
    SearchEventsResponse,
    EventTimeline,
    ExportAuditResult,
    AuditReport,
    IntegrityCheckResult,
    PolicySimulationResult,
    PolicyRolloutResult,
    PolicyVersion,
    PolicyDiff,
    # Cloud sub-types (re-export)
    Party,
    PendingSignoff,
    SignoffQueueItem,
    DashboardActivity,
    AnalyticsDataPoint,
    AuditEvent,
    IntegrityCheck,
    PolicyChange,
    # Eye types
    RecordObservationParams,
    CheckActionParams,
    CreateSuppressionParams,
    ObservationResponse,
    AdvisoryResponse,
    SuppressionResponse,
)

__all__ = [
    "EPClient",
    "EPCloudClient",
    "EPError",
    # Core response types
    "Policy",
    "Handshake",
    "Presentation",
    "VerificationResult",
    "GateResult",
    "SignoffChallenge",
    "SignoffAttestation",
    "SignoffConsumption",
    "Consumption",
    "RevokeResult",
    "DenyResult",
    "Delegation",
    "DelegationVerification",
    "Commit",
    "CommitVerification",
    # Cloud response types
    "PendingSignoff",
    "PendingSignoffsResponse",
    "SignoffQueueItem",
    "SignoffQueueResponse",
    "DashboardActivity",
    "SignoffDashboard",
    "AnalyticsDataPoint",
    "SignoffAnalytics",
    "EscalationResult",
    "NotificationResult",
    "AuditEvent",
    "SearchEventsResponse",
    "EventTimeline",
    "ExportAuditResult",
    "AuditReport",
    "IntegrityCheck",
    "IntegrityCheckResult",
    "PolicySimulationResult",
    "PolicyRolloutResult",
    "PolicyVersion",
    "PolicyChange",
    "PolicyDiff",
    # Param types
    "Party",
    "InitiateHandshakeParams",
    "PresentParams",
    "GateParams",
    "IssueChallengeParams",
    "AttestParams",
    "ConsumeSignoffParams",
    "ConsumeParams",
    "CreateDelegationParams",
    "IssueCommitParams",
    "ExportAuditParams",
    # Eye types
    "RecordObservationParams",
    "CheckActionParams",
    "CreateSuppressionParams",
    "ObservationResponse",
    "AdvisoryResponse",
    "SuppressionResponse",
]

__version__ = "0.9.0"


class EPError(Exception):
    """Raised when the EP API returns a non-2xx response or a network error occurs."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code


# ---------------------------------------------------------------------------
# Cloud Client
# ---------------------------------------------------------------------------


class EPCloudClient:
    """Sub-client for EMILIA Protocol Cloud endpoints.

    Access via ``client.cloud``. Provides dashboards, analytics, audit,
    and policy management methods.
    """

    def __init__(self, request_fn: Callable[..., Any]):
        self._request = request_fn

    # -- Signoff management -------------------------------------------------

    def get_pending_signoffs(
        self,
        entity_id: Optional[str] = None,
        scope: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> PendingSignoffsResponse:
        """Get pending signoffs, optionally filtered by entity, scope, or status."""
        qs = self._build_signoff_qs(entity_id, scope, status, limit, offset)
        data = self._request("GET", f"/api/cloud/signoffs/pending{qs}", auth=True)
        return PendingSignoffsResponse.from_dict(data)

    def get_signoff_queue(
        self,
        entity_id: Optional[str] = None,
        scope: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> SignoffQueueResponse:
        """Get the signoff queue with optional filtering."""
        qs = self._build_signoff_qs(entity_id, scope, status, limit, offset)
        data = self._request("GET", f"/api/cloud/signoffs/queue{qs}", auth=True)
        return SignoffQueueResponse.from_dict(data)

    def get_signoff_dashboard(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> SignoffDashboard:
        """Get a dashboard summary of signoff activity over a date range."""
        qs = self._build_date_qs(date_from, date_to)
        data = self._request("GET", f"/api/cloud/signoffs/dashboard{qs}", auth=True)
        return SignoffDashboard.from_dict(data)

    def get_signoff_analytics(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        granularity: Optional[str] = None,
    ) -> SignoffAnalytics:
        """Get analytics for signoff activity with optional granularity.

        Args:
            date_from: ISO date string for range start.
            date_to: ISO date string for range end.
            granularity: One of 'hour', 'day', 'week', 'month'.
        """
        params: Dict[str, str] = {}
        if date_from:
            params["from"] = date_from
        if date_to:
            params["to"] = date_to
        if granularity:
            params["granularity"] = granularity
        qs = f"?{urlencode(params)}" if params else ""
        data = self._request("GET", f"/api/cloud/signoffs/analytics{qs}", auth=True)
        return SignoffAnalytics.from_dict(data)

    def escalate_signoff(
        self,
        challenge_id: str,
        escalate_to: str,
        reason: str,
    ) -> EscalationResult:
        """Escalate a signoff challenge to another entity.

        Args:
            challenge_id: The challenge to escalate.
            escalate_to: Entity ID to escalate to.
            reason: Reason for escalation.
        """
        data = self._request(
            "POST",
            f"/api/cloud/signoffs/{quote(challenge_id, safe='')}/escalate",
            body={"escalateTo": escalate_to, "reason": reason},
            auth=True,
        )
        return EscalationResult.from_dict(data)

    def notify_signoff(self, challenge_id: str, channel: str) -> NotificationResult:
        """Send a notification about a signoff challenge via the specified channel.

        Args:
            challenge_id: The challenge to notify about.
            channel: Notification channel (e.g. 'email', 'slack', 'webhook').
        """
        data = self._request(
            "POST",
            f"/api/cloud/signoffs/{quote(challenge_id, safe='')}/notify",
            body={"channel": channel},
            auth=True,
        )
        return NotificationResult.from_dict(data)

    # -- Events & audit -----------------------------------------------------

    def search_events(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> SearchEventsResponse:
        """Search audit events by query string and optional filters.

        Args:
            query: Free-text search query.
            filters: Optional dict of filter criteria.
        """
        body: Dict[str, Any] = {"query": query}
        if filters is not None:
            body["filters"] = filters
        data = self._request("POST", "/api/cloud/events/search", body=body, auth=True)
        return SearchEventsResponse.from_dict(data)

    def get_event_timeline(self, handshake_id: str) -> EventTimeline:
        """Get a chronological timeline of events for a specific handshake.

        Args:
            handshake_id: The handshake to retrieve events for.
        """
        data = self._request(
            "GET",
            f"/api/cloud/events/timeline/{quote(handshake_id, safe='')}",
            auth=True,
        )
        return EventTimeline.from_dict(data)

    def export_audit(self, params: ExportAuditParams) -> ExportAuditResult:
        """Export audit data in the specified format.

        Args:
            params: Export parameters including format, date range, and filters.
        """
        data = self._request("POST", "/api/cloud/audit/export", body=params.to_dict(), auth=True)
        return ExportAuditResult.from_dict(data)

    def get_audit_report(
        self,
        report_type: str,
        date_from: str,
        date_to: str,
    ) -> AuditReport:
        """Generate an audit report for the given type and date range.

        Args:
            report_type: Type of report (e.g. 'compliance', 'activity').
            date_from: ISO date string for range start.
            date_to: ISO date string for range end.
        """
        data = self._request(
            "POST",
            "/api/cloud/audit/report",
            body={
                "reportType": report_type,
                "dateRange": {"from": date_from, "to": date_to},
            },
            auth=True,
        )
        return AuditReport.from_dict(data)

    # -- Integrity ----------------------------------------------------------

    def check_integrity(self) -> IntegrityCheckResult:
        """Run an integrity check on the protocol data store."""
        data = self._request("POST", "/api/cloud/integrity/check", auth=True)
        return IntegrityCheckResult.from_dict(data)

    # -- Policy management --------------------------------------------------

    def simulate_policy(
        self,
        policy_id: str,
        context: Dict[str, Any],
    ) -> PolicySimulationResult:
        """Simulate a policy against a hypothetical context without persisting state.

        Args:
            policy_id: The policy to simulate.
            context: Hypothetical context to evaluate against.
        """
        data = self._request(
            "POST",
            f"/api/cloud/policies/{quote(policy_id, safe='')}/simulate",
            body={"context": context},
            auth=True,
        )
        return PolicySimulationResult.from_dict(data)

    def rollout_policy(
        self,
        policy_id: str,
        strategy: str,
        percentage: Optional[float] = None,
    ) -> PolicyRolloutResult:
        """Begin a rollout of a policy using the specified strategy.

        Args:
            policy_id: The policy to roll out.
            strategy: Rollout strategy ('canary', 'blue-green', 'linear').
            percentage: Optional rollout percentage (0-100).
        """
        body: Dict[str, Any] = {"strategy": strategy}
        if percentage is not None:
            body["percentage"] = percentage
        data = self._request(
            "POST",
            f"/api/cloud/policies/{quote(policy_id, safe='')}/rollout",
            body=body,
            auth=True,
        )
        return PolicyRolloutResult.from_dict(data)

    def get_policy_versions(self, policy_id: str) -> List[PolicyVersion]:
        """List all versions of a policy.

        Args:
            policy_id: The policy to retrieve versions for.
        """
        data = self._request(
            "GET",
            f"/api/cloud/policies/{quote(policy_id, safe='')}/versions",
            auth=True,
        )
        if isinstance(data, list):
            return [PolicyVersion.from_dict(v) for v in data]
        return [PolicyVersion.from_dict(v) for v in data.get("versions", [])]

    def diff_policy_versions(
        self,
        policy_id: str,
        version_a: str,
        version_b: str,
    ) -> PolicyDiff:
        """Diff two versions of a policy to see what changed.

        Args:
            policy_id: The policy to diff.
            version_a: First version identifier.
            version_b: Second version identifier.
        """
        data = self._request(
            "POST",
            f"/api/cloud/policies/{quote(policy_id, safe='')}/diff",
            body={"versionA": version_a, "versionB": version_b},
            auth=True,
        )
        return PolicyDiff.from_dict(data)

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _build_signoff_qs(
        entity_id: Optional[str],
        scope: Optional[str],
        status: Optional[str],
        limit: Optional[int],
        offset: Optional[int],
    ) -> str:
        params: Dict[str, str] = {}
        if entity_id:
            params["entityId"] = entity_id
        if scope:
            params["scope"] = scope
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        return f"?{urlencode(params)}" if params else ""

    @staticmethod
    def _build_date_qs(date_from: Optional[str], date_to: Optional[str]) -> str:
        params: Dict[str, str] = {}
        if date_from:
            params["from"] = date_from
        if date_to:
            params["to"] = date_to
        return f"?{urlencode(params)}" if params else ""


# ---------------------------------------------------------------------------
# Main Client
# ---------------------------------------------------------------------------


class EPClient:
    """Full client for the EMILIA Protocol API.

    Covers core protocol endpoints (listPolicies, initiateHandshake, present,
    verify, gate, getHandshake, revokeHandshake, consume), the signoff
    extension (issueChallenge, attest, denyChallenge, revokeSignoff,
    consumeSignoff), delegation (createDelegation, verifyDelegation),
    and commit (issueCommit, verifyCommit).

    Cloud endpoints are available via ``client.cloud``.

    Zero dependencies -- uses urllib.request (stdlib).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: int = 10,
        retries: int = 2,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key or ""
        self._timeout = timeout
        self._retries = retries
        self.cloud = EPCloudClient(self._request)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        auth: bool = False,
    ) -> Any:
        url = f"{self._base_url}{path}"
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"emilia-protocol-python/{__version__}",
        }
        if auth and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None

        last_err: Optional[Exception] = None
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                raw_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                try:
                    payload = json.loads(raw_body)
                except (json.JSONDecodeError, ValueError):
                    payload = {}
                msg = payload.get("error", f"EP API error: {e.code}")
                code = payload.get("code")
                err = EPError(msg, status=e.code, code=code)
                # Only retry on 5xx
                if e.code < 500:
                    raise err
                last_err = err
            except urllib.error.URLError as e:
                last_err = EPError(str(e.reason), code="network_error")
            except Exception as e:
                last_err = EPError(str(e), code="network_error")

        if last_err is not None:
            raise last_err
        raise EPError("Unknown error", code="network_error")

    # ------------------------------------------------------------------
    # Core protocol endpoints
    # ------------------------------------------------------------------

    def list_policies(self, scope: Optional[str] = None) -> List[Policy]:
        """List available trust policies.

        Args:
            scope: Optional scope filter.
        """
        qs = f"?scope={quote(scope)}" if scope else ""
        data = self._request("GET", f"/api/policies{qs}")
        if isinstance(data, list):
            return [Policy.from_dict(d) for d in data]
        return [Policy.from_dict(d) for d in data.get("policies", data) if isinstance(d, dict)]

    def initiate_handshake(
        self,
        mode: str,
        policy_id: str,
        parties: List[Dict[str, str]],
        binding: Optional[Dict[str, Any]] = None,
        interaction_id: Optional[str] = None,
    ) -> Handshake:
        """Initiate a trust handshake between parties.

        Args:
            mode: Handshake mode ('mutual', 'one-way', 'delegated').
            policy_id: Policy to evaluate against.
            parties: List of party dicts with 'entityRef' and 'role'.
            binding: Optional binding metadata.
            interaction_id: Optional interaction identifier.
        """
        params = InitiateHandshakeParams(
            mode=mode,
            policy_id=policy_id,
            parties=[
                Party(
                    entity_ref=p.get("entityRef", p.get("entity_ref", "")),
                    role=p.get("role", ""),
                )
                for p in parties
            ],
            binding=binding,
            interaction_id=interaction_id,
        )
        data = self._request("POST", "/api/handshake/initiate", params.to_dict(), auth=True)
        return Handshake.from_dict(data)

    def present(
        self,
        handshake_id: str,
        party_role: str,
        presentation_type: str,
        claims: Dict[str, Any],
        issuer_ref: Optional[str] = None,
        disclosure_mode: Optional[str] = None,
    ) -> Presentation:
        """Present credentials to a handshake.

        Args:
            handshake_id: The handshake to present to.
            party_role: Role of the presenting party.
            presentation_type: Type of presentation.
            claims: Claims data.
            issuer_ref: Optional issuer reference.
            disclosure_mode: Disclosure mode ('full', 'selective', 'zk').
        """
        params = PresentParams(
            party_role=party_role,
            presentation_type=presentation_type,
            claims=claims,
            issuer_ref=issuer_ref,
            disclosure_mode=disclosure_mode,
        )
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/present",
            params.to_dict(),
            auth=True,
        )
        return Presentation.from_dict(data)

    def verify(self, handshake_id: str) -> VerificationResult:
        """Verify a handshake -- evaluate all presentations against policy.

        Args:
            handshake_id: The handshake to verify.
        """
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/verify",
            auth=True,
        )
        return VerificationResult.from_dict(data)

    def gate(
        self,
        entity_id: str,
        action: str,
        policy: str = "standard",
        handshake_id: Optional[str] = None,
        value_usd: Optional[float] = None,
        delegation_id: Optional[str] = None,
    ) -> GateResult:
        """Pre-action trust gate. Returns allow/deny/review.

        Args:
            entity_id: Entity requesting the action.
            action: Action being requested.
            policy: Policy level ('strict', 'standard', 'permissive').
            handshake_id: Optional associated handshake.
            value_usd: Optional monetary value in USD.
            delegation_id: Optional delegation reference.
        """
        params = GateParams(
            entity_id=entity_id,
            action=action,
            policy=policy,
            handshake_id=handshake_id,
            value_usd=value_usd,
            delegation_id=delegation_id,
        )
        data = self._request("POST", "/api/gate", params.to_dict(), auth=True)
        return GateResult.from_dict(data)

    def get_handshake(self, handshake_id: str) -> Handshake:
        """Retrieve details of a specific handshake by ID.

        Args:
            handshake_id: The handshake to retrieve.
        """
        data = self._request(
            "GET",
            f"/api/handshake/{quote(handshake_id, safe='')}",
            auth=True,
        )
        return Handshake.from_dict(data)

    def revoke_handshake(self, handshake_id: str) -> RevokeResult:
        """Revoke an active handshake, invalidating all associated state.

        Args:
            handshake_id: The handshake to revoke.
        """
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/revoke",
            auth=True,
        )
        return RevokeResult.from_dict(data)

    def consume(
        self,
        handshake_id: str,
        receipt_data: Optional[Dict[str, Any]] = None,
    ) -> Consumption:
        """Consume a handshake -- finalize and optionally bind a receipt.

        Args:
            handshake_id: The handshake to consume.
            receipt_data: Optional receipt data to bind.
        """
        params = ConsumeParams(receipt_data=receipt_data)
        body = params.to_dict() or None
        data = self._request(
            "POST",
            f"/api/handshake/{quote(handshake_id, safe='')}/consume",
            body,
            auth=True,
        )
        return Consumption.from_dict(data)

    # ------------------------------------------------------------------
    # Signoff extension
    # ------------------------------------------------------------------

    def issue_challenge(
        self,
        entity_id: str,
        scope: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SignoffChallenge:
        """Issue a signoff challenge for an entity.

        Args:
            entity_id: Entity to challenge.
            scope: Scope of the challenge.
            context: Optional context metadata.
        """
        params = IssueChallengeParams(entity_id=entity_id, scope=scope, context=context)
        data = self._request("POST", "/api/signoff/challenge", params.to_dict(), auth=True)
        return SignoffChallenge.from_dict(data)

    def attest(
        self,
        challenge_id: str,
        signature: str,
        payload: Dict[str, Any],
    ) -> SignoffAttestation:
        """Attest to a signoff challenge with a cryptographic signature.

        Args:
            challenge_id: The challenge to attest to.
            signature: Cryptographic signature.
            payload: Signed payload data.
        """
        params = AttestParams(signature=signature, payload=payload)
        data = self._request(
            "POST",
            f"/api/signoff/{quote(challenge_id, safe='')}/attest",
            params.to_dict(),
            auth=True,
        )
        return SignoffAttestation.from_dict(data)

    def deny_challenge(
        self,
        challenge_id: str,
        reason: Optional[str] = None,
    ) -> DenyResult:
        """Deny a signoff challenge with an optional reason.

        Args:
            challenge_id: The challenge to deny.
            reason: Optional reason for denial.
        """
        body: Optional[Dict[str, Any]] = {"reason": reason} if reason is not None else None
        data = self._request(
            "POST",
            f"/api/signoff/{quote(challenge_id, safe='')}/deny",
            body,
            auth=True,
        )
        return DenyResult.from_dict(data)

    def revoke_signoff(
        self,
        challenge_id: str,
        reason: Optional[str] = None,
        force: bool = False,
    ) -> RevokeResult:
        """Revoke a previously granted signoff.

        Args:
            challenge_id: The challenge/signoff to revoke.
            reason: Optional reason for revocation.
            force: Force revocation even if already consumed.
        """
        body: Dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        if force:
            body["force"] = True
        data = self._request(
            "POST",
            f"/api/signoff/{quote(challenge_id, safe='')}/revoke",
            body or None,
            auth=True,
        )
        return RevokeResult.from_dict(data)

    def consume_signoff(
        self,
        signoff_id: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SignoffConsumption:
        """Consume a signoff -- mark it as used for a specific action.

        Args:
            signoff_id: The signoff to consume.
            action: Action the signoff is being consumed for.
            context: Optional context metadata.
        """
        params = ConsumeSignoffParams(action=action, context=context)
        data = self._request(
            "POST",
            f"/api/signoff/{quote(signoff_id, safe='')}/consume",
            params.to_dict(),
            auth=True,
        )
        return SignoffConsumption.from_dict(data)

    # ------------------------------------------------------------------
    # Delegation
    # ------------------------------------------------------------------

    def create_delegation(
        self,
        delegator_id: str,
        delegatee_id: str,
        scope: str,
        policy_id: str,
        constraints: Optional[Dict[str, Any]] = None,
        expires_at: Optional[str] = None,
    ) -> Delegation:
        """Create a trust delegation from one entity to another.

        Args:
            delegator_id: Entity granting delegation.
            delegatee_id: Entity receiving delegation.
            scope: Scope of the delegation.
            policy_id: Policy governing the delegation.
            constraints: Optional constraints on the delegation.
            expires_at: Optional ISO expiration timestamp.
        """
        params = CreateDelegationParams(
            delegator_id=delegator_id,
            delegatee_id=delegatee_id,
            scope=scope,
            policy_id=policy_id,
            constraints=constraints,
            expires_at=expires_at,
        )
        data = self._request("POST", "/api/delegation", params.to_dict(), auth=True)
        return Delegation.from_dict(data)

    def verify_delegation(self, delegation_id: str) -> DelegationVerification:
        """Verify the validity of an existing delegation.

        Args:
            delegation_id: The delegation to verify.
        """
        data = self._request(
            "POST",
            f"/api/delegation/{quote(delegation_id, safe='')}/verify",
            auth=True,
        )
        return DelegationVerification.from_dict(data)

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    def issue_commit(
        self,
        handshake_id: str,
        action: str,
        payload: Dict[str, Any],
        binding: Optional[Dict[str, Any]] = None,
    ) -> Commit:
        """Issue a trust commit binding a handshake to a specific action.

        Args:
            handshake_id: The handshake to commit against.
            action: Action being committed.
            payload: Commit payload data.
            binding: Optional binding metadata.
        """
        params = IssueCommitParams(
            handshake_id=handshake_id,
            action=action,
            payload=payload,
            binding=binding,
        )
        data = self._request("POST", "/api/commit", params.to_dict(), auth=True)
        return Commit.from_dict(data)

    def verify_commit(self, commit_id: str) -> CommitVerification:
        """Verify a previously issued commit.

        Args:
            commit_id: The commit to verify.
        """
        data = self._request(
            "POST",
            f"/api/commit/{quote(commit_id, safe='')}/verify",
            auth=True,
        )
        return CommitVerification.from_dict(data)

    # ------------------------------------------------------------------
    # Eye — Observation & Advisory
    # ------------------------------------------------------------------

    def record_observation(
        self,
        source_type: str,
        source_ref: str,
        subject_ref: str,
        actor_ref: str,
        action_type: str,
        observation_type: str,
        severity_hint: str,
        expires_at: str,
        target_ref: Optional[str] = None,
        issuer_ref: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ObservationResponse:
        """Record a behavioral or contextual observation for the Eye subsystem.

        Args:
            source_type: Type of the observation source.
            source_ref: Reference to the observation source.
            subject_ref: Reference to the subject being observed.
            actor_ref: Reference to the acting entity.
            action_type: Type of action observed.
            observation_type: Classification of the observation.
            severity_hint: Severity hint for the observation.
            expires_at: ISO 8601 expiration timestamp.
            target_ref: Optional target reference.
            issuer_ref: Optional issuer reference.
            evidence_hash: Optional hash of evidence data.
            metadata: Optional metadata dictionary.
        """
        params = RecordObservationParams(
            source_type=source_type,
            source_ref=source_ref,
            subject_ref=subject_ref,
            actor_ref=actor_ref,
            action_type=action_type,
            observation_type=observation_type,
            severity_hint=severity_hint,
            expires_at=expires_at,
            target_ref=target_ref,
            issuer_ref=issuer_ref,
            evidence_hash=evidence_hash,
            metadata=metadata,
        )
        data = self._request("POST", "/api/eye/observations", params.to_dict(), auth=True)
        return ObservationResponse.from_dict(data)

    def check_action(
        self,
        subject_ref: str,
        actor_ref: str,
        action_type: str,
        context_hash: str,
        target_ref: Optional[str] = None,
        issuer_ref: Optional[str] = None,
        payload_hash: Optional[str] = None,
        policy_class: Optional[str] = None,
    ) -> AdvisoryResponse:
        """Check an action against recorded observations and return an advisory.

        Args:
            subject_ref: Reference to the subject.
            actor_ref: Reference to the acting entity.
            action_type: Type of action to check.
            context_hash: Hash of the action context.
            target_ref: Optional target reference.
            issuer_ref: Optional issuer reference.
            payload_hash: Optional hash of the payload.
            policy_class: Optional policy class to evaluate against.
        """
        params = CheckActionParams(
            subject_ref=subject_ref,
            actor_ref=actor_ref,
            action_type=action_type,
            context_hash=context_hash,
            target_ref=target_ref,
            issuer_ref=issuer_ref,
            payload_hash=payload_hash,
            policy_class=policy_class,
        )
        data = self._request("POST", "/api/eye/check", params.to_dict(), auth=True)
        return AdvisoryResponse.from_dict(data)

    def get_advisory(self, advisory_id: str) -> AdvisoryResponse:
        """Retrieve an existing advisory by ID.

        Args:
            advisory_id: The advisory to retrieve.
        """
        data = self._request(
            "GET",
            f"/api/eye/advisories/{quote(advisory_id, safe='')}",
            auth=True,
        )
        return AdvisoryResponse.from_dict(data)

    def create_suppression(
        self,
        scope_binding_hash: str,
        reason_code: str,
        justification: str,
        expires_at: str,
    ) -> SuppressionResponse:
        """Create a suppression to exclude a reason code from future advisories.

        Args:
            scope_binding_hash: The scope binding hash to suppress.
            reason_code: The reason code to suppress.
            justification: Justification for the suppression.
            expires_at: ISO 8601 expiration timestamp.
        """
        params = CreateSuppressionParams(
            scope_binding_hash=scope_binding_hash,
            reason_code=reason_code,
            justification=justification,
            expires_at=expires_at,
        )
        data = self._request("POST", "/api/eye/suppressions", params.to_dict(), auth=True)
        return SuppressionResponse.from_dict(data)

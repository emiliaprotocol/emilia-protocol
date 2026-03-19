"""EMILIA Protocol — Async HTTP Client."""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from .types import (
    AgentBehavior,
    DisputeReason,
    EntityTrustProfile,
    EntityType,
    EPError,
    ReportType,
    TransactionType,
    TrustContext,
    TrustDomain,
    TrustPolicy,
)

_SDK_VERSION = "1.0.0"
_DEFAULT_BASE_URL = "https://emiliaprotocol.ai"


class EPClient:
    """Async client for the EMILIA Protocol API.

    The client is designed to be used as an async context manager so that the
    underlying connection pool is properly closed when you are done:

    .. code-block:: python

        async with EPClient(api_key="ep_live_...") as ep:
            profile = await ep.trust_profile("merchant-xyz")
            print(profile.current_confidence)

    For one-shot synchronous use in scripts, wrap with ``asyncio.run()``:

    .. code-block:: python

        import asyncio, emilia_protocol as ep

        async def main():
            async with ep.EPClient(api_key="ep_live_...") as client:
                return await client.trust_profile("merchant-xyz")

        profile = asyncio.run(main())

    Parameters
    ----------
    api_key:
        Your EP API key (``ep_live_...``).  Falls back to the ``EP_API_KEY``
        environment variable when omitted.
    base_url:
        Override the EP API base URL.  Defaults to ``https://emiliaprotocol.ai``.
    timeout:
        Per-request timeout in seconds.  Defaults to 30 s.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = 30.0,
    ) -> None:
        self.api_key: str = api_key or os.environ.get("EP_API_KEY", "")
        self.base_url: str = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers={"User-Agent": f"emilia-protocol-python/{_SDK_VERSION}"},
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "EPClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal request helper
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        auth: bool = False,
        params: Optional[dict[str, str]] = None,
        body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Execute an HTTP request and return the parsed JSON body.

        Parameters
        ----------
        method:  HTTP verb (``"GET"``, ``"POST"``, …).
        path:    API path starting with ``/``.
        auth:    When ``True`` and an API key is set, send ``Authorization: Bearer``.
        params:  URL query parameters.
        body:    Request body serialised as JSON.

        Raises
        ------
        EPError
            On non-2xx responses, timeouts, or network failures.
        """
        headers: dict[str, str] = {}
        if auth and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        # Remove None values from body to avoid sending nulls for unset fields
        if body is not None:
            body = {k: v for k, v in body.items() if v is not None}

        try:
            response = await self._client.request(
                method,
                path,
                headers=headers,
                params=params,
                json=body if body else None,
            )
            data: dict[str, Any] = response.json()
            if not response.is_success:
                raise EPError(
                    data.get("error", f"EP API error: {response.status_code}"),
                    status=response.status_code,
                    code=data.get("code"),
                )
            return data
        except EPError:
            raise
        except httpx.TimeoutException as exc:
            raise EPError(f"Request timed out: {exc}") from exc
        except httpx.RequestError as exc:
            raise EPError(f"Request failed: {exc}") from exc

    # ==================================================================
    # Trust Profile & Evaluation
    # ==================================================================

    async def trust_profile(self, entity_id: str) -> EntityTrustProfile:
        """Get an entity's full trust profile (canonical read surface).

        This is the primary method for checking trust before transacting with
        any counterparty or installing any software.  It returns behavioral
        rates, signal breakdowns, provenance composition, consistency,
        anomaly alerts, current confidence, historical establishment, and
        dispute summary.

        Parameters
        ----------
        entity_id:
            Entity ID slug (e.g. ``"merchant-xyz"``) or UUID.

        Returns
        -------
        EntityTrustProfile
            Parsed trust profile dataclass.

        Example
        -------
        .. code-block:: python

            profile = await ep.trust_profile("merchant-xyz")
            if profile.current_confidence == "established":
                print("Safe to transact.")
        """
        data = await self._request("GET", f"/api/trust/profile/{entity_id}")
        return EntityTrustProfile.from_dict(data)

    async def trust_evaluate(
        self,
        entity_id: str,
        policy: TrustPolicy = "standard",
        context: Optional[TrustContext] = None,
    ) -> dict[str, Any]:
        """Evaluate an entity against a named trust policy.

        Returns a Trust Decision (allow/review/deny) with specific failure reasons. Use this
        to make routing and payment decisions.

        Parameters
        ----------
        entity_id:
            Entity ID to evaluate.
        policy:
            ``"strict"`` (high-value), ``"standard"`` (normal),
            ``"permissive"`` (low-risk), or ``"discovery"`` (allow unevaluated).
        context:
            Optional :class:`TrustContext` for context-aware evaluation
            (e.g. ``{"category": "furniture", "geo": "US-CA"}``).

        Example
        -------
        .. code-block:: python

            result = await ep.trust_evaluate(
                "merchant-xyz",
                policy="strict",
                context={"category": "electronics", "value_band": "high"},
            )
            if result["decision"] == "allow":
                proceed()
        """
        body: dict[str, Any] = {"entity_id": entity_id, "policy": policy}
        if context:
            body["context"] = dict(context)
        return await self._request("POST", "/api/trust/evaluate", body=body)

    async def trust_gate(
        self,
        entity_id: str,
        action: str,
        policy: TrustPolicy = "standard",
        value_usd: Optional[float] = None,
        delegation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Pre-action trust gate — call before any high-stakes action.

        A lightweight check that combines policy evaluation with action-specific
        context. Recommended for agent decision loops where you want a single
        authoritative go/no-go before executing an action.

        Parameters
        ----------
        entity_id:
            The entity being evaluated.
        action:
            Semantic action label (e.g. ``"purchase"``, ``"file_upload"``).
        policy:
            Trust policy to apply.
        value_usd:
            Monetary value of the action, used for value-band gating.
        delegation_id:
            If the agent is acting under a delegation, supply the delegation ID
            to gate-check the delegation's scope as well.

        Example
        -------
        .. code-block:: python

            gate = await ep.trust_gate(
                "merchant-xyz", action="purchase", value_usd=450.00
            )
            if gate["decision"] == "allow":
                await checkout()
        """
        return await self._request(
            "POST",
            "/api/trust/gate",
            body={
                "entity_id": entity_id,
                "action": action,
                "policy": policy,
                "value_usd": value_usd,
                "delegation_id": delegation_id,
            },
        )

    async def domain_score(
        self,
        entity_id: str,
        domains: Optional[list[TrustDomain]] = None,
    ) -> dict[str, Any]:
        """Get domain-specific trust scores for an entity.

        Parameters
        ----------
        entity_id:
            Entity ID to score.
        domains:
            Optional list of :data:`TrustDomain` values to filter by.
            When omitted all domains are returned.

        Example
        -------
        .. code-block:: python

            scores = await ep.domain_score(
                "my-agent", domains=["financial", "delegation"]
            )
        """
        params: dict[str, str] = {}
        if domains:
            params["domains"] = ",".join(domains)
        return await self._request(
            "GET", f"/api/trust/domain-score/{entity_id}", params=params
        )

    async def install_preflight(
        self,
        entity_id: str,
        policy: Optional[str] = None,
        context: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """EP-SX install preflight — should I install this software entity?

        Evaluates a software entity against a software-specific trust policy.
        Returns ``allow`` / ``review`` / ``deny`` with specific reasons covering
        publisher verification, permissions, provenance, and trust history.

        Parameters
        ----------
        entity_id:
            Software entity ID, e.g. ``"github_app:acme/code-helper"`` or
            ``"npm_package:lodash"``.
        policy:
            Software policy name: ``"github_private_repo_safe_v1"``,
            ``"npm_buildtime_safe_v1"``, ``"browser_extension_safe_v1"``,
            ``"mcp_server_safe_v1"``, or any standard EP policy.
            Defaults to ``"standard"``.
        context:
            Install context metadata, e.g.
            ``{"host": "mcp", "permission_class": "bounded_external_access"}``.

        Example
        -------
        .. code-block:: python

            result = await ep.install_preflight(
                "mcp-server-ep-v1",
                policy="mcp_server_safe_v1",
                context={"host": "mcp", "permission_class": "bounded_external_access"},
            )
            if result["decision"] == "deny":
                raise RuntimeError(result["reasons"])
        """
        body: dict[str, Any] = {
            "entity_id": entity_id,
            "policy": policy or "standard",
        }
        if context:
            body["context"] = context
        return await self._request("POST", "/api/trust/install-preflight", body=body)

    # ==================================================================
    # Entities
    # ==================================================================

    async def register_entity(
        self,
        entity_id: str,
        display_name: str,
        entity_type: EntityType,
        description: str,
        capabilities: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Register a new entity. Public — no API key required.

        Returns the newly created entity together with its first API key.
        **Save the API key immediately — it will not be shown again.**

        Parameters
        ----------
        entity_id:
            Lowercase slug with hyphens, e.g. ``"my-cool-agent"``.
        display_name:
            Human-readable name.
        entity_type:
            One of the :data:`EntityType` literals.
        description:
            Short description of what the entity does.
        capabilities:
            Optional list of capability tags.

        Example
        -------
        .. code-block:: python

            result = await ep.register_entity(
                entity_id="my-agent-v1",
                display_name="My Agent",
                entity_type="agent",
                description="Handles e-commerce checkout flows.",
                capabilities=["checkout", "purchase"],
            )
            api_key = result["api_key"]  # save this!
        """
        return await self._request(
            "POST",
            "/api/entities/register",
            body={
                "entity_id": entity_id,
                "display_name": display_name,
                "entity_type": entity_type,
                "description": description,
                "capabilities": capabilities,
            },
        )

    async def search_entities(
        self,
        query: str,
        entity_type: Optional[EntityType] = None,
    ) -> dict[str, Any]:
        """Search entities by name, capability, or category.

        Parameters
        ----------
        query:
            Free-text search query.
        entity_type:
            Optional :data:`EntityType` filter.

        Example
        -------
        .. code-block:: python

            results = await ep.search_entities("shopify checkout", entity_type="merchant")
        """
        params: dict[str, str] = {"q": query}
        if entity_type:
            params["type"] = entity_type
        return await self._request("GET", "/api/entities/search", params=params)

    async def leaderboard(
        self,
        limit: int = 10,
        entity_type: Optional[EntityType] = None,
    ) -> dict[str, Any]:
        """Get top entities ranked by trust confidence.

        Parameters
        ----------
        limit:
            Maximum number of entities to return (capped at 50).
        entity_type:
            Optional :data:`EntityType` filter.

        Example
        -------
        .. code-block:: python

            top = await ep.leaderboard(limit=20, entity_type="merchant")
        """
        params: dict[str, str] = {"limit": str(min(limit, 50))}
        if entity_type:
            params["type"] = entity_type
        return await self._request("GET", "/api/leaderboard", params=params)

    # ==================================================================
    # Receipts
    # ==================================================================

    async def submit_receipt(
        self,
        entity_id: str,
        transaction_ref: str,
        transaction_type: TransactionType,
        agent_behavior: Optional[AgentBehavior] = None,
        delivery_accuracy: Optional[float] = None,
        product_accuracy: Optional[float] = None,
        price_integrity: Optional[float] = None,
        return_processing: Optional[float] = None,
        claims: Optional[dict[str, bool]] = None,
        evidence: Optional[dict[str, Any]] = None,
        context: Optional[TrustContext] = None,
    ) -> dict[str, Any]:
        """Submit a transaction receipt to the EP ledger. Requires an API key.

        Receipts are append-only, cryptographically hashed, and chain-linked.
        ``agent_behavior`` is the strongest Phase 1 signal.

        Parameters
        ----------
        entity_id:
            Entity being evaluated.
        transaction_ref:
            External transaction reference (required, must be unique per entity).
        transaction_type:
            One of the :data:`TransactionType` literals.
        agent_behavior:
            Observable behavioral outcome — the strongest trust signal.
        delivery_accuracy:
            0–100 delivery accuracy score.
        product_accuracy:
            0–100 product accuracy score.
        price_integrity:
            0–100 price integrity score.
        return_processing:
            0–100 return processing score.
        claims:
            Structured boolean claims, e.g.
            ``{"delivered": True, "on_time": True, "price_honored": True}``.
        evidence:
            Supporting evidence references.
        context:
            :class:`TrustContext` for context-aware scoring.

        Example
        -------
        .. code-block:: python

            receipt = await ep.submit_receipt(
                entity_id="merchant-xyz",
                transaction_ref="order-8812",
                transaction_type="purchase",
                agent_behavior="completed",
                delivery_accuracy=97,
                price_integrity=100,
                claims={"delivered": True, "price_honored": True},
            )
            print(receipt["receipt"]["receipt_id"])
        """
        body: dict[str, Any] = {
            "entity_id": entity_id,
            "transaction_ref": transaction_ref,
            "transaction_type": transaction_type,
            "agent_behavior": agent_behavior,
            "delivery_accuracy": delivery_accuracy,
            "product_accuracy": product_accuracy,
            "price_integrity": price_integrity,
            "return_processing": return_processing,
            "claims": claims,
            "evidence": evidence,
            "context": dict(context) if context else None,
        }
        return await self._request("POST", "/api/receipts/submit", auth=True, body=body)

    async def batch_submit(
        self, receipts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Submit up to 50 receipts atomically.

        Parameters
        ----------
        receipts:
            List of receipt dicts (same shape as :meth:`submit_receipt` body).
            Silently capped at 50.

        Example
        -------
        .. code-block:: python

            result = await ep.batch_submit([
                {"entity_id": "merchant-a", "transaction_ref": "t1", ...},
                {"entity_id": "merchant-b", "transaction_ref": "t2", ...},
            ])
        """
        return await self._request(
            "POST",
            "/api/receipts/batch",
            auth=True,
            body={"receipts": receipts[:50]},
        )

    async def verify_receipt(self, receipt_id: str) -> dict[str, Any]:
        """Verify a receipt against the on-chain Merkle root.

        Parameters
        ----------
        receipt_id:
            Receipt ID (``ep_rcpt_...``).

        Example
        -------
        .. code-block:: python

            v = await ep.verify_receipt("ep_rcpt_abc123")
            assert v["verified"]
        """
        return await self._request("GET", f"/api/verify/{receipt_id}")

    # ==================================================================
    # Disputes & Appeals
    # ==================================================================

    async def file_dispute(
        self,
        receipt_id: str,
        reason: DisputeReason,
        description: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """File a dispute against a receipt. Requires an API key.

        Any affected party can challenge a receipt.  The submitter has 7 days
        to respond.

        Parameters
        ----------
        receipt_id:
            Receipt ID to dispute (``ep_rcpt_...``).
        reason:
            One of the :data:`DisputeReason` literals.
        description:
            Human-readable explanation of the dispute.
        evidence:
            Supporting evidence references.

        Example
        -------
        .. code-block:: python

            dispute = await ep.file_dispute(
                receipt_id="ep_rcpt_abc123",
                reason="fraudulent_receipt",
                description="This receipt was not submitted by us.",
            )
            print(dispute["dispute_id"])
        """
        return await self._request(
            "POST",
            "/api/disputes/file",
            auth=True,
            body={
                "receipt_id": receipt_id,
                "reason": reason,
                "description": description,
                "evidence": evidence,
            },
        )

    async def dispute_status(self, dispute_id: str) -> dict[str, Any]:
        """Get the current status of a dispute. Public — transparency is a protocol value.

        Parameters
        ----------
        dispute_id:
            Dispute ID (``ep_disp_...``).

        Example
        -------
        .. code-block:: python

            status = await ep.dispute_status("ep_disp_xyz")
            print(status["status"])   # "pending", "upheld", "reversed", ...
        """
        return await self._request("GET", f"/api/disputes/{dispute_id}")

    async def appeal_dispute(
        self,
        dispute_id: str,
        reason: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Appeal a dispute resolution. Requires an API key.

        Only dispute participants can appeal.  The dispute must be in an
        ``upheld``, ``reversed``, or ``dismissed`` state.

        "Trust must never be more powerful than appeal."

        Parameters
        ----------
        dispute_id:
            The dispute ID to appeal.
        reason:
            Why the resolution should be reconsidered (minimum 10 characters).
        evidence:
            Optional supporting evidence.

        Example
        -------
        .. code-block:: python

            appeal = await ep.appeal_dispute(
                dispute_id="ep_disp_xyz",
                reason="The resolution ignored the delivery confirmation screenshot.",
                evidence={"screenshot_url": "https://..."},
            )
        """
        return await self._request(
            "POST",
            "/api/disputes/appeal",
            auth=True,
            body={
                "dispute_id": dispute_id,
                "reason": reason,
                "evidence": evidence,
            },
        )

    async def report_trust_issue(
        self,
        entity_id: str,
        report_type: ReportType,
        description: str,
        contact_email: Optional[str] = None,
    ) -> dict[str, Any]:
        """Report a trust issue as a human. No authentication required.

        For when someone is wrongly downgraded, harmed by a trusted entity,
        or observes fraudulent behaviour.  EP must never make trust more
        powerful than appeal.

        Parameters
        ----------
        entity_id:
            Entity the report is about.
        report_type:
            One of the :data:`ReportType` literals.
        description:
            What happened.
        contact_email:
            Optional email address for EP follow-up.

        Example
        -------
        .. code-block:: python

            report = await ep.report_trust_issue(
                entity_id="merchant-xyz",
                report_type="harmed_by_trusted_entity",
                description="They charged me twice and won't refund.",
                contact_email="alice@example.com",
            )
        """
        return await self._request(
            "POST",
            "/api/disputes/report",
            body={
                "entity_id": entity_id,
                "report_type": report_type,
                "description": description,
                "contact_email": contact_email,
            },
        )

    # ==================================================================
    # Delegation
    # ==================================================================

    async def create_delegation(
        self,
        principal_id: str,
        agent_entity_id: str,
        scope: list[str],
        max_value_usd: Optional[float] = None,
        expires_at: Optional[str] = None,
        constraints: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Create a delegation: authorise an agent to act on behalf of a principal.

        Requires an API key.

        Parameters
        ----------
        principal_id:
            The principal granting delegation.
        agent_entity_id:
            The agent entity being delegated to.
        scope:
            List of permitted action types, e.g. ``["purchase", "file_upload"]``.
        max_value_usd:
            Monetary ceiling for the delegation.
        expires_at:
            ISO-8601 expiry timestamp.
        constraints:
            Additional structured constraints.

        Example
        -------
        .. code-block:: python

            delegation = await ep.create_delegation(
                principal_id="ep_principal_abc",
                agent_entity_id="my-agent-v1",
                scope=["purchase"],
                max_value_usd=500.00,
                expires_at="2026-12-31T23:59:59Z",
            )
            delegation_id = delegation["delegation_id"]
        """
        return await self._request(
            "POST",
            "/api/delegations/create",
            auth=True,
            body={
                "principal_id": principal_id,
                "agent_entity_id": agent_entity_id,
                "scope": scope,
                "max_value_usd": max_value_usd,
                "expires_at": expires_at,
                "constraints": constraints,
            },
        )

    async def verify_delegation(
        self,
        delegation_id: str,
        action_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Verify a delegation is valid — and optionally that it covers a specific action.

        Parameters
        ----------
        delegation_id:
            Delegation ID to verify.
        action_type:
            Optional action type to check against the delegation's scope.

        Example
        -------
        .. code-block:: python

            result = await ep.verify_delegation(
                "ep_del_abc123", action_type="purchase"
            )
            assert result["valid"]
        """
        params: dict[str, str] = {}
        if action_type:
            params["action_type"] = action_type
        return await self._request(
            "GET",
            f"/api/delegations/{delegation_id}/verify",
            params=params,
        )

    # ==================================================================
    # Identity Continuity (EP-IX)
    # ==================================================================

    async def principal_lookup(self, principal_id: str) -> dict[str, Any]:
        """Look up a principal — the enduring actor behind entities.

        Returns bindings, controlled entities, and continuity history.

        Parameters
        ----------
        principal_id:
            Principal ID, e.g. ``"ep_principal_abc"``.

        Example
        -------
        .. code-block:: python

            principal = await ep.principal_lookup("ep_principal_abc")
            for entity in principal["entities"]:
                print(entity["entity_id"])
        """
        return await self._request(
            "GET", f"/api/identity/principal/{principal_id}"
        )

    async def lineage(self, entity_id: str) -> dict[str, Any]:
        """Get entity lineage — predecessors, successors, and continuity history.

        Use to check whether an entity has suspicious continuity gaps or
        attempted whitewashing of a poor trust history.

        Parameters
        ----------
        entity_id:
            Entity ID to retrieve lineage for.

        Example
        -------
        .. code-block:: python

            lineage = await ep.lineage("merchant-xyz-v2")
            for pred in lineage.get("predecessors", []):
                print(pred["from"], pred["reason"])
        """
        return await self._request(
            "GET", f"/api/identity/lineage/{entity_id}"
        )

    # ==================================================================
    # Policies
    # ==================================================================

    async def list_policies(self) -> dict[str, Any]:
        """List all available trust policies with their requirements and families.

        Use to discover which policy to evaluate an entity against.

        Example
        -------
        .. code-block:: python

            policies = await ep.list_policies()
            for p in policies["policies"]:
                print(p["name"], p["family"])
        """
        return await self._request("GET", "/api/policies")

    # ==================================================================
    # EP Commit
    # ==================================================================

    async def issue_commit(self, params: dict[str, Any]) -> dict[str, Any]:
        """Issue a signed EP Commit before a high-stakes action.

        The commit binds the agent to a specific action type, entity, and policy
        before execution. Returns ``{ "decision": ..., "commit": { ... } }``.

        Parameters
        ----------
        params:
            Dict with ``action_type`` (required), ``entity_id`` (required), and
            optional keys: ``principal_id``, ``counterparty_entity_id``,
            ``delegation_id``, ``scope``, ``max_value_usd``, ``context``, ``policy``.

        Example
        -------
        .. code-block:: python

            result = await ep.issue_commit({
                "action_type": "transact",
                "entity_id": "payment-agent-v2",
                "max_value_usd": 500,
                "policy": "strict",
            })
            if result["decision"] != "allow":
                raise RuntimeError("Commit denied")
            commit_id = result["commit"]["commit_id"]
        """
        return await self._request(
            "POST", "/api/commit/issue", auth=True, body=params
        )

    async def verify_commit(self, commit_id: str) -> dict[str, Any]:
        """Verify a commit's signature, status, and validity.

        Parameters
        ----------
        commit_id:
            Commit ID (``epc_...``).

        Example
        -------
        .. code-block:: python

            result = await ep.verify_commit("epc_abc123")
            assert result["valid"]
        """
        return await self._request(
            "POST", "/api/commit/verify", body={"commit_id": commit_id}
        )

    async def get_commit_status(self, commit_id: str) -> dict[str, Any]:
        """Get the current state of a commit. Requires an API key.

        Returns ``{ "commit": { ... } }`` where the nested commit object
        contains ``commit_id``, ``status``, ``action_type``, etc.

        Parameters
        ----------
        commit_id:
            Commit ID (``epc_...``).

        Example
        -------
        .. code-block:: python

            result = await ep.get_commit_status("epc_abc123")
            print(result["commit"]["status"])  # "active", "revoked", "expired", "fulfilled"
        """
        return await self._request("GET", f"/api/commit/{commit_id}", auth=True)

    async def revoke_commit(
        self, commit_id: str, reason: str
    ) -> dict[str, Any]:
        """Revoke an active commit before it is fulfilled or expires.

        Parameters
        ----------
        commit_id:
            Commit ID to revoke (``epc_...``).
        reason:
            Reason for revocation.

        Example
        -------
        .. code-block:: python

            await ep.revoke_commit("epc_abc123", "Action no longer needed")
        """
        return await self._request(
            "POST",
            f"/api/commit/{commit_id}/revoke",
            auth=True,
            body={"reason": reason},
        )

    async def bind_receipt_to_commit(
        self, commit_id: str, receipt_id: str
    ) -> dict[str, Any]:
        """Bind a post-action receipt to a commit, completing the commit-execute-receipt cycle.

        Parameters
        ----------
        commit_id:
            Commit ID to bind to (``epc_...``).
        receipt_id:
            Receipt ID to bind (``ep_rcpt_...``).

        Example
        -------
        .. code-block:: python

            await ep.bind_receipt_to_commit("epc_abc123", "ep_rcpt_xyz789")
        """
        return await self._request(
            "POST",
            f"/api/commit/{commit_id}/receipt",
            auth=True,
            body={"receipt_id": receipt_id},
        )

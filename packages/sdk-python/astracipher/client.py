"""
AstraCipher Python Client — Main SDK entry point.

Provides async HTTP client for all AstraCipher server API operations:
- DID creation, resolution, deactivation
- Credential registration, verification, revocation
- Audit trail querying
- Server health checks

Usage::

    from astracipher import AstraCipherClient

    async with AstraCipherClient(
        server_url="http://localhost:3456",
        api_key="ap_your_key",
    ) as client:
        agent = await client.create_agent(name="my-agent")
        print(agent.did_id)
"""

from __future__ import annotations

from typing import Any

import httpx

from astracipher.exceptions import (
    AstraCipherError,
    AuthenticationError,
    ConnectionError,
    NotFoundError,
    ServerError,
    ValidationError,
)
from astracipher.models import (
    AstraCipherConfig,
    AuditEntry,
    AuditTrailResponse,
    CreateAgentResponse,
    Credential,
    DIDDocument,
    VerificationResult,
)


class AstraCipherClient:
    """
    Async Python client for the AstraCipher server API.

    Args:
        server_url: Base URL of the AstraCipher server (default: http://localhost:3456)
        api_key: API key for authentication (X-AstraCipher-Key header)
        network: Default network for DID operations (mainnet, testnet, local)
        timeout: HTTP request timeout in seconds
    """

    def __init__(
        self,
        server_url: str = "http://localhost:3456",
        api_key: str | None = None,
        network: str = "testnet",
        timeout: float = 30.0,
    ) -> None:
        self.config = AstraCipherConfig(
            server_url=server_url.rstrip("/"),
            api_key=api_key,
            network=network,
            timeout=timeout,
        )
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AstraCipherClient:
        self._client = httpx.AsyncClient(
            base_url=self.config.server_url,
            timeout=self.config.timeout,
            headers=self._build_headers(),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "astracipher-python/0.1.0",
        }
        if self.config.api_key:
            headers["X-AstraCipher-Key"] = self.config.api_key
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.server_url,
                timeout=self.config.timeout,
                headers=self._build_headers(),
            )
        return self._client

    async def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the AstraCipher server."""
        client = await self._get_client()

        try:
            response = await client.request(method, path, json=json, params=params)
        except httpx.ConnectError:
            raise ConnectionError(self.config.server_url)

        if response.status_code == 401:
            raise AuthenticationError()
        if response.status_code == 403:
            raise AuthenticationError("Insufficient permissions")
        if response.status_code == 404:
            raise NotFoundError("Resource", path)
        if response.status_code == 400:
            body = response.json() if response.content else {}
            raise ValidationError(body.get("error", "Validation failed"))
        if response.status_code == 410:
            raise NotFoundError("Resource (deactivated)", path)
        if response.status_code >= 500:
            raise ServerError()

        if not response.content:
            return {}

        return response.json()  # type: ignore[no-any-return]

    # ============================
    # DID Operations
    # ============================

    async def create_agent(
        self,
        name: str,
        *,
        network: str | None = None,
        description: str | None = None,
        controller: str | None = None,
    ) -> CreateAgentResponse:
        """
        Create a new agent DID on the AstraCipher server.

        Args:
            name: Agent name
            network: Network (mainnet, testnet, local). Defaults to config network.
            description: Agent description
            controller: Controller DID (who controls this agent)

        Returns:
            CreateAgentResponse with DID ID and document
        """
        payload: dict[str, Any] = {
            "name": name,
            "network": network or self.config.network,
        }
        if description:
            payload["description"] = description
        if controller:
            payload["controller"] = controller

        data = await self._request("POST", "/api/v1/did", json=payload)

        return CreateAgentResponse(
            did_id=data.get("didId", data.get("did", {}).get("id", "")),
            did_document=DIDDocument(**data.get("did", data.get("didDocument", {}))),
            network=network or self.config.network,
        )

    async def resolve_did(self, did: str) -> DIDDocument | None:
        """
        Resolve a DID to its document from the registry.

        Args:
            did: The DID to resolve (e.g. did:astracipher:testnet:abc123)

        Returns:
            DIDDocument if found, None if not found
        """
        try:
            data = await self._request("GET", f"/api/v1/did/{did}")
            did_data = data.get("did", data.get("didDocument", data))
            return DIDDocument(**did_data)
        except NotFoundError:
            return None

    async def list_agents(
        self, *, limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        """
        List all registered agent DIDs.

        Args:
            limit: Maximum number of results (default 50)
            offset: Offset for pagination

        Returns:
            Dict with 'dids' list and 'total' count
        """
        return await self._request(
            "GET", "/api/v1/did", params={"limit": limit, "offset": offset}
        )

    async def deactivate_agent(self, did: str) -> bool:
        """
        Deactivate an agent DID.

        Args:
            did: The DID to deactivate

        Returns:
            True if successfully deactivated
        """
        await self._request("DELETE", f"/api/v1/did/{did}")
        return True

    # ============================
    # Credential Operations
    # ============================

    async def register_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        """
        Register a credential with the server.

        Args:
            credential: The full credential JSON object

        Returns:
            Registration confirmation
        """
        return await self._request("POST", "/api/v1/credentials", json=credential)

    async def verify_credential(self, credential: dict[str, Any]) -> VerificationResult:
        """
        Verify a credential's signature, expiration, and revocation status.

        Args:
            credential: The credential JSON to verify

        Returns:
            VerificationResult with check details
        """
        data = await self._request(
            "POST", "/api/v1/credentials/verify", json={"credential": credential}
        )
        return VerificationResult(**data)

    async def revoke_credential(
        self, credential_id: str, *, reason: str = "revoked"
    ) -> bool:
        """
        Revoke a credential.

        Args:
            credential_id: The credential ID to revoke
            reason: Reason for revocation

        Returns:
            True if successfully revoked
        """
        await self._request(
            "POST",
            "/api/v1/credentials/revoke",
            json={"credentialId": credential_id, "reason": reason},
        )
        return True

    async def get_credential(self, credential_id: str) -> Credential:
        """
        Retrieve a registered credential by ID.

        Args:
            credential_id: The credential ID

        Returns:
            Credential object
        """
        data = await self._request("GET", f"/api/v1/credentials/{credential_id}")
        return Credential(**data.get("credential", data))

    # ============================
    # Audit Trail
    # ============================

    async def query_audit_trail(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        agent_did: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
    ) -> AuditTrailResponse:
        """
        Query the audit trail.

        Args:
            limit: Maximum entries to return
            offset: Offset for pagination
            agent_did: Filter by agent DID
            action: Filter by action type
            outcome: Filter by outcome (success, failure, denied, error)

        Returns:
            AuditTrailResponse with entries and pagination
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if agent_did:
            params["agentDid"] = agent_did
        if action:
            params["action"] = action
        if outcome:
            params["outcome"] = outcome

        data = await self._request("GET", "/api/v1/audit", params=params)
        return AuditTrailResponse(**data)

    async def log_action(
        self,
        *,
        agent_did: str,
        action: str,
        resource: str,
        outcome: str = "success",
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """
        Log an agent action to the audit trail.

        Args:
            agent_did: The agent's DID
            action: Action performed
            resource: Resource accessed
            outcome: Outcome of the action
            details: Additional action details

        Returns:
            The created audit entry
        """
        payload: dict[str, Any] = {
            "agentDid": agent_did,
            "action": action,
            "resource": resource,
            "outcome": outcome,
        }
        if details:
            payload["details"] = details

        data = await self._request("POST", "/api/v1/audit", json=payload)
        return AuditEntry(**data.get("entry", data))

    # ============================
    # Server Health
    # ============================

    async def health(self) -> dict[str, Any]:
        """
        Check server health.

        Returns:
            Health status dict with status, version, services, uptime
        """
        return await self._request("GET", "/health")

    async def is_healthy(self) -> bool:
        """
        Quick check if the server is healthy.

        Returns:
            True if server is healthy and responsive
        """
        try:
            data = await self.health()
            return data.get("status") == "healthy"
        except AstraCipherError:
            return False

    # ============================
    # Setup
    # ============================

    async def setup(
        self, organization_name: str, admin_email: str
    ) -> dict[str, Any]:
        """
        First-time server setup. Creates an organization and returns an API key.

        WARNING: The API key is shown only once. Store it securely.

        Args:
            organization_name: Name of your organization
            admin_email: Admin email address

        Returns:
            Dict with 'apiKey' and 'organizationId'
        """
        return await self._request(
            "POST",
            "/api/v1/setup",
            json={"name": organization_name, "email": admin_email},
        )

    # ============================
    # Cleanup
    # ============================

    async def close(self) -> None:
        """Close the HTTP client connection."""
        if self._client:
            await self._client.aclose()
            self._client = None

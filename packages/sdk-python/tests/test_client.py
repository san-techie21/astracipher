"""Tests for AgentPass Python SDK client."""

import pytest
import httpx
import pytest_httpx

from agentpass import AgentPassClient, AuthenticationError, NotFoundError


@pytest.fixture
def mock_server(httpx_mock: pytest_httpx.HTTPXMock) -> pytest_httpx.HTTPXMock:
    return httpx_mock


@pytest.mark.asyncio
async def test_health_check(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/health",
        json={"status": "healthy", "version": "0.1.0", "uptime": 120},
    )

    async with AgentPassClient() as client:
        result = await client.health()
        assert result["status"] == "healthy"


@pytest.mark.asyncio
async def test_is_healthy(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/health",
        json={"status": "healthy"},
    )

    async with AgentPassClient() as client:
        assert await client.is_healthy() is True


@pytest.mark.asyncio
async def test_create_agent(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/api/v1/did",
        method="POST",
        json={
            "didId": "did:agentpass:testnet:abc123",
            "did": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:agentpass:testnet:abc123",
                "controller": "did:agentpass:testnet:abc123",
                "verificationMethod": [],
                "authentication": [],
                "assertionMethod": [],
                "created": "2025-01-01T00:00:00Z",
                "updated": "2025-01-01T00:00:00Z",
            },
        },
    )

    async with AgentPassClient(api_key="ap_test_key") as client:
        result = await client.create_agent(name="test-agent")
        assert result.did_id == "did:agentpass:testnet:abc123"


@pytest.mark.asyncio
async def test_resolve_did(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/api/v1/did/did:agentpass:testnet:abc123",
        json={
            "did": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:agentpass:testnet:abc123",
                "controller": "did:agentpass:testnet:abc123",
                "verificationMethod": [],
                "authentication": [],
                "assertionMethod": [],
                "created": "2025-01-01T00:00:00Z",
                "updated": "2025-01-01T00:00:00Z",
            },
        },
    )

    async with AgentPassClient() as client:
        doc = await client.resolve_did("did:agentpass:testnet:abc123")
        assert doc is not None
        assert doc.id == "did:agentpass:testnet:abc123"


@pytest.mark.asyncio
async def test_resolve_did_not_found(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/api/v1/did/did:agentpass:testnet:missing",
        status_code=404,
        json={"error": "DID not found"},
    )

    async with AgentPassClient() as client:
        doc = await client.resolve_did("did:agentpass:testnet:missing")
        assert doc is None


@pytest.mark.asyncio
async def test_verify_credential(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/api/v1/credentials/verify",
        method="POST",
        json={
            "valid": True,
            "checks": {
                "structure": {"passed": True, "detail": "valid structure"},
                "expiration": {"passed": True, "detail": "not expired"},
            },
            "credentialId": "urn:agentpass:credential:test",
        },
    )

    async with AgentPassClient(api_key="ap_test") as client:
        result = await client.verify_credential({"id": "test-cred"})
        assert result.valid is True
        assert "structure" in result.checks


@pytest.mark.asyncio
async def test_authentication_error(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/api/v1/did",
        method="GET",
        status_code=401,
    )

    async with AgentPassClient() as client:
        with pytest.raises(AuthenticationError):
            await client.list_agents()


@pytest.mark.asyncio
async def test_api_key_header(mock_server: pytest_httpx.HTTPXMock) -> None:
    mock_server.add_response(
        url="http://localhost:3456/health",
        json={"status": "healthy"},
    )

    async with AgentPassClient(api_key="ap_secret_key") as client:
        await client.health()

    request = mock_server.get_requests()[0]
    assert request.headers["X-AgentPass-Key"] == "ap_secret_key"

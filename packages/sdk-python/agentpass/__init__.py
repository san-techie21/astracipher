"""
AgentPass Python SDK — Cryptographic Identity & Trust for AI Agents.

The SSL certificates of the AI agent economy.

Usage::

    from agentpass import AgentPassClient

    client = AgentPassClient(
        server_url="http://localhost:3456",
        api_key="ap_your_key_here",
    )

    # Create an agent DID
    agent = await client.create_agent(name="my-agent", network="testnet")
    print(agent.did_id)

    # Resolve a DID
    did_doc = await client.resolve_did("did:agentpass:testnet:abc123")

    # Verify a credential
    result = await client.verify_credential(credential_json)

:copyright: (c) 2025 Astra Fintech Labs.
:license: Apache-2.0
"""

__version__ = "0.1.0"
__all__ = [
    "AgentPassClient",
    "AgentPassError",
    "AuthenticationError",
    "NotFoundError",
    "ValidationError",
    "DIDDocument",
    "Credential",
    "VerificationResult",
    "AuditEntry",
    "AgentPassConfig",
]

from agentpass.client import AgentPassClient
from agentpass.exceptions import (
    AgentPassError,
    AuthenticationError,
    NotFoundError,
    ValidationError,
)
from agentpass.models import (
    AgentPassConfig,
    AuditEntry,
    Credential,
    DIDDocument,
    VerificationResult,
)

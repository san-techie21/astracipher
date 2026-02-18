"""
AstraCipher Python SDK — Cryptographic Identity & Trust for AI Agents.

The SSL certificates of the AI agent economy.

Usage::

    from astracipher import AstraCipherClient

    client = AstraCipherClient(
        server_url="http://localhost:3456",
        api_key="ap_your_key_here",
    )

    # Create an agent DID
    agent = await client.create_agent(name="my-agent", network="testnet")
    print(agent.did_id)

    # Resolve a DID
    did_doc = await client.resolve_did("did:astracipher:testnet:abc123")

    # Verify a credential
    result = await client.verify_credential(credential_json)

:copyright: (c) 2025 Astra Fintech Labs.
:license: Apache-2.0
"""

__version__ = "0.1.0"
__all__ = [
    "AstraCipherClient",
    "AstraCipherError",
    "AuthenticationError",
    "NotFoundError",
    "ValidationError",
    "DIDDocument",
    "Credential",
    "VerificationResult",
    "AuditEntry",
    "AstraCipherConfig",
]

from astracipher.client import AstraCipherClient
from astracipher.exceptions import (
    AstraCipherError,
    AuthenticationError,
    NotFoundError,
    ValidationError,
)
from astracipher.models import (
    AstraCipherConfig,
    AuditEntry,
    Credential,
    DIDDocument,
    VerificationResult,
)

"""
Pydantic models for AgentPass protocol objects.

These models mirror the TypeScript types in @agentpass/core.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ============================
# Configuration
# ============================


class AgentPassConfig(BaseModel):
    """Configuration for the AgentPass client."""

    server_url: str = "http://localhost:3456"
    api_key: str | None = None
    network: str = "testnet"
    timeout: float = 30.0


# ============================
# DID Models
# ============================


class VerificationMethod(BaseModel):
    """A DID verification method (public key)."""

    id: str
    type: str
    controller: str
    public_key_multibase: str | None = Field(None, alias="publicKeyMultibase")

    model_config = {"populate_by_name": True}


class DIDService(BaseModel):
    """A DID service endpoint."""

    id: str
    type: str
    service_endpoint: str = Field(alias="serviceEndpoint")
    description: str | None = None

    model_config = {"populate_by_name": True}


class SignatureResult(BaseModel):
    """Cryptographic signature result (hybrid PQC + classical)."""

    mode: str
    pqc_signature: str | None = Field(None, alias="pqcSignature")
    classical_signature: str | None = Field(None, alias="classicalSignature")
    algorithms: dict[str, str] = {}
    key_id: str = Field(alias="keyId")
    signed_at: str = Field(alias="signedAt")
    message_hash: str = Field(alias="messageHash")

    model_config = {"populate_by_name": True}


class DIDDocument(BaseModel):
    """W3C DID Document for an AI agent."""

    context: list[str] = Field(alias="@context")
    id: str
    controller: str | list[str]
    verification_method: list[VerificationMethod] = Field(alias="verificationMethod")
    authentication: list[str]
    assertion_method: list[str] = Field(alias="assertionMethod")
    key_agreement: list[str] | None = Field(None, alias="keyAgreement")
    service: list[DIDService] | None = None
    created: str
    updated: str
    deactivated: bool | None = None
    proof: SignatureResult | None = None

    model_config = {"populate_by_name": True}


class CreateAgentResponse(BaseModel):
    """Response from creating a new agent DID."""

    did_id: str
    did_document: DIDDocument
    network: str


# ============================
# Credential Models
# ============================


class AgentPermission(BaseModel):
    """Permission grant on a resource."""

    resource: str
    actions: list[Literal["read", "write", "execute", "delete", "admin"]]
    conditions: dict[str, Any] | None = None
    expires_at: str | None = Field(None, alias="expiresAt")

    model_config = {"populate_by_name": True}


class CredentialSubject(BaseModel):
    """The agent described by a credential."""

    id: str
    name: str
    description: str | None = None
    model: str | None = None
    version: str | None = None
    capabilities: list[str]
    permissions: list[AgentPermission]
    trust_level: int = Field(alias="trustLevel")
    rate_limits: dict[str, int] | None = Field(None, alias="rateLimits")
    compliance: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}


class CredentialProof(BaseModel):
    """Cryptographic proof attached to a credential."""

    type: str
    created: str
    verification_method: str = Field(alias="verificationMethod")
    proof_purpose: str = Field(alias="proofPurpose")
    signature: SignatureResult

    model_config = {"populate_by_name": True}


class Credential(BaseModel):
    """W3C Verifiable Credential for an AI agent."""

    context: list[str] = Field(alias="@context")
    id: str
    type: list[str]
    issuer: str
    issuance_date: str = Field(alias="issuanceDate")
    expiration_date: str = Field(alias="expirationDate")
    credential_subject: CredentialSubject = Field(alias="credentialSubject")
    proof: CredentialProof | None = None

    model_config = {"populate_by_name": True}

    @property
    def is_expired(self) -> bool:
        """Check if the credential has expired."""
        exp = datetime.fromisoformat(self.expiration_date.replace("Z", "+00:00"))
        return datetime.now(exp.tzinfo) > exp

    def has_capability(self, capability: str) -> bool:
        """Check if the credential grants a specific capability."""
        return capability in self.credential_subject.capabilities

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if the credential grants a specific permission.

        LOW-4 FIX: Supports glob/wildcard matching matching the TypeScript version:
          '*'           → matches everything
          'api/*'       → matches 'api/users', 'api/orders', 'api/orders/123', etc.
          'api/orders*' → matches 'api/orders', 'api/orders/123', etc.
        Also checks permission-level expiration.
        """
        from datetime import datetime

        now = datetime.utcnow()

        for perm in self.credential_subject.permissions:
            # Check permission-level expiration
            if perm.expires_at:
                try:
                    exp = datetime.fromisoformat(perm.expires_at.replace("Z", "+00:00"))
                    if datetime.now(exp.tzinfo) > exp:
                        continue  # This permission has expired
                except (ValueError, TypeError):
                    continue

            if action not in perm.actions:
                continue

            # Exact match or global wildcard
            if perm.resource == resource or perm.resource == "*":
                return True

            # Glob pattern: 'api/*' matches 'api/users' and 'api/orders/123'
            if perm.resource.endswith("/*"):
                prefix = perm.resource[:-2]  # remove /*
                if resource == prefix or resource.startswith(prefix + "/"):
                    return True

            # Prefix pattern: 'api/orders*' matches 'api/orders/123'
            elif perm.resource.endswith("*"):
                prefix = perm.resource[:-1]  # remove *
                if resource.startswith(prefix):
                    return True

        return False


# ============================
# Verification Models
# ============================


class VerificationCheck(BaseModel):
    """A single verification check result."""

    passed: bool
    detail: str


class VerificationResult(BaseModel):
    """Result of verifying a credential."""

    valid: bool
    checks: dict[str, VerificationCheck] = {}
    credential_id: str | None = Field(None, alias="credentialId")

    model_config = {"populate_by_name": True}


# ============================
# Audit Models
# ============================


class AuditEntry(BaseModel):
    """An entry in the audit trail."""

    id: str
    agent_did: str = Field(alias="agentDid")
    action: str
    resource: str
    outcome: Literal["success", "failure", "denied", "error"]
    details: dict[str, Any] | None = None
    timestamp: str
    signature: str | None = None

    model_config = {"populate_by_name": True}


class AuditTrailResponse(BaseModel):
    """Response from querying the audit trail."""

    entries: list[AuditEntry]
    total: int
    limit: int
    offset: int

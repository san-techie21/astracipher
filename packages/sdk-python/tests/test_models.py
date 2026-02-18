"""Tests for AstraCipher Python SDK models."""

import pytest

from astracipher.models import (
    Credential,
    CredentialSubject,
    DIDDocument,
    VerificationMethod,
    VerificationResult,
)


class TestDIDDocument:
    def test_parse_did_document(self) -> None:
        raw = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://astracipher.com/ns/v1",
            ],
            "id": "did:astracipher:testnet:abc123",
            "controller": "did:astracipher:testnet:abc123",
            "verificationMethod": [
                {
                    "id": "did:astracipher:testnet:abc123#key-pqc-1",
                    "type": "ML-DSA-65-2024",
                    "controller": "did:astracipher:testnet:abc123",
                    "publicKeyMultibase": "zbase64encodedkey",
                }
            ],
            "authentication": ["did:astracipher:testnet:abc123#key-pqc-1"],
            "assertionMethod": ["did:astracipher:testnet:abc123#key-pqc-1"],
            "created": "2025-01-01T00:00:00.000Z",
            "updated": "2025-01-01T00:00:00.000Z",
        }

        doc = DIDDocument(**raw)
        assert doc.id == "did:astracipher:testnet:abc123"
        assert len(doc.verification_method) == 1
        assert doc.verification_method[0].type == "ML-DSA-65-2024"
        assert doc.deactivated is None


class TestCredential:
    def _make_credential(self, **overrides: object) -> Credential:
        data = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://astracipher.com/ns/credentials/v1",
            ],
            "id": "urn:astracipher:credential:test-001",
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": "did:astracipher:testnet:issuer",
            "issuanceDate": "2025-01-01T00:00:00.000Z",
            "expirationDate": "2026-01-01T00:00:00.000Z",
            "credentialSubject": {
                "id": "did:astracipher:testnet:agent",
                "name": "TestAgent",
                "capabilities": ["read", "write"],
                "permissions": [{"resource": "*", "actions": ["read", "write"]}],
                "trustLevel": 7,
            },
        }
        data.update(overrides)
        return Credential(**data)

    def test_parse_credential(self) -> None:
        cred = self._make_credential()
        assert cred.issuer == "did:astracipher:testnet:issuer"
        assert cred.credential_subject.name == "TestAgent"
        assert cred.credential_subject.trust_level == 7

    def test_has_capability(self) -> None:
        cred = self._make_credential()
        assert cred.has_capability("read") is True
        assert cred.has_capability("delete") is False

    def test_has_permission(self) -> None:
        cred = self._make_credential()
        # Wildcard resource
        assert cred.has_permission("any-resource", "read") is True
        assert cred.has_permission("any-resource", "delete") is False

    def test_is_expired_future(self) -> None:
        cred = self._make_credential(expirationDate="2099-01-01T00:00:00.000Z")
        assert cred.is_expired is False

    def test_is_expired_past(self) -> None:
        cred = self._make_credential(expirationDate="2020-01-01T00:00:00.000Z")
        assert cred.is_expired is True


class TestVerificationResult:
    def test_valid_result(self) -> None:
        result = VerificationResult(
            valid=True,
            checks={},
            credentialId="test-001",
        )
        assert result.valid is True
        assert result.credential_id == "test-001"

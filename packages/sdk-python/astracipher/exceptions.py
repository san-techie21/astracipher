"""
Exception classes for the AstraCipher Python SDK.
"""


class AstraCipherError(Exception):
    """Base exception for all AstraCipher errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class AuthenticationError(AstraCipherError):
    """Raised when API authentication fails (401/403)."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, status_code=401)


class NotFoundError(AstraCipherError):
    """Raised when a resource is not found (404)."""

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            f"{resource} not found: {identifier}",
            status_code=404,
        )
        self.resource = resource
        self.identifier = identifier


class ValidationError(AstraCipherError):
    """Raised when input validation fails (400)."""

    def __init__(self, message: str, fields: dict[str, str] | None = None) -> None:
        super().__init__(message, status_code=400)
        self.fields = fields or {}


class ServerError(AstraCipherError):
    """Raised when the server returns a 5xx error."""

    def __init__(self, message: str = "Internal server error") -> None:
        super().__init__(message, status_code=500)


class ConnectionError(AstraCipherError):
    """Raised when the SDK cannot connect to the server."""

    def __init__(self, url: str) -> None:
        super().__init__(
            f"Cannot connect to AstraCipher server at {url}. "
            "Ensure the server is running."
        )
        self.url = url

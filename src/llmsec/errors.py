"""Custom exception hierarchy for llmsec."""


class LLMSecError(Exception):
    """Base exception for all llmsec runtime and configuration errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ConfigurationError(LLMSecError):
    """Raised when configuration validation or loading fails."""


class AuthorizationError(LLMSecError):
    """Raised when authorization acknowledgment is missing, invalid, or target is unauthorized."""


class LLMSecConnectionError(LLMSecError):
    """Raised when connection to target LLM endpoint fails or times out."""


class TargetResponseError(LLMSecError):
    """Raised when the target endpoint returns an unparseable or error response."""


class VerificationError(LLMSecError):
    """Raised when verification, canary generation, or detection encounters an error."""


class CanaryError(LLMSecError):
    """Raised when canary generation, seeding, or session operations fail."""

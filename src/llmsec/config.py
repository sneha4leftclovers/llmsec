"""Configuration models and schema validation for llmsec."""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, HttpUrl, field_validator


class HttpMethod(str, Enum):
    """Supported HTTP request methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class TargetFormat(str, Enum):
    """Target API schema format."""

    OPENAI_COMPATIBLE = "openai_compatible"
    CUSTOM_HTTP = "custom_http"


class ResponseExtractionConfig(BaseModel):
    """Configuration for extracting the model's text response from an HTTP response payload.

    Designed to be forward-compatible with Garak's REST generator response_json_field.
    """

    extraction_type: str = Field(
        default="json_path",
        description="Mechanism to parse response: 'json_path', 'plain_text', or 'regex'.",
    )
    json_path: str = Field(
        default="choices.0.message.content",
        description="Path notation to target response text (e.g., 'choices.0.message.content' or 'response.text').",
    )
    regex_pattern: str | None = Field(
        default=None,
        description="Optional regex pattern to extract or isolate candidate text from response body.",
    )


class Identity(BaseModel):
    """Configuration for a specific test identity/tenant.

    Essential for testing BOLA/IDOR cross-user and cross-tenant boundaries.
    """

    name: str = Field(description="Logical name or label for this identity (e.g. 'tenant_a', 'victim_user').")
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP headers specific to this identity (e.g. tenant-specific session tokens or API keys).",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Optional explicit tenant identifier for tracking multi-tenant separation.",
    )
    user_id: str | None = Field(
        default=None,
        description="Optional user identifier associated with this test profile.",
    )


TestIdentityConfig = Identity


class TestIdentitiesConfig(BaseModel):
    """Pair of test identities used to evaluate multi-tenant and authorization boundaries."""

    primary_identity: Identity = Field(
        default_factory=lambda: Identity(name="primary_identity"),
        description="Primary test identity under evaluation.",
    )
    secondary_identity: Identity | None = Field(
        default=None,
        description="Secondary test identity for cross-boundary/BOLA exfiltration tests.",
    )


class CanaryConfig(BaseModel):
    """Configuration for canary token generation, planting, and tracking."""

    prefix: str = Field(
        default="CANARY_LLMSEC_",
        description="Prefix used to identify planted canary tokens uniquely.",
    )
    token_length: int = Field(
        default=16,
        ge=8,
        le=64,
        description="Length of unique random suffix appended to the prefix.",
    )
    entropy_encoding: str = Field(
        default="hex",
        description="Encoding format for random bytes ('hex' or 'alphanumeric').",
    )


class AuthorizationConfig(BaseModel):
    """Mandatory authorization declaration confirming testing permissions.

    Structural enforcement ensures tests are never initiated without explicit authorization acknowledgment.
    """

    authorized: bool = Field(
        ...,
        description="Required boolean confirming that testing against target URL is explicitly authorized.",
    )
    authorized_by: str | None = Field(
        default=None,
        description="Individual, team, or organization granting testing authorization.",
    )
    scope_description: str | None = Field(
        default=None,
        description="Brief summary of authorization scope or assessment agreement reference.",
    )

    @field_validator("authorized")
    @classmethod
    def validate_authorization(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "Testing unauthorized systems is prohibited. 'authorized' must be explicitly set to True."
            )
        return v


class LLMSecConfig(BaseModel):
    """Primary configuration schema for an llmsec security assessment run."""

    target_url: HttpUrl = Field(
        description="Target endpoint URL to test (must be an authorized system).",
    )
    target_format: TargetFormat = Field(
        default=TargetFormat.OPENAI_COMPATIBLE,
        description="Target API format ('openai_compatible' or 'custom_http').",
    )
    http_method: HttpMethod = Field(
        default=HttpMethod.POST,
        description="HTTP method used when calling the endpoint.",
    )
    auth_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Sensitive authentication headers (e.g., {'Authorization': 'Bearer sk-...'}) applied to requests.",
    )
    request_headers: dict[str, str] = Field(
        default_factory=lambda: {"Content-Type": "application/json"},
        description="Standard HTTP headers sent with each request.",
    )
    body_template: dict[str, Any] = Field(
        default_factory=lambda: {
            "model": "default",
            "messages": [{"role": "user", "content": "{{prompt}}"}],
        },
        description="Request body template with '{{prompt}}' placeholder for payload injection.",
    )
    response_extraction: ResponseExtractionConfig = Field(
        default_factory=ResponseExtractionConfig,
        description="Configuration for extracting textual response from API response body.",
    )
    identities: TestIdentitiesConfig = Field(
        default_factory=TestIdentitiesConfig,
        description="Identity configurations for single-user or cross-tenant evaluation.",
    )
    canary: CanaryConfig = Field(
        default_factory=CanaryConfig,
        description="Canary token formatting and entropy settings.",
    )
    authorization: AuthorizationConfig = Field(
        ...,
        description="Explicit authorization acknowledgment required for any assessment.",
    )
    timeout: float = Field(
        default=30.0,
        gt=0.0,
        le=300.0,
        description="Request timeout in seconds.",
    )
    selected_test_suites: list[str] = Field(
        default_factory=lambda: ["canary_leakage", "cross_tenant_isolation"],
        description="List of test suites to execute during scan.",
    )

    @classmethod
    def create_openai_compatible(
        cls,
        target_url: str,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        authorized: bool = True,
        authorized_by: str | None = None,
    ) -> "LLMSecConfig":
        """Convenience factory creating a standard OpenAI-compatible endpoint configuration."""
        auth_headers = {}
        if api_key:
            auth_headers["Authorization"] = f"Bearer {api_key}"

        return cls(
            target_url=HttpUrl(target_url),
            target_format=TargetFormat.OPENAI_COMPATIBLE,
            http_method=HttpMethod.POST,
            auth_headers=auth_headers,
            request_headers={"Content-Type": "application/json"},
            body_template={
                "model": model,
                "messages": [{"role": "user", "content": "{{prompt}}"}],
            },
            response_extraction=ResponseExtractionConfig(
                extraction_type="json_path",
                json_path="choices.0.message.content",
            ),
            authorization=AuthorizationConfig(
                authorized=authorized,
                authorized_by=authorized_by,
            ),
        )

    def to_effective_headers(self, identity: Identity | None = None) -> dict[str, str]:
        """Combine base headers, auth headers, and identity-specific headers."""
        headers = dict(self.request_headers)
        headers.update(self.auth_headers)
        if identity and identity.headers:
            headers.update(identity.headers)
        return headers

    def effective_headers(self, identity: Identity | None = None) -> dict[str, str]:
        """Alias for to_effective_headers."""
        return self.to_effective_headers(identity)

    @property
    def request_body_template(self) -> dict[str, Any]:
        """Alias property for body_template."""
        return self.body_template

    @property
    def timeout_seconds(self) -> float:
        """Alias property for timeout in seconds."""
        return self.timeout

    @property
    def response_extraction_path(self) -> str:
        """Alias property for response_extraction.json_path."""
        return self.response_extraction.json_path

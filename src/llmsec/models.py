"""Data models and schemas for security findings in llmsec."""

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any

from pydantic import BaseModel, Field, model_validator


class OWASPCategory(str, Enum):
    """OWASP Top 10 for LLM Applications (2025 Edition)."""

    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Sensitive Information Disclosure"
    LLM03 = "LLM03: Supply Chain"
    LLM04 = "LLM04: Data and Model Poisoning"
    LLM05 = "LLM05: Improper Output Handling"
    LLM06 = "LLM06: Excessive Agency"
    LLM07 = "LLM07: System Prompt Leakage"
    LLM08 = "LLM08: Vector and Embedding Weaknesses"
    LLM09 = "LLM09: Misinformation"
    LLM10 = "LLM10: Unbounded Consumption"

    @property
    def code(self) -> str:
        """Returns the category code (e.g., 'LLM01')."""
        return self.value.split(":")[0]

    @property
    def label(self) -> str:
        """Returns the human-readable category name."""
        return self.value.split(":", 1)[1].strip()


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(str, Enum):
    """Verification outcome status.

    Explicitly separates deterministic findings from probabilistic model judgments.
    """

    CONFIRMED_DETERMINISTIC = "confirmed_deterministic"
    MODEL_JUDGED = "model_judged"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NOT_RUN = "not_run"


class VerificationMethod(str, Enum):
    """Mechanism used to verify or judge the finding."""

    CANARY_TOKEN = "canary_token"
    HEURISTIC_MATCH = "heuristic_match"
    MODEL_JUDGE = "model_judge"
    NONE = "none"


class RequestResponseReference(BaseModel):
    """Reference metadata connecting a finding to concrete HTTP exchanges."""

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the HTTP exchange.",
    )
    endpoint: str = Field(description="Target URL endpoint evaluated.")
    http_status: int | None = Field(default=None, description="HTTP status code returned by target.")
    prompt_snippet: str | None = Field(default=None, description="Redacted or representative prompt snippet.")
    response_snippet: str | None = Field(default=None, description="Representative response text containing evidence.")
    sent_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the request was dispatched.",
    )


class Evidence(BaseModel):
    """Structured evidence backing a security finding."""

    summary: str = Field(description="High-level description of observed evidence.")
    matched_canary: str | None = Field(
        default=None,
        description="Exact canary token detected in response (for deterministic verification).",
    )
    canary_leak_offset: int | None = Field(
        default=None,
        description="Character offset where canary token was located in output string.",
    )
    raw_evidence: str | None = Field(
        default=None,
        description="Raw output snippet, header value, or log line containing evidence.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary additional context, probe metadata, or extractor outputs.",
    )


class Finding(BaseModel):
    """Core security assessment finding representation."""

    id: str = Field(
        default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}",
        description="Unique identifier for the finding.",
    )
    title: str = Field(description="Concise description of the detected security weakness.")
    owasp_category: OWASPCategory = Field(
        description="Standardized OWASP Top 10 for LLM Applications (2025) category.",
    )
    severity: Severity = Field(description="Assessed severity impact level.")
    confidence: Confidence = Field(description="Confidence rating of the finding determination.")
    verification_status: VerificationStatus = Field(
        description="Five-state outcome clearly separating deterministic from model-judged findings.",
    )
    verification_method: VerificationMethod = Field(
        default=VerificationMethod.NONE,
        description="Concrete method utilized for verification.",
    )
    evidence: Evidence = Field(description="Structured evidence supporting the finding.")
    affected_identity: str | None = Field(
        default=None,
        description="Specific user/tenant identity impacted (critical for BOLA/cross-tenant findings).",
    )
    reproduction_steps: list[str] = Field(
        default_factory=list,
        description="Step-by-step instructions to reproduce the vulnerability.",
    )
    remediation: str | None = Field(
        default=None,
        description="Actionable mitigation or remediation guidance.",
    )
    references: list[RequestResponseReference] = Field(
        default_factory=list,
        description="Associated request/response exchanges demonstrating the weakness.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the finding was recorded.",
    )

    @property
    def is_deterministic(self) -> bool:
        """True if the finding is backed by confirmed deterministic evidence."""
        return self.verification_status == VerificationStatus.CONFIRMED_DETERMINISTIC

    @property
    def is_model_judged(self) -> bool:
        """True if the finding relies on an LLM judge."""
        return self.verification_status == VerificationStatus.MODEL_JUDGED

    @model_validator(mode="after")
    def validate_deterministic_evidence(self) -> "Finding":
        """Ensure semantic consistency between verification status and method."""
        if (
            self.verification_status == VerificationStatus.CONFIRMED_DETERMINISTIC
            and self.verification_method == VerificationMethod.MODEL_JUDGE
        ):
            raise ValueError(
                "A confirmed deterministic finding cannot have verification_method='model_judge'."
            )
        if (
            self.verification_method == VerificationMethod.CANARY_TOKEN
            and self.verification_status == VerificationStatus.CONFIRMED_DETERMINISTIC
            and not self.evidence.matched_canary
        ):
            raise ValueError(
                "Canary-verified deterministic finding must include the matched canary token in evidence."
            )
        return self


class CanaryFinding(BaseModel):
    """Specific canary detection finding resulting from scanning a response string."""

    run_id: str = Field(description="Unique run ID of the CanarySession.")
    label: str = Field(description="Label identifying what seed content was tagged.")
    token: str = Field(description="Exact canary token string.")
    matched_in_response: str = Field(description="The full response text in which the token was detected.")
    finding_index: int = Field(description="Character position/offset of match in response.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the finding detection.",
    )


class ProbeRequest(BaseModel):
    """Rendered probe request model sent over the wire."""

    url: str
    method: str
    headers: dict[str, str]
    body: dict
    prompt: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the probe request was created.",
    )


class ProbeResponse(BaseModel):
    """Probe response model containing raw telemetry and extracted model text."""

    status_code: int
    raw_body: str
    extracted_text: str | None
    latency_ms: float
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the probe response was recorded.",
    )


class AuthzFinding(BaseModel):
    """Finding representing cross-identity authorization or tenant boundary leakage."""

    run_id: str
    probe_prompt: str
    requesting_identity_id: str
    leaking_identity_id: str
    canary_finding: CanaryFinding
    probe_request: ProbeRequest
    probe_response: ProbeResponse
    owasp_category: OWASPCategory
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the authorization finding was recorded.",
    )


class ScanResult(BaseModel):
    """Complete result of a Scanner.run() execution."""

    run_id: str = Field(description="Unique run identifier matching the CanarySession run_id.")
    config_target_url: str = Field(description="Target URL from the assessment configuration.")
    started_at: datetime = Field(description="UTC timestamp when the scan started.")
    completed_at: datetime = Field(description="UTC timestamp when the scan completed.")
    findings: list[Finding] = Field(
        default_factory=list,
        description="Full Finding objects converted from confirmed canary detections.",
    )
    authz_findings: list[AuthzFinding] = Field(
        default_factory=list,
        description="AuthzFinding objects from the two-identity authorization suite.",
    )
    canary_findings: list[CanaryFinding] = Field(
        default_factory=list,
        description="Raw CanaryFinding objects from canary probe scanning.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal error messages collected during the scan run.",
    )
    skipped_suites: list[str] = Field(
        default_factory=list,
        description="Test suite names that were skipped due to missing configuration.",
    )

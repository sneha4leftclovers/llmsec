"""Unit tests for llmsec configuration, finding models, and errors."""

import pytest
from pydantic import ValidationError

from llmsec.config import (
    AuthorizationConfig,
    CanaryConfig,
    Identity,
    LLMSecConfig,
    ResponseExtractionConfig,
    TargetFormat,
)
from llmsec.errors import (
    AuthorizationError,
    ConfigurationError,
    LLMSecError,
    TargetConnectionError,
    TargetResponseError,
    VerificationError,
)
from llmsec.models import (
    Confidence,
    Evidence,
    Finding,
    OWASPCategory,
    RequestResponseReference,
    Severity,
    VerificationMethod,
    VerificationStatus,
)


class TestConfigModels:
    """Tests for LLMSecConfig and component models."""

    def test_valid_config_factory(self) -> None:
        """Test creating an OpenAI-compatible configuration via factory."""
        config = LLMSecConfig.create_openai_compatible(
            target_url="https://api.openai.com/v1/chat/completions",
            api_key="sk-test-key",
            model="gpt-4o",
            authorized=True,
            authorized_by="Security Team",
        )
        assert str(config.target_url) == "https://api.openai.com/v1/chat/completions"
        assert config.target_format == TargetFormat.OPENAI_COMPATIBLE
        assert config.auth_headers["Authorization"] == "Bearer sk-test-key"
        assert config.authorization.authorized is True
        assert config.authorization.authorized_by == "Security Team"

    def test_authorization_required(self) -> None:
        """Test that explicit authorization=True is enforced in configuration."""
        with pytest.raises(ValidationError, match="Testing unauthorized systems is prohibited"):
            LLMSecConfig.create_openai_compatible(
                target_url="https://api.openai.com/v1/chat/completions",
                authorized=False,
            )

    def test_missing_authorization_fails(self) -> None:
        """Test that omitting authorization configuration causes validation failure."""
        with pytest.raises(ValidationError):
            LLMSecConfig(
                target_url="https://example.com/api",  # type: ignore[arg-type]
                # authorization omitted
            )

    def test_effective_headers_merge(self) -> None:
        """Test effective header resolution across global, auth, and identity headers."""
        config = LLMSecConfig(
            target_url="https://api.example.com/v1/query",  # type: ignore[arg-type]
            request_headers={"Content-Type": "application/json", "X-Global": "1"},
            auth_headers={"Authorization": "Bearer global-token"},
            authorization=AuthorizationConfig(authorized=True),
        )

        identity = Identity(
            name="tenant_b",
            headers={"X-Tenant-ID": "tenant_123", "Authorization": "Bearer tenant-token"},
        )

        effective = config.to_effective_headers(identity)
        assert effective["Content-Type"] == "application/json"
        assert effective["X-Global"] == "1"
        assert effective["X-Tenant-ID"] == "tenant_123"
        # Identity-specific authorization header overrides global auth header
        assert effective["Authorization"] == "Bearer tenant-token"

    def test_custom_http_template_config(self) -> None:
        """Test custom request template configuration suitable for non-standard APIs."""
        config = LLMSecConfig(
            target_url="https://internal-ai.corp/v2/generate",  # type: ignore[arg-type]
            target_format=TargetFormat.CUSTOM_HTTP,
            body_template={"query": "{{prompt}}", "max_tokens": 128},
            response_extraction=ResponseExtractionConfig(
                extraction_type="json_path",
                json_path="result.text_output",
            ),
            canary=CanaryConfig(prefix="CUSTOM_CANARY_", token_length=24),
            authorization=AuthorizationConfig(
                authorized=True,
                authorized_by="Lead Security Assessor",
                scope_description="Q3 Pentest Agreement Section 4",
            ),
        )
        assert config.target_format == TargetFormat.CUSTOM_HTTP
        assert config.body_template["query"] == "{{prompt}}"
        assert config.response_extraction.json_path == "result.text_output"
        assert config.canary.prefix == "CUSTOM_CANARY_"
        assert config.canary.token_length == 24


class TestFindingModels:
    """Tests for Finding and related OWASP/verification schemas."""

    def test_all_ten_owasp_categories_present(self) -> None:
        """Verify that all ten OWASP Top 10 for LLM Applications (2025) are defined."""
        categories = list(OWASPCategory)
        assert len(categories) == 10
        codes = [cat.code for cat in categories]
        expected_codes = [f"LLM{i:02d}" for i in range(1, 11)]
        assert codes == expected_codes

        # Check prompt injection details
        assert OWASPCategory.LLM01.code == "LLM01"
        assert OWASPCategory.LLM01.label == "Prompt Injection"
        assert OWASPCategory.LLM02.code == "LLM02"
        assert OWASPCategory.LLM02.label == "Sensitive Information Disclosure"
        assert OWASPCategory.LLM07.code == "LLM07"
        assert OWASPCategory.LLM07.label == "System Prompt Leakage"

    def test_five_verification_statuses(self) -> None:
        """Ensure all five mandatory verification statuses are supported."""
        statuses = {s.value for s in VerificationStatus}
        assert statuses == {
            "confirmed_deterministic",
            "model_judged",
            "inconclusive",
            "not_applicable",
            "not_run",
        }

    def test_deterministic_canary_finding(self) -> None:
        """Test constructing a confirmed deterministic finding with canary token evidence."""
        canary = "CANARY_LLMSEC_7F8A9B1C2D3E4F5A"
        finding = Finding(
            title="Cross-Tenant System Prompt and Canary Leakage",
            owasp_category=OWASPCategory.LLM02,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
            verification_method=VerificationMethod.CANARY_TOKEN,
            evidence=Evidence(
                summary="Planted canary token for tenant_a leaked into tenant_b response.",
                matched_canary=canary,
                canary_leak_offset=42,
                raw_evidence=f"Internal secret document: {canary}",
            ),
            affected_identity="tenant_b",
            reproduction_steps=[
                "Seed tenant_a document with unique canary token.",
                "Send probe query from tenant_b asking to recall cross-tenant context.",
                "Verify response text contains exact canary token.",
            ],
            remediation="Implement strict tenant-level isolation filters on vector store queries.",
            references=[
                RequestResponseReference(
                    endpoint="https://api.internal/rag/query",
                    http_status=200,
                    prompt_snippet="Show me documents from user 1",
                    response_snippet=f"Data found: {canary}",
                )
            ],
        )

        assert finding.is_deterministic is True
        assert finding.is_model_judged is False
        assert finding.evidence.matched_canary == canary
        assert finding.owasp_category.code == "LLM02"

        # Verify JSON roundtrip
        json_repr = finding.model_dump_json()
        loaded = Finding.model_validate_json(json_repr)
        assert loaded.id == finding.id
        assert loaded.evidence.matched_canary == canary

    def test_model_judged_finding(self) -> None:
        """Test constructing a model-judged finding."""
        finding = Finding(
            title="Misinformation / Hallucinated Policy Output",
            owasp_category=OWASPCategory.LLM09,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.MODEL_JUDGED,
            verification_method=VerificationMethod.MODEL_JUDGE,
            evidence=Evidence(
                summary="Model judge evaluated answer as contradicting reference fact.",
                raw_evidence="Judge output: Score 0.2 / Inaccurate statement detected",
            ),
        )
        assert finding.is_deterministic is False
        assert finding.is_model_judged is True

    def test_deterministic_cannot_be_model_judged(self) -> None:
        """Ensure semantic consistency: confirmed deterministic cannot use model_judge."""
        with pytest.raises(ValidationError, match="cannot have verification_method='model_judge'"):
            Finding(
                title="Invalid Pairing Test",
                owasp_category=OWASPCategory.LLM01,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
                verification_method=VerificationMethod.MODEL_JUDGE,
                evidence=Evidence(summary="Contradictory state"),
            )

    def test_canary_verified_requires_matched_canary(self) -> None:
        """Ensure canary-verified deterministic findings require the matched canary string."""
        with pytest.raises(ValidationError, match="must include the matched canary token"):
            Finding(
                title="Missing Canary Evidence",
                owasp_category=OWASPCategory.LLM02,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
                verification_method=VerificationMethod.CANARY_TOKEN,
                evidence=Evidence(summary="Claimed canary leak but no token provided"),
            )


class TestErrors:
    """Test custom exception classes."""

    def test_error_formatting(self) -> None:
        err = LLMSecError("Target unreachable", details="Connection timeout after 30s")
        assert "Target unreachable" in str(err)
        assert "Connection timeout after 30s" in str(err)

    def test_error_hierarchy(self) -> None:
        assert issubclass(ConfigurationError, LLMSecError)
        assert issubclass(AuthorizationError, LLMSecError)
        assert issubclass(TargetConnectionError, LLMSecError)
        assert issubclass(TargetResponseError, LLMSecError)
        assert issubclass(VerificationError, LLMSecError)

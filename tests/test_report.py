"""Comprehensive test suite for ReportGenerator (Phase 7B)."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from llmsec import __version__
from llmsec.config import AuthorizationConfig, LLMSecConfig, TestIdentitiesConfig
from llmsec.errors import IntegrationError
from llmsec.models import (
    Confidence,
    Evidence,
    Finding,
    OWASPCategory,
    Severity,
    VerificationMethod,
    VerificationStatus,
)
from llmsec.report import (
    BlockedURLFetcher,
    ReportGenerator,
    sanitize_target_url,
)


def _create_test_config(
    auth_headers: dict | None = None,
    target_url: str = "https://api.example.com/v1/chat/completions",
    identities: TestIdentitiesConfig | None = None,
) -> LLMSecConfig:
    """Helper to create a standard valid test configuration."""
    return LLMSecConfig(
        target_url=target_url,
        auth_headers=auth_headers or {"Authorization": "Bearer sk-test-SECRET123"},
        authorization=AuthorizationConfig(
            authorized=True,
            authorized_by="Security Lead",
            scope_description="https://api.example.com/*",
        ),
        test_identities=identities,
    )


def _create_sample_findings() -> list[Finding]:
    """Helper creating a mix of deterministic, model-judged, and inconclusive findings."""
    f1 = Finding(
        title="Cross-tenant canary token leaked in response",
        owasp_category=OWASPCategory.LLM02,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
        verification_method=VerificationMethod.CANARY_TOKEN,
        evidence=Evidence(
            summary="Tenant A canary found in Tenant B session",
            matched_canary="CANARY-9A8B7C6D5E4F1234",
            canary_leak_offset=42,
            raw_evidence="Confidential data CANARY-9A8B7C6D5E4F1234 leaked.",
            details={"run_id": "RUN-TEST-UUID"},
        ),
        reproduction_steps=["Send cross-tenant query", "Observe canary leakage"],
        remediation="Enforce vector isolation per tenant.",
    )
    f2 = Finding(
        title="Excessive Agency via tool hijacking",
        owasp_category=OWASPCategory.LLM06,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        verification_status=VerificationStatus.MODEL_JUDGED,
        verification_method=VerificationMethod.MODEL_JUDGE,
        evidence=Evidence(
            summary="Model executed unapproved tool deletion action.",
            raw_evidence="Tool execution output.",
            details={
                "judge_model": "mistral",
                "judge_verdict": "VULNERABLE",
                "judge_raw_output": "VULNERABLE",
            },
        ),
        reproduction_steps=["Inject tool command in prompt", "Verify execution"],
        remediation="Implement user approval gates for tool calls.",
    )
    f3 = Finding(
        title="Potential prompt injection fuzzing hit",
        owasp_category=OWASPCategory.LLM01,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        verification_status=VerificationStatus.INCONCLUSIVE,
        verification_method=VerificationMethod.NONE,
        evidence=Evidence(
            summary="Suspicious system behavior observed.",
            raw_evidence="System response anomaly.",
        ),
        remediation="Harden system prompt delimiters.",
    )
    # Return deliberately out of order (High before Critical)
    return [f1, f2, f3]


class TestReportGeneratorCoreSpec:
    """Core specification tests 1 through 9 for ReportGenerator."""

    def test_render_html_produces_non_empty_html_containing_target_url(self) -> None:
        """1. render_html() produces a non-empty HTML string containing the target URL."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        html_out = generator.render_html()

        assert isinstance(html_out, str)
        assert len(html_out) > 0
        assert "https://api.example.com/v1/chat/completions" in html_out

    def test_all_finding_titles_appear_in_rendered_html(self) -> None:
        """2. All finding titles appear in the rendered HTML."""
        config = _create_test_config()
        findings = _create_sample_findings()
        generator = ReportGenerator(findings, config)
        html_out = generator.render_html()

        for f in findings:
            assert f.title in html_out

    def test_findings_ordered_correctly_by_severity(self) -> None:
        """3. Findings are ordered correctly by severity (Critical -> High -> Medium)."""
        config = _create_test_config()
        findings = _create_sample_findings()  # [High, Critical, Medium]
        generator = ReportGenerator(findings, config)
        html_out = generator.render_html()

        pos_crit = html_out.find("Excessive Agency via tool hijacking")
        pos_high = html_out.find("Cross-tenant canary token leaked")
        pos_med = html_out.find("Potential prompt injection fuzzing hit")

        assert pos_crit != -1
        assert pos_high != -1
        assert pos_med != -1
        assert pos_crit < pos_high < pos_med

    def test_confirmed_deterministic_shows_canary_token_in_output(self) -> None:
        """4. A CONFIRMED_DETERMINISTIC finding shows the canary token in the output."""
        config = _create_test_config()
        findings = _create_sample_findings()
        generator = ReportGenerator(findings, config)
        html_out = generator.render_html()

        assert "CANARY-9A8B7C6D5E4F1234" in html_out
        assert "CONFIRMED DETERMINISTIC" in html_out

    def test_model_judged_labelled_differently_from_deterministic(self) -> None:
        """5. A MODEL_JUDGED finding is labelled differently from a deterministic finding."""
        config = _create_test_config()
        findings = _create_sample_findings()
        generator = ReportGenerator(findings, config)
        html_out = generator.render_html()

        assert "CONFIRMED DETERMINISTIC" in html_out
        assert "MODEL JUDGED" in html_out
        assert "model opinion, not deterministic proof" in html_out

    def test_owasp_coverage_matrix_present_in_html(self) -> None:
        """6. The OWASP coverage matrix is present in the HTML."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        html_out = generator.render_html()

        assert "OWASP Top 10 Coverage Matrix" in html_out
        for code in ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"]:
            assert code in html_out
        assert "not applicable (black-box)" in html_out

    def test_authorization_statement_appears_in_html(self) -> None:
        """7. The authorization statement appears in the HTML."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        html_out = generator.render_html()

        assert "Authorization Statement" in html_out
        assert "Security Lead" in html_out
        assert "https://api.example.com/*" in html_out

    def test_render_pdf_weasyprint_missing_raises_integration_error(self, tmp_path: Path) -> None:
        """8. render_pdf() with WeasyPrint not installed raises IntegrationError."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        out_pdf = tmp_path / "test.pdf"

        with patch.dict("sys.modules", {"weasyprint": None}):
            with pytest.raises(IntegrationError, match="WeasyPrint is not installed or importable"):
                generator.render_pdf(out_pdf)

    def test_run_id_appears_in_appendix_section(self) -> None:
        """9. Run ID appears in the appendix section."""
        config = _create_test_config()
        findings = _create_sample_findings()
        generator = ReportGenerator(findings, config)
        html_out = generator.render_html()

        assert "4. Appendix" in html_out
        assert "RUN-TEST-UUID" in html_out


class TestReportGeneratorAdditionsAndSecurity:
    """Security, secret scrubbing, sanitization, and URL fetcher tests."""

    def test_render_html_writes_to_output_path_and_returns_path_string(self, tmp_path: Path) -> None:
        """render_html() writes to output_path if supplied and returns path string."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        out_file = tmp_path / "custom_report.html"

        result = generator.render_html(str(out_file))
        assert result == str(out_file)
        assert out_file.exists()
        assert "https://api.example.com/v1/chat/completions" in out_file.read_text(encoding="utf-8")

    def test_render_pdf_mocked_calls_weasyprint_and_returns_path(self, tmp_path: Path) -> None:
        """render_pdf() mocked call to WeasyPrint creates PDF at output_path and returns path."""
        config = _create_test_config()
        generator = ReportGenerator(_create_sample_findings(), config)
        out_pdf = tmp_path / "output.pdf"

        mock_html_class = MagicMock()
        mock_instance = MagicMock()
        mock_html_class.return_value = mock_instance

        with patch("weasyprint.HTML", mock_html_class):
            result = generator.render_pdf(out_pdf)
            assert result == str(out_pdf)
            mock_html_class.assert_called_once()
            mock_instance.write_pdf.assert_called_once_with(target=str(out_pdf))

    def test_autoescaping_escapes_script_tags(self) -> None:
        """Autoescaping must be ON in Jinja2."""
        config = _create_test_config()
        malicious_finding = Finding(
            title="XSS <script>alert(1)</script>",
            owasp_category=OWASPCategory.LLM05,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
            verification_method=VerificationMethod.CANARY_TOKEN,
            evidence=Evidence(
                summary="Observed <script>alert(1)</script> injection",
                matched_canary="CANARY-1122334455667788",
            ),
        )
        generator = ReportGenerator([malicious_finding], config)
        html_out = generator.render_html()

        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out

    def test_blocked_url_fetcher_refuses_http_and_file_schemes(self) -> None:
        """BlockedURLFetcher blocks http, https, and file:// (only data: allowed)."""
        fetcher = BlockedURLFetcher()

        with pytest.raises(ValueError, match="Resource loading blocked for security"):
            fetcher.fetch("http://example.com/x.png")
        assert "http://example.com/x.png" in fetcher.refused_urls

        with pytest.raises(ValueError, match="Resource loading blocked for security"):
            fetcher.fetch("file:///etc/passwd")
        assert "file:///etc/passwd" in fetcher.refused_urls

        data_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        resp = fetcher.fetch(data_uri)
        assert resp is not None

    def test_never_render_auth_headers_in_html(self) -> None:
        """Auth header secret values must never be rendered."""
        secret_token = "sk-test-SECRET123"
        config = _create_test_config(auth_headers={"Authorization": f"Bearer {secret_token}"})
        generator = ReportGenerator(_create_sample_findings(), config)
        html_out = generator.render_html()

        assert secret_token not in html_out
        assert "sk-test-" not in html_out
        assert "Authorization:" not in html_out

    def test_finding_evidence_echoing_secret_is_scrubbed_to_redacted(self) -> None:
        """Echoed secret tokens in finding evidence are scrubbed to [REDACTED]."""
        secret_token = "sk-test-SECRET123"
        config = _create_test_config(auth_headers={"Authorization": f"Bearer {secret_token}"})
        leaked_finding = Finding(
            title="Model echoed authorization token",
            owasp_category=OWASPCategory.LLM02,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
            verification_method=VerificationMethod.CANARY_TOKEN,
            evidence=Evidence(
                summary=f"Found Authorization token {secret_token} in completion",
                raw_evidence=f"API responded with header Authorization: Bearer {secret_token}",
                matched_canary="CANARY-1122334455667788",
            ),
        )
        generator = ReportGenerator([leaked_finding], config)
        html_out = generator.render_html()

        assert secret_token not in html_out
        assert "[REDACTED]" in html_out

    def test_target_url_sanitization_strips_credentials_and_query_params(self) -> None:
        """Strip query string and userinfo from target URL before showing it."""
        raw_url = "https://user:pass@api.corp.internal:8443/v1/chat?api_key=SECRET999&debug=true"
        sanitized = sanitize_target_url(raw_url)
        assert sanitized == "https://api.corp.internal:8443/v1/chat"
        assert "user" not in sanitized
        assert "pass" not in sanitized
        assert "SECRET999" not in sanitized

        config = _create_test_config(target_url=raw_url)
        generator = ReportGenerator([], config)
        html_out = generator.render_html()

        assert "SECRET999" not in html_out
        assert "user:pass" not in html_out
        assert "https://api.corp.internal:8443/v1/chat" in html_out

    def test_zero_findings_narrative_and_coverage(self) -> None:
        """Zero findings summary must say 'no findings recorded in the tested categories' and not claim target is secure."""
        config = _create_test_config()
        generator = ReportGenerator([], config)
        html_out = generator.render_html()

        assert "no findings recorded in the tested categories" in html_out
        assert ">tested<" not in html_out
        assert ">passed<" not in html_out
        assert ">evaluated<" not in html_out
        assert "run status not recorded" in html_out
        assert "not applicable (black-box)" in html_out

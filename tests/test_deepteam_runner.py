"""Unit tests for DeepTeam runner integration (all DeepTeam API execution is mocked)."""

import asyncio
from unittest.mock import MagicMock, patch
import pytest

from llmsec.config import LLMSecConfig
from llmsec.errors import ConfigurationError, IntegrationError
from llmsec.integrations.deepteam_runner import DeepTeamRunner
from llmsec.models import Finding, OWASPCategory, ProbeRequest, ProbeResponse, VerificationMethod, VerificationStatus


def _create_test_config() -> LLMSecConfig:
    return LLMSecConfig.create_openai_compatible(
        target_url="https://api.openai.com/v1/chat/completions",
        api_key="sk-test-key",
        model="gpt-4o",
        authorized=True,
    )


class MockRTResult:
    """Mock DeepTeam test case / result object."""

    def __init__(
        self,
        vulnerability: str = "BOLA",
        vulnerability_type: str = "bola",
        risk_category: str | None = None,
        score: float = 0.0,
        reason: str = "Cross-tenant record accessed.",
        actual_output: str = "Leaked data output",
        test_input: str = "Get user 2 data",
        attack_method: str = "DirectPrompt",
    ):
        self.vulnerability = vulnerability
        self.vulnerability_type = vulnerability_type
        self.risk_category = risk_category
        self.score = score
        self.reason = reason
        self.actual_output = actual_output
        self.input = test_input
        self.attack_method = attack_method


def test_build_model_callback_calls_llmsec_client_probe() -> None:
    """1. _build_model_callback() returns a callable that calls LLMSecClient.probe() correctly."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    callback = runner._build_model_callback()
    assert callable(callback)
    assert asyncio.iscoroutinefunction(callback)

    fake_req = MagicMock(spec=ProbeRequest)
    fake_resp = MagicMock(spec=ProbeResponse)
    fake_resp.extracted_text = "Expected assistant response"

    with patch.object(runner.client, "probe", return_value=(fake_req, fake_resp)) as mock_probe:
        result = asyncio.run(callback("Hello LLM"))
        mock_probe.assert_called_once_with("Hello LLM")
        assert result == "Expected assistant response"

    # Test returning empty string if extracted_text is None
    fake_resp_none = MagicMock(spec=ProbeResponse)
    fake_resp_none.extracted_text = None
    with patch.object(runner.client, "probe", return_value=(fake_req, fake_resp_none)):
        result = asyncio.run(callback("Prompt"))
        assert result == ""


def test_deepteam_result_with_known_type_converted_to_finding() -> None:
    """2. A DeepTeam result with a known vulnerability type is converted to a Finding with MODEL_JUDGED status."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    result_obj = MockRTResult(
        vulnerability="BOLA",
        vulnerability_type="bola",
        score=0.0,
        reason="Model disclosed tenant B data to tenant A.",
        actual_output="Secret records",
    )

    finding = runner._convert_result(result_obj)
    assert finding is not None
    assert isinstance(finding, Finding)
    assert finding.verification_status == VerificationStatus.MODEL_JUDGED
    assert finding.verification_method == VerificationMethod.MODEL_JUDGE
    assert finding.is_model_judged is True
    assert finding.is_deterministic is False
    assert finding.owasp_category == OWASPCategory.LLM06
    assert "BOLA" in finding.title
    assert "Model disclosed tenant B data" in finding.evidence.summary


def test_unknown_vulnerability_type_is_skipped_without_raising() -> None:
    """3. An unknown vulnerability type is skipped without raising."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    result_obj = MockRTResult(
        vulnerability="TotallyFictionalExploit",
        vulnerability_type="totally_fictional_exploit_xyz",
        risk_category=None,
        score=0.0,
    )

    finding = runner._convert_result(result_obj)
    assert finding is None


def test_owasp_category_is_correctly_assigned() -> None:
    """4. OWASP category is correctly assigned from risk category or vulnerability type."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    # 1. From risk_category label
    res_label = MockRTResult(risk_category="LLM_02", vulnerability="Unknown")
    f_label = runner._convert_result(res_label)
    assert f_label is not None
    assert f_label.owasp_category == OWASPCategory.LLM02

    # 2. From SQL Injection vulnerability type -> LLM05
    res_sql = MockRTResult(vulnerability_type="sql_injection", risk_category=None)
    f_sql = runner._convert_result(res_sql)
    assert f_sql is not None
    assert f_sql.owasp_category == OWASPCategory.LLM05

    # 3. From Misinformation vulnerability type -> LLM09
    res_misinfo = MockRTResult(vulnerability_type="misinformation", risk_category=None)
    f_misinfo = runner._convert_result(res_misinfo)
    assert f_misinfo is not None
    assert f_misinfo.owasp_category == OWASPCategory.LLM09

    # 4. From Prompt Leakage -> LLM07
    res_prompt = MockRTResult(vulnerability_type="prompt_leakage", risk_category=None)
    f_prompt = runner._convert_result(res_prompt)
    assert f_prompt is not None
    assert f_prompt.owasp_category == OWASPCategory.LLM07


def test_missing_openai_api_key_raises_configuration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """5. Missing OPENAI_API_KEY raises ConfigurationError."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY environment variable is required"):
        runner.run()


def test_uninstalled_deepteam_raises_integration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """6. Uninstalled deepteam raises IntegrationError."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    monkeypatch.setenv("OPENAI_API_KEY", "test-key-mock")
    with patch.dict("sys.modules", {"deepteam": None, "deepteam.red_team": None}):
        with pytest.raises(IntegrationError, match="not installed or importable"):
            runner.run()


def test_unmappable_or_passing_result_returns_none() -> None:
    """7. A result that cannot be mapped returns None from _convert_result()."""
    config = _create_test_config()
    runner = DeepTeamRunner(config)

    # Empty / unmappable object
    res_unmappable = MockRTResult(vulnerability="", vulnerability_type="", risk_category=None)
    assert runner._convert_result(res_unmappable) is None

    # Passing test case (score = 1.0) returns None (not a vulnerability finding)
    res_passing = MockRTResult(vulnerability_type="bola", score=1.0)
    assert runner._convert_result(res_passing) is None


def test_run_executes_red_team_and_collects_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test full DeepTeamRunner.run() execution with mocked deepteam.red_team."""
    config = _create_test_config()
    runner = DeepTeamRunner(config, vulnerabilities=[])

    monkeypatch.setenv("OPENAI_API_KEY", "sk-mock-key")

    mock_assessment = MagicMock()
    mock_assessment.test_cases = [
        MockRTResult(vulnerability_type="bola", score=0.0),
        MockRTResult(vulnerability_type="sql_injection", score=0.0),
        MockRTResult(vulnerability_type="robustness", score=1.0),  # passed -> ignored
    ]

    mock_red_team = MagicMock(return_value=mock_assessment)
    mock_deepteam = MagicMock()
    mock_deepteam.red_team = mock_red_team

    with patch.dict("sys.modules", {"deepteam": mock_deepteam, "deepteam.red_team": mock_red_team}):
        findings = runner.run()
        assert len(findings) == 2
        categories = {f.owasp_category for f in findings}
        assert categories == {OWASPCategory.LLM06, OWASPCategory.LLM05}
        assert all(f.verification_status == VerificationStatus.MODEL_JUDGED for f in findings)

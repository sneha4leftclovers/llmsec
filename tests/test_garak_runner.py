"""Unit tests for Garak runner integration (all Garak execution is mocked)."""

import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from llmsec.config import LLMSecConfig
from llmsec.errors import IntegrationError
from llmsec.integrations.garak_runner import (
    GarakRunner,
    get_available_probe_namespaces,
    get_default_probe_namespaces,
    map_probe_to_owasp,
)
from llmsec.models import Finding, OWASPCategory, VerificationMethod, VerificationStatus


def _create_test_config() -> LLMSecConfig:
    return LLMSecConfig.create_openai_compatible(
        target_url="https://api.openai.com/v1/chat/completions",
        api_key="sk-test-key",
        model="gpt-4o",
        authorized=True,
    )


def test_build_garak_config_produces_correct_rest_fields() -> None:
    """1. _build_garak_config() produces a dict with the correct REST generator fields for installed Garak."""
    config = _create_test_config()
    runner = GarakRunner(config)

    garak_conf = runner._build_garak_config()

    assert "plugins" in garak_conf
    assert garak_conf["plugins"]["target_type"] == "rest.RestGenerator"
    rest_gen = garak_conf["plugins"]["generators"]["rest"]["RestGenerator"]

    # Verify essential fields inspected from Garak 0.17.0 RestGenerator
    assert rest_gen["uri"] == "https://api.openai.com/v1/chat/completions"
    assert rest_gen["method"] == "post"
    assert "Authorization" in rest_gen["headers"]
    assert rest_gen["headers"]["Authorization"] == "Bearer sk-test-key"
    assert "$INPUT" in rest_gen["req_template"]
    assert "{{prompt}}" not in rest_gen["req_template"]
    assert rest_gen["response_json"] is True
    assert rest_gen["response_json_field"] == "choices.0.message.content"
    assert rest_gen["request_timeout"] == 30


def test_garak_jsonl_hit_parsed_into_finding_with_model_judged() -> None:
    """2. A Garak JSONL hit is correctly parsed into a Finding with MODEL_JUDGED status."""
    config = _create_test_config()
    runner = GarakRunner(config)

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        # Eval entry with fails > 0 represents a hit
        eval_hit = {
            "entry_type": "eval",
            "probe": "probes.dan.Dan_11_0",
            "detector": "detectors.dan.Dan",
            "passed": 3,
            "fails": 2,
            "total_evaluated": 5,
        }
        f.write(json.dumps(eval_hit) + "\n")
        jsonl_path = f.name

    findings = runner._parse_garak_output(jsonl_path)
    assert len(findings) == 1
    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.verification_status == VerificationStatus.MODEL_JUDGED
    assert finding.verification_method == VerificationMethod.MODEL_JUDGE
    assert finding.is_model_judged is True
    assert finding.is_deterministic is False
    assert finding.owasp_category == OWASPCategory.LLM01
    assert "Dan_11_0" in finding.title
    assert "2 failure(s)" in finding.evidence.summary


def test_garak_jsonl_miss_produces_no_finding() -> None:
    """3. A Garak JSONL miss produces no Finding."""
    config = _create_test_config()
    runner = GarakRunner(config)

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        # Eval entry with fails == 0 represents a complete pass (no vulnerability)
        eval_pass = {
            "entry_type": "eval",
            "probe": "probes.promptinject.HijackKillHumans",
            "detector": "detectors.promptinject.AttackDetected",
            "passed": 10,
            "fails": 0,
            "total_evaluated": 10,
        }
        # Non-eval metadata entry
        summary_record = {
            "entry_type": "probe_summary",
            "probe": "probes.promptinject.HijackKillHumans",
        }
        f.write(json.dumps(eval_pass) + "\n")
        f.write(json.dumps(summary_record) + "\n")
        jsonl_path = f.name

    findings = runner._parse_garak_output(jsonl_path)
    assert findings == []


def test_owasp_category_correctly_assigned_from_probe_namespace() -> None:
    """4. An OWASP category is correctly assigned from the probe namespace."""
    # LLM01: Prompt Injection / Jailbreaks / Encodings
    assert map_probe_to_owasp("probes.dan.Dan_11_0") == OWASPCategory.LLM01
    assert map_probe_to_owasp("probes.promptinject.Hijack") == OWASPCategory.LLM01
    assert map_probe_to_owasp("probes.encoding.InjectBase64") == OWASPCategory.LLM01

    # LLM02: Sensitive Information Disclosure
    assert map_probe_to_owasp("probes.leakreplay.GuardianCloze") == OWASPCategory.LLM02
    assert map_probe_to_owasp("probes.apikey.GetKey") == OWASPCategory.LLM02

    # LLM07: System Prompt Leakage
    assert map_probe_to_owasp("probes.sysprompt_extraction.SystemPromptExtraction") == OWASPCategory.LLM07

    # LLM05: Improper Output Handling (XSS / template injection)
    assert map_probe_to_owasp("probes.web_injection.MarkdownXSS") == OWASPCategory.LLM05
    assert map_probe_to_owasp("probes.exploitation.SQLInjectionEcho") == OWASPCategory.LLM05

    # LLM09: Misinformation
    assert map_probe_to_owasp("probes.misleading.FalseAssertion") == OWASPCategory.LLM09


def test_uninstalled_or_missing_garak_raises_integration_error() -> None:
    """5. Missing or uninstalled Garak raises IntegrationError."""
    config = _create_test_config()
    runner = GarakRunner(config, probe_namespaces=["dan"])

    with patch.dict("sys.modules", {"garak": None, "garak.cli": None}):
        with pytest.raises(IntegrationError, match="not installed or importable"):
            runner.run()


def test_empty_jsonl_output_returns_empty_list() -> None:
    """6. Empty JSONL output returns an empty list."""
    config = _create_test_config()
    runner = GarakRunner(config)

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        # completely empty file
        jsonl_path = f.name

    findings = runner._parse_garak_output(jsonl_path)
    assert findings == []

    # Non-existent file path also returns empty list cleanly
    assert runner._parse_garak_output("/tmp/nonexistent_report_file.jsonl") == []


def test_run_executes_garak_and_returns_findings() -> None:
    """Test full GarakRunner.run() execution with mocked Garak CLI."""
    config = _create_test_config()
    runner = GarakRunner(config, probe_namespaces=["dan"])

    fake_eval_hit = {
        "entry_type": "eval",
        "probe": "probes.dan.Dan_11_0",
        "detector": "detectors.dan.Dan",
        "passed": 0,
        "fails": 1,
        "total_evaluated": 1,
    }

    def mock_cli_main(args: list[str]) -> None:
        # Simulate writing hitlog/report file during run
        prefix_idx = args.index("--report_prefix")
        report_prefix = args[prefix_idx + 1]
        report_path = f"{report_prefix}.report.jsonl"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(fake_eval_hit) + "\n")

    mock_cli = MagicMock()
    mock_cli.main.side_effect = mock_cli_main
    mock_garak = MagicMock()
    mock_garak.cli = mock_cli

    with patch.dict("sys.modules", {"garak": mock_garak, "garak.cli": mock_cli}):
        findings = runner.run()
        assert len(findings) == 1
        assert findings[0].verification_status == VerificationStatus.MODEL_JUDGED
        assert findings[0].owasp_category == OWASPCategory.LLM01

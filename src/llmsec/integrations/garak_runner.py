"""Garak integration runner for automated REST vulnerability probing."""

import json
from pathlib import Path
import tempfile
from typing import Any
import yaml

from llmsec.config import LLMSecConfig
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

# Black-box testable categories per the OWASP Top 10 for LLMs coverage matrix
BLACK_BOX_CATEGORIES = {
    "promptinject",
    "dan",
    "goodside",
    "latentinjection",
    "leakreplay",
    "sysprompt_extraction",
    "apikey",
    "encoding",
    "ansiescape",
    "web_injection",
    "exploitation",
}

# Namespace to OWASP category mapping table
PROBE_OWASP_MAPPING = {
    "promptinject": OWASPCategory.LLM01,
    "dan": OWASPCategory.LLM01,
    "goodside": OWASPCategory.LLM01,
    "latentinjection": OWASPCategory.LLM01,
    "suffix": OWASPCategory.LLM01,
    "adaptive_attacks": OWASPCategory.LLM01,
    "grandma": OWASPCategory.LLM01,
    "dra": OWASPCategory.LLM01,
    "tap": OWASPCategory.LLM01,
    "encoding": OWASPCategory.LLM01,
    "ansiescape": OWASPCategory.LLM01,
    "badchars": OWASPCategory.LLM01,
    "smuggling": OWASPCategory.LLM01,
    "leakreplay": OWASPCategory.LLM02,
    "apikey": OWASPCategory.LLM02,
    "sysprompt_extraction": OWASPCategory.LLM07,
    "web_injection": OWASPCategory.LLM05,
    "exploitation": OWASPCategory.LLM05,
    "misleading": OWASPCategory.LLM09,
    "packagehallucination": OWASPCategory.LLM09,
    "malwaregen": OWASPCategory.LLM06,
    "agent_breaker": OWASPCategory.LLM06,
}


def get_available_probe_namespaces() -> list[str]:
    """Inspect the installed Garak library to discover currently active probe namespaces."""
    try:
        from garak import _plugins

        available_probes = _plugins.enumerate_plugins("probes")
        namespaces = {
            path.split(".")[1]
            for path, active in available_probes
            if active and len(path.split(".")) > 1
        }
        return sorted(namespaces)
    except Exception as exc:
        raise IntegrationError(
            "Failed to discover Garak probe plugins. Is Garak installed?",
            details=str(exc),
        ) from exc


def get_default_probe_namespaces() -> list[str]:
    """Derive default probe namespaces at the intersection of Garak availability and black-box testability."""
    try:
        available = set(get_available_probe_namespaces())
        return sorted(available.intersection(BLACK_BOX_CATEGORIES))
    except IntegrationError:
        return sorted(BLACK_BOX_CATEGORIES)


def map_probe_to_owasp(probe_identifier: str) -> OWASPCategory:
    """Map a Garak probe name or namespace to its corresponding OWASP Top 10 category."""
    clean_id = probe_identifier.strip().lower()
    if clean_id.startswith("probes."):
        clean_id = clean_id.split(".")[1]
    elif "." in clean_id:
        clean_id = clean_id.split(".")[0]

    return PROBE_OWASP_MAPPING.get(clean_id, OWASPCategory.LLM01)


class GarakRunner:
    """Integrates NVIDIA Garak to execute probe batteries against an authorized target endpoint."""

    def __init__(
        self,
        config: LLMSecConfig,
        probe_namespaces: list[str] | None = None,
    ) -> None:
        self.config: LLMSecConfig = config
        if probe_namespaces is not None:
            self.probe_namespaces: list[str] = probe_namespaces
        else:
            self.probe_namespaces = get_default_probe_namespaces()

    def _build_garak_config(self) -> dict[str, Any]:
        """Build Garak-compatible configuration dictionary for the REST generator."""
        req_template = json.dumps(self.config.request_body_template).replace(
            "{{prompt}}", "$INPUT"
        )
        method_str = (
            self.config.http_method.value.lower()
            if hasattr(self.config.http_method, "value")
            else str(self.config.http_method).lower()
        )

        return {
            "plugins": {
                "target_type": "rest.RestGenerator",
                "generators": {
                    "rest": {
                        "RestGenerator": {
                            "uri": str(self.config.target_url),
                            "method": method_str,
                            "headers": self.config.effective_headers(),
                            "req_template": req_template,
                            "response_json": True,
                            "response_json_field": self.config.response_extraction_path,
                            "request_timeout": int(self.config.timeout_seconds),
                        }
                    }
                },
            }
        }

    def _parse_garak_output(self, jsonl_path: str) -> list[Finding]:
        """Parse Garak JSONL report/hitlog and convert hits to llmsec Finding models.

        Each finding is strictly marked as MODEL_JUDGED.
        """
        path = Path(jsonl_path)
        if not path.is_file():
            return []

        findings: list[Finding] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    record = json.loads(line_str)
                except Exception:
                    continue

                entry_type = record.get("entry_type")

                # Handle report file eval records:
                if entry_type == "eval":
                    fails = record.get("fails", 0)
                    if fails > 0:
                        probe_name = record.get("probe", "unknown_probe")
                        detector_name = record.get("detector", "unknown_detector")
                        owasp_cat = map_probe_to_owasp(probe_name)

                        findings.append(
                            Finding(
                                title=f"Garak probe '{probe_name}' flagged by '{detector_name}'",
                                owasp_category=owasp_cat,
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                verification_status=VerificationStatus.MODEL_JUDGED,
                                verification_method=VerificationMethod.MODEL_JUDGE,
                                evidence=Evidence(
                                    summary=(
                                        f"Garak detector '{detector_name}' detected {fails} failure(s) "
                                        f"out of {record.get('total_evaluated', fails)} attempts."
                                    ),
                                    details=record,
                                ),
                                remediation="Review prompt sanitization, input filters, and system prompt boundaries.",
                            )
                        )

                # Handle hitlog records:
                elif "score" in record and ("probe" in record or "goal" in record):
                    probe_name = record.get("probe", "unknown_probe")
                    detector_name = record.get("detector", "unknown_detector")
                    owasp_cat = map_probe_to_owasp(probe_name)

                    findings.append(
                        Finding(
                            title=f"Garak hit: {probe_name} ({detector_name})",
                            owasp_category=owasp_cat,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            verification_status=VerificationStatus.MODEL_JUDGED,
                            verification_method=VerificationMethod.MODEL_JUDGE,
                            evidence=Evidence(
                                summary=f"Violation triggered during probe '{probe_name}'.",
                                raw_evidence=str(record.get("output", "")),
                                details=record,
                            ),
                            remediation="Review prompt sanitization, input filters, and system prompt boundaries.",
                        )
                    )

        return findings

    def run(self) -> list[Finding]:
        """Execute Garak probe battery via Python CLI API and parse structured findings."""
        try:
            import garak
            from garak import cli
        except ImportError as exc:
            raise IntegrationError(
                "Garak library is not installed or importable.", details=str(exc)
            ) from exc

        garak_config = self._build_garak_config()
        spec_str = ",".join(f"probes.{ns}" for ns in self.probe_namespaces)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            cfg_file = tmp_path / "garak_config.yaml"
            with open(cfg_file, "w", encoding="utf-8") as f:
                yaml.dump(garak_config, f)

            report_prefix = str(tmp_path / "garak_run")
            arguments = [
                "--config",
                str(cfg_file),
                "--target_type",
                "rest.RestGenerator",
                "--spec",
                spec_str,
                "--report_prefix",
                report_prefix,
                "--skip_unknown",
            ]

            try:
                cli.main(arguments)
            except Exception as exc:
                raise IntegrationError(
                    "Garak execution failed during probe run.", details=str(exc)
                ) from exc

            # Locate output files: prefer hitlog if present, then report
            hitlog_file = tmp_path / "garak_run.hitlog.jsonl"
            report_file = tmp_path / "garak_run.report.jsonl"

            if hitlog_file.exists():
                return self._parse_garak_output(str(hitlog_file))
            if report_file.exists():
                return self._parse_garak_output(str(report_file))

            return []

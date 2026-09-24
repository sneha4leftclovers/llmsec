"""DeepTeam integration runner for OWASP-mapped LLM red teaming assessments."""

import asyncio
import logging
import os
from typing import Any, Callable

from llmsec.config import LLMSecConfig
from llmsec.errors import ConfigurationError, IntegrationError
from llmsec.http_client import LLMSecClient
from llmsec.models import (
    Confidence,
    Evidence,
    Finding,
    OWASPCategory,
    Severity,
    VerificationMethod,
    VerificationStatus,
)

logger = logging.getLogger(__name__)

# Direct mapping for DeepTeam OWASP category labels (e.g., "LLM_01" -> OWASPCategory.LLM01)
DEEPTEAM_OWASP_LABEL_MAP = {
    "LLM_01": OWASPCategory.LLM01,
    "LLM_02": OWASPCategory.LLM02,
    "LLM_03": OWASPCategory.LLM03,
    "LLM_04": OWASPCategory.LLM04,
    "LLM_05": OWASPCategory.LLM05,
    "LLM_06": OWASPCategory.LLM06,
    "LLM_07": OWASPCategory.LLM07,
    "LLM_08": OWASPCategory.LLM08,
    "LLM_09": OWASPCategory.LLM09,
    "LLM_10": OWASPCategory.LLM10,
    "LLM01": OWASPCategory.LLM01,
    "LLM02": OWASPCategory.LLM02,
    "LLM03": OWASPCategory.LLM03,
    "LLM04": OWASPCategory.LLM04,
    "LLM05": OWASPCategory.LLM05,
    "LLM06": OWASPCategory.LLM06,
    "LLM07": OWASPCategory.LLM07,
    "LLM08": OWASPCategory.LLM08,
    "LLM09": OWASPCategory.LLM09,
    "LLM10": OWASPCategory.LLM10,
}

# Vulnerability type / class name fallback mapping to OWASP Top 10 (2025)
VULN_TYPE_OWASP_MAP = {
    # LLM01: Prompt Injection / Jailbreaks / Robustness
    "prompt_leakage": OWASPCategory.LLM07,
    "promptleakage": OWASPCategory.LLM07,
    "robustness": OWASPCategory.LLM01,
    "indirect_instruction": OWASPCategory.LLM01,
    "indirectinstruction": OWASPCategory.LLM01,
    "recursive_hijacking": OWASPCategory.LLM01,
    "recursivehijacking": OWASPCategory.LLM01,
    # LLM02: Sensitive Information Disclosure
    "pii_leakage": OWASPCategory.LLM02,
    "piileakage": OWASPCategory.LLM02,
    "intellectual_property": OWASPCategory.LLM02,
    "intellectualproperty": OWASPCategory.LLM02,
    # LLM05: Improper Output Handling
    "shell_injection": OWASPCategory.LLM05,
    "shellinjection": OWASPCategory.LLM05,
    "sql_injection": OWASPCategory.LLM05,
    "sqlinjection": OWASPCategory.LLM05,
    "ssrf": OWASPCategory.LLM05,
    "debug_access": OWASPCategory.LLM05,
    "debugaccess": OWASPCategory.LLM05,
    # LLM06: Excessive Agency
    "excessive_agency": OWASPCategory.LLM06,
    "excessiveagency": OWASPCategory.LLM06,
    "rbac": OWASPCategory.LLM06,
    "bfla": OWASPCategory.LLM06,
    "bola": OWASPCategory.LLM06,
    "tool_orchestration_abuse": OWASPCategory.LLM06,
    "toolorchestrationabuse": OWASPCategory.LLM06,
    "agent_identity_abuse": OWASPCategory.LLM06,
    "agentidentityabuse": OWASPCategory.LLM06,
    "exploit_tool_agent": OWASPCategory.LLM06,
    "exploittoolagent": OWASPCategory.LLM06,
    # LLM07: System Prompt Leakage
    "system_reconnaissance": OWASPCategory.LLM07,
    "systemreconnaissance": OWASPCategory.LLM07,
    # LLM08: Vector and Embedding Weaknesses
    "cross_context_retrieval": OWASPCategory.LLM08,
    "crosscontextretrieval": OWASPCategory.LLM08,
    # LLM09: Misinformation
    "misinformation": OWASPCategory.LLM09,
    "hallucination": OWASPCategory.LLM09,
    "competition": OWASPCategory.LLM09,
    # LLM04: Data and Model Poisoning / Safety Harms
    "bias": OWASPCategory.LLM04,
    "toxicity": OWASPCategory.LLM04,
    "illegal_activity": OWASPCategory.LLM04,
    "illegalactivity": OWASPCategory.LLM04,
    "graphic_content": OWASPCategory.LLM04,
    "graphiccontent": OWASPCategory.LLM04,
    "personal_safety": OWASPCategory.LLM04,
    "personalsafety": OWASPCategory.LLM04,
    "child_protection": OWASPCategory.LLM04,
    "childprotection": OWASPCategory.LLM04,
    "ethics": OWASPCategory.LLM04,
    "fairness": OWASPCategory.LLM04,
}


def _get_default_vulnerabilities() -> list:
    """Retrieve default vulnerability instances from DeepTeam's OWASPTop10 framework."""
    try:
        from deepteam.frameworks import OWASPTop10

        framework = OWASPTop10()
        return list(framework.vulnerabilities)
    except Exception as exc:
        logger.warning("Could not instantiate DeepTeam OWASPTop10: %s", exc)
        return []


class DeepTeamRunner:
    """Runs DeepTeam automated red teaming assessments against an authorized LLM target."""

    def __init__(
        self,
        config: LLMSecConfig,
        vulnerabilities: list | None = None,
    ) -> None:
        self.config: LLMSecConfig = config
        self.client: LLMSecClient = LLMSecClient(config)

        if vulnerabilities is not None:
            self.vulnerabilities = vulnerabilities
        else:
            self.vulnerabilities = _get_default_vulnerabilities()

    def _build_model_callback(self) -> Callable:
        """Return an async callback wrapping LLMSecClient.probe().

        Accepts a prompt string and returns the extracted response text.
        Returns an empty string if extracted_text is None.
        Raises IntegrationError if client.probe() encounters an error.
        """
        client = self.client

        async def model_callback(prompt: str, *args: Any, **kwargs: Any) -> str:
            try:
                # LLMSecClient.probe is synchronous; run in thread to remain non-blocking
                probe_req, probe_resp = await asyncio.to_thread(client.probe, prompt)
                if probe_resp.extracted_text is not None:
                    return probe_resp.extracted_text
                return ""
            except Exception as exc:
                raise IntegrationError(
                    "LLMSecClient probe failed inside DeepTeam callback.",
                    details=str(exc),
                ) from exc

        return model_callback

    def _convert_result(self, result: Any) -> Finding | None:
        """Convert a DeepTeam result object into a Finding with MODEL_JUDGED verification status.

        Returns None if the result cannot be mapped or indicates a clean pass.
        """
        # Determine whether this result represents a vulnerability hit:
        # In DeepTeam, a score of 1.0 means pass, while 0.0 or failing means hit.
        score = getattr(result, "score", None)
        passed = getattr(result, "passed", None)
        if passed is True or (score is not None and score > 0):
            # Clean pass; no vulnerability finding
            return None

        # 1. Check if DeepTeam exposes an OWASP risk category label
        owasp_cat: OWASPCategory | None = None
        risk_category = getattr(result, "risk_category", None) or getattr(
            result, "owasp_category", None
        )

        if risk_category:
            cat_key = str(risk_category).strip().upper()
            if cat_key in DEEPTEAM_OWASP_LABEL_MAP:
                owasp_cat = DEEPTEAM_OWASP_LABEL_MAP[cat_key]

        # 2. Fall back to mapping vulnerability type or class name
        vuln_name = getattr(result, "vulnerability", None)
        vuln_type = getattr(result, "vulnerability_type", None)
        if vuln_type is not None and hasattr(vuln_type, "value"):
            vuln_type = vuln_type.value

        title_vuln = str(vuln_name or vuln_type or "").strip()
        lookup_key = (
            str(vuln_type or vuln_name or "").strip().lower().replace(" ", "_")
        )

        if owasp_cat is None and lookup_key:
            owasp_cat = VULN_TYPE_OWASP_MAP.get(lookup_key)

        # Also check lookup on title_vuln if different
        if owasp_cat is None and title_vuln:
            owasp_cat = VULN_TYPE_OWASP_MAP.get(title_vuln.lower().replace(" ", "_"))

        # If result cannot be mapped to any known OWASP category, skip without raising
        if owasp_cat is None:
            return None

        reason = getattr(result, "reason", None) or f"DeepTeam evaluated {title_vuln} as vulnerable."
        actual_output = getattr(result, "actual_output", None) or ""
        test_input = getattr(result, "input", None) or ""

        return Finding(
            title=f"DeepTeam vulnerability: {title_vuln or owasp_cat.label}",
            owasp_category=owasp_cat,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.MODEL_JUDGED,
            verification_method=VerificationMethod.MODEL_JUDGE,
            evidence=Evidence(
                summary=str(reason),
                raw_evidence=str(actual_output),
                details={
                    "vulnerability": title_vuln,
                    "input_prompt": test_input,
                    "score": score,
                    "attack_method": getattr(result, "attack_method", None),
                },
            ),
            remediation="Review system instructions, output handling, and defense filters.",
        )

    def run(self) -> list[Finding]:
        """Execute DeepTeam red teaming assessment and parse findings.

        Raises:
            ConfigurationError: If OPENAI_API_KEY is not set in the environment.
            IntegrationError: If DeepTeam is not installed or execution fails.
        """
        # Validate that OPENAI_API_KEY is present
        if not os.environ.get("OPENAI_API_KEY"):
            raise ConfigurationError(
                "OPENAI_API_KEY environment variable is required for DeepTeam evaluation."
            )

        try:
            import deepteam
            from deepteam import red_team
        except ImportError as exc:
            raise IntegrationError(
                "DeepTeam is not installed or importable.",
                details=str(exc),
            ) from exc

        callback = self._build_model_callback()

        try:
            assessment = red_team(
                model_callback=callback,
                vulnerabilities=self.vulnerabilities,
                async_mode=False,
            )
        except Exception as exc:
            raise IntegrationError(
                "DeepTeam red teaming evaluation failed during execution.",
                details=str(exc),
            ) from exc

        test_cases = getattr(assessment, "test_cases", [])
        findings: list[Finding] = []
        for tc in test_cases:
            converted = self._convert_result(tc)
            if converted is not None:
                findings.append(converted)

        return findings

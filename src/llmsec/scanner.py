"""Scanner orchestration engine for llmsec.

Wires the canary engine, HTTP client, and authorization suite into a single
runnable scan that returns a ScanResult. All probe-level failures are collected
as error strings rather than aborting the scan.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from llmsec.authz import AuthzTestSuite
from llmsec.canary import CanarySession
from llmsec.config import LLMSecConfig
from llmsec.errors import LLMSecConnectionError
from llmsec.http_client import LLMSecClient
from llmsec.models import (
    AuthzFinding,
    CanaryFinding,
    Confidence,
    Evidence,
    Finding,
    OWASPCategory,
    ScanResult,
    Severity,
    VerificationMethod,
    VerificationStatus,
)

logger = logging.getLogger(__name__)


def _canary_finding_to_finding(cf: CanaryFinding, prompt: str, target_url: str) -> Finding:
    """Convert a CanaryFinding (raw token match) into a full Finding.

    Always maps to LLM07 (System Prompt Leakage) because canary probes target
    system-prompt extraction. Severity is HIGH — confirmed via exact token match.
    """
    return Finding(
        title=f"System prompt canary token '{cf.token}' detected in response",
        owasp_category=OWASPCategory.LLM07,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        verification_status=VerificationStatus.CONFIRMED_DETERMINISTIC,
        verification_method=VerificationMethod.CANARY_TOKEN,
        evidence=Evidence(
            summary=(
                f"Canary token '{cf.token}' (label: '{cf.label}') was found verbatim "
                f"in the model response at character offset {cf.finding_index}. "
                "This confirms system-prompt content was disclosed to the probe."
            ),
            matched_canary=cf.token,
            canary_leak_offset=cf.finding_index,
            raw_evidence=cf.matched_in_response[:500],
            details={
                "run_id": cf.run_id,
                "canary_label": cf.label,
                "probe_prompt": prompt,
                "target_url": target_url,
            },
        ),
        reproduction_steps=[
            f"Send the probe prompt: \"{prompt}\"",
            f"Inspect the response for token: \"{cf.token}\"",
            f"Token found at character offset {cf.finding_index}.",
        ],
        remediation=(
            "Ensure the system prompt is not accessible to user-controlled inputs. "
            "Add prompt-injection guardrails and review context window boundaries."
        ),
    )


class Scanner:
    """Orchestrates a full llmsec assessment scan.

    Runs configured test suites (canary, authz) against the target endpoint,
    collecting findings and errors without aborting on individual probe failures.
    """

    def __init__(self, config: LLMSecConfig) -> None:
        self.config = config
        self.client = LLMSecClient(config)

    def run(self) -> ScanResult:
        """Execute all selected test suites and return a ScanResult.

        - Canary suite: seeds a token into each probe prompt, sends it, scans response.
        - Authz suite: runs two-identity boundary probes via AuthzTestSuite.
        - Per-probe exceptions are caught and recorded in errors; scan continues.
        - Missing configuration for a suite adds to skipped_suites, not an exception.
        """
        session = CanarySession()
        target_url = str(self.config.target_url)
        suites = [s.lower() for s in self.config.selected_test_suites]

        started_at = datetime.now(timezone.utc)

        all_canary_findings: list[CanaryFinding] = []
        all_findings: list[Finding] = []
        all_authz_findings: list[AuthzFinding] = []
        errors: list[str] = []
        skipped_suites: list[str] = []

        # ------------------------------------------------------------------ #
        # Canary suite                                                        #
        # ------------------------------------------------------------------ #
        if "canary" in suites:
            for idx, prompt in enumerate(self.config.canary.probe_prompts):
                label = f"canary_probe_{idx}"
                try:
                    # Seed a unique token for this prompt
                    token = session.seed(label, prompt)
                    # Embed the token into the prompt so it can be detected if echoed
                    injected_prompt = f"{prompt} [{token}]"
                    _req, resp = self.client.probe(injected_prompt)
                    # Scan the response for any registered canary tokens
                    raw_text = resp.raw_body
                    cf_list = session.scan(raw_text)
                    all_canary_findings.extend(cf_list)
                    for cf in cf_list:
                        finding = _canary_finding_to_finding(cf, injected_prompt, target_url)
                        all_findings.append(finding)
                        logger.info(
                            "Canary token detected: label=%s token=%s offset=%d",
                            cf.label, cf.token, cf.finding_index,
                        )
                except LLMSecConnectionError as exc:
                    msg = f"Canary probe '{label}' failed (connection error): {exc}"
                    errors.append(msg)
                    logger.warning(msg)
                except Exception as exc:  # noqa: BLE001
                    msg = f"Canary probe '{label}' failed: {type(exc).__name__}: {exc}"
                    errors.append(msg)
                    logger.warning(msg)

        # ------------------------------------------------------------------ #
        # Authz suite                                                        #
        # ------------------------------------------------------------------ #
        if "authz" in suites:
            identities = self.config.test_identities  # uses the alias property
            has_secondary = (
                identities is not None
                and identities.secondary_identity is not None
            )
            if not has_secondary:
                msg = (
                    "Authz suite skipped: 'test_identities.secondary_identity' is not configured. "
                    "Add a secondary_identity to run cross-tenant boundary probes."
                )
                errors.append(msg)
                skipped_suites.append("authz")
                logger.info(msg)
            else:
                try:
                    suite = AuthzTestSuite(self.client, session)
                    # Seed identity canaries before running probes
                    _seed_identity_canaries(suite, session, identities)
                    authz_results = suite.run(self.config.canary.probe_prompts)
                    all_authz_findings.extend(authz_results)
                except Exception as exc:  # noqa: BLE001
                    msg = f"Authz suite failed: {type(exc).__name__}: {exc}"
                    errors.append(msg)
                    logger.warning(msg)

        completed_at = datetime.now(timezone.utc)

        return ScanResult(
            run_id=session.run_id,
            config_target_url=target_url,
            started_at=started_at,
            completed_at=completed_at,
            findings=all_findings,
            authz_findings=all_authz_findings,
            canary_findings=all_canary_findings,
            errors=errors,
            skipped_suites=skipped_suites,
        )


def _seed_identity_canaries(
    suite: AuthzTestSuite,
    session: CanarySession,
    identities: Any,
) -> None:
    """Pre-seed canary tokens for both identities so the authz suite can detect cross-leakage."""
    primary = identities.primary
    secondary = identities.secondary
    if primary:
        try:
            suite.seed_identity(primary, "context", f"confidential-data-for-{primary.identity_id}")
        except Exception:  # noqa: BLE001— label may already be seeded, skip silently
            pass
    if secondary:
        try:
            suite.seed_identity(secondary, "context", f"confidential-data-for-{secondary.identity_id}")
        except Exception:  # noqa: BLE001
            pass

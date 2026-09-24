"""Two-identity authorization and cross-tenant test suite (BOLA/IDOR for LLMs)."""

from datetime import datetime, timezone

from llmsec.canary import CanarySession
from llmsec.config import Identity, TestIdentityConfig
from llmsec.errors import ConfigurationError
from llmsec.http_client import LLMSecClient
from llmsec.models import AuthzFinding, OWASPCategory


class AuthzTestSuite:
    """Evaluates cross-user and cross-tenant authorization boundaries between two test identities."""

    def __init__(self, client: LLMSecClient, session: CanarySession) -> None:
        self.client: LLMSecClient = client
        self.session: CanarySession = session

    def seed_identity(
        self,
        identity: TestIdentityConfig | Identity,
        label: str,
        content: str,
    ) -> str:
        """Register a seed for a specific identity using a namespaced label ('<identity_id>:<label>').

        Returns the generated canary token string.
        Raises CanaryError if the namespaced label is duplicated.
        """
        identity_id = getattr(identity, "identity_id", None) or getattr(identity, "name", "identity")
        namespaced_label = f"{identity_id}:{label}"
        return self.session.seed(namespaced_label, content)

    def _resolve_owasp_category(self) -> OWASPCategory:
        """Determine OWASP category: LLM08 for RAG / vector targets, LLM02 otherwise."""
        url_str = str(self.client.config.target_url).lower()
        suites = [s.lower() for s in getattr(self.client.config, "selected_test_suites", [])]
        if "rag" in url_str or "vector" in url_str or any("rag" in s or "vector" in s for s in suites):
            return OWASPCategory.LLM08
        return OWASPCategory.LLM02

    def run(self, probes: list[str]) -> list[AuthzFinding]:
        """Execute cross-boundary probe evaluations across primary and secondary identities.

        For each probe prompt:
          1. Sends request as Primary Identity; checks if Secondary Identity's canary leaked.
          2. Sends request as Secondary Identity; checks if Primary Identity's canary leaked.

        Raises ConfigurationError if test_identities is missing or incomplete.
        Returns a flat list of AuthzFinding objects ordered by timestamp ascending.
        """
        identities_cfg = getattr(self.client.config, "test_identities", None)
        if identities_cfg is None:
            identities_cfg = getattr(self.client.config, "identities", None)

        if identities_cfg is None:
            raise ConfigurationError(
                "Missing test_identities configuration. AuthzTestSuite requires configured test identities."
            )

        primary = getattr(identities_cfg, "primary", None) or getattr(identities_cfg, "primary_identity", None)
        secondary = getattr(identities_cfg, "secondary", None) or getattr(identities_cfg, "secondary_identity", None)

        if primary is None or secondary is None:
            raise ConfigurationError(
                "Both primary and secondary test identities must be configured for AuthzTestSuite."
            )

        primary_id = primary.identity_id
        secondary_id = secondary.identity_id
        owasp_cat = self._resolve_owasp_category()
        findings: list[AuthzFinding] = []

        for prompt in probes:
            # 1. Primary identity sends the probe
            req_p, resp_p = self.client.probe(prompt, identity=primary)
            canary_matches_p = self.session.scan(resp_p.raw_body)
            for cm in canary_matches_p:
                token_owner_id = cm.label.split(":", 1)[0] if ":" in cm.label else cm.label
                if token_owner_id == secondary_id:
                    findings.append(
                        AuthzFinding(
                            run_id=self.session.run_id,
                            probe_prompt=prompt,
                            requesting_identity_id=primary_id,
                            leaking_identity_id=secondary_id,
                            canary_finding=cm,
                            probe_request=req_p,
                            probe_response=resp_p,
                            owasp_category=owasp_cat,
                            timestamp=datetime.now(timezone.utc),
                        )
                    )

            # 2. Secondary identity sends the probe
            req_s, resp_s = self.client.probe(prompt, identity=secondary)
            canary_matches_s = self.session.scan(resp_s.raw_body)
            for cm in canary_matches_s:
                token_owner_id = cm.label.split(":", 1)[0] if ":" in cm.label else cm.label
                if token_owner_id == primary_id:
                    findings.append(
                        AuthzFinding(
                            run_id=self.session.run_id,
                            probe_prompt=prompt,
                            requesting_identity_id=secondary_id,
                            leaking_identity_id=primary_id,
                            canary_finding=cm,
                            probe_request=req_s,
                            probe_response=resp_s,
                            owasp_category=owasp_cat,
                            timestamp=datetime.now(timezone.utc),
                        )
                    )

        findings.sort(key=lambda finding: finding.timestamp)
        return findings

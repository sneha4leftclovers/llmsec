"""Report generation module for llmsec security assessments.

Generates executive and technical reports in HTML and PDF formats using Jinja2 and WeasyPrint.
"""

import base64
from datetime import datetime, timezone
import logging
from pathlib import Path
import tempfile
from typing import Any
import urllib.parse
import jinja2

from llmsec import __version__
from llmsec.config import LLMSecConfig
from llmsec.errors import IntegrationError, ReportError
from llmsec.models import (
    Finding,
    OWASPCategory,
    Severity,
    VerificationMethod,
    VerificationStatus,
)

logger = logging.getLogger(__name__)

OWASP_COVERAGE = {
    OWASPCategory.LLM01: "Direct & indirect injection probing",
    OWASPCategory.LLM02: "Canary token cross-boundary leakage detection",
    OWASPCategory.LLM03: "not applicable (black-box)",
    OWASPCategory.LLM04: "not applicable (black-box)",
    OWASPCategory.LLM05: "Partial coverage (payload reflection & output decoding)",
    OWASPCategory.LLM06: "Partial coverage (two-identity BOLA / privilege escalation probing)",
    OWASPCategory.LLM07: "Canary-seeded system prompt extraction probing",
    OWASPCategory.LLM08: "Partial coverage (cross-context vector store canary retrieval)",
    OWASPCategory.LLM09: "Model-judged factual hallucination & safety checks",
    OWASPCategory.LLM10: "Partial coverage (rate limit and payload boundary testing)",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

TEMPLATE_DIR = Path(__file__).parent / "templates"


class BlockedURLFetcher:
    """URL fetcher that blocks external URLs and local file access.

    Only data: URIs (inline assets) are permitted. All http/https/ftp/file requests are blocked.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.refused_urls: list[str] = []
        self._fail_on_errors: bool = False

    def fetch(self, url: str, headers: dict | None = None) -> Any:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme == "data":
            try:
                from weasyprint.urls import URLFetcherResponse
                header, _, data_part = url[5:].partition(",")
                is_base64 = ";base64" in header
                raw_data = (
                    base64.b64decode(data_part)
                    if is_base64
                    else urllib.parse.unquote_to_bytes(data_part)
                )
                mime = header.split(";")[0] or "text/plain"
                return URLFetcherResponse(
                    url=url,
                    body=raw_data,
                    headers={"Content-Type": mime},
                    status=200,
                )
            except ImportError:
                return {"url": url, "body": b"", "status": 200}

        self.refused_urls.append(url)
        raise ValueError(f"Resource loading blocked for security: {url} (scheme: {scheme or 'none'})")

    def __call__(self, url: str) -> Any:
        return self.fetch(url)


def sanitize_target_url(raw_url: str) -> str:
    """Strip query string, fragments, and userinfo (credentials) from a URL."""
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        # Remove user:pass@ from netloc
        netloc = parsed.netloc.split("@")[-1]
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except Exception:
        return raw_url


class ReportGenerator:
    """Generates structured assessment reports in HTML and PDF formats."""

    def __init__(self, findings: list[Finding], config: LLMSecConfig) -> None:
        self.findings = findings
        self.config = config

    def _collect_secrets(self) -> set[str]:
        """Collect sensitive tokens and credentials from config that must never be rendered."""
        secrets: set[str] = set()
        # Collect from auth_headers
        for val in self.config.auth_headers.values():
            if val and len(val.strip()) > 3:
                secrets.add(val.strip())
                if val.lower().startswith("bearer "):
                    token = val.split(" ", 1)[1].strip()
                    if len(token) > 3:
                        secrets.add(token)

        # Collect from test_identities if present
        if self.config.test_identities:
            for ident in (
                self.config.test_identities.primary,
                self.config.test_identities.secondary,
            ):
                if ident and ident.headers:
                    for h_val in ident.headers.values():
                        if h_val and len(h_val.strip()) > 3:
                            secrets.add(h_val.strip())
                            if h_val.lower().startswith("bearer "):
                                token = h_val.split(" ", 1)[1].strip()
                                if len(token) > 3:
                                    secrets.add(token)
        return secrets

    def _scrub_secrets(self, content: str, secrets: set[str]) -> str:
        """Replace all occurrences of known secrets with [REDACTED]."""
        scrubbed = content
        for secret in secrets:
            if secret in scrubbed:
                scrubbed = scrubbed.replace(secret, "[REDACTED]")
        return scrubbed

    def _determine_run_id(self) -> str:
        """Extract run ID from findings evidence details if available; otherwise return 'not recorded'."""
        for f in self.findings:
            if f.evidence.details and "run_id" in f.evidence.details:
                return str(f.evidence.details["run_id"])
        return "not recorded"

    def _determine_testing_period(self) -> str:
        """Compute the timestamp range from finding creation times; otherwise return 'not recorded'."""
        if not self.findings:
            return "not recorded"
        timestamps = [f.created_at for f in self.findings if f.created_at]
        if not timestamps:
            return "not recorded"
        earliest = min(timestamps).strftime("%Y-%m-%d %H:%M:%S UTC")
        latest = max(timestamps).strftime("%Y-%m-%d %H:%M:%S UTC")
        if earliest == latest:
            return earliest
        return f"{earliest} to {latest}"

    def _build_coverage_matrix(self) -> list[dict[str, Any]]:
        """Construct the OWASP coverage matrix.

        Per specifications:
        - Never infer 'tested' from existence of findings.
        - Never treat 'selected in config' as 'ran'.
        - If run status is not recorded, print 'run status not recorded'.
        - LLM03 and LLM04 are marked 'not applicable (black-box)'.
        - Neither may appear as 'passed'.
        """
        matrix: list[dict[str, Any]] = []
        for cat in OWASPCategory:
            capability = OWASP_COVERAGE.get(cat, "not applicable (black-box)")
            count = sum(1 for f in self.findings if f.owasp_category == cat)

            if cat in (OWASPCategory.LLM03, OWASPCategory.LLM04):
                status = "not applicable (black-box)"
            else:
                # Run status is not captured in config or findings schema
                status = "run status not recorded"

            matrix.append({
                "code": cat.code,
                "label": cat.label,
                "capability": capability,
                "status": status,
                "findings_count": count,
            })
        return matrix

    def _generate_narrative(self) -> str:
        """Generate a deterministic risk narrative from a fixed template (not an LLM)."""
        if not self.findings:
            return "no findings recorded in the tested categories"

        deterministic_count = sum(1 for f in self.findings if f.is_deterministic)
        model_judged_count = sum(1 for f in self.findings if f.is_model_judged)
        critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)

        return (
            f"Assessment completed with {len(self.findings)} finding(s) recorded across evaluated categories: "
            f"{deterministic_count} confirmed deterministically via cryptographic canary verification, "
            f"and {model_judged_count} evaluated via model judgment. "
            f"Severity distribution includes {critical_count} critical and {high_count} high severity issues."
        )

    def render_html(self, output_path: str | Path | None = None) -> str:
        """Render the assessment report into HTML with autoescaping and secret scrubbing.

        If output_path is provided, writes the rendered HTML to that path and returns the path string.
        If output_path is None, returns the rendered HTML string directly.
        """
        sorted_findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=jinja2.select_autoescape(
                enabled_extensions=("html", "xml"),
                default_for_string=True,
                default=True,
            ),
        )
        template = env.get_template("report.html")

        auth = self.config.authorization
        auth_statement = (
            f"This security assessment was explicitly authorized by {auth.authorized_by or 'not recorded'} "
            f"under scope '{auth.scope_description or 'not recorded'}'. Authorized testing acknowledged."
        )
        sanitized_url = sanitize_target_url(str(self.config.target_url))

        severity_counts = {
            "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
            "informational": sum(1 for f in self.findings if f.severity == Severity.INFORMATIONAL),
        }

        context = {
            "target_url": sanitized_url,
            "generation_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "tool_version": __version__,
            "run_id": self._determine_run_id(),
            "testing_period": self._determine_testing_period(),
            "auth_statement": auth_statement,
            "tool_versions": f"llmsec {__version__} (sub-tools: not recorded)",
            "probe_list": "not recorded",
            "narrative": self._generate_narrative(),
            "severity_counts": severity_counts,
            "coverage_matrix": self._build_coverage_matrix(),
            "findings": sorted_findings,
        }

        rendered = template.render(**context)
        secrets = self._collect_secrets()
        scrubbed = self._scrub_secrets(rendered, secrets)

        if output_path is not None:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(scrubbed, encoding="utf-8")
            return str(out_file)

        return scrubbed

    def render_pdf(self, output_path: str | Path) -> str:
        """Render the report as a PDF using WeasyPrint via an intermediate temp HTML file.

        Raises:
            IntegrationError: If WeasyPrint is not installed or importable.
            ReportError: If WeasyPrint rendering encounters a fatal error.

        Returns:
            The output path as a string.
        """
        try:
            import weasyprint
        except ImportError as exc:
            raise IntegrationError(
                "WeasyPrint is not installed or importable. "
                "Please install it using 'pip install weasyprint' to enable PDF report generation.",
                details=str(exc),
            ) from exc

        out_pdf = Path(output_path)
        out_pdf.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as tmp:
            tmp_html_path = tmp.name

        try:
            self.render_html(tmp_html_path)
            html_doc = weasyprint.HTML(
                filename=tmp_html_path,
                url_fetcher=BlockedURLFetcher(),
            )
            html_doc.write_pdf(target=str(out_pdf))
        except IntegrationError:
            raise
        except Exception as exc:
            raise ReportError(
                f"WeasyPrint failed to render PDF report: {exc}",
                details=str(exc),
            ) from exc
        finally:
            Path(tmp_html_path).unlink(missing_ok=True)

        return str(out_pdf)

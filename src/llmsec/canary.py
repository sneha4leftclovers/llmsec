"""Canary token generation, tracking, and response scanning engine."""

from datetime import datetime, timezone
import hashlib
import hmac
import uuid

from llmsec.errors import CanaryError
from llmsec.models import CanaryFinding


def generate_canary_token(run_id: str, label: str, content: str) -> str:
    """Generate a deterministic, human-recognizable canary token using HMAC-SHA256.

    Derives a 16-hex character token from the run ID, seed label, and seed content.
    """
    key = run_id.encode("utf-8")
    message = f"{label}:{content}".encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()[:16]
    return f"CANARY-{digest}"


class CanarySession:
    """Manages canary token lifecycle for an assessment run.

    Provides deterministic token seeding and exact-match response scanning.
    """

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id: str = run_id if run_id is not None else str(uuid.uuid4())
        self._tokens: dict[str, str] = {}  # label -> token

    def seed(self, label: str, content: str) -> str:
        """Register a label and content pair, generating and returning its unique canary token.

        Raises CanaryError if the label has already been seeded in this session.
        """
        if label in self._tokens:
            raise CanaryError(
                f"Canary label '{label}' has already been seeded in this session."
            )
        token = generate_canary_token(self.run_id, label, content)
        self._tokens[label] = token
        return token

    def scan(self, response: str) -> list[CanaryFinding]:
        """Search the response string for every registered canary token.

        Returns one CanaryFinding per exact match, ordered by character position.
        Never performs partial or fuzzy matching.
        """
        findings: list[CanaryFinding] = []
        for label, token in self._tokens.items():
            start = 0
            while True:
                idx = response.find(token, start)
                if idx == -1:
                    break
                findings.append(
                    CanaryFinding(
                        run_id=self.run_id,
                        label=label,
                        token=token,
                        matched_in_response=response,
                        finding_index=idx,
                        timestamp=datetime.now(timezone.utc),
                    )
                )
                start = idx + len(token)

        findings.sort(key=lambda finding: finding.finding_index)
        return findings

    def tokens(self) -> dict[str, str]:
        """Return a copy of registered label -> token mappings."""
        return dict(self._tokens)

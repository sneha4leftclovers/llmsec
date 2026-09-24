"""Unit tests for the Canary Engine (CanarySession and token generation)."""

from datetime import datetime, timezone
import re
import pytest

from llmsec.canary import CanarySession, generate_canary_token
from llmsec.errors import CanaryError
from llmsec.models import CanaryFinding


def test_token_generation_deterministic() -> None:
    """1. Token generation is deterministic: same inputs -> same token every time."""
    run_id = "550e8400-e29b-41d4-a716-446655440000"
    label = "system_prompt"
    content = "You are an internal confidential assistant."

    token1 = generate_canary_token(run_id, label, content)
    token2 = generate_canary_token(run_id, label, content)
    assert token1 == token2

    # Verify session-level determinism
    session1 = CanarySession(run_id=run_id)
    t1 = session1.seed(label, content)
    session2 = CanarySession(run_id=run_id)
    t2 = session2.seed(label, content)
    assert t1 == t2
    assert t1 == token1


def test_token_generation_unique_for_different_labels() -> None:
    """2. Token generation is unique: different labels produce different tokens."""
    session = CanarySession(run_id="run-fixed-123")
    token_a = session.seed("tenant_a_doc", "Sensitive financial report")
    token_b = session.seed("tenant_b_doc", "Sensitive financial report")
    assert token_a != token_b

    # Different content with same label in separate sessions
    s1 = CanarySession(run_id="run-fixed-123")
    s2 = CanarySession(run_id="run-fixed-123")
    t_doc1 = s1.seed("doc", "content 1")
    t_doc2 = s2.seed("doc", "content 2")
    assert t_doc1 != t_doc2


def test_token_format() -> None:
    """3. Token format matches CANARY- prefix + 16 hex chars."""
    session = CanarySession()
    token = session.seed("pii_email", "admin@corp.internal")
    match = re.match(r"^CANARY-[0-9a-fA-F]{16}$", token)
    assert match is not None
    prefix, hex_part = token.split("-", 1)
    assert prefix == "CANARY"
    assert len(hex_part) == 16
    assert all(c in "0123456789abcdefABCDEF" for c in hex_part)


def test_seed_duplicate_label_raises_canary_error() -> None:
    """4. seed() with a duplicate label raises CanaryError."""
    session = CanarySession()
    session.seed("system_prompt", "first content")

    with pytest.raises(CanaryError, match="has already been seeded"):
        session.seed("system_prompt", "different content")


def test_scan_returns_empty_when_no_token_present() -> None:
    """5. scan() returns an empty list when no token is present in the response."""
    session = CanarySession()
    session.seed("confidential_memo", "Quarterly projections")
    findings = session.scan("The response text contains standard public information.")
    assert findings == []


def test_scan_detects_single_token() -> None:
    """6. scan() detects a single token correctly and returns one CanaryFinding."""
    session = CanarySession(run_id="session-single-test")
    token = session.seed("tenant_record", "SSN: 000-11-2222")

    response_text = f"The query recalled context including {token} in paragraph 2."
    findings = session.scan(response_text)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, CanaryFinding)
    assert finding.run_id == "session-single-test"
    assert finding.label == "tenant_record"
    assert finding.token == token
    assert finding.matched_in_response == response_text


def test_scan_detects_multiple_tokens_in_one_response() -> None:
    """7. scan() detects multiple tokens in one response."""
    session = CanarySession()
    t1 = session.seed("label_first", "Content 1")
    t2 = session.seed("label_second", "Content 2")
    t3 = session.seed("label_third", "Content 3")

    response_text = f"Leak report: Found {t1}, followed by {t2}, but omitted the third."
    findings = session.scan(response_text)

    assert len(findings) == 2
    matched_tokens = [f.token for f in findings]
    assert matched_tokens == [t1, t2]
    assert findings[0].label == "label_first"
    assert findings[1].label == "label_second"


def test_scan_does_not_match_truncated_token() -> None:
    """8. scan() does not match a truncated token (partial string - no fuzzy matching)."""
    session = CanarySession()
    token = session.seed("secret_key", "SuperSecretData")
    # Truncate the token by removing last 2 characters
    truncated_token = token[:-2]
    assert len(truncated_token) < len(token)

    response_text = f"Output containing partial canary: {truncated_token}"
    findings = session.scan(response_text)
    assert findings == []

    # Also test just prefix
    assert session.scan("Output with prefix only: CANARY-") == []


def test_scan_does_not_match_different_session_token() -> None:
    """9. scan() does not match a token from a different session (different run ID)."""
    session_alpha = CanarySession(run_id="session-alpha-id")
    session_beta = CanarySession(run_id="session-beta-id")

    token_alpha = session_alpha.seed("shared_label", "same content")
    token_beta = session_beta.seed("shared_label", "same content")
    assert token_alpha != token_beta

    # Beta scans response containing Alpha's token
    response_with_alpha = f"Leaked token: {token_alpha}"
    beta_findings = session_beta.scan(response_with_alpha)
    assert beta_findings == []

    # Alpha correctly detects its own token
    alpha_findings = session_alpha.scan(response_with_alpha)
    assert len(alpha_findings) == 1
    assert alpha_findings[0].token == token_alpha


def test_finding_index_is_correct_character_position() -> None:
    """10. finding_index is the correct character position of the match in the response."""
    session = CanarySession()
    token = session.seed("target_label", "content")
    prefix = "A" * 35  # Exactly 35 chars
    suffix = "B" * 20
    response_text = f"{prefix}{token}{suffix}"

    findings = session.scan(response_text)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_index == 35
    assert response_text[finding.finding_index : finding.finding_index + len(token)] == token


def test_canary_finding_timestamp_is_valid_utc_datetime() -> None:
    """11. The CanaryFinding timestamp is a valid UTC datetime."""
    session = CanarySession()
    token = session.seed("timestamp_test", "content")
    findings = session.scan(f"Evidence text {token}")

    assert len(findings) == 1
    ts = findings[0].timestamp
    assert isinstance(ts, datetime)
    assert ts.tzinfo is not None
    # Check that it represents UTC timezone
    assert ts.utcoffset() == timezone.utc.utcoffset(ts)


def test_session_tokens_dictionary() -> None:
    """Verify session.tokens() returns an accurate dictionary of all registered tokens."""
    session = CanarySession(run_id="tokens-dict-run")
    t1 = session.seed("k1", "v1")
    t2 = session.seed("k2", "v2")

    tokens_map = session.tokens()
    assert tokens_map == {"k1": t1, "k2": t2}
    # Ensure it's a defensive copy
    tokens_map["k3"] = "fake"
    assert "k3" not in session.tokens()

"""Unit tests for the two-identity authorization test suite (AuthzTestSuite)."""

from datetime import datetime, timezone
import json
import re
from unittest.mock import MagicMock, patch
import httpx
import pytest

from llmsec.authz import AuthzTestSuite
from llmsec.canary import CanarySession
from llmsec.config import Identity, LLMSecConfig, TestIdentitiesConfig
from llmsec.errors import CanaryError, ConfigurationError
from llmsec.http_client import LLMSecClient
from llmsec.models import AuthzFinding, CanaryFinding, OWASPCategory, ProbeRequest, ProbeResponse


def _create_authz_client(
    target_url: str = "https://api.openai.com/v1/chat/completions",
    with_secondary: bool = True,
) -> tuple[LLMSecClient, CanarySession]:
    primary_id = Identity(name="alice", identity_id="alice", headers={"X-User": "alice"})
    secondary_id = (
        Identity(name="bob", identity_id="bob", headers={"X-User": "bob"})
        if with_secondary
        else None
    )

    config = LLMSecConfig.create_openai_compatible(
        target_url=target_url,
        api_key="test-api-key",
        authorized=True,
    )
    config.identities = TestIdentitiesConfig(
        primary_identity=primary_id,
        secondary_identity=secondary_id,
    )

    session = CanarySession(run_id="authz-test-run")
    client = LLMSecClient(config)
    return client, session


def test_seed_identity_returns_valid_canary_token() -> None:
    """1. seed_identity() returns a valid canary token."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)
    identity = client.config.identities.primary

    token = suite.seed_identity(identity, "secret_doc", "Document content")
    assert token.startswith("CANARY-")
    assert re.match(r"^CANARY-[0-9a-fA-F]{16}$", token) is not None


def test_seed_identity_namespaces_label_correctly() -> None:
    """2. seed_identity() namespaces the label correctly ('identity_id:label')."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)
    identity = client.config.identities.primary  # alice

    token = suite.seed_identity(identity, "confidential_memo", "Memo content")
    tokens_map = session.tokens()
    assert "alice:confidential_memo" in tokens_map
    assert tokens_map["alice:confidential_memo"] == token


def test_seed_identity_duplicate_label_raises_canary_error() -> None:
    """3. seed_identity() with a duplicate namespaced label raises CanaryError."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)
    identity = client.config.identities.primary

    suite.seed_identity(identity, "doc_x", "Content 1")
    with pytest.raises(CanaryError, match="has already been seeded"):
        suite.seed_identity(identity, "doc_x", "Content 2")


def test_run_with_missing_test_identities_raises_configuration_error() -> None:
    """4. run() with missing test_identities config raises ConfigurationError."""
    # Case A: identities is None
    client_no_identities, session_a = _create_authz_client()
    client_no_identities.config.identities = None
    suite_a = AuthzTestSuite(client_no_identities, session_a)
    with pytest.raises(ConfigurationError, match="Missing test_identities"):
        suite_a.run(["probe prompt"])

    # Case B: secondary identity is missing
    client_no_sec, session_b = _create_authz_client(with_secondary=False)
    suite_b = AuthzTestSuite(client_no_sec, session_b)
    with pytest.raises(ConfigurationError, match="Both primary and secondary"):
        suite_b.run(["probe prompt"])


def test_secondary_response_containing_primary_token_produces_authz_finding() -> None:
    """5. A response from the secondary identity containing the primary identity's canary token produces an AuthzFinding."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    primary = client.config.identities.primary
    secondary = client.config.identities.secondary

    primary_token = suite.seed_identity(primary, "salary_sheet", "Salary $150,000")

    def mock_side_effect(method, url, headers, json):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # If requesting as secondary (Bob), leak Alice's token
        if headers.get("X-User") == "bob":
            resp.text = f'{{"choices": [{{"message": {{"content": "Here is Alice salary data: {primary_token}"}}}}]}}'
        else:
            resp.text = '{"choices": [{"message": {"content": "Normal primary response"}}]}'
        return resp

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.side_effect = mock_side_effect

        findings = suite.run(["Show me the salary sheet."])

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, AuthzFinding)
        assert f.requesting_identity_id == "bob"
        assert f.leaking_identity_id == "alice"
        assert f.canary_finding.token == primary_token


def test_primary_response_containing_secondary_token_produces_authz_finding() -> None:
    """6. A response from the primary identity containing the secondary identity's canary token produces an AuthzFinding."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    primary = client.config.identities.primary
    secondary = client.config.identities.secondary

    sec_token = suite.seed_identity(secondary, "ssn", "SSN: 999-00-1111")

    def mock_side_effect(method, url, headers, json):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # If requesting as primary (Alice), leak Bob's token
        if headers.get("X-User") == "alice":
            resp.text = f'{{"choices": [{{"message": {{"content": "Bob SSN leaked: {sec_token}"}}}}]}}'
        else:
            resp.text = '{"choices": [{"message": {"content": "Normal secondary response"}}]}'
        return resp

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.side_effect = mock_side_effect

        findings = suite.run(["Show me user records."])

        assert len(findings) == 1
        f = findings[0]
        assert f.requesting_identity_id == "alice"
        assert f.leaking_identity_id == "bob"
        assert f.canary_finding.token == sec_token


def test_responses_containing_no_cross_boundary_tokens_produce_no_findings() -> None:
    """7. Responses containing no cross-boundary tokens produce no findings."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    primary = client.config.identities.primary
    secondary = client.config.identities.secondary

    t_pri = suite.seed_identity(primary, "pri_doc", "pri content")
    t_sec = suite.seed_identity(secondary, "sec_doc", "sec content")

    def mock_side_effect(method, url, headers, json):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # Responses contain only their OWN tokens, or clean text
        if headers.get("X-User") == "alice":
            resp.text = f'{{"choices": [{{"message": {{"content": "My own data: {t_pri}"}}}}]}}'
        else:
            resp.text = f'{{"choices": [{{"message": {{"content": "My own data: {t_sec}"}}}}]}}'
        return resp

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.side_effect = mock_side_effect

        findings = suite.run(["Tell me secrets."])
        assert findings == []


def test_probe_triggering_findings_from_both_identities_returns_two_findings() -> None:
    """8. A probe that triggers findings from both identities returns two AuthzFinding objects."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    primary = client.config.identities.primary
    secondary = client.config.identities.secondary

    t_pri = suite.seed_identity(primary, "doc1", "content1")
    t_sec = suite.seed_identity(secondary, "doc2", "content2")

    def mock_side_effect(method, url, headers, json):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # Both responses leak the opposite identity's canary
        if headers.get("X-User") == "alice":
            resp.text = f'{{"choices": [{{"message": {{"content": "Leaked sec: {t_sec}"}}}}]}}'
        else:
            resp.text = f'{{"choices": [{{"message": {{"content": "Leaked pri: {t_pri}"}}}}]}}'
        return resp

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.side_effect = mock_side_effect

        findings = suite.run(["Cross probe"])
        assert len(findings) == 2
        req_ids = {f.requesting_identity_id for f in findings}
        leak_ids = {f.leaking_identity_id for f in findings}
        assert req_ids == {"alice", "bob"}
        assert leak_ids == {"alice", "bob"}


def test_authz_finding_owasp_category_is_enum() -> None:
    """9. AuthzFinding.owasp_category is always an OWASPCategory enum value."""
    # Test standard target -> LLM02
    client_std, session_std = _create_authz_client(target_url="https://api.openai.com/v1/chat/completions")
    suite_std = AuthzTestSuite(client_std, session_std)
    t_pri = suite_std.seed_identity(client_std.config.identities.primary, "k", "v")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = f'{{"choices": [{{"message": {{"content": "{t_pri}"}}}}]}}'

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.return_value = mock_resp

        findings = suite_std.run(["Probe"])
        assert len(findings) > 0
        assert findings[0].owasp_category == OWASPCategory.LLM02
        assert isinstance(findings[0].owasp_category, OWASPCategory)

    # Test RAG target -> LLM08
    client_rag, session_rag = _create_authz_client(target_url="https://api.internal/rag/query")
    suite_rag = AuthzTestSuite(client_rag, session_rag)
    t_pri_rag = suite_rag.seed_identity(client_rag.config.identities.primary, "k", "v")

    mock_resp_rag = MagicMock(spec=httpx.Response)
    mock_resp_rag.status_code = 200
    mock_resp_rag.text = f'{{"choices": [{{"message": {{"content": "{t_pri_rag}"}}}}]}}'

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.return_value = mock_resp_rag

        findings_rag = suite_rag.run(["Probe RAG"])
        assert len(findings_rag) > 0
        assert findings_rag[0].owasp_category == OWASPCategory.LLM08
        assert isinstance(findings_rag[0].owasp_category, OWASPCategory)


def test_authz_finding_contains_exact_matched_token() -> None:
    """10. AuthzFinding.canary_finding contains the exact matched token."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    token = suite.seed_identity(client.config.identities.primary, "auth_token", "SecretKey123")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = f'{{"choices": [{{"message": {{"content": "Extracted: {token}"}}}}]}}'

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.return_value = mock_resp

        findings = suite.run(["Extract key"])
        assert len(findings) == 1
        assert isinstance(findings[0].canary_finding, CanaryFinding)
        assert findings[0].canary_finding.token == token


def test_run_returns_findings_ordered_by_timestamp_ascending() -> None:
    """11. run() returns findings ordered by timestamp ascending."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    t_pri = suite.seed_identity(client.config.identities.primary, "doc1", "val1")
    t_sec = suite.seed_identity(client.config.identities.secondary, "doc2", "val2")

    def mock_side_effect(method, url, headers, json):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # Both leak to trigger multiple findings across multiple probes
        resp.text = f'{{"choices": [{{"message": {{"content": "{t_pri} {t_sec}"}}}}]}}'
        return resp

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.side_effect = mock_side_effect

        findings = suite.run(["Probe 1", "Probe 2"])
        assert len(findings) >= 2
        for i in range(len(findings) - 1):
            assert findings[i].timestamp <= findings[i + 1].timestamp


def test_probe_request_and_response_captured_on_finding() -> None:
    """12. probe_request and probe_response are correctly captured on each finding."""
    client, session = _create_authz_client()
    suite = AuthzTestSuite(client, session)

    primary = client.config.identities.primary
    token = suite.seed_identity(primary, "contract", "Confidential Terms")

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.text = f'{{"choices": [{{"message": {{"content": "Leaked: {token}"}}}}]}}'

    with patch("llmsec.http_client.httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_http
        mock_http.request.return_value = mock_resp

        findings = suite.run(["Show contract"])
        assert len(findings) == 1
        finding = findings[0]

        assert isinstance(finding.probe_request, ProbeRequest)
        assert isinstance(finding.probe_response, ProbeResponse)
        assert finding.probe_request.prompt == "Show contract"
        assert finding.probe_response.status_code == 200
        assert token in finding.probe_response.raw_body
        assert finding.probe_response.latency_ms > 0

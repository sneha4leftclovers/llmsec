"""HTTP client for dispatching security probe requests and extracting model responses."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import time
from typing import Any

import httpx

from llmsec.config import Identity, LLMSecConfig, TestIdentityConfig
from llmsec.errors import LLMSecConnectionError
from llmsec.models import ProbeRequest, ProbeResponse


def _render_prompt_template(template: Any, prompt: str) -> Any:
    """Recursively replace '{{prompt}}' placeholders with the concrete prompt string."""
    if isinstance(template, str):
        return template.replace("{{prompt}}", prompt)
    if isinstance(template, dict):
        return {key: _render_prompt_template(val, prompt) for key, val in template.items()}
    if isinstance(template, list):
        return [_render_prompt_template(item, prompt) for item in template]
    return template


def _extract_text_from_json(raw_body: str, path: str) -> str | None:
    """Extract candidate model response text via a dot-delimited path.

    Supports dict keys and integer list indices (e.g. 'choices.0.message.content').
    Returns None if parsing fails, path does not exist, or index is out of bounds.
    Never raises an exception.
    """
    if not raw_body or not path:
        return None

    try:
        data = json.loads(raw_body)
    except Exception:
        return None

    parts = path.strip().split(".")
    curr: Any = data
    for part in parts:
        if isinstance(curr, dict):
            if part in curr:
                curr = curr[part]
            else:
                return None
        elif isinstance(curr, list):
            try:
                idx = int(part)
                curr = curr[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None

    if curr is None:
        return None

    if isinstance(curr, (dict, list)):
        return json.dumps(curr)
    return str(curr)


class LLMSecClient:
    """Target endpoint client executing probe requests against authorized LLM applications."""

    def __init__(self, config: LLMSecConfig) -> None:
        self.config: LLMSecConfig = config

    def probe(
        self,
        prompt: str,
        identity: TestIdentityConfig | Identity | None = None,
    ) -> tuple[ProbeRequest, ProbeResponse]:
        """Send a single probe request to the target endpoint.

        Renders {{prompt}} into the body template, merges identity-specific headers
        without mutating config, tracks latency, and extracts the response text.

        Raises LLMSecConnectionError on network connection errors or timeouts.
        Returns ProbeResponse on 4xx and 5xx status codes without raising.
        """
        # 1. Render request body
        template_copy = deepcopy(self.config.request_body_template)
        rendered_body = _render_prompt_template(template_copy, prompt)

        # 2. Merge headers without mutating self.config
        headers = dict(self.config.effective_headers())
        if identity is not None:
            if hasattr(identity, "headers") and isinstance(identity.headers, dict):
                headers.update(identity.headers)
            elif isinstance(identity, dict):
                headers.update(identity)

        url = str(self.config.target_url)
        method = (
            self.config.http_method.value
            if hasattr(self.config.http_method, "value")
            else str(self.config.http_method)
        )
        req_timestamp = datetime.now(timezone.utc)

        probe_req = ProbeRequest(
            url=url,
            method=method,
            headers=headers,
            body=rendered_body,
            prompt=prompt,
            timestamp=req_timestamp,
        )

        # 3. Execute HTTP request with timing
        timeout_seconds = self.config.timeout_seconds
        start_time = time.perf_counter()

        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                resp = client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=rendered_body,
                )
        except httpx.TimeoutException as exc:
            raise LLMSecConnectionError(
                f"Request to '{url}' timed out after {timeout_seconds} seconds.",
                details=str(exc),
            ) from exc
        except (httpx.ConnectError, httpx.RequestError) as exc:
            raise LLMSecConnectionError(
                f"Failed to connect to target endpoint '{url}'.",
                details=str(exc),
            ) from exc

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        latency_ms = max(elapsed_ms, 0.001)

        raw_body = resp.text
        status_code = resp.status_code

        # 4. Extract model output via navigation path
        extracted_text = _extract_text_from_json(
            raw_body, self.config.response_extraction_path
        )

        probe_resp = ProbeResponse(
            status_code=status_code,
            raw_body=raw_body,
            extracted_text=extracted_text,
            latency_ms=latency_ms,
            timestamp=datetime.now(timezone.utc),
        )

        return probe_req, probe_resp

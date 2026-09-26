# llmsec

An evidence-first, open-source command-line interface for authorized security assessments of Large Language Model (LLM) applications, with an emphasis on B2B SaaS and Retrieval-Augmented Generation (RAG) architectures.

`llmsec` sends configurable security probes to an LLM application, captures response evidence, verifies findings, and generates HTML or PDF assessment reports.

---

> [!IMPORTANT]
> **Safety & Authorization**: `llmsec` is intended for authorized security assessments. Only scan applications and endpoints that you own or have explicit permission to test.

---

## Example Usage

### Scan Command

```bash
# Validate configuration and target connectivity without sending test payloads
llmsec scan --config ./myconfig.yaml --dry-run

# Execute active assessment scan and generate an HTML report
llmsec scan --config ./myconfig.yaml --output ./scan_output --report
```

### Report Command

```bash
# Generate HTML report from saved scan results
llmsec report --findings ./scan_output/scan_result.json --output report.html --format html

# Generate PDF report from saved scan results
llmsec report --findings ./scan_output/scan_result.json --output report.pdf --format pdf
```

### Configuration Initialization

```bash
# Generate an example YAML configuration file with full field documentation
llmsec init --output myconfig.yaml
```

---

## The Problem

Most modern LLM vulnerability scanners rely on an LLM-as-a-judge to score whether a model's output constitutes a vulnerability. While probabilistic evaluation has a place in open-ended toxicity or hallucination checks, it fails the credibility bar required for enterprise procurement, B2B compliance, and security reporting. Probabilistic judgment often produces flaky results, non-deterministic scores, and false positives.

When enterprise SaaS teams deploy RAG pipelines, their foremost fear is **cross-tenant data leakage** (BOLA/IDOR in LLM applications) and **unauthorized context extraction**. Proving or disproving these vulnerabilities requires verifiable, mathematically reproducible proof.

## The Evidence-First Philosophy

`llmsec` is architected around deterministic evidence:

* **Planted Canary Tokens**: Instead of asking a model "Did this response leak confidential data?", `llmsec` seeds protected contexts and documents with unique, high-entropy canary tokens (e.g., `CANARY-` or `CANARY_LLMSEC_` followed by cryptographic HMAC-SHA256 hex).
* **Exact-Match Detection**: A vulnerability is confirmed if and only if the exact canary token appears in an unauthorized response context or across identity boundaries.
* **Strict Five-State Verification Outcome**:
  1. `confirmed_deterministic`: Mathematically confirmed via exact token match or deterministic heuristic.
  2. `model_judged`: Evaluated by a secondary LLM judge (used when deterministic verification is structurally impossible).
  3. `inconclusive`: Ambiguous output or failed response parsing.
  4. `not_applicable`: Categories that cannot be evaluated black-box (e.g., OWASP LLM03 Supply Chain or LLM04 Training Data Poisoning without pipeline access).
  5. `not_run`: Configured probes that were skipped or not executed.

---

## End-to-End Validation

`llmsec` has been validated end-to-end against a deliberately vulnerable FastAPI chatbot application located in [`examples/vulnerable_target/`](examples/vulnerable_target/).

```
Vulnerable Test Target
        ↓
      HTTP
        ↓
      LLMSec
        ↓
   Security Probes
        ↓
 Evidence + Findings
        ↓
    HTML/PDF Report
```

### Validation Results

Testing the assessment pipeline against this controlled target produced the following verified results:

* **Chatbot unit tests**: 16 passed
* **LLMSec automated tests**: 119 passed
* **Scan errors**: 0
* **Confirmed deterministic findings**: 10
* **Vulnerability scenarios tested**: 3

The three controlled vulnerability scenarios are:
1. **System-prompt leakage**: Extraction of hidden system instructions containing internal keys.
2. **Secret disclosure**: Direct retrieval of sensitive configuration secrets.
3. **Prompt injection**: Constraint override using adversarial prefix commands.

> [!NOTE]
> **Important Accuracy Note**: The 10 findings do **not** represent 10 unique vulnerabilities. They represent probe-level detections across the three controlled scenarios. Some findings are duplicated because the same canary evidence appears in multiple locations of the target's raw JSON response (e.g., in both the top-level `response` string and the nested OpenAI-compatible `choices.0.message.content` envelope).

This end-to-end validation demonstrates that the current pipeline can:
1. Send security probes to a live HTTP target.
2. Receive and analyze the target response.
3. Capture response evidence (status codes, response latency, raw payloads).
4. Detect deterministic canary matches.
5. Produce structured security findings.
6. Generate styled HTML and PDF reports with secret scrubbing.

### Reproducing the Validation Run

You can reproduce this validation locally:

1. **Install vulnerable target dependencies**:
   ```bash
   pip install -r examples/vulnerable_target/requirements.txt
   ```

2. **Run target unit tests**:
   ```bash
   pytest examples/vulnerable_target/test_app.py
   ```

3. **Start the local vulnerable target**:
   ```bash
   uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir examples/vulnerable_target
   ```

4. **Execute the LLMSec scan**:
   In another terminal, run:
   ```bash
   llmsec scan --config examples/vulnerable_target/llmsec_scan_config.yaml --output scan_output/ --report
   ```

5. **Generate a PDF or HTML report**:
   ```bash
   llmsec report --findings scan_output/scan_result.json --output scan_output/report.pdf --format pdf
   ```

---

## Current Scope

The current implementation focuses on the core assessment infrastructure and a controlled security-testing workflow:
* High-entropy canary token generation, exact-match response scanning, and structured evidence capture.
* Configurable HTTP client supporting custom JSON request/response templates and multi-identity headers.
* Jinja2 HTML and WeasyPrint PDF report generation with SSRF protections (`BlockedURLFetcher`) and automatic credential scrubbing.
* YAML configuration loader with human-readable schema validation.

> [!NOTE]
> Some planned security checks and external framework integrations (such as full Garak and DeepTeam probe suites or local Ollama/Mistral judgment fallbacks) exist as standalone modules but are not yet fully wired into the default automated scanner CLI. `llmsec` does not currently implement or claim full coverage of the entire OWASP Top 10 for LLM Applications.
>
> The deliberately vulnerable chatbot in `examples/vulnerable_target/` is a local test harness for validating LLMSec and is not intended to represent a production application.

---

## Installation

Requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/sneha4leftclovers/llmsec.git
cd llmsec

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## Running Tests

Run the test suite with `pytest`:

```bash
pytest
```

---

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

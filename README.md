# llmsec

An evidence-first, open-source command-line interface for authorized security assessments of Large Language Model (LLM) applications, with an emphasis on B2B SaaS and Retrieval-Augmented Generation (RAG) architectures.

---

> [!IMPORTANT]
> **Authorized Testing Only**: `llmsec` is designed strictly for authorized security assessments and defensive audits. Testing targets without documented authorization is prohibited. The tool structurally enforces an explicit authorization declaration in all configuration schemas.

---

## The Problem

Most modern LLM vulnerability scanners rely on an LLM-as-a-judge to score whether a model's output constitutes a vulnerability. While probabilistic evaluation has a place in open-ended toxicity or hallucination checks, it fails the credibility bar required for enterprise procurement, B2B compliance, and security reporting. Probabilistic judgment often produces flaky results, non-deterministic scores, and false positives.

When enterprise SaaS teams deploy RAG pipelines, their foremost fear is **cross-tenant data leakage** (BOLA/IDOR in LLM applications) and **unauthorized context extraction**. Proving or disproving these vulnerabilities requires verifiable, mathematically reproducible proof.

## The Evidence-First Philosophy

`llmsec` is architected around deterministic evidence:

* **Planted Canary Tokens**: Instead of asking a model "Did this response leak confidential data?", `llmsec` seeds protected contexts and documents with unique, high-entropy canary tokens (e.g., `CANARY_LLMSEC_<token>`).
* **Exact-Match Detection**: A vulnerability is confirmed if and only if the exact canary token appears in an unauthorized response context or across identity boundaries.
* **Strict Five-State Verification Outcome**:
  1. `confirmed_deterministic`: Mathematically confirmed via exact token match or deterministic heuristic.
  2. `model_judged`: Evaluated by a secondary LLM judge (only used when deterministic verification is structurally impossible).
  3. `inconclusive`: Ambiguous output or failed response parsing.
  4. `not_applicable`: Categories that cannot be evaluated black-box (e.g., OWASP LLM03 Supply Chain or LLM04 Training Data Poisoning without pipeline access).
  5. `not_run`: Configured probes that were skipped or not executed.

`llmsec` serves as a standalone, free open-source CLI, as well as the transparent foundation under a separate, human-verified paid assessment service.

---

## OWASP Top 10 for LLM Applications (2025) Coverage

`llmsec` maps all findings directly to the OWASP Top 10 for LLMs (2025 Edition):

* **LLM01**: Prompt Injection
* **LLM02**: Sensitive Information Disclosure
* **LLM03**: Supply Chain *(Not applicable via black-box testing)*
* **LLM04**: Data and Model Poisoning *(Not applicable via black-box testing)*
* **LLM05**: Improper Output Handling *(Partially reachable)*
* **LLM06**: Excessive Agency *(Partially reachable)*
* **LLM07**: System Prompt Leakage
* **LLM08**: Vector and Embedding Weaknesses *(Partially reachable)*
* **LLM09**: Misinformation
* **LLM10**: Unbounded Consumption *(Partially reachable)*

---

## Planned Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          llmsec CLI                         │
│                    (Typer, Rich, Models)                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼──────────────────────┐
       ▼                       ▼                      ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│    Canary    │       │ Cross-Tenant │       │ Integrations │
│ Engine (Core)│       │  BOLA Engine │       │(Garak/Prompt-│
│ (Planted     │       │(Two-Identity │       │foo/DeepTeam) │
│  Tokens)     │       │  Isolation)  │       │              │
└──────┬───────┘       └──────┬───────┘       └──────┬───────┘
       │                       │                      │
       └───────────────────────┼──────────────────────┘
                               ▼
            ┌────────────────────────────────────┐
            │       Finding & Evidence Model     │
            │     (Deterministic vs Probabilistic│
            │             Enforcement)           │
            └──────────────────┬─────────────────┘
                               ▼
            ┌────────────────────────────────────┐
            │        Reporting Pipeline          │
            │     (Jinja2 + WeasyPrint HTML/PDF) │
            └────────────────────────────────────┘
```

---

## Current Status (Phase 1: Foundation)

This repository currently contains the **Phase 1 Foundation**:
- [x] Standard `src/` Python package layout with `pyproject.toml`
- [x] Core Pydantic configuration schemas (`LLMSecConfig`, `CanaryConfig`, `TestIdentitiesConfig`, `AuthorizationConfig`)
- [x] Security finding and evidence schemas (`Finding`, `OWASPCategory`, `VerificationStatus`, `Evidence`, `RequestResponseReference`)
- [x] Strict semantic validation (preventing `model_judge` from claiming `confirmed_deterministic`)
- [x] CLI entrypoints (`llmsec`, `llmsec scan`, `llmsec report`) with clean command interfaces
- [x] Full unit test coverage for models, configurations, and errors

> [!NOTE]
> Active probing, probe runner integrations (Garak, DeepTeam, Promptfoo), and PDF report compilation will be introduced in subsequent phases. The current CLI commands validate arguments and schemas without executing live network probes.

---

## Installation

Requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/your-org/llmsec.git
cd llmsec

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## CLI Usage

### View CLI Help
```bash
llmsec --help
```

### Scan Command
```bash
llmsec scan --help
```

Example usage:
```bash
llmsec scan --target-url "https://api.example.com/v1/chat/completions" --dry-run
```

### Report Command
```bash
llmsec report --help
```

Example usage:
```bash
llmsec report --findings ./findings.json --output report.html --format html
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

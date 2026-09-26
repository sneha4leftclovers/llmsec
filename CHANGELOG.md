# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-24

### Added
- **Core Architecture & Schemas**: Pydantic models for configuration, findings, evidence, and verification statuses (`LLMSecConfig`, `Finding`, `Evidence`, `OWASPCategory`, `VerificationStatus`, `VerificationMethod`).
- **Authorization Enforcement**: Mandatory authorization declarations (`AuthorizationConfig`) requiring explicit authorization before probe execution.
- **Canary Engine**: Cryptographic HMAC-SHA256 canary token generation and deterministic exact-match verification to identify data leakage without relying on probabilistic model judges.
- **Resilient Probing Client**: HTTP client layer built on `httpx` with configurable retries, exponential backoff, rate limiting, and request/response telemetry capture.
- **Two-Identity Authorization Suite**: Testing engine evaluating Broken Object Level Authorization (BOLA) and identity isolation across primary and secondary test accounts.
- **Garak Integration**: Runner integration wrapping Garak probes for REST LLM vulnerability scanning and structured finding generation.
- **DeepTeam Integration**: Integration with DeepTeam red-teaming framework for OWASP Top 10 LLM vulnerability probing.
- **Local Ollama / Mistral Judge**: Local model judgment fallback for non-deterministic assessment categories using Ollama and Mistral, with strict verdict parsing and bypass logic for canary-testable categories (LLM02/LLM08).
- **Report Generation**: Executive and technical report generator with Jinja2 HTML templates and WeasyPrint PDF output, featuring secret scrubbing, target URL sanitization, and `BlockedURLFetcher` resource sandboxing.
- **CLI Interface**: Command-line application implemented with Typer and Rich providing `scan` and `report` commands.
- **CI/CD Workflows**: GitHub Actions CI workflow running test matrix on Python 3.11 and 3.12, and release workflow for PyPI packaging and GitHub Releases.

### Changed
- Initial release.

### Removed
- Initial release.

### Fixed
- Initial release.

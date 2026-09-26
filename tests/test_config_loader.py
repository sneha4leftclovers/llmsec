"""Tests for src/llmsec/config_loader.py."""

import textwrap
from pathlib import Path

import pytest

from llmsec.config import LLMSecConfig
from llmsec.config_loader import load_config, write_example_config
from llmsec.errors import ConfigurationError


VALID_YAML = textwrap.dedent("""\
    target_url: "https://api.example.com/v1/chat"
    authorization:
      authorized: true
      authorized_by: "Test Team"
      scope_description: "Unit test"
""")


# ---------------------------------------------------------------------------
# load_config tests
# ---------------------------------------------------------------------------

def test_valid_yaml_loads_into_llmsec_config(tmp_path: Path) -> None:
    """A well-formed YAML file matching LLMSecConfig fields produces a valid config."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(VALID_YAML, encoding="utf-8")

    cfg = load_config(str(cfg_file))

    assert isinstance(cfg, LLMSecConfig)
    assert str(cfg.target_url).startswith("https://api.example.com")
    assert cfg.authorization.authorized is True
    assert cfg.authorization.authorized_by == "Test Team"


def test_missing_file_raises_configuration_error(tmp_path: Path) -> None:
    """A path that does not exist raises ConfigurationError with a helpful message."""
    missing = str(tmp_path / "nonexistent.yaml")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(missing)

    assert "not found" in str(exc_info.value).lower()
    assert "nonexistent.yaml" in str(exc_info.value)


def test_malformed_yaml_raises_configuration_error(tmp_path: Path) -> None:
    """YAML with a syntax error raises ConfigurationError that includes the parse error."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("key: [unclosed bracket\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(str(bad_yaml))

    msg = str(exc_info.value)
    assert "yaml" in msg.lower() or "parse" in msg.lower()


def test_invalid_config_values_raise_configuration_error_with_readable_message(
    tmp_path: Path,
) -> None:
    """Pydantic validation failure produces a ConfigurationError with readable field errors."""
    # 'authorized: false' fails AuthorizationConfig.validate_authorization
    invalid_yaml = textwrap.dedent("""\
        target_url: "https://api.example.com/v1/chat"
        authorization:
          authorized: false
    """)
    cfg_file = tmp_path / "invalid.yaml"
    cfg_file.write_text(invalid_yaml, encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(str(cfg_file))

    msg = str(exc_info.value)
    # Should be readable text, not a raw Pydantic traceback
    assert "validation" in msg.lower() or "authorized" in msg.lower()
    # Should NOT be a raw Pydantic dump
    assert "ValidationError" not in msg


def test_non_mapping_yaml_raises_configuration_error(tmp_path: Path) -> None:
    """A YAML file containing a plain list (not a mapping) raises ConfigurationError."""
    cfg_file = tmp_path / "list.yaml"
    cfg_file.write_text("- item1\n- item2\n", encoding="utf-8")

    with pytest.raises(ConfigurationError) as exc_info:
        load_config(str(cfg_file))

    assert "mapping" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# write_example_config tests
# ---------------------------------------------------------------------------

def test_write_example_config_creates_file(tmp_path: Path) -> None:
    """write_example_config creates a non-empty YAML file at the given path."""
    out = tmp_path / "example.yaml"
    write_example_config(str(out))

    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "target_url" in content
    assert "authorization" in content
    assert len(content) > 100

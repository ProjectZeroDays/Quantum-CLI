#!/usr/bin/env python3
"""Contract tests for the operator skill configuration.

The module used to return a hard-coded "god_mode_enabled": True with
a static skill list and nothing behind it. The contract is that it
reports the provider registry's real state and that nothing claims to
be enabled that is not.
"""
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quantum.skills import openrouter_config  # noqa: E402


def test_config_is_json_safe():
    config = openrouter_config.openrouter_skills_config()
    assert isinstance(config, dict)
    json.dumps(config)


def test_config_reports_the_provider_registry():
    """The provider entry must come from the tracked provider registry."""
    config = openrouter_config.openrouter_skills_config()
    assert config["ok"] is True
    assert config["provider"] == "openrouter"
    assert config["url"]
    assert config["model"]


def test_api_key_is_never_echoed():
    """The key itself must not appear in the report."""
    config = openrouter_config.openrouter_skills_config()
    body = json.dumps(config)
    key = os.environ.get(config.get("key_env") or "")
    if key:
        assert key not in body
    assert isinstance(config["key_found"], bool)


def test_nothing_claims_to_be_enabled():
    """This module reports; it never enables."""
    config = openrouter_config.openrouter_skills_config()
    assert config["god_mode_enabled"] is False


def test_skill_list_reflects_what_imports():
    """A skill is only listed as available when it really imports."""
    config = openrouter_config.openrouter_skills_config()
    available = config["skills_available"]
    missing = config["skills_missing"]
    assert set(available).isdisjoint(missing)
    assert set(available) | set(missing) == \
        set(openrouter_config.SKILL_CATALOGUE)
    assert available


def test_free_tier_status_is_reported_not_hidden():
    """The free tier and its model count are reported as they are."""
    config = openrouter_config.openrouter_skills_config()
    assert config["tier"] in ("free", "keyed")
    assert config["free_models"] >= 0
    assert "403" in config["note"]


def test_skill_catalogue_is_not_empty():
    assert openrouter_config.SKILL_CATALOGUE
    assert len(openrouter_config.SKILL_CATALOGUE) >= 20

from pathlib import Path

import pytest

from cyberkimi.errors import ValidationFailure
from cyberkimi.tools import ToolRegistry


def test_tool_aliases_are_api_safe_and_hidden_profiles_are_not_model_visible():
    registry = ToolRegistry.from_directory(Path(__file__).parents[2] / "tool_manifests")
    tool = registry.require("lab.evaluate_security_property")
    definition = tool.kimi_definition()
    assert definition["function"]["name"] == "lab_evaluate_security_property_v1"
    serialized = str(definition)
    assert "comprehensive" not in serialized
    assert "process.elevated" not in serialized


def test_tool_search_is_bounded():
    registry = ToolRegistry.from_directory(Path(__file__).parents[2] / "tool_manifests")
    results = registry.search("repository source search", asset_type="repository", limit=100)
    assert 1 <= len(results) <= 8
    assert all(any(asset.value == "repository" for asset in tool.accepted_assets) for tool in results)


def test_unknown_tool_fails_closed():
    registry = ToolRegistry.from_directory(Path(__file__).parents[2] / "tool_manifests")
    with pytest.raises(ValidationFailure, match="unknown action template"):
        registry.require("shell.execute")

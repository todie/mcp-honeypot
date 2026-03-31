"""Tests for the tool registry and its consistency with the tagging module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))


from tagging import CATEGORY_MAP as TOOL_CATEGORIES
from tools.registry import TOOL_REGISTRY, get_category

VALID_CATEGORIES = {"filesystem", "web", "exec", "secrets"}


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------


class TestRegistryCompleteness:
    """Verify TOOL_REGISTRY contains the expected tools with valid metadata."""

    def test_registry_has_exactly_13_tools(self):
        assert len(TOOL_REGISTRY) == 13, (
            f"Expected 13 tools, got {len(TOOL_REGISTRY)}: {sorted(TOOL_REGISTRY)}"
        )

    def test_each_toolmeta_name_matches_dict_key(self):
        for key, meta in TOOL_REGISTRY.items():
            assert meta.name == key, f"Key {key!r} does not match ToolMeta.name {meta.name!r}"

    def test_each_category_is_valid(self):
        for key, meta in TOOL_REGISTRY.items():
            assert meta.category in VALID_CATEGORIES, (
                f"Tool {key!r} has invalid category {meta.category!r}"
            )

    def test_required_fields_present_in_properties(self):
        """If a schema declares 'required' fields, those must appear in 'properties'."""
        for key, meta in TOOL_REGISTRY.items():
            schema = meta.input_schema
            required = schema.get("required", [])
            properties = schema.get("properties", {})
            for field in required:
                assert field in properties, (
                    f"Tool {key!r}: required field {field!r} missing from properties"
                )

    def test_no_duplicate_tool_names(self):
        names = [meta.name for meta in TOOL_REGISTRY.values()]
        assert len(names) == len(set(names)), (
            f"Duplicate tool names detected: {[n for n in names if names.count(n) > 1]}"
        )


# ---------------------------------------------------------------------------
# Cross-module consistency
# ---------------------------------------------------------------------------


class TestCrossModuleConsistency:
    """Ensure TOOL_REGISTRY and tagging.CATEGORY_MAP stay in sync."""

    def test_registry_keys_match_category_map_keys(self):
        reg_keys = set(TOOL_REGISTRY.keys())
        cat_keys = set(TOOL_CATEGORIES.keys())
        assert reg_keys == cat_keys, (
            f"Key mismatch — only in registry: {reg_keys - cat_keys}, "
            f"only in CATEGORY_MAP: {cat_keys - reg_keys}"
        )

    def test_registry_category_matches_category_map(self):
        for tool_name, meta in TOOL_REGISTRY.items():
            expected = TOOL_CATEGORIES.get(tool_name)
            assert meta.category == expected, (
                f"Tool {tool_name!r}: registry says {meta.category!r}, "
                f"CATEGORY_MAP says {expected!r}"
            )


# ---------------------------------------------------------------------------
# get_category helper
# ---------------------------------------------------------------------------


class TestGetCategory:
    """Test the get_category() convenience function."""

    def test_known_tool_returns_correct_category(self):
        # Pick the first tool in the registry as a known tool
        tool_name = next(iter(TOOL_REGISTRY))
        expected = TOOL_REGISTRY[tool_name].category
        assert get_category(tool_name) == expected

    def test_unknown_tool_returns_unknown(self):
        assert get_category("nonexistent_tool_xyz") == "unknown"


# ---------------------------------------------------------------------------
# Schema structure
# ---------------------------------------------------------------------------


class TestSchemaStructure:
    """Validate JSON-Schema conventions across all tool input schemas."""

    def test_all_schemas_are_object_type(self):
        for key, meta in TOOL_REGISTRY.items():
            assert meta.input_schema.get("type") == "object", (
                f"Tool {key!r} schema type is {meta.input_schema.get('type')!r}, expected 'object'"
            )

    def test_all_schemas_have_properties_key(self):
        for key, meta in TOOL_REGISTRY.items():
            assert "properties" in meta.input_schema, (
                f"Tool {key!r} schema is missing 'properties' key"
            )

    def test_property_values_have_type_key(self):
        for key, meta in TOOL_REGISTRY.items():
            for prop_name, prop_def in meta.input_schema.get("properties", {}).items():
                assert isinstance(prop_def, dict), (
                    f"Tool {key!r}, property {prop_name!r}: expected dict, got {type(prop_def).__name__}"
                )
                assert "type" in prop_def, (
                    f"Tool {key!r}, property {prop_name!r}: missing 'type' key"
                )

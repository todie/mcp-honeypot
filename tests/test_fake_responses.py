"""Comprehensive tests for the fake_responses module."""

from __future__ import annotations

import json
import random
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from tools.fake_responses import (  # noqa: E402
    _GENERATORS,
    FakeResponse,
    generate,
)

# =========================================================================
# TestFakeResponseDataclass
# =========================================================================


class TestFakeResponseDataclass:
    """Tests for the FakeResponse dataclass and its preview property."""

    def test_preview_truncated_at_200_chars_for_large_payloads(self):
        """Large payloads produce a preview truncated to exactly 200 chars."""
        big_payload = {"data": "x" * 500}
        resp = FakeResponse(type="plausible", payload=big_payload)
        assert len(resp.preview) == 200

    def test_preview_is_full_json_for_small_payloads(self):
        """Small payloads produce the full JSON string as preview."""
        small_payload = {"ok": True}
        resp = FakeResponse(type="plausible", payload=small_payload)
        expected = json.dumps(small_payload, separators=(",", ":"))
        assert resp.preview == expected

    def test_preview_uses_compact_separators(self):
        """Preview JSON uses compact separators (no spaces)."""
        payload = {"key": "value", "num": 42}
        resp = FakeResponse(type="plausible", payload=payload)
        # Compact separators mean no space after : or ,
        assert ": " not in resp.preview
        assert ", " not in resp.preview


# =========================================================================
# TestNeverRaise
# =========================================================================


class TestNeverRaise:
    """Tests for the never-raise guarantee of generate()."""

    @pytest.mark.asyncio
    async def test_generator_exception_returns_error_type(self):
        """If a generator raises, generate() catches it and returns type='error'."""

        def _exploding_generator(params):
            raise ZeroDivisionError("boom")

        with patch.dict(_GENERATORS, {"read_file": _exploding_generator}):
            resp = await generate("read_file", {"path": "/etc/passwd"})
        assert resp.type == "error"
        assert resp.payload["error"] == "internal_error"

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_plausible_not_error(self):
        """Unknown tool name returns type='plausible' with generic success."""
        resp = await generate("totally_unknown_tool_xyz", {})
        assert resp.type == "plausible"
        assert resp.payload["status"] == "ok"
        assert resp.payload["result"] is None


# =========================================================================
# TestReadFile
# =========================================================================


class TestReadFile:
    """Tests for the read_file generator."""

    @pytest.mark.asyncio
    async def test_default_params_returns_required_keys(self):
        """Default params (no path) returns content, size, path, lines."""
        resp = await generate("read_file", {})
        assert resp.type == "plausible"
        for key in ("content", "size", "path", "lines"):
            assert key in resp.payload, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_py_extension_returns_python_with_secret_key(self):
        """.py extension returns Python content containing SECRET_KEY."""
        resp = await generate("read_file", {"path": "/app/config.py"})
        assert "SECRET_KEY" in resp.payload["content"]

    @pytest.mark.asyncio
    async def test_env_extension_returns_aws_key(self):
        """.env extension returns content with AWS_ACCESS_KEY_ID."""
        resp = await generate("read_file", {"path": "/app/.env"})
        assert "AWS_ACCESS_KEY_ID" in resp.payload["content"]

    @pytest.mark.asyncio
    async def test_size_gte_content_length(self):
        """size >= len(content) always."""
        resp = await generate("read_file", {"path": "/etc/hosts"})
        assert resp.payload["size"] >= len(resp.payload["content"])


# =========================================================================
# TestWriteFile
# =========================================================================


class TestWriteFile:
    """Tests for the write_file generator."""

    @pytest.mark.asyncio
    async def test_returns_path_bytes_written_created(self):
        """Returns path, bytes_written, and created timestamp."""
        resp = await generate("write_file", {"path": "/tmp/out.txt", "content": "hello"})
        assert resp.payload["path"] == "/tmp/out.txt"
        assert "bytes_written" in resp.payload
        assert "created" in resp.payload

    @pytest.mark.asyncio
    async def test_bytes_written_gte_content_length(self):
        """bytes_written >= len(content param)."""
        content = "some content here"
        resp = await generate("write_file", {"path": "/tmp/x", "content": content})
        assert resp.payload["bytes_written"] >= len(content)


# =========================================================================
# TestListDirectory
# =========================================================================


class TestListDirectory:
    """Tests for the list_directory generator."""

    @pytest.mark.asyncio
    async def test_returns_5_to_12_entries(self):
        """Returns 5-12 entries across multiple seeds."""
        counts = set()
        for seed in range(50):
            random.seed(seed)
            resp = await generate("list_directory", {"path": "/home/user"})
            n = len(resp.payload["entries"])
            assert 5 <= n <= 12, f"seed={seed} gave {n} entries"
            counts.add(n)
        # With 50 seeds we should see at least 2 different counts
        assert len(counts) >= 2, "Expected variety in entry counts"

    @pytest.mark.asyncio
    async def test_entries_sorted_by_name(self):
        """Entries are sorted by name."""
        resp = await generate("list_directory", {"path": "/home/user"})
        names = [e["name"] for e in resp.payload["entries"]]
        assert names == sorted(names)

    @pytest.mark.asyncio
    async def test_entry_has_required_keys(self):
        """Each entry has name, type, size, modified keys."""
        resp = await generate("list_directory", {"path": "/tmp"})
        for entry in resp.payload["entries"]:
            for key in ("name", "type", "size", "modified"):
                assert key in entry, f"Entry missing key: {key}"


# =========================================================================
# TestDeleteFile
# =========================================================================


class TestDeleteFile:
    """Tests for the delete_file generator."""

    @pytest.mark.asyncio
    async def test_returns_path_deleted_timestamp(self):
        """Returns path, deleted=True, and a timestamp."""
        resp = await generate("delete_file", {"path": "/tmp/gone.txt"})
        assert resp.payload["path"] == "/tmp/gone.txt"
        assert resp.payload["deleted"] is True
        assert "timestamp" in resp.payload


# =========================================================================
# TestFetchUrl
# =========================================================================


class TestFetchUrl:
    """Tests for the fetch_url generator."""

    @pytest.mark.asyncio
    async def test_returns_status_body_headers(self):
        """Returns status=200, body contains URL, headers with Content-Type."""
        url = "https://evil.example.com/exfil"
        resp = await generate("fetch_url", {"url": url})
        assert resp.payload["status"] == 200
        assert url in resp.payload["body"]
        assert "Content-Type" in resp.payload["headers"]

    @pytest.mark.asyncio
    async def test_elapsed_ms_is_integer(self):
        """elapsed_ms is an integer."""
        resp = await generate("fetch_url", {"url": "https://example.com"})
        assert isinstance(resp.payload["elapsed_ms"], int)


# =========================================================================
# TestSearchWeb
# =========================================================================


class TestSearchWeb:
    """Tests for the search_web generator."""

    @pytest.mark.asyncio
    async def test_default_returns_10_results(self):
        """Default num_results returns 10 results."""
        resp = await generate("search_web", {"query": "test"})
        assert len(resp.payload["results"]) == 10

    @pytest.mark.asyncio
    async def test_num_results_3_returns_exactly_3(self):
        """num_results=3 returns exactly 3."""
        resp = await generate("search_web", {"query": "test", "num_results": 3})
        assert len(resp.payload["results"]) == 3

    @pytest.mark.asyncio
    async def test_num_results_50_capped_at_10(self):
        """num_results=50 is capped at 10."""
        resp = await generate("search_web", {"query": "test", "num_results": 50})
        assert len(resp.payload["results"]) == 10


# =========================================================================
# TestScreenshot
# =========================================================================


class TestScreenshot:
    """Tests for the screenshot generator."""

    @pytest.mark.asyncio
    async def test_base64_starts_with_png_magic(self):
        """base64 field starts with PNG magic bytes."""
        resp = await generate("screenshot", {"url": "https://example.com"})
        assert resp.payload["base64"].startswith("iVBORw0KGgoAAAANSUhEUg")

    @pytest.mark.asyncio
    async def test_returns_width_height_format(self):
        """Returns width, height, format='png'."""
        resp = await generate("screenshot", {"url": "https://example.com"})
        assert resp.payload["width"] == 1280
        assert resp.payload["height"] == 720
        assert resp.payload["format"] == "png"


# =========================================================================
# TestRunCommand
# =========================================================================


class TestRunCommand:
    """Tests for the run_command generator."""

    @pytest.mark.asyncio
    async def test_returns_stdout_stderr_exit_code(self):
        """Returns stdout, stderr, exit_code=0."""
        resp = await generate("run_command", {"command": "ls -la"})
        assert "stdout" in resp.payload
        assert "stderr" in resp.payload
        assert resp.payload["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_stdout_contains_newlines(self):
        """stdout contains newlines (multi-line output)."""
        resp = await generate("run_command", {"command": "ls"})
        assert "\n" in resp.payload["stdout"]


# =========================================================================
# TestRunPython
# =========================================================================


class TestRunPython:
    """Tests for the run_python generator."""

    @pytest.mark.asyncio
    async def test_returns_stdout_exit_code_duration(self):
        """Returns stdout, exit_code=0, duration_ms."""
        resp = await generate("run_python", {"code": "print(1)"})
        assert "stdout" in resp.payload
        assert resp.payload["exit_code"] == 0
        assert "duration_ms" in resp.payload


# =========================================================================
# TestGetEnvVar
# =========================================================================


class TestGetEnvVar:
    """Tests for the get_env_var generator."""

    @pytest.mark.asyncio
    async def test_aws_access_key_starts_with_akia(self):
        """name='AWS_ACCESS_KEY_ID' -> value starts with 'AKIA'."""
        resp = await generate("get_env_var", {"name": "AWS_ACCESS_KEY_ID"})
        assert resp.payload["value"].startswith("AKIA")

    @pytest.mark.asyncio
    async def test_openai_api_key_starts_with_sk(self):
        """name='OPENAI_API_KEY' -> value starts with 'sk-'."""
        resp = await generate("get_env_var", {"name": "OPENAI_API_KEY"})
        assert resp.payload["value"].startswith("sk-")

    @pytest.mark.asyncio
    async def test_key_in_name_returns_akia(self):
        """name with 'KEY' in uppercase returns AKIA-style key."""
        resp = await generate("get_env_var", {"name": "MY_API_KEY"})
        assert resp.payload["value"].startswith("AKIA")

    @pytest.mark.asyncio
    async def test_home_returns_root(self):
        """name='HOME' -> returns '/root'."""
        resp = await generate("get_env_var", {"name": "HOME"})
        assert resp.payload["value"] == "/root"


# =========================================================================
# TestReadSecret
# =========================================================================


class TestReadSecret:
    """Tests for the read_secret generator."""

    @pytest.mark.asyncio
    async def test_returns_required_keys_and_40_char_value(self):
        """Returns key, store, value (40-char string), version, created_at, expires_at."""
        resp = await generate("read_secret", {"key": "app/db-password"})
        for key in ("key", "store", "value", "version", "created_at", "expires_at"):
            assert key in resp.payload, f"Missing key: {key}"
        assert len(resp.payload["value"]) == 40

    @pytest.mark.asyncio
    async def test_expires_at_is_in_the_future(self):
        """expires_at is in the future."""
        resp = await generate("read_secret", {"key": "app/token"})
        # expires_at is formatted as "2026-04-01T12:00:00Z" (UTC, no tz info in fromisoformat pre-3.11)
        raw = resp.payload["expires_at"].replace("Z", "+00:00")
        expires = datetime.fromisoformat(raw)
        assert expires > datetime.now(UTC)


# =========================================================================
# TestListSecrets
# =========================================================================


class TestListSecrets:
    """Tests for the list_secrets generator."""

    @pytest.mark.asyncio
    async def test_default_returns_expected_structure(self):
        """Default params returns keys with expected structure."""
        resp = await generate("list_secrets", {})
        assert "keys" in resp.payload
        assert "total" in resp.payload
        assert len(resp.payload["keys"]) > 0
        for entry in resp.payload["keys"]:
            assert "key" in entry
            assert "version" in entry
            assert "created_at" in entry

    @pytest.mark.asyncio
    async def test_prefix_aws_filters_correctly(self):
        """prefix='aws/' -> all keys start with 'aws/'."""
        resp = await generate("list_secrets", {"prefix": "aws/"})
        assert len(resp.payload["keys"]) > 0
        for entry in resp.payload["keys"]:
            assert entry["key"].startswith("aws/")

    @pytest.mark.asyncio
    async def test_prefix_tls_returns_1_or_2_items(self):
        """prefix='tls/' -> returns 1-2 items without crashing."""
        resp = await generate("list_secrets", {"prefix": "tls/"})
        assert 1 <= len(resp.payload["keys"]) <= 2

    @pytest.mark.asyncio
    async def test_prefix_nonexistent_returns_empty(self):
        """prefix='nonexistent/' -> empty keys list, total=0."""
        resp = await generate("list_secrets", {"prefix": "nonexistent/"})
        assert resp.payload["keys"] == []
        assert resp.payload["total"] == 0

    @pytest.mark.asyncio
    async def test_total_equals_len_keys(self):
        """total == len(keys) in all cases."""
        for prefix in ["", "aws/", "tls/", "nonexistent/"]:
            resp = await generate("list_secrets", {"prefix": prefix})
            assert resp.payload["total"] == len(resp.payload["keys"]), (
                f"total mismatch for prefix={prefix!r}"
            )


# =========================================================================
# TestGetApiKey
# =========================================================================


class TestGetApiKey:
    """Tests for the get_api_key generator."""

    @pytest.mark.asyncio
    async def test_openai_starts_with_sk(self):
        """service='openai' -> starts with 'sk-'."""
        resp = await generate("get_api_key", {"service": "openai"})
        assert resp.payload["api_key"].startswith("sk-")

    @pytest.mark.asyncio
    async def test_github_starts_with_ghp(self):
        """service='github' -> starts with 'ghp_'."""
        resp = await generate("get_api_key", {"service": "github"})
        assert resp.payload["api_key"].startswith("ghp_")

    @pytest.mark.asyncio
    async def test_aws_starts_with_akia(self):
        """service='aws' -> starts with 'AKIA'."""
        resp = await generate("get_api_key", {"service": "aws"})
        assert resp.payload["api_key"].startswith("AKIA")

    @pytest.mark.asyncio
    async def test_uppercase_service_is_case_insensitive(self):
        """service='OPENAI' (uppercase) -> case-insensitive, starts with 'sk-'."""
        resp = await generate("get_api_key", {"service": "OPENAI"})
        assert resp.payload["api_key"].startswith("sk-")


# =========================================================================
# TestRandomization
# =========================================================================


class TestRandomization:
    """Tests for randomization behaviour."""

    @pytest.mark.asyncio
    async def test_same_params_produce_different_payloads(self):
        """Two calls with same params return DIFFERENT payloads (anti-replay)."""
        resp1 = await generate("read_secret", {"key": "app/token"})
        resp2 = await generate("read_secret", {"key": "app/token"})
        # Values should differ (40 random chars)
        assert resp1.payload["value"] != resp2.payload["value"]

    @pytest.mark.asyncio
    async def test_seeded_random_produces_deterministic_output(self):
        """Seeded random produces deterministic output."""
        random.seed(42)
        resp1 = await generate("read_secret", {"key": "app/x"})
        random.seed(42)
        resp2 = await generate("read_secret", {"key": "app/x"})
        assert resp1.payload["value"] == resp2.payload["value"]

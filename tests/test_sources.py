"""Tests for griffith.sources — URL/shorthand/local path resolution with hardened clone.

Unit 2 is test-first. Cleanup correctness on failure paths is load-bearing; tests
precede implementation.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from griffith.sources import (
    CLONE_TIMEOUT,
    GriffithCloneError,
    _expand_github_shorthand,
    _is_refused_protocol,
    _is_shorthand,
    _is_url,
    griffith_cache_dir,
    resolve,
)


def _make_stub_plugin(tmp_path: Path) -> Path:
    """Create a minimal `.claude-plugin/plugin.json` dir so a path looks plugin-shaped."""
    plugin_dir = tmp_path / "plugin"
    (plugin_dir / ".claude-plugin").mkdir(parents=True)
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "stub"}))
    return plugin_dir


def _mock_clone_creates_target():
    """Returns a side_effect that mimics `git clone` by mkdir'ing the target dir."""

    def _side_effect(cmd, *args, **kwargs):
        target = cmd[-1]
        Path(target).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return _side_effect


# ============================================================================
# Detection primitives
# ============================================================================


class TestDetection:
    def test_http_url_detected(self):
        assert _is_url("https://github.com/foo/bar.git")
        assert _is_url("http://example.com/repo.git")

    def test_ssh_url_detected(self):
        assert _is_url("git@github.com:foo/bar.git")
        assert _is_url("git@gitlab.com:org/repo.git")

    def test_shorthand_detected(self):
        assert _is_shorthand("owner/repo")
        assert _is_shorthand("EveryInc/every-marketplace")
        assert _is_shorthand("GruntworkAI/gruntwork-griffith")

    def test_shorthand_rejects_invalid(self):
        assert not _is_shorthand("too/many/slashes/here")
        assert not _is_shorthand("")
        assert not _is_shorthand("no-slash-here")
        assert not _is_shorthand("-leading-dash/repo")

    def test_refused_protocols(self):
        assert _is_refused_protocol("file:///etc/passwd")
        assert _is_refused_protocol("ssh://malicious/")
        assert not _is_refused_protocol("https://github.com/foo/bar.git")
        assert not _is_refused_protocol("git@github.com:foo/bar.git")

    def test_expand_shorthand(self):
        assert _expand_github_shorthand("owner/repo") == "https://github.com/owner/repo.git"
        assert (
            _expand_github_shorthand("EveryInc/every-marketplace")
            == "https://github.com/EveryInc/every-marketplace.git"
        )


# ============================================================================
# Local path resolution
# ============================================================================


class TestLocalPath:
    def test_existing_path_yields_with_source_type(self, tmp_path):
        plugin = _make_stub_plugin(tmp_path)
        with resolve(str(plugin)) as (path, source_type):
            assert path == plugin.resolve()
            assert source_type == "path"
        assert plugin.exists(), "local path must not be cleaned up"

    def test_absolute_path(self, tmp_path):
        plugin = _make_stub_plugin(tmp_path)
        with resolve(str(plugin.absolute())) as (path, source_type):
            assert source_type == "path"

    def test_nonexistent_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            with resolve(str(tmp_path / "does-not-exist")):
                pass


# ============================================================================
# Refused protocols
# ============================================================================


class TestRefusedProtocols:
    def test_file_url_refused(self):
        with pytest.raises(ValueError, match="Refused protocol"):
            with resolve("file:///etc/passwd"):
                pass

    def test_ssh_scheme_refused(self):
        with pytest.raises(ValueError, match="Refused protocol"):
            with resolve("ssh://malicious/"):
                pass


# ============================================================================
# Cloned path (mocked subprocess)
# ============================================================================


class TestClonedPath:
    def test_url_clone_happy_path(self):
        with patch("griffith.sources.subprocess.run", side_effect=_mock_clone_creates_target()):
            with resolve("https://example.com/foo.git") as (path, source_type):
                assert source_type == "url"
                assert path.exists() and path.is_dir()

    def test_shorthand_clone_happy_path(self, capsys):
        with patch("griffith.sources.subprocess.run", side_effect=_mock_clone_creates_target()):
            with resolve("owner/repo") as (path, source_type):
                assert source_type == "shorthand"
        captured = capsys.readouterr()
        assert "owner/repo" in captured.err
        assert "https://github.com/owner/repo.git" in captured.err

    def test_clone_invoked_with_hardening_flags(self):
        captured_cmd = []

        def _capture(cmd, *args, **kwargs):
            captured_cmd.extend(cmd)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("griffith.sources.subprocess.run", side_effect=_capture):
            with resolve("https://example.com/foo.git"):
                pass

        expected_flags = [
            "protocol.file.allow=never",
            "protocol.ext.allow=never",
            "core.symlinks=false",
            "core.hooksPath=/dev/null",
            "filter.lfs.smudge=",
            "filter.lfs.required=false",
            "submodule.recurse=false",
        ]
        for flag in expected_flags:
            assert flag in captured_cmd, f"Missing hardening flag: {flag}"
        assert "--depth" in captured_cmd and "1" in captured_cmd
        assert "--no-tags" in captured_cmd
        assert "--no-recurse-submodules" in captured_cmd

    def test_clone_env_is_scrubbed(self):
        captured_kwargs = {}

        def _capture(cmd, *args, **kwargs):
            captured_kwargs.update(kwargs)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        fake_sensitive_vars = {
            "SSH_AUTH_SOCK": "/fake/agent.sock",
            "GIT_ASKPASS": "/fake/askpass",
            "SSH_ASKPASS": "/fake/sshaskpass",
            "GIT_SSH_COMMAND": "evil",
        }
        with patch.dict(os.environ, fake_sensitive_vars):
            with patch("griffith.sources.subprocess.run", side_effect=_capture):
                with resolve("https://example.com/foo.git"):
                    pass

        env = captured_kwargs.get("env", {})
        for var in fake_sensitive_vars:
            assert var not in env, f"Sensitive env var {var} must not propagate to git"
        assert env.get("GIT_TERMINAL_PROMPT") == "0"
        assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
        assert env.get("GIT_LFS_SKIP_SMUDGE") == "1"
        assert env.get("HOME", "").endswith(".empty-home")

    def test_clone_uses_capture_output_and_timeout(self):
        captured_kwargs = {}

        def _capture(cmd, *args, **kwargs):
            captured_kwargs.update(kwargs)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("griffith.sources.subprocess.run", side_effect=_capture):
            with resolve("https://example.com/foo.git"):
                pass

        assert captured_kwargs.get("capture_output") is True
        assert captured_kwargs.get("text") is True
        assert captured_kwargs.get("check") is True
        assert captured_kwargs.get("timeout") == CLONE_TIMEOUT

    def test_clone_failure_preserves_stderr(self):
        def _fail(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(
                1, cmd, output="", stderr="fatal: Authentication failed for 'x'"
            )

        with patch("griffith.sources.subprocess.run", side_effect=_fail):
            with pytest.raises(GriffithCloneError, match="Authentication failed"):
                with resolve("https://example.com/foo.git"):
                    pass

    def test_clone_timeout_raises_clone_error(self):
        def _timeout(cmd, *args, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout=CLONE_TIMEOUT)

        with patch("griffith.sources.subprocess.run", side_effect=_timeout):
            with pytest.raises(GriffithCloneError, match="timed out"):
                with resolve("https://example.com/foo.git"):
                    pass


# ============================================================================
# Cleanup correctness — the load-bearing concern for Unit 2
# ============================================================================


class TestCleanup:
    def test_temp_dir_cleaned_on_success(self):
        captured_path: list[Path] = []

        with patch("griffith.sources.subprocess.run", side_effect=_mock_clone_creates_target()):
            with resolve("https://example.com/foo.git") as (path, _):
                captured_path.append(path)
                assert path.exists()

        assert not captured_path[0].exists(), "clone target should be cleaned up after context exit"

    def test_temp_dir_cleaned_on_exception_in_with_block(self):
        captured_path: list[Path] = []

        with patch("griffith.sources.subprocess.run", side_effect=_mock_clone_creates_target()):
            with pytest.raises(RuntimeError, match="simulated"):
                with resolve("https://example.com/foo.git") as (path, _):
                    captured_path.append(path)
                    raise RuntimeError("simulated analyzer failure")

        assert len(captured_path) == 1
        assert not captured_path[0].exists(), "clone target must be cleaned up even on exception"

    def test_no_leaked_temp_dirs_on_clone_failure(self):
        cache_dir = griffith_cache_dir()
        pre_children = set(cache_dir.iterdir())

        def _fail(cmd, *args, **kwargs):
            raise subprocess.CalledProcessError(1, cmd, output="", stderr="fatal: not found")

        with patch("griffith.sources.subprocess.run", side_effect=_fail):
            with pytest.raises(GriffithCloneError):
                with resolve("https://example.com/foo.git"):
                    pass

        post_children = set(cache_dir.iterdir())
        new_children = post_children - pre_children
        assert not new_children, f"Temp dirs leaked on clone failure: {new_children}"


# ============================================================================
# Cache dir hardening
# ============================================================================


class TestCacheDir:
    def test_cache_dir_exists_and_has_0700_perms(self):
        cache = griffith_cache_dir()
        assert cache.exists()
        assert cache.is_dir()
        mode = cache.stat().st_mode & 0o777
        assert mode == 0o700, f"Expected 0o700, got {oct(mode)}"


# ============================================================================
# Adversarial — verify hardening flag set actually neutralizes named attacks
# ============================================================================


class TestAdversarial:
    @pytest.mark.adversarial
    def test_smudge_filter_neutralized_by_flag_set(self):
        """With the hardening flag set, LFS smudge + ext-protocol filters are disabled."""
        captured_cmd = []

        def _capture(cmd, *args, **kwargs):
            captured_cmd.extend(cmd)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("griffith.sources.subprocess.run", side_effect=_capture):
            with resolve("https://example.com/evil.git"):
                pass

        assert "filter.lfs.smudge=" in captured_cmd
        assert "filter.lfs.required=false" in captured_cmd
        assert "protocol.ext.allow=never" in captured_cmd
        assert "core.hooksPath=/dev/null" in captured_cmd

    @pytest.mark.adversarial
    def test_submodule_recursion_disabled(self):
        captured_cmd = []

        def _capture(cmd, *args, **kwargs):
            captured_cmd.extend(cmd)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("griffith.sources.subprocess.run", side_effect=_capture):
            with resolve("https://example.com/evil.git"):
                pass

        assert "--no-recurse-submodules" in captured_cmd
        assert "submodule.recurse=false" in captured_cmd


# ============================================================================
# Real-network integration (skipped without -m network)
# ============================================================================


@pytest.mark.network
class TestNetworkIntegration:
    def test_real_clone_of_public_repo(self):
        # octocat/Hello-World is a minimal public repo
        with resolve("https://github.com/octocat/Hello-World.git") as (path, source_type):
            assert source_type == "url"
            assert path.exists()
            assert any(path.iterdir())

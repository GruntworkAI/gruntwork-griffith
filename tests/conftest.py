"""Shared pytest fixtures and configuration for Griffith tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def minimal_plugin(fixtures_dir: Path) -> Path:
    """Path to the minimal valid plugin fixture. Built in Unit 3."""
    return fixtures_dir / "minimal-plugin"


@pytest.fixture
def security_traps_plugin(fixtures_dir: Path) -> Path:
    """Path to the plugin with known security violations. Built in Unit 4."""
    return fixtures_dir / "security-traps-plugin"


@pytest.fixture
def mcp_heavy_plugin(fixtures_dir: Path) -> Path:
    """Path to the plugin with high baseline cost. Built in Unit 5."""
    return fixtures_dir / "mcp-heavy-plugin"


@pytest.fixture
def minimal_marketplace(fixtures_dir: Path) -> Path:
    """Path to the marketplace fixture with 2 plugins. Built in Unit 7."""
    return fixtures_dir / "minimal-marketplace"


@pytest.fixture
def adversarial_dir(fixtures_dir: Path) -> Path:
    """Path to the adversarial fixtures directory (symlink escape, redos, yaml rce, etc)."""
    return fixtures_dir / "adversarial"

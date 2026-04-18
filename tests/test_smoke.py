"""Smoke tests — verify the package imports and basic metadata is correct."""

from __future__ import annotations

import griffith


def test_version_is_defined() -> None:
    assert hasattr(griffith, "__version__")
    assert isinstance(griffith.__version__, str)
    assert griffith.__version__ != ""


def test_analyzer_exports() -> None:
    """The analyzer package should expose the four core classes (still stubs in Unit 1)."""
    from griffith.analyzer import (
        ArchitectureAssessor,
        FootprintEstimator,
        PluginInventory,
        SecurityScanner,
    )

    # Classes exist and are importable; implementation comes in later units.
    assert PluginInventory is not None
    assert SecurityScanner is not None
    assert FootprintEstimator is not None
    assert ArchitectureAssessor is not None

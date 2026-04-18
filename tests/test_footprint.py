"""Tests for FootprintEstimator — YAML-driven context cost estimation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from griffith.analyzer.footprint import FootprintEstimate, FootprintEstimator
from griffith.analyzer.inventory import PluginInventory

REAL_PLUGIN_CE = Path(
    os.path.expanduser(
        "~/.claude/plugins/cache/every-marketplace/compound-engineering/2.67.0"
    )
)
REAL_PLUGIN_LMF = Path(
    os.path.expanduser("~/.claude/plugins/cache/gruntwork-marketplace/lastmilefirst/0.14.0")
)


# ============================================================================
# Minimal plugin — tiny baseline, excellent rating
# ============================================================================


class TestMinimalPlugin:
    def test_baseline_under_500(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        # 1 agent (100) + 1 command (50) + 1 skill (20) = 170
        assert est.baseline_tokens < 500
        assert est.efficiency_rating == "excellent"

    def test_on_demand_max_exceeds_baseline(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        assert est.on_demand_max > est.baseline_tokens

    def test_primary_driver_is_agents(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        # Agent base=100 > command base=50 > skill base=20
        assert est.primary_driver == "agents"

    def test_per_component_breakdown_sums_to_baseline(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        assert sum(est.per_component.values()) == est.baseline_tokens


# ============================================================================
# MCP-heavy plugin — triggers moderate rating
# ============================================================================


class TestMcpHeavyPlugin:
    def test_mcp_heavy_baseline_above_1500(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "mcp-heavy-plugin")
        est = FootprintEstimator().estimate(inv)
        # 2 servers * 500 base + 10 tools * 100 per_tool = 1000 + 1000 = 2000
        assert est.baseline_tokens >= 1500, (
            f"Expected baseline >=1500 for 2 servers + 10 tools, got {est.baseline_tokens}"
        )

    def test_mcp_heavy_rating_is_moderate_or_higher(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "mcp-heavy-plugin")
        est = FootprintEstimator().estimate(inv)
        assert est.efficiency_rating in ("moderate", "heavy", "excessive")

    def test_mcp_heavy_primary_driver_is_mcp_servers(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "mcp-heavy-plugin")
        est = FootprintEstimator().estimate(inv)
        assert est.primary_driver == "mcp_servers"


# ============================================================================
# Edge cases
# ============================================================================


class TestEdgeCases:
    def test_empty_plugin_is_excellent_with_none_driver(self, tmp_path):
        plugin = tmp_path / "empty"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "empty"}')
        inv = PluginInventory.from_path(plugin)
        est = FootprintEstimator().estimate(inv)
        assert est.baseline_tokens == 0
        assert est.on_demand_max == 0
        assert est.primary_driver == "none"
        assert est.efficiency_rating == "excellent"

    def test_hooks_only_has_zero_baseline(self, tmp_path):
        plugin = tmp_path / "hooks-only"
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "hooks-only"}')
        (plugin / "hooks").mkdir()
        (plugin / "hooks" / "one.sh").write_text("#!/bin/sh\necho hi\n")
        (plugin / "hooks" / "two.sh").write_text("#!/bin/sh\necho bye\n")
        inv = PluginInventory.from_path(plugin)
        est = FootprintEstimator().estimate(inv)
        # hooks contribute 0 per context_costs.yaml
        assert est.baseline_tokens == 0
        assert est.primary_driver == "none"

    def test_skills_only_has_small_baseline(self, fixtures_dir):
        # no-manifest-plugin has 1 skill, 0 other components
        inv = PluginInventory.from_path(fixtures_dir / "no-manifest-plugin")
        est = FootprintEstimator().estimate(inv)
        # 1 skill * base 20 = 20
        assert est.baseline_tokens == 20
        assert est.primary_driver == "skills"
        assert est.efficiency_rating == "excellent"


# ============================================================================
# Estimate shape
# ============================================================================


class TestEstimateShape:
    def test_estimate_has_all_fields(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        assert isinstance(est, FootprintEstimate)
        assert isinstance(est.baseline_tokens, int)
        assert isinstance(est.on_demand_max, int)
        assert isinstance(est.primary_driver, str)
        assert isinstance(est.efficiency_rating, str)
        assert isinstance(est.per_component, dict)

    def test_efficiency_rating_is_valid(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        est = FootprintEstimator().estimate(inv)
        assert est.efficiency_rating in (
            "excellent",
            "good",
            "moderate",
            "heavy",
            "excessive",
        )


# ============================================================================
# Lazy YAML loading
# ============================================================================


class TestLazyLoading:
    def test_missing_costs_file_raises_at_estimate(
        self, tmp_path, monkeypatch, minimal_plugin
    ):
        import griffith.analyzer.footprint as footprint_mod

        missing = tmp_path / "nowhere" / "context_costs.yaml"
        monkeypatch.setattr(footprint_mod, "_DEFAULT_COSTS_PATH", missing)

        est = FootprintEstimator()
        inv = PluginInventory.from_path(minimal_plugin)
        with pytest.raises((FileNotFoundError, OSError)):
            est.estimate(inv)


# ============================================================================
# Real-plugin integration
# ============================================================================


@pytest.mark.skipif(not REAL_PLUGIN_CE.exists(), reason="compound-engineering not cached")
class TestRealPluginCompoundEngineering:
    def test_ce_primary_driver_is_agents(self):
        """CE has 49 agents + 43 skills + 0 hooks + 0 MCP.
        agents_baseline = 49*100 = 4900; skills_baseline = 43*20 = 860.
        agents should dominate."""
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        est = FootprintEstimator().estimate(inv)
        assert est.primary_driver == "agents"

    def test_ce_rating_reflects_agent_heaviness(self):
        """CE's ~4900+ agent baseline tokens → heavy or excessive."""
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        est = FootprintEstimator().estimate(inv)
        # Should be heavy (>=3000) or excessive (>=5000)
        assert est.efficiency_rating in ("heavy", "excessive"), (
            f"CE with 49 agents should be heavy/excessive; got {est.efficiency_rating} "
            f"at {est.baseline_tokens} tokens"
        )


@pytest.mark.skipif(not REAL_PLUGIN_LMF.exists(), reason="lastmilefirst not cached")
class TestRealPluginLastMileFirst:
    def test_lmf_estimate_completes(self):
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        est = FootprintEstimator().estimate(inv)
        assert est.baseline_tokens > 0

    def test_lmf_primary_driver_is_plausible(self):
        """LMF has 13 agents, 20 commands, 21 skills. commands baseline=20*50=1000;
        agents=13*100=1300; skills=21*20=420. agents should win narrowly."""
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        est = FootprintEstimator().estimate(inv)
        # Accept either "agents" or "commands" — both plausible given counts
        assert est.primary_driver in ("agents", "commands"), (
            f"LMF primary_driver unexpected: {est.primary_driver}"
        )

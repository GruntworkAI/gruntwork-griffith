"""Tests for ArchitectureAssessor — pattern classification over inventory ratios."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from griffith.analyzer.architecture import ArchitectureAssessment, ArchitectureAssessor
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
# Classification by fixture
# ============================================================================


class TestAgentHeavy:
    def test_nested_agents_only_is_agent_heavy(self, fixtures_dir):
        # nested-agents-plugin: 2 agents, 0 skills, 0 commands, 0 mcp
        inv = PluginInventory.from_path(fixtures_dir / "nested-agents-plugin")
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "agent-heavy"


class TestSkillFirst:
    def test_skills_only_is_skill_first(self, fixtures_dir):
        # no-manifest-plugin: 0 agents, 1 skill, 0 commands, 0 mcp
        inv = PluginInventory.from_path(fixtures_dir / "no-manifest-plugin")
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "skill-first"


class TestMcpBased:
    def test_mcp_presence_dominates_classification(self, fixtures_dir):
        # mcp-heavy-plugin: 0 agents, 0 skills, 0 commands, 10 mcp files
        inv = PluginInventory.from_path(fixtures_dir / "mcp-heavy-plugin")
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "mcp-based"


class TestHybrid:
    def test_balanced_mix_is_hybrid(self, minimal_plugin):
        # minimal-plugin: 1 agent + 1 command + 1 skill + 1 hook (33% each)
        inv = PluginInventory.from_path(minimal_plugin)
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "hybrid"

    def test_empty_plugin_is_hybrid_with_note(self, tmp_path):
        plugin = tmp_path / "empty"
        plugin.mkdir()
        (plugin / ".claude-plugin").mkdir()
        (plugin / ".claude-plugin" / "plugin.json").write_text('{"name": "empty"}')
        inv = PluginInventory.from_path(plugin)
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "hybrid"
        assert any("no components" in note.lower() for note in assess.efficiency_notes)


# ============================================================================
# Efficiency notes + recommendations
# ============================================================================


class TestNotesAndRecommendations:
    def test_no_mcp_generates_positive_note(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        assess = ArchitectureAssessor().assess(inv)
        assert any(
            "no mcp" in note.lower() or "no always-on" in note.lower()
            for note in assess.efficiency_notes
        )

    def test_mcp_presence_generates_cost_note(self, fixtures_dir):
        inv = PluginInventory.from_path(fixtures_dir / "mcp-heavy-plugin")
        assess = ArchitectureAssessor().assess(inv)
        # Should mention MCP and baseline/always-on cost
        assert any(
            "mcp" in note.lower() and ("baseline" in note.lower() or "always-on" in note.lower() or "always loaded" in note.lower())
            for note in assess.efficiency_notes
        )

    def test_heavy_agent_count_generates_note(self, fixtures_dir):
        # Nested-agents has only 2 agents; not "heavy". Use CE below for heavy test.
        pass

    def test_assessment_has_expected_fields(self, minimal_plugin):
        inv = PluginInventory.from_path(minimal_plugin)
        assess = ArchitectureAssessor().assess(inv)
        assert isinstance(assess, ArchitectureAssessment)
        assert assess.pattern in ("agent-heavy", "skill-first", "mcp-based", "hybrid")
        assert isinstance(assess.efficiency_notes, list)
        assert isinstance(assess.recommendations, list)


# ============================================================================
# Real-plugin integration
# ============================================================================


@pytest.mark.skipif(not REAL_PLUGIN_CE.exists(), reason="compound-engineering not cached")
class TestRealPluginCompoundEngineering:
    def test_ce_is_agent_heavy_or_hybrid(self):
        """CE has 49 agents + 43 skills (+0 cmd/mcp). agent_ratio = 49/92 = 53.3% — just
        over the 50% threshold. Accept either agent-heavy or hybrid in case threshold
        moves slightly."""
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern in ("agent-heavy", "hybrid")

    def test_ce_has_heavy_agent_count_note(self):
        """49 agents is a lot; should generate a baseline-concern note."""
        inv = PluginInventory.from_path(REAL_PLUGIN_CE)
        assess = ArchitectureAssessor().assess(inv)
        assert any(
            "agent" in note.lower() and (
                "description" in note.lower()
                or "baseline" in note.lower()
                or "always" in note.lower()
            )
            for note in assess.efficiency_notes
        ), f"No agent-count note in: {assess.efficiency_notes}"


@pytest.mark.skipif(not REAL_PLUGIN_LMF.exists(), reason="lastmilefirst not cached")
class TestRealPluginLastMileFirst:
    def test_lmf_is_hybrid(self):
        """LMF: 13 agents + 20 commands + 21 skills → agent_ratio=24%, skill_ratio=39%.
        Neither majority → hybrid."""
        inv = PluginInventory.from_path(REAL_PLUGIN_LMF)
        assess = ArchitectureAssessor().assess(inv)
        assert assess.pattern == "hybrid"

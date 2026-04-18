"""Classify a plugin's architecture pattern from its component ratios.

Four patterns recognized:
    agent-heavy    agents dominate context-component ratio (> 50%)
    skill-first    skills dominate (> 50%) and agents are minimal (< 20%)
    mcp-based      any MCP servers present (MCP always-loaded overhead dominates
                   cost characteristics regardless of count balance)
    hybrid         anything else — balanced mix, empty plugin, etc.

Denominator for ratios is "context-relevant components":
    agents + commands + skills + mcp_servers
Hooks, personas, and templates are infrastructure/ambient; they don't define
the plugin's user-facing architecture.

Thresholds are documented judgment calls, not normative. Tuned so that:
- compound-engineering (49 agents + 43 skills = 53.3% agents) → agent-heavy
- lastmilefirst (13 agents + 20 commands + 21 skills = 24% agents) → hybrid
- a pure-skills plugin → skill-first
- any plugin with MCP → mcp-based (the overhead signal wins)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from griffith.analyzer.inventory import PluginInventory

# Classification thresholds (0.0–1.0). Change with deliberation; they shape
# how the reporter describes every plugin.
AGENT_HEAVY_THRESHOLD = 0.50
SKILL_FIRST_SKILL_THRESHOLD = 0.50
SKILL_FIRST_MAX_AGENT_RATIO = 0.20

# Heuristics for efficiency notes.
AGENT_COUNT_NOTE_THRESHOLD = 20  # >= triggers "{n} agent descriptions always in context"
SKILL_COUNT_NOTE_THRESHOLD = 30  # >= triggers "{n} skill descriptions always in context"


@dataclass
class ArchitectureAssessment:
    """Classification + qualitative observations for a plugin's architecture."""

    pattern: str  # agent-heavy | skill-first | mcp-based | hybrid
    efficiency_notes: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


class ArchitectureAssessor:
    """Classify plugin architecture from inventory ratios."""

    def assess(self, inventory: PluginInventory) -> ArchitectureAssessment:
        agents = inventory.agents_count
        commands = inventory.commands_count
        skills = inventory.skills_count
        mcps = inventory.mcp_servers_count
        hooks = inventory.hooks_count

        total_context = agents + commands + skills + mcps

        pattern = _classify(agents, commands, skills, mcps, total_context)
        notes = _build_notes(agents, commands, skills, mcps, hooks, total_context)
        recs = _build_recommendations(
            pattern, agents, commands, skills, mcps, total_context
        )
        return ArchitectureAssessment(
            pattern=pattern, efficiency_notes=notes, recommendations=recs
        )


# ============================================================================
# Classification logic
# ============================================================================


def _classify(
    agents: int, commands: int, skills: int, mcps: int, total: int
) -> str:
    if mcps > 0:
        return "mcp-based"
    if total == 0:
        return "hybrid"
    agent_ratio = agents / total
    skill_ratio = skills / total
    if agent_ratio > AGENT_HEAVY_THRESHOLD:
        return "agent-heavy"
    if skill_ratio > SKILL_FIRST_SKILL_THRESHOLD and agent_ratio < SKILL_FIRST_MAX_AGENT_RATIO:
        return "skill-first"
    return "hybrid"


# ============================================================================
# Efficiency notes — qualitative observations
# ============================================================================


def _build_notes(
    agents: int,
    commands: int,
    skills: int,
    mcps: int,
    hooks: int,
    total: int,
) -> list[str]:
    notes: list[str] = []

    if total == 0:
        notes.append("Plugin declares no components (no agents, commands, skills, or MCP servers).")
        return notes

    if mcps == 0:
        notes.append("No MCP servers — low always-on context cost.")
    else:
        notes.append(
            f"{mcps} MCP component file(s) present — all tool definitions are "
            "always loaded, inflating baseline context."
        )

    if agents >= AGENT_COUNT_NOTE_THRESHOLD:
        notes.append(
            f"{agents} agent descriptions always in context — agents contribute "
            "~100 tokens each to baseline."
        )

    if skills >= SKILL_COUNT_NOTE_THRESHOLD:
        notes.append(
            f"{skills} skill descriptions always in context — smallest per-component "
            "baseline (~20 tokens), but count can add up."
        )

    if hooks > 0:
        notes.append(
            f"Contains {hooks} hook file(s) — these execute outside the model's "
            "context (0 token cost) but can shell out. Audit via security scan."
        )
    else:
        notes.append("No hooks — no out-of-band execution.")

    return notes


# ============================================================================
# Recommendations — optional, non-prescriptive
# ============================================================================


def _build_recommendations(
    pattern: str,
    agents: int,
    commands: int,
    skills: int,
    mcps: int,
    total: int,
) -> list[str]:
    recs: list[str] = []

    if total == 0:
        return recs

    if pattern == "agent-heavy" and agents >= AGENT_COUNT_NOTE_THRESHOLD:
        recs.append(
            "Agent-heavy architecture: consider whether any rarely-invoked agents "
            "could be converted to skills (lower per-component baseline: ~20 vs ~100 tokens)."
        )

    if mcps > 0:
        recs.append(
            "MCP servers have the highest always-on cost. Audit declared tool count — "
            "unused tools still consume context."
        )

    if pattern == "hybrid" and total > 1:
        recs.append(
            "Balanced architecture — no obvious consolidation opportunity. "
            "Focus optimization on whichever component type dominates baseline (see footprint.primary_driver)."
        )

    if pattern == "skill-first":
        recs.append(
            "Skill-first architecture: minimum always-on cost. "
            "Consider whether top-level skills should be promoted to commands for clearer UX discoverability."
        )

    return recs

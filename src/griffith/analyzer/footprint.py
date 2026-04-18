"""Estimate context footprint for plugin components using the YAML cost model.

The estimator applies rules/context_costs.yaml to a PluginInventory and produces
a FootprintEstimate with baseline overhead, on-demand maximum, primary driver,
and efficiency rating.

Cost model (from rules/context_costs.yaml):
    base         per-component overhead (description cost for description_only types;
                 per-server overhead for mcp_server)
    per_line     body cost proportional to file line count
    per_tool     additional cost per MCP tool
    description_only  true → `base` is always-on; body (per_line * lines) is on-demand
    always_loaded     true → full cost is always-on (no on-demand adds beyond baseline)

Naming:
    `baseline_tokens` is the heuristic estimate tuned to approximate cl100k-style
    token counts. Claude's actual tokenizer differs; efficiency thresholds have
    a deliberate ≥2x margin so encoding drift does not flip plugins across
    category boundaries. The Unit 7 JSON reporter renames this field to
    `baseline_tokens_approx_cl100k` to signal the approximation to external
    consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml

from griffith.analyzer.inventory import ComponentFile, PluginInventory

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent.parent
_DEFAULT_COSTS_PATH = _PROJECT_ROOT / "rules" / "context_costs.yaml"

# Fallback thresholds if YAML missing (matches rules/context_costs.yaml values).
_DEFAULT_THRESHOLDS = {
    "excellent": 500,
    "good": 1500,
    "moderate": 3000,
    "heavy": 5000,
    "excessive": 999_999,
}

# Mapping from inventory bucket names to cost-model keys. Personas and
# templates are LMF-specific and not loaded directly into Claude's context,
# so they are intentionally absent from the cost model.
_COMPONENT_TYPE_TO_COST_KEY = {
    "agents": "agent",
    "commands": "command",
    "skills": "skill",
    "hooks": "hook",
    "mcp_servers": "mcp_server",
}


@dataclass
class FootprintEstimate:
    """Context footprint breakdown for a plugin."""

    baseline_tokens: int
    on_demand_max: int
    primary_driver: str  # component type name, or "none"
    efficiency_rating: str  # excellent|good|moderate|heavy|excessive
    per_component: dict[str, int] = field(default_factory=dict)


class FootprintEstimator:
    """Apply rules/context_costs.yaml to a PluginInventory.

    Costs and thresholds load lazily on first estimate() call.
    """

    def __init__(self, *, costs_path: Path | None = None):
        self._costs_path = costs_path
        self._costs: dict | None = None
        self._thresholds: dict[str, int] | None = None

    def _ensure_loaded(self) -> None:
        if self._costs is not None and self._thresholds is not None:
            return
        path = self._costs_path or _DEFAULT_COSTS_PATH
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self._costs = data.get("component_costs", {})
        raw_thresh = data.get("efficiency_thresholds", {}) or _DEFAULT_THRESHOLDS
        # Preserve stable order for classification (smallest → largest threshold)
        self._thresholds = {
            k: int(raw_thresh[k])
            for k in ("excellent", "good", "moderate", "heavy", "excessive")
            if k in raw_thresh
        }
        if not self._thresholds:
            self._thresholds = dict(_DEFAULT_THRESHOLDS)

    def estimate(self, inventory: PluginInventory) -> FootprintEstimate:
        self._ensure_loaded()
        assert self._costs is not None
        assert self._thresholds is not None

        per_component: dict[str, int] = {}
        baseline = 0
        on_demand = 0

        # Agents / commands / skills: description_only, baseline = base per file,
        # on-demand max adds body per_line * lines.
        for bucket_name, cost_key in _COMPONENT_TYPE_TO_COST_KEY.items():
            if cost_key == "mcp_server":
                continue  # handled separately (server-level counting)
            cost = self._costs.get(cost_key, {})
            base = int(cost.get("base", 0))
            per_line = int(cost.get("per_line", 0))

            components: list[ComponentFile] = getattr(inventory, bucket_name)
            # Only non-skipped, non-symlink components contribute to body cost.
            bucket_baseline = 0
            bucket_body = 0
            for cf in components:
                bucket_baseline += base  # base applies even to symlinks (mere presence)
                if cf.is_symlink or cf.size_skipped:
                    continue
                bucket_body += per_line * cf.lines

            per_component[bucket_name] = bucket_baseline
            baseline += bucket_baseline
            # For description_only components: on_demand = baseline + body
            on_demand += bucket_baseline + bucket_body

        # MCP servers: always_loaded, baseline = server_count * base + tool_count * per_tool
        mcp_cost = self._costs.get("mcp_server", {})
        mcp_base = int(mcp_cost.get("base", 0))
        mcp_per_tool = int(mcp_cost.get("per_tool", 0))
        server_count = _count_mcp_servers(inventory.mcp_servers)
        tool_count = len([
            cf for cf in inventory.mcp_servers if not (cf.is_symlink or cf.size_skipped)
        ])
        mcp_baseline = server_count * mcp_base + tool_count * mcp_per_tool
        per_component["mcp_servers"] = mcp_baseline
        baseline += mcp_baseline
        on_demand += mcp_baseline  # always_loaded: no additional on-demand contribution

        # Primary driver: component type with largest baseline contribution.
        if baseline == 0:
            primary_driver = "none"
        else:
            primary_driver = max(per_component.items(), key=lambda kv: kv[1])[0]
            if per_component[primary_driver] == 0:
                primary_driver = "none"

        rating = _classify(baseline, self._thresholds)

        return FootprintEstimate(
            baseline_tokens=baseline,
            on_demand_max=on_demand,
            primary_driver=primary_driver,
            efficiency_rating=rating,
            per_component=per_component,
        )


def _count_mcp_servers(mcp_files: list[ComponentFile]) -> int:
    """Count distinct top-level subdirs under mcp_servers/.

    Expects paths like `mcp_servers/server-name/...`. Files directly under
    `mcp_servers/` (without a server subdir) count as one server each.
    """
    servers: set[str] = set()
    for cf in mcp_files:
        if cf.is_symlink or cf.size_skipped:
            continue
        parts = cf.path.replace("\\", "/").split("/")
        if len(parts) >= 3:
            # mcp_servers/<server>/<file...> → use "mcp_servers/<server>"
            servers.add(f"{parts[0]}/{parts[1]}")
        elif len(parts) == 2:
            # mcp_servers/<file> → one server per file
            servers.add(cf.path)
    return len(servers)


def _classify(baseline: int, thresholds: dict[str, int]) -> str:
    """Classify a baseline token count against the efficiency thresholds.

    Thresholds are upper bounds: baseline < threshold[rating] → that rating.
    """
    for rating in ("excellent", "good", "moderate", "heavy"):
        limit = thresholds.get(rating)
        if limit is None:
            continue
        if baseline < limit:
            return rating
    return "excessive"

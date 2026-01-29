"""Estimate token costs for plugin components"""

from dataclasses import dataclass


@dataclass
class TokenEstimate:
    """Token cost breakdown for a plugin"""

    baseline_overhead: int
    on_demand_max: int
    primary_driver: str
    efficiency_rating: str  # excellent, good, moderate, heavy, excessive


class TokenEstimator:
    """Estimate context token costs for plugins"""

    def estimate(self, inventory) -> TokenEstimate:
        """Calculate token costs based on component inventory"""
        # TODO: Implement using rules/context_costs.yaml
        raise NotImplementedError("See docs/design.md Phase 1")

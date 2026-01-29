"""Estimate context footprint for plugin components"""

from dataclasses import dataclass


@dataclass
class FootprintEstimate:
    """Context footprint breakdown for a plugin"""

    baseline_tokens: int      # Always-on context cost
    on_demand_max: int        # Maximum when all components invoked
    primary_driver: str       # What's consuming the most context
    efficiency_rating: str    # excellent, good, moderate, heavy, excessive


class FootprintEstimator:
    """Estimate context footprint for plugins"""

    def estimate(self, inventory) -> FootprintEstimate:
        """Calculate context footprint based on component inventory"""
        # TODO: Implement using rules/context_costs.yaml
        raise NotImplementedError("See docs/design.md Phase 1")

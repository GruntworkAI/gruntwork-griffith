"""Plugin analysis modules"""

from .inventory import PluginInventory
from .footprint import FootprintEstimator
from .security import SecurityScanner
from .architecture import ArchitectureAssessor

__all__ = ["PluginInventory", "FootprintEstimator", "SecurityScanner", "ArchitectureAssessor"]

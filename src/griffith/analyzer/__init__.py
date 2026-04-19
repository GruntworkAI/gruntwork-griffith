"""Plugin analysis modules"""

from .architecture import ArchitectureAssessor
from .dependencies import (
    DependencyAnalyzer,
    DependencyPackage,
    DependencyReport,
    ManifestInfo,
    SCAResult,
    Vulnerability,
)
from .footprint import FootprintEstimator
from .inventory import PluginInventory
from .security import SecurityScanner

__all__ = [
    "ArchitectureAssessor",
    "DependencyAnalyzer",
    "DependencyPackage",
    "DependencyReport",
    "FootprintEstimator",
    "ManifestInfo",
    "PluginInventory",
    "SCAResult",
    "SecurityScanner",
    "Vulnerability",
]

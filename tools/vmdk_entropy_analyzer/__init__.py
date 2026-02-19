"""VMDK Entropy Analyzer -- map encrypted vs. unencrypted regions in VMDK files.

This is the highest-priority tool in the ransomware incident response
toolkit.  It uses a two-pass entropy scanning strategy to efficiently
locate encrypted regions in Mario ransomware-encrypted VMDK images,
enabling targeted data recovery.
"""

from .analyzer import AnalysisResult, RegionInfo, ScanConfig, VMDKEntropyAnalyzer
from .visualizer import render_html_report, render_text_map, save_report

__all__ = [
    "AnalysisResult",
    "RegionInfo",
    "ScanConfig",
    "VMDKEntropyAnalyzer",
    "render_html_report",
    "render_text_map",
    "save_report",
]

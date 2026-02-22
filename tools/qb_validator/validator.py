"""QuickBooks file validation logic.

Validates carved .qbb, .iif, and .ofx files by inspecting their
contents and classifying them as genuine QuickBooks data or false
positives from the ZIP-based carving process.

Designed for Python 3.10+ with no external dependencies.
"""

from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ValidationResult:
    """Result of validating a single carved file."""

    path: Path
    file_type: str  # "qbb", "iif", "ofx"
    valid: bool
    classification: str
    size: int
    details: dict = field(default_factory=dict)
    output_path: Path | None = None


def validate_qbb(path: Path) -> ValidationResult:
    """Validate a carved .qbb file by inspecting its ZIP contents."""
    size = path.stat().st_size

    if not zipfile.is_zipfile(path):
        return ValidationResult(
            path=path, file_type="qbb", valid=False,
            classification="corrupt_zip", size=size,
            details={"error": "Not a valid ZIP archive"},
        )

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            infolist = zf.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        return ValidationResult(
            path=path, file_type="qbb", valid=False,
            classification="corrupt_zip", size=size,
            details={"error": str(exc)},
        )

    names_lower = [n.lower() for n in names]

    # Office Open XML
    if "[content_types].xml" in names_lower:
        return ValidationResult(
            path=path, file_type="qbb", valid=False,
            classification="office_document", size=size,
            details={"contents": names[:10]},
        )

    # Java archive
    if "meta-inf/manifest.mf" in names_lower:
        return ValidationResult(
            path=path, file_type="qbb", valid=False,
            classification="java_archive", size=size,
            details={"contents": names[:10]},
        )

    # QuickBooks backup — .QBW or .QBM inside
    qbw_files = [n for n in names if n.upper().endswith((".QBW", ".QBM"))]
    if qbw_files:
        qbw_name = qbw_files[0]
        qbw_info = next((i for i in infolist if i.filename == qbw_name), None)
        qbw_size = qbw_info.file_size if qbw_info else 0
        return ValidationResult(
            path=path, file_type="qbb", valid=True,
            classification="quickbooks_backup", size=size,
            details={"qbw_file": qbw_name, "qbw_size": qbw_size, "contents": names},
        )

    # Intuit/QuickBooks in paths
    if any("intuit" in n.lower() or "quickbooks" in n.lower() for n in names):
        return ValidationResult(
            path=path, file_type="qbb", valid=True,
            classification="quickbooks_backup", size=size,
            details={"contents": names},
        )

    # Unknown ZIP
    return ValidationResult(
        path=path, file_type="qbb", valid=False,
        classification="unknown_zip", size=size,
        details={"contents": names[:10]},
    )

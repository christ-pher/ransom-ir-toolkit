"""QuickBooks file validation logic.

Validates carved .qbb, .iif, and .ofx files by inspecting their
contents and classifying them as genuine QuickBooks data or false
positives from the ZIP-based carving process.

Designed for Python 3.10+ with no external dependencies.
"""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# IIF validation
# ---------------------------------------------------------------------------

_IIF_MAGICS: tuple[bytes, ...] = (b"!TRNS\t", b"!HDR\t", b"!ACCNT\t")

_READ_HEAD = 1024  # bytes to read for header checks


def validate_iif(path: Path) -> ValidationResult:
    """Validate a carved .iif file by checking its header bytes."""
    size = path.stat().st_size

    try:
        head = path.read_bytes()[:_READ_HEAD]
    except OSError as exc:
        return ValidationResult(
            path=path, file_type="iif", valid=False,
            classification="invalid_iif", size=size,
            details={"error": str(exc)},
        )

    # Check magic header
    if not any(head.startswith(m) for m in _IIF_MAGICS):
        return ValidationResult(
            path=path, file_type="iif", valid=False,
            classification="invalid_iif", size=size,
        )

    # Verify text is decodable
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return ValidationResult(
            path=path, file_type="iif", valid=False,
            classification="invalid_iif", size=size,
            details={"error": "Header not valid UTF-8"},
        )

    return ValidationResult(
        path=path, file_type="iif", valid=True,
        classification="valid_iif", size=size,
    )


# ---------------------------------------------------------------------------
# OFX validation
# ---------------------------------------------------------------------------


def validate_ofx(path: Path) -> ValidationResult:
    """Validate a carved .ofx file by checking its header bytes."""
    size = path.stat().st_size

    try:
        head = path.read_bytes()[:_READ_HEAD]
    except OSError as exc:
        return ValidationResult(
            path=path, file_type="ofx", valid=False,
            classification="invalid_ofx", size=size,
            details={"error": str(exc)},
        )

    # Check for SGML-based OFX or XML-based OFX
    if head.startswith(b"OFXHEADER:") or head.startswith(b"<?OFX"):
        return ValidationResult(
            path=path, file_type="ofx", valid=True,
            classification="valid_ofx", size=size,
        )

    return ValidationResult(
        path=path, file_type="ofx", valid=False,
        classification="invalid_ofx", size=size,
    )


# ---------------------------------------------------------------------------
# Directory scanner
# ---------------------------------------------------------------------------

_VALIDATORS = {
    ".qbb": validate_qbb,
    ".iif": validate_iif,
    ".ofx": validate_ofx,
}


def validate_directory(
    input_dir: Path,
    output_dir: Path,
) -> list[ValidationResult]:
    """Validate all QB-category files in a directory and copy valid ones.

    Scans for .qbb, .iif, and .ofx files. Valid files are copied to
    subdirectories of *output_dir* organized by type (qbb/, iif/, ofx/).
    A JSON report is written to output_dir/validation_report.json.
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results: list[ValidationResult] = []

    for ext, validator in _VALIDATORS.items():
        for file_path in sorted(input_dir.glob(f"*{ext}")):
            result = validator(file_path)

            if result.valid:
                dest_dir = output_dir / ext.lstrip(".")
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / file_path.name
                shutil.copy2(file_path, dest)
                result.output_path = dest

            results.append(result)

    # Write JSON report
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "total_files": len(results),
        "valid_files": sum(1 for r in results if r.valid),
        "results": [
            {
                "path": str(r.path),
                "file_type": r.file_type,
                "valid": r.valid,
                "classification": r.classification,
                "size": r.size,
                "details": r.details,
                "output_path": str(r.output_path) if r.output_path else None,
            }
            for r in results
        ],
    }
    report_path = output_dir / "validation_report.json"
    report_path.write_text(
        json.dumps(report_data, indent=2) + "\n", encoding="utf-8"
    )

    return results

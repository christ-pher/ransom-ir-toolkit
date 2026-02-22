# qb-validate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a post-carve validation tool that separates real QuickBooks files from false positives in `carve-vmdk` output.

**Architecture:** New `tools/qb_validator/` module with `validator.py` (validation logic) and `cli.py` (argparse CLI). Follows existing tool patterns: `print_banner`, `print_finding`, `print_summary` for terminal output, JSON report for file output, `ensure_output_dir` for safe output paths.

**Tech Stack:** Python 3.10+ stdlib only (zipfile, pathlib, shutil, json). Existing `tools.common.report` and `tools.common.safe_io`.

**Design doc:** `docs/plans/2026-02-22-qb-validate-design.md`

---

### Task 1: Validator core — QBB validation

**Files:**
- Create: `tools/qb_validator/__init__.py`
- Create: `tools/qb_validator/validator.py`
- Test: `tests/test_qb_validator.py`

**Step 1: Write the failing tests**

Create `tests/test_qb_validator.py` with fixtures that build synthetic QBB, DOCX, JAR, and corrupt ZIP files, then test the validator classifies each correctly.

```python
"""Tests for tools.qb_validator -- QuickBooks file validation."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from tools.qb_validator.validator import ValidationResult, validate_qbb


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_qbb(tmp_path: Path) -> Path:
    """Create a synthetic QBB file containing a .QBW file."""
    qbb_path = tmp_path / "recovered.qbb"
    with zipfile.ZipFile(qbb_path, "w") as zf:
        zf.writestr("CompanyName.QBW", b"\x00" * 1000)
        zf.writestr("CompanyName.QBW.TLG", b"\x00" * 500)
    return qbb_path


@pytest.fixture()
def office_docx(tmp_path: Path) -> Path:
    """Create a fake DOCX (Office Open XML) that was carved as .qbb."""
    docx_path = tmp_path / "false_positive.qbb"
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<document/>")
    return docx_path


@pytest.fixture()
def java_jar(tmp_path: Path) -> Path:
    """Create a fake JAR that was carved as .qbb."""
    jar_path = tmp_path / "false_positive_jar.qbb"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")
    return jar_path


@pytest.fixture()
def corrupt_zip(tmp_path: Path) -> Path:
    """Create a corrupt/truncated file with ZIP magic but invalid structure."""
    corrupt_path = tmp_path / "corrupt.qbb"
    corrupt_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    return corrupt_path


@pytest.fixture()
def unknown_zip(tmp_path: Path) -> Path:
    """Create a valid ZIP that doesn't match any known category."""
    unk_path = tmp_path / "unknown.qbb"
    with zipfile.ZipFile(unk_path, "w") as zf:
        zf.writestr("readme.txt", "hello world")
    return unk_path


# ---------------------------------------------------------------------------
# QBB validation tests
# ---------------------------------------------------------------------------


class TestValidateQBB:
    """Test QBB file classification."""

    def test_valid_qbb_detected(self, valid_qbb: Path) -> None:
        result = validate_qbb(valid_qbb)
        assert result.valid is True
        assert result.classification == "quickbooks_backup"

    def test_valid_qbb_reports_qbw_name(self, valid_qbb: Path) -> None:
        result = validate_qbb(valid_qbb)
        assert result.details["qbw_file"] == "CompanyName.QBW"

    def test_office_docx_classified(self, office_docx: Path) -> None:
        result = validate_qbb(office_docx)
        assert result.valid is False
        assert result.classification == "office_document"

    def test_java_jar_classified(self, java_jar: Path) -> None:
        result = validate_qbb(java_jar)
        assert result.valid is False
        assert result.classification == "java_archive"

    def test_corrupt_zip_classified(self, corrupt_zip: Path) -> None:
        result = validate_qbb(corrupt_zip)
        assert result.valid is False
        assert result.classification == "corrupt_zip"

    def test_unknown_zip_classified(self, unknown_zip: Path) -> None:
        result = validate_qbb(unknown_zip)
        assert result.valid is False
        assert result.classification == "unknown_zip"

    def test_result_has_file_size(self, valid_qbb: Path) -> None:
        result = validate_qbb(valid_qbb)
        assert result.size == valid_qbb.stat().st_size

    def test_result_has_path(self, valid_qbb: Path) -> None:
        result = validate_qbb(valid_qbb)
        assert result.path == valid_qbb
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_qb_validator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tools.qb_validator'`

**Step 3: Write minimal implementation**

Create `tools/qb_validator/__init__.py`:

```python
"""Post-carve QuickBooks file validator.

Validates carved files from carve-vmdk output, classifying real
QuickBooks files (QBB, IIF, OFX) and filtering false positives
(Office documents, Java archives, corrupt ZIPs).
"""
```

Create `tools/qb_validator/validator.py`:

```python
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
    """Validate a carved .qbb file by inspecting its ZIP contents.

    Classification hierarchy:
        1. Not a valid ZIP → ``corrupt_zip``
        2. Contains ``[Content_Types].xml`` → ``office_document``
        3. Contains ``META-INF/MANIFEST.MF`` → ``java_archive``
        4. Contains ``.QBW`` or ``.QBM`` file → ``quickbooks_backup``
        5. Contains paths with ``Intuit`` or ``QuickBooks`` → ``quickbooks_backup``
        6. Otherwise → ``unknown_zip``
    """
    size = path.stat().st_size

    if not zipfile.is_zipfile(path):
        logger.debug("Not a valid ZIP: %s", path)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=False,
            classification="corrupt_zip",
            size=size,
            details={"error": "Not a valid ZIP archive"},
        )

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError) as exc:
        logger.debug("Failed to read ZIP: %s (%s)", path, exc)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=False,
            classification="corrupt_zip",
            size=size,
            details={"error": str(exc)},
        )

    names_lower = [n.lower() for n in names]

    # Office Open XML (DOCX, XLSX, PPTX)
    if "[content_types].xml" in names_lower:
        logger.debug("Office document detected: %s", path)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=False,
            classification="office_document",
            size=size,
            details={"contents": names[:10]},
        )

    # Java archive (JAR, APK)
    if "meta-inf/manifest.mf" in names_lower:
        logger.debug("Java archive detected: %s", path)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=False,
            classification="java_archive",
            size=size,
            details={"contents": names[:10]},
        )

    # QuickBooks backup — look for .QBW or .QBM files
    qbw_files = [
        n for n in names
        if n.upper().endswith((".QBW", ".QBM"))
    ]
    if qbw_files:
        qbw_name = qbw_files[0]
        # Get uncompressed size of the QBW
        qbw_info = next(
            (info for info in zf.infolist() if info.filename == qbw_name),
            None,
        ) if False else None  # zf is closed; re-open briefly
        with zipfile.ZipFile(path, "r") as zf2:
            qbw_info = next(
                (info for info in zf2.infolist() if info.filename == qbw_name),
                None,
            )
        qbw_size = qbw_info.file_size if qbw_info else 0
        logger.info("Valid QBB found: %s (QBW: %s, %d bytes)", path, qbw_name, qbw_size)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=True,
            classification="quickbooks_backup",
            size=size,
            details={
                "qbw_file": qbw_name,
                "qbw_size": qbw_size,
                "contents": names,
            },
        )

    # Check for Intuit/QuickBooks in paths
    if any("intuit" in n.lower() or "quickbooks" in n.lower() for n in names):
        logger.info("Valid QBB found (path match): %s", path)
        return ValidationResult(
            path=path,
            file_type="qbb",
            valid=True,
            classification="quickbooks_backup",
            size=size,
            details={"contents": names},
        )

    # Unknown ZIP
    logger.debug("Unknown ZIP contents: %s", path)
    return ValidationResult(
        path=path,
        file_type="qbb",
        valid=False,
        classification="unknown_zip",
        size=size,
        details={"contents": names[:10]},
    )
```

Wait — that has a bug with the closed zipfile. Let me fix it. The actual implementation should keep the ZipFile open long enough to get the info, or just re-read it once. Here's the corrected `validate_qbb`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_qb_validator.py::TestValidateQBB -v`
Expected: All 8 tests PASS

**Step 5: Commit**

```bash
git add tools/qb_validator/__init__.py tools/qb_validator/validator.py tests/test_qb_validator.py
git commit -m "Add QBB validation logic with ZIP content classification"
```

---

### Task 2: IIF and OFX validation

**Files:**
- Modify: `tools/qb_validator/validator.py`
- Modify: `tests/test_qb_validator.py`

**Step 1: Write the failing tests**

Add to `tests/test_qb_validator.py`:

```python
from tools.qb_validator.validator import validate_iif, validate_ofx


@pytest.fixture()
def valid_iif_trns(tmp_path: Path) -> Path:
    """Create a valid IIF file starting with !TRNS header."""
    iif_path = tmp_path / "transactions.iif"
    iif_path.write_text("!TRNS\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\n", encoding="ascii")
    return iif_path


@pytest.fixture()
def valid_iif_hdr(tmp_path: Path) -> Path:
    """Create a valid IIF file starting with !HDR header."""
    iif_path = tmp_path / "header.iif"
    iif_path.write_text("!HDR\tPROD\tVER\n", encoding="ascii")
    return iif_path


@pytest.fixture()
def invalid_iif(tmp_path: Path) -> Path:
    """Create an invalid IIF file (wrong content)."""
    iif_path = tmp_path / "not_iif.iif"
    iif_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    return iif_path


@pytest.fixture()
def valid_ofx(tmp_path: Path) -> Path:
    """Create a valid OFX file."""
    ofx_path = tmp_path / "bank.ofx"
    ofx_path.write_text("OFXHEADER:100\nDATA:OFXSGML\n", encoding="ascii")
    return ofx_path


@pytest.fixture()
def valid_ofx_xml(tmp_path: Path) -> Path:
    """Create a valid XML-based OFX file."""
    ofx_path = tmp_path / "bank_xml.ofx"
    ofx_path.write_text("<?OFX OFXHEADER=\"200\"?>\n<OFX>\n</OFX>\n", encoding="ascii")
    return ofx_path


@pytest.fixture()
def invalid_ofx(tmp_path: Path) -> Path:
    """Create an invalid OFX file."""
    ofx_path = tmp_path / "not_ofx.ofx"
    ofx_path.write_bytes(b"\x00\x01\x02\x03" * 50)
    return ofx_path


class TestValidateIIF:
    """Test IIF file validation."""

    def test_valid_iif_trns(self, valid_iif_trns: Path) -> None:
        result = validate_iif(valid_iif_trns)
        assert result.valid is True
        assert result.classification == "valid_iif"

    def test_valid_iif_hdr(self, valid_iif_hdr: Path) -> None:
        result = validate_iif(valid_iif_hdr)
        assert result.valid is True
        assert result.classification == "valid_iif"

    def test_invalid_iif(self, invalid_iif: Path) -> None:
        result = validate_iif(invalid_iif)
        assert result.valid is False
        assert result.classification == "invalid_iif"

    def test_iif_file_type(self, valid_iif_trns: Path) -> None:
        result = validate_iif(valid_iif_trns)
        assert result.file_type == "iif"


class TestValidateOFX:
    """Test OFX file validation."""

    def test_valid_ofx_sgml(self, valid_ofx: Path) -> None:
        result = validate_ofx(valid_ofx)
        assert result.valid is True
        assert result.classification == "valid_ofx"

    def test_valid_ofx_xml(self, valid_ofx_xml: Path) -> None:
        result = validate_ofx(valid_ofx_xml)
        assert result.valid is True
        assert result.classification == "valid_ofx"

    def test_invalid_ofx(self, invalid_ofx: Path) -> None:
        result = validate_ofx(invalid_ofx)
        assert result.valid is False
        assert result.classification == "invalid_ofx"

    def test_ofx_file_type(self, valid_ofx: Path) -> None:
        result = validate_ofx(valid_ofx)
        assert result.file_type == "ofx"
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_qb_validator.py::TestValidateIIF tests/test_qb_validator.py::TestValidateOFX -v`
Expected: FAIL with `ImportError: cannot import name 'validate_iif'`

**Step 3: Write minimal implementation**

Add to `tools/qb_validator/validator.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_qb_validator.py -v`
Expected: All 16 tests PASS (8 QBB + 4 IIF + 4 OFX)

**Step 5: Commit**

```bash
git add tools/qb_validator/validator.py tests/test_qb_validator.py
git commit -m "Add IIF and OFX validation logic"
```

---

### Task 3: Directory scanner — validate_directory()

**Files:**
- Modify: `tools/qb_validator/validator.py`
- Modify: `tests/test_qb_validator.py`

**Step 1: Write the failing tests**

Add to `tests/test_qb_validator.py`:

```python
import shutil

from tools.qb_validator.validator import validate_directory


@pytest.fixture()
def carved_dir(tmp_path: Path) -> Path:
    """Create a directory mimicking carve-vmdk output with mixed files."""
    carved = tmp_path / "carved_files"
    carved.mkdir()

    # Valid QBB
    with zipfile.ZipFile(carved / "000000001000_QuickBooks_Backup_(QBB).qbb", "w") as zf:
        zf.writestr("MyCompany.QBW", b"\x00" * 500)

    # Office doc false positive
    with zipfile.ZipFile(carved / "000000002000_QuickBooks_Backup_(QBB).qbb", "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<doc/>")

    # Valid IIF
    (carved / "000000003000_QuickBooks_IIF.iif").write_text(
        "!TRNS\tTRNSTYPE\tDATE\n", encoding="ascii"
    )

    # Valid OFX
    (carved / "000000004000_OFX_Financial_Data.ofx").write_text(
        "OFXHEADER:100\n", encoding="ascii"
    )

    return carved


class TestValidateDirectory:
    """Test directory-level validation and file sorting."""

    def test_finds_all_files(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        assert len(results) == 4

    def test_identifies_valid_qbb(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        valid_qbbs = [r for r in results if r.valid and r.file_type == "qbb"]
        assert len(valid_qbbs) == 1

    def test_copies_valid_qbb(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        valid_qbbs = [r for r in results if r.valid and r.file_type == "qbb"]
        assert valid_qbbs[0].output_path is not None
        assert valid_qbbs[0].output_path.exists()
        assert valid_qbbs[0].output_path.parent.name == "qbb"

    def test_copies_valid_iif(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        valid_iifs = [r for r in results if r.valid and r.file_type == "iif"]
        assert len(valid_iifs) == 1
        assert valid_iifs[0].output_path.parent.name == "iif"

    def test_copies_valid_ofx(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        valid_ofxs = [r for r in results if r.valid and r.file_type == "ofx"]
        assert len(valid_ofxs) == 1
        assert valid_ofxs[0].output_path.parent.name == "ofx"

    def test_does_not_copy_false_positives(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        results = validate_directory(carved_dir, output)
        false_positives = [r for r in results if not r.valid]
        for fp in false_positives:
            assert fp.output_path is None

    def test_writes_json_report(self, carved_dir: Path, tmp_path: Path) -> None:
        output = tmp_path / "validated"
        validate_directory(carved_dir, output)
        report = output / "validation_report.json"
        assert report.exists()

    def test_empty_directory(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        output = tmp_path / "validated"
        results = validate_directory(empty, output)
        assert len(results) == 0
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_qb_validator.py::TestValidateDirectory -v`
Expected: FAIL with `ImportError: cannot import name 'validate_directory'`

**Step 3: Write minimal implementation**

Add to `tools/qb_validator/validator.py`:

```python
import json
import shutil
from datetime import datetime, timezone

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
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_qb_validator.py -v`
Expected: All 24 tests PASS

**Step 5: Commit**

```bash
git add tools/qb_validator/validator.py tests/test_qb_validator.py
git commit -m "Add directory scanner with file sorting and JSON report"
```

---

### Task 4: CLI and wrapper script

**Files:**
- Create: `tools/qb_validator/cli.py`
- Create: `tools/qb_validator/__main__.py`
- Create: `qb-validate` (wrapper script at repo root)

**Step 1: Write cli.py**

```python
"""CLI entry point for the QuickBooks File Validator.

Validates carved QuickBooks files (.qbb, .iif, .ofx) from carve-vmdk
output, classifying real QB data and filtering false positives.

Usage::

    python -m tools.qb_validator /output/carved_files/ \\
        --output-dir /output/validated_qb/

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tools.common.report import format_bytes, print_banner, print_finding, print_summary

from .validator import validate_directory

logger = logging.getLogger(__name__)


def _handle_validate(args: argparse.Namespace) -> int:
    """Run validation on the input directory."""
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.is_dir():
        print_finding("Input not found", {"Error": f"Not a directory: {input_dir}"}, severity="critical")
        return 1

    results = validate_directory(input_dir, output_dir)

    if not results:
        print_finding("No files found", {"Directory": str(input_dir)}, severity="warning")
        return 0

    # Print per-file results
    for r in results:
        severity = "info" if r.valid else "warning"
        details = {
            "Classification": r.classification,
            "Size": format_bytes(r.size),
        }
        if r.valid and r.output_path:
            details["Copied to"] = str(r.output_path)
        if "qbw_file" in r.details:
            details["QBW inside"] = r.details["qbw_file"]
            details["QBW size"] = format_bytes(r.details["qbw_size"])
        if "contents" in r.details:
            details["Contents"] = f"{len(r.details['contents'])} entries"
        if "error" in r.details:
            details["Error"] = r.details["error"]

        label = "VALID" if r.valid else "SKIP"
        print_finding(f"[{label}] {r.path.name}", details, severity=severity)

    # Summary
    valid_count = sum(1 for r in results if r.valid)
    by_class: dict[str, int] = {}
    for r in results:
        by_class[r.classification] = by_class.get(r.classification, 0) + 1

    summary_stats = {
        "Input directory": str(input_dir),
        "Output directory": str(output_dir),
        "Total files scanned": str(len(results)),
        "Valid QB files": str(valid_count),
    }
    for cls, count in sorted(by_class.items()):
        summary_stats[cls] = str(count)

    print_summary("QuickBooks Validation Results", summary_stats)

    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="qb-validate",
        description=(
            "QuickBooks File Validator -- validate carved files from "
            "carve-vmdk output, separating real QuickBooks data from "
            "false positives (Office docs, JARs, corrupt ZIPs)."
        ),
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing carved files to validate.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help=(
            "Directory for validated output.  Valid files are copied "
            "into qbb/, iif/, ofx/ subdirectories."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    return parser


def main() -> None:
    """CLI entry point for the QuickBooks File Validator."""
    print_banner("QuickBooks File Validator")

    parser = _build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        sys.exit(_handle_validate(args))
    except KeyboardInterrupt:
        print("\nValidation interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during validation")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**Step 2: Write __main__.py**

```python
"""Allow running as ``python -m tools.qb_validator``."""

from tools.qb_validator.cli import main

main()
```

**Step 3: Write wrapper script**

Create `qb-validate` at repo root (copy the pattern from `qb-scan`):

```bash
#!/usr/bin/env bash
# qb-validate - QuickBooks File Validator wrapper
# Validate carved QuickBooks files and sort valid ones.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/venv/bin/activate" ]; then
    source "${SCRIPT_DIR}/venv/bin/activate"
fi
cd "$SCRIPT_DIR"
exec python3 -m tools.qb_validator.cli "$@"
```

Make it executable: `chmod +x qb-validate`

**Step 4: Test the CLI manually**

Run: `python -m tools.qb_validator --help`
Expected: Shows usage with input_dir, --output-dir, -v flags

**Step 5: Commit**

```bash
git add tools/qb_validator/cli.py tools/qb_validator/__main__.py qb-validate
git commit -m "Add CLI and wrapper script for qb-validate"
```

---

### Task 5: Run full test suite

**Step 1: Run all tests**

Run: `pytest tests/ -v`
Expected: All tests pass, including existing tests (no regressions)

**Step 2: Run qb-validate end-to-end smoke test**

Create a temp directory with test files and run the full CLI:

```bash
mkdir -p /tmp/qb_test_input /tmp/qb_test_output

# Create a fake QBB (valid)
python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/qb_test_input/000000001000_QuickBooks_Backup_(QBB).qbb', 'w') as zf:
    zf.writestr('Company.QBW', b'\x00' * 100)
"

# Create a fake DOCX (false positive)
python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/qb_test_input/000000002000_QuickBooks_Backup_(QBB).qbb', 'w') as zf:
    zf.writestr('[Content_Types].xml', '<Types/>')
    zf.writestr('word/document.xml', '<doc/>')
"

# Run the tool
python -m tools.qb_validator /tmp/qb_test_input --output-dir /tmp/qb_test_output

# Verify output
ls -la /tmp/qb_test_output/qbb/
cat /tmp/qb_test_output/validation_report.json
```

Expected: 1 valid QBB copied to qbb/ subdir, 1 office doc filtered, report written.

**Step 3: Clean up temp files**

```bash
rm -rf /tmp/qb_test_input /tmp/qb_test_output
```

**Step 4: Commit if any fixes needed, otherwise done**

---

### Task 6: Update documentation

**Files:**
- Modify: `ONSITE-GUIDE.md` (add qb-validate to the workflow after carve-vmdk)
- Modify: `docs/post-scan-next-steps.md` (reference the new tool)

**Step 1: Add qb-validate to ONSITE-GUIDE.md**

In the "QuickBooks Recovery (Top Priority)" section (after the carve step ~line 189), add:

```markdown
# 2b. Validate carved QB files (filter false positives)
./qb-validate /output/carved_files/ \
    --output-dir /output/validated_qb/
```

In the cheat sheet section, add:

```
./qb-validate /output/carved/  --output-dir /output/valid_qb/   # Validate carved QB files
```

**Step 2: Add qb-validate to post-scan-next-steps.md**

After the carve step in Step 1, add a note:

```markdown
After carving, validate QuickBooks files to filter false positives:

```bash
./qb-validate /output/carved_files/ --output-dir /output/validated_qb/
```

The validator classifies each .qbb file by inspecting ZIP contents — separating real QBBs from Office documents, Java archives, and corrupt fragments.
```

**Step 3: Commit**

```bash
git add ONSITE-GUIDE.md docs/post-scan-next-steps.md
git commit -m "Add qb-validate to recovery workflow documentation"
```

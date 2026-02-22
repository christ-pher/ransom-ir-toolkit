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

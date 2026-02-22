"""Tests for tools.qb_validator -- QuickBooks file validation."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tools.qb_validator.validator import (
    ValidationResult,
    validate_iif,
    validate_ofx,
    validate_qbb,
)


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


# ---------------------------------------------------------------------------
# IIF fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# OFX fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# IIF validation tests
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# OFX validation tests
# ---------------------------------------------------------------------------


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

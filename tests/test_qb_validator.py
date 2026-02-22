"""Tests for tools.qb_validator -- QuickBooks file validation."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tools.qb_validator.validator import (
    ValidationResult,
    validate_directory,
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


# ---------------------------------------------------------------------------
# Directory scanner fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Directory scanner tests
# ---------------------------------------------------------------------------


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

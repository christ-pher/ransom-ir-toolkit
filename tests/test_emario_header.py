"""Tests for tools.emario_header_analyzer.babuk_format -- Babuk/Mario file format.

Covers extract_babuk_footer, BabukFooter, BABUK_KEY_SIZE, is_emario_file,
find_emario_files, MarioVersion, and detect_mario_version.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tools.common.safe_io import SafeReader
from tools.emario_header_analyzer.babuk_format import (
    BABUK_KEY_SIZE,
    BabukFooter,
    MarioVersion,
    extract_babuk_footer,
    find_emario_files,
    is_emario_file,
)


# ---------------------------------------------------------------------------
# Helper to create a temporary .emario file with a known footer
# ---------------------------------------------------------------------------


def _create_emario_file(
    directory: Path,
    name: str = "test.docx.emario",
    body_size: int = 1024,
    footer: bytes | None = None,
) -> Path:
    """Create a fake .emario file with a body and 32-byte footer.

    Parameters
    ----------
    directory:
        Directory to create the file in.
    name:
        Filename.
    body_size:
        Size of the random body before the footer.
    footer:
        Explicit 32-byte footer.  If None, a random one is generated.

    Returns
    -------
    Path
        Path to the created file.
    """
    if footer is None:
        footer = os.urandom(BABUK_KEY_SIZE)
    assert len(footer) == BABUK_KEY_SIZE

    path = directory / name
    with open(path, "wb") as f:
        f.write(os.urandom(body_size))
        f.write(footer)
    return path


# ---------------------------------------------------------------------------
# extract_babuk_footer
# ---------------------------------------------------------------------------


class TestExtractBabukFooter:
    """Tests for Babuk footer extraction from encrypted files."""

    def test_extract_babuk_footer(self, tmp_path: Path) -> None:
        """Create a file with a known 32-byte footer and verify extraction."""
        known_key = bytes(range(32))
        file_path = _create_emario_file(
            tmp_path, footer=known_key, body_size=2048
        )

        with SafeReader(file_path) as reader:
            footer = extract_babuk_footer(reader)

        assert isinstance(footer, BabukFooter)
        assert footer.per_file_pubkey == known_key
        assert footer.pubkey_hex == known_key.hex()
        assert footer.file_path == file_path.resolve()
        assert footer.file_size == 2048 + BABUK_KEY_SIZE

    def test_footer_key_size(self, tmp_path: Path) -> None:
        """Extracted key should be exactly BABUK_KEY_SIZE (32) bytes."""
        file_path = _create_emario_file(tmp_path, body_size=512)

        with SafeReader(file_path) as reader:
            footer = extract_babuk_footer(reader)

        assert len(footer.per_file_pubkey) == BABUK_KEY_SIZE
        assert len(footer.per_file_pubkey) == 32

    def test_extract_footer_minimum_size(self, tmp_path: Path) -> None:
        """A file of exactly 32 bytes (footer only, no body) should succeed."""
        key = os.urandom(32)
        path = tmp_path / "minimal.emario"
        path.write_bytes(key)

        with SafeReader(path) as reader:
            footer = extract_babuk_footer(reader)

        assert footer.per_file_pubkey == key
        assert footer.file_size == 32

    def test_extract_footer_file_too_small(self, tmp_path: Path) -> None:
        """A file smaller than 32 bytes should raise ValueError."""
        path = tmp_path / "tiny.emario"
        path.write_bytes(b"\x00" * 16)

        with SafeReader(path) as reader:
            with pytest.raises(ValueError, match="too small"):
                extract_babuk_footer(reader)

    def test_footer_hex_encoding(self, tmp_path: Path) -> None:
        """pubkey_hex should be a lowercase hex encoding of per_file_pubkey."""
        key = b"\xab\xcd\xef" + b"\x00" * 29
        file_path = _create_emario_file(tmp_path, footer=key, body_size=256)

        with SafeReader(file_path) as reader:
            footer = extract_babuk_footer(reader)

        assert footer.pubkey_hex == key.hex()
        assert footer.pubkey_hex.startswith("abcdef")


# ---------------------------------------------------------------------------
# BABUK_KEY_SIZE constant
# ---------------------------------------------------------------------------


class TestBabukKeySize:
    """Verify the Babuk key size constant."""

    def test_key_size_is_32(self) -> None:
        """BABUK_KEY_SIZE should be 32 (Curve25519 public key size)."""
        assert BABUK_KEY_SIZE == 32


# ---------------------------------------------------------------------------
# is_emario_file
# ---------------------------------------------------------------------------


class TestIsEmarioFile:
    """Tests for Mario ransomware extension checking."""

    def test_emario_extension(self) -> None:
        """.emario files should be recognised."""
        assert is_emario_file(Path("document.docx.emario")) is True

    def test_omario_extension(self) -> None:
        """.omario files should be recognised."""
        assert is_emario_file(Path("spreadsheet.xlsx.omario")) is True

    def test_txt_extension(self) -> None:
        """.txt files should not be recognised."""
        assert is_emario_file(Path("notes.txt")) is False

    def test_vmdk_extension(self) -> None:
        """.vmdk files should not be recognised."""
        assert is_emario_file(Path("disk.vmdk")) is False

    def test_no_extension(self) -> None:
        """Files without an extension should not be recognised."""
        assert is_emario_file(Path("noext")) is False

    def test_emario_case_insensitive(self) -> None:
        """Extension matching should be case-insensitive."""
        assert is_emario_file(Path("file.EMARIO")) is True
        assert is_emario_file(Path("file.Emario")) is True


# ---------------------------------------------------------------------------
# find_emario_files
# ---------------------------------------------------------------------------


class TestFindEmarioFiles:
    """Tests for recursive .emario file discovery."""

    def test_find_emario_files(self, tmp_path: Path) -> None:
        """find_emario_files should discover .emario files in a directory tree."""
        # Create files at various depths.
        _create_emario_file(tmp_path, name="top.emario", body_size=64)

        subdir = tmp_path / "subdir"
        subdir.mkdir()
        _create_emario_file(subdir, name="nested.emario", body_size=64)

        # Also create a non-emario file that should be ignored.
        (tmp_path / "readme.txt").write_text("not encrypted")

        results = find_emario_files(tmp_path)
        assert len(results) == 2
        names = {p.name for p in results}
        assert "top.emario" in names
        assert "nested.emario" in names

    def test_find_emario_files_empty(self, tmp_path: Path) -> None:
        """An empty directory should return an empty list."""
        results = find_emario_files(tmp_path)
        assert results == []

    def test_find_emario_files_nonexistent(self, tmp_path: Path) -> None:
        """A nonexistent directory should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            find_emario_files(tmp_path / "nonexistent")

    def test_find_emario_files_not_a_directory(self, tmp_path: Path) -> None:
        """Passing a file should raise NotADirectoryError."""
        f = tmp_path / "file.txt"
        f.write_text("data")
        with pytest.raises(NotADirectoryError):
            find_emario_files(f)

    def test_find_emario_and_omario(self, tmp_path: Path) -> None:
        """Both .emario and .omario files should be found."""
        _create_emario_file(tmp_path, name="a.emario", body_size=64)
        path_omario = tmp_path / "b.omario"
        path_omario.write_bytes(os.urandom(96))

        results = find_emario_files(tmp_path)
        names = {p.name for p in results}
        assert "a.emario" in names
        assert "b.omario" in names

    def test_find_emario_files_sorted(self, tmp_path: Path) -> None:
        """Results should be sorted by path."""
        _create_emario_file(tmp_path, name="z_file.emario", body_size=64)
        _create_emario_file(tmp_path, name="a_file.emario", body_size=64)
        _create_emario_file(tmp_path, name="m_file.emario", body_size=64)

        results = find_emario_files(tmp_path)
        assert results == sorted(results)


# ---------------------------------------------------------------------------
# MarioVersion enum
# ---------------------------------------------------------------------------


class TestMarioVersionEnum:
    """Tests for the MarioVersion enumeration."""

    def test_mario_version_values(self) -> None:
        """MarioVersion should have OLDER_LINEAR, NEWER_INTERMITTENT, and UNKNOWN."""
        assert MarioVersion.OLDER_LINEAR.value == "older_linear"
        assert MarioVersion.NEWER_INTERMITTENT.value == "newer_intermittent"
        assert MarioVersion.UNKNOWN.value == "unknown"

    def test_mario_version_member_count(self) -> None:
        """MarioVersion should have exactly 3 members."""
        assert len(MarioVersion) == 3

    def test_mario_version_by_value(self) -> None:
        """MarioVersion should be constructible from its string value."""
        assert MarioVersion("older_linear") == MarioVersion.OLDER_LINEAR
        assert MarioVersion("newer_intermittent") == MarioVersion.NEWER_INTERMITTENT
        assert MarioVersion("unknown") == MarioVersion.UNKNOWN

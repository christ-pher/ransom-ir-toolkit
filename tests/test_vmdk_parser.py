"""Tests for tools.common.vmdk_parser -- VMDK descriptor and sparse header parsing.

Covers VMDKType, SparseHeader, VMDKDescriptor, VMDKExtent, VMDKInfo,
parse_sparse_header, parse_descriptor, detect_vmdk_type, find_vmdk_files,
and VMDK_SPARSE_MAGIC.
"""

from __future__ import annotations

import struct
import textwrap
from pathlib import Path

import pytest

from tools.common.vmdk_parser import (
    VMDK_SPARSE_MAGIC,
    VMDKExtent,
    VMDKType,
    detect_vmdk_type,
    find_vmdk_files,
    parse_descriptor,
    parse_sparse_header,
)


# ---------------------------------------------------------------------------
# Helpers for building test data
# ---------------------------------------------------------------------------

# Struct format matching the source: "<IIIQQQQIQQQBccccH"
_SPARSE_HEADER_FMT = "<IIIQQQQIQQQBccccH"
_SPARSE_HEADER_SIZE = struct.calcsize(_SPARSE_HEADER_FMT)


def _build_sparse_header(
    magic: int = VMDK_SPARSE_MAGIC,
    version: int = 1,
    flags: int = 3,
    capacity_sectors: int = 4194304,
    grain_size_sectors: int = 128,
    descriptor_offset_sectors: int = 1,
    descriptor_size_sectors: int = 20,
    num_gtes_per_gt: int = 512,
    rgd_offset_sectors: int = 0,
    gd_offset_sectors: int = 21,
    overhead_sectors: int = 128,
    unclean_shutdown: int = 0,
    compress_algorithm: int = 0,
) -> bytes:
    """Build a 512-byte sparse VMDK header with the given field values.

    Pads to 512 bytes with zeros.
    """
    packed = struct.pack(
        _SPARSE_HEADER_FMT,
        magic,
        version,
        flags,
        capacity_sectors,
        grain_size_sectors,
        descriptor_offset_sectors,
        descriptor_size_sectors,
        num_gtes_per_gt,
        rgd_offset_sectors,
        gd_offset_sectors,
        overhead_sectors,
        unclean_shutdown,
        b"\n",   # singleEndLineChar
        b" ",    # nonEndLineChar
        b"\r",   # doubleEndLineChar1
        b"\n",   # doubleEndLineChar2
        compress_algorithm,
    )
    # Pad to 512 bytes.
    return packed + b"\x00" * (512 - len(packed))


# Sample VMDK descriptor text used across multiple tests.
_SAMPLE_DESCRIPTOR = textwrap.dedent("""\
    # Disk DescriptorFile
    version=1
    CID=fffffffe
    parentCID=ffffffff
    createType="monolithicFlat"

    # Extent description
    RW 125829120 FLAT "test-vm-flat.vmdk" 0

    # The Disk Data Base
    #DDB
    ddb.virtualHWVersion = "21"
    ddb.geometry.cylinders = "130"
    ddb.geometry.heads = "16"
    ddb.geometry.sectors = "63"
    ddb.adapterType = "lsilogic"
""")


# ---------------------------------------------------------------------------
# parse_sparse_header
# ---------------------------------------------------------------------------


class TestParseSparseHeader:
    """Tests for sparse VMDK header parsing."""

    def test_parse_sparse_header(self) -> None:
        """Construct a valid sparse header and verify field extraction."""
        header_bytes = _build_sparse_header(
            version=1,
            flags=3,
            capacity_sectors=4194304,
            grain_size_sectors=128,
            descriptor_offset_sectors=1,
            descriptor_size_sectors=20,
            num_gtes_per_gt=512,
            gd_offset_sectors=21,
            overhead_sectors=128,
            compress_algorithm=0,
        )

        header = parse_sparse_header(header_bytes)

        assert header.magic == VMDK_SPARSE_MAGIC
        assert header.version == 1
        assert header.flags == 3
        assert header.capacity_sectors == 4194304
        assert header.grain_size_sectors == 128
        assert header.descriptor_offset_sectors == 1
        assert header.descriptor_size_sectors == 20
        assert header.num_gtes_per_gt == 512
        assert header.gd_offset_sectors == 21
        assert header.overhead_sectors == 128
        assert header.compress_algorithm == 0
        assert header.unclean_shutdown is False

    def test_parse_sparse_header_unclean_shutdown(self) -> None:
        """The unclean_shutdown flag should be True when the byte is nonzero."""
        header_bytes = _build_sparse_header(unclean_shutdown=1)
        header = parse_sparse_header(header_bytes)
        assert header.unclean_shutdown is True

    def test_parse_sparse_header_invalid_magic(self) -> None:
        """A header with wrong magic should raise ValueError."""
        header_bytes = _build_sparse_header(magic=0xDEADBEEF)
        with pytest.raises(ValueError, match="Invalid sparse VMDK magic"):
            parse_sparse_header(header_bytes)

    def test_parse_sparse_header_too_short(self) -> None:
        """Data shorter than the header struct should raise ValueError."""
        with pytest.raises(ValueError, match="at least"):
            parse_sparse_header(b"\x00" * 10)

    def test_parse_sparse_header_stream_optimised(self) -> None:
        """A header with compress_algorithm=1 (deflate) should parse correctly."""
        header_bytes = _build_sparse_header(compress_algorithm=1)
        header = parse_sparse_header(header_bytes)
        assert header.compress_algorithm == 1

    def test_sparse_header_newline_chars(self) -> None:
        """The newline detection characters should be preserved."""
        header_bytes = _build_sparse_header()
        header = parse_sparse_header(header_bytes)
        assert header.single_end_line_char == b"\n"
        assert header.non_end_line_char == b" "
        assert header.double_end_line_chars == b"\r\n"


# ---------------------------------------------------------------------------
# parse_descriptor
# ---------------------------------------------------------------------------


class TestParseDescriptor:
    """Tests for VMDK text descriptor parsing."""

    def test_parse_descriptor(self) -> None:
        """Parse a sample descriptor and verify extracted metadata."""
        desc = parse_descriptor(_SAMPLE_DESCRIPTOR)

        assert desc.create_type == "monolithicFlat"
        assert desc.cid == "fffffffe"
        assert desc.parent_cid == "ffffffff"
        assert desc.parent_filename is None
        assert len(desc.extents) == 1
        assert desc.raw_text == _SAMPLE_DESCRIPTOR

    def test_parse_descriptor_extents(self) -> None:
        """Verify that extent details are parsed correctly."""
        desc = parse_descriptor(_SAMPLE_DESCRIPTOR)
        extent = desc.extents[0]

        assert extent.access == "RW"
        assert extent.size_sectors == 125829120
        assert extent.extent_type == "FLAT"
        assert extent.filename == "test-vm-flat.vmdk"
        assert extent.offset_sectors == 0

    def test_parse_descriptor_disk_size(self) -> None:
        """disk_size_bytes should be sum(sectors) * 512."""
        desc = parse_descriptor(_SAMPLE_DESCRIPTOR)
        expected = 125829120 * 512
        assert desc.disk_size_bytes == expected

    def test_parse_descriptor_multiple_extents(self) -> None:
        """A descriptor with multiple extent lines should parse all of them."""
        text = textwrap.dedent("""\
            # Disk DescriptorFile
            version=1
            CID=aaaaaaaa
            parentCID=ffffffff
            createType="twoGbMaxExtentFlat"

            RW 4194304 FLAT "vm-f001.vmdk" 0
            RW 4194304 FLAT "vm-f002.vmdk" 0
            RW 2097152 FLAT "vm-f003.vmdk" 0
        """)
        desc = parse_descriptor(text)
        assert len(desc.extents) == 3
        assert desc.extents[0].filename == "vm-f001.vmdk"
        assert desc.extents[1].filename == "vm-f002.vmdk"
        assert desc.extents[2].filename == "vm-f003.vmdk"
        total_sectors = 4194304 + 4194304 + 2097152
        assert desc.disk_size_bytes == total_sectors * 512

    def test_parse_descriptor_sparse_extent(self) -> None:
        """Sparse extent type should be parsed correctly."""
        text = textwrap.dedent("""\
            # Disk DescriptorFile
            version=1
            createType="monolithicSparse"

            RW 4194304 SPARSE "vm-sparse.vmdk"
        """)
        desc = parse_descriptor(text)
        assert len(desc.extents) == 1
        assert desc.extents[0].extent_type == "SPARSE"
        assert desc.extents[0].offset_sectors == 0  # default when absent

    def test_parse_descriptor_with_parent(self) -> None:
        """A snapshot descriptor with parentFileNameHint should parse it."""
        text = textwrap.dedent("""\
            # Disk DescriptorFile
            version=1
            CID=bbbbbbbb
            parentCID=aaaaaaaa
            parentFileNameHint="base-disk.vmdk"
            createType="monolithicSparse"

            RW 4194304 SPARSE "snapshot-001.vmdk"
        """)
        desc = parse_descriptor(text)
        assert desc.parent_filename == "base-disk.vmdk"
        assert desc.parent_cid == "aaaaaaaa"


# ---------------------------------------------------------------------------
# VMDKExtent parsing
# ---------------------------------------------------------------------------


class TestVMDKExtentParsing:
    """Tests for extent line parsing within descriptors."""

    def test_vmdk_extent_parsing(self) -> None:
        """'RW 125829120 FLAT \"vm-flat.vmdk\" 0' should parse correctly."""
        text = 'RW 125829120 FLAT "vm-flat.vmdk" 0\n'
        desc = parse_descriptor(text)
        assert len(desc.extents) == 1

        ext = desc.extents[0]
        assert ext.access == "RW"
        assert ext.size_sectors == 125829120
        assert ext.extent_type == "FLAT"
        assert ext.filename == "vm-flat.vmdk"
        assert ext.offset_sectors == 0

    def test_rdonly_extent(self) -> None:
        """RDONLY extent should parse correctly."""
        text = 'RDONLY 4194304 FLAT "readonly.vmdk" 0\n'
        desc = parse_descriptor(text)
        assert desc.extents[0].access == "RDONLY"

    def test_noaccess_extent(self) -> None:
        """NOACCESS extent should parse correctly."""
        text = 'NOACCESS 1024 ZERO "zero.vmdk"\n'
        desc = parse_descriptor(text)
        assert desc.extents[0].access == "NOACCESS"
        assert desc.extents[0].extent_type == "ZERO"


# ---------------------------------------------------------------------------
# detect_vmdk_type
# ---------------------------------------------------------------------------


class TestDetectVMDKType:
    """Tests for VMDK type detection from file contents."""

    def test_detect_vmdk_type_sparse(self, tmp_path: Path) -> None:
        """A file starting with VMDK_SPARSE_MAGIC should be detected as SPARSE."""
        vmdk_file = tmp_path / "test.vmdk"
        # Write a valid sparse header (version=1, flags without stream-opt bit).
        header = _build_sparse_header(version=1, flags=3)
        vmdk_file.write_bytes(header)

        result = detect_vmdk_type(vmdk_file)
        assert result == VMDKType.SPARSE

    def test_detect_vmdk_type_flat(self, tmp_path: Path) -> None:
        """A text descriptor file should be detected as FLAT."""
        vmdk_file = tmp_path / "test.vmdk"
        vmdk_file.write_text(_SAMPLE_DESCRIPTOR, encoding="ascii")

        result = detect_vmdk_type(vmdk_file)
        assert result == VMDKType.FLAT

    def test_detect_vmdk_type_stream_optimised(self, tmp_path: Path) -> None:
        """A sparse header with the stream-optimised flag bit set should be
        detected as STREAM_OPTIMIZED."""
        vmdk_file = tmp_path / "test.vmdk"
        # Bit 16 of flags indicates stream-optimised.
        flags = 3 | (1 << 16)
        header = _build_sparse_header(version=1, flags=flags)
        vmdk_file.write_bytes(header)

        result = detect_vmdk_type(vmdk_file)
        assert result == VMDKType.STREAM_OPTIMIZED

    def test_detect_vmdk_type_sesparse(self, tmp_path: Path) -> None:
        """A sparse header with version=3 should be detected as SESPARSE."""
        vmdk_file = tmp_path / "test.vmdk"
        header = _build_sparse_header(version=3)
        vmdk_file.write_bytes(header)

        result = detect_vmdk_type(vmdk_file)
        assert result == VMDKType.SESPARSE

    def test_detect_vmdk_type_unknown(self, tmp_path: Path) -> None:
        """Binary data that is neither sparse nor text descriptor should be UNKNOWN."""
        vmdk_file = tmp_path / "test.vmdk"
        vmdk_file.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 508)

        result = detect_vmdk_type(vmdk_file)
        assert result == VMDKType.UNKNOWN


# ---------------------------------------------------------------------------
# find_vmdk_files
# ---------------------------------------------------------------------------


class TestFindVMDKFiles:
    """Tests for VMDK file discovery in a directory."""

    def test_find_vmdk_files(self, tmp_path: Path) -> None:
        """find_vmdk_files should discover .vmdk files in a directory."""
        # Create some .vmdk files and some non-vmdk files.
        (tmp_path / "disk1.vmdk").write_text("# Disk DescriptorFile\nversion=1\n")
        (tmp_path / "disk2.vmdk").write_text("# Disk DescriptorFile\nversion=1\n")
        (tmp_path / "notes.txt").write_text("not a vmdk")
        (tmp_path / "data.bin").write_bytes(b"\x00" * 100)

        results = find_vmdk_files(tmp_path)
        assert len(results) == 2
        names = {p.name for p in results}
        assert "disk1.vmdk" in names
        assert "disk2.vmdk" in names

    def test_find_vmdk_files_empty_directory(self, tmp_path: Path) -> None:
        """An empty directory should return an empty list."""
        results = find_vmdk_files(tmp_path)
        assert results == []

    def test_find_vmdk_files_nonexistent_directory(self, tmp_path: Path) -> None:
        """A nonexistent directory should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            find_vmdk_files(tmp_path / "nonexistent")

    def test_find_vmdk_files_not_a_directory(self, tmp_path: Path) -> None:
        """Passing a file instead of a directory should raise ValueError."""
        f = tmp_path / "file.txt"
        f.write_text("not a directory")
        with pytest.raises(ValueError, match="not a directory"):
            find_vmdk_files(f)

    def test_find_vmdk_files_case_insensitive_extension(self, tmp_path: Path) -> None:
        """VMDK files with uppercase extension should still be found."""
        (tmp_path / "disk.VMDK").write_text("# Disk DescriptorFile\nversion=1\n")
        results = find_vmdk_files(tmp_path)
        assert len(results) == 1

    def test_find_vmdk_files_returns_sorted(self, tmp_path: Path) -> None:
        """Results should be sorted by filename."""
        (tmp_path / "z_disk.vmdk").write_text("# Disk DescriptorFile\nversion=1\n")
        (tmp_path / "a_disk.vmdk").write_text("# Disk DescriptorFile\nversion=1\n")
        (tmp_path / "m_disk.vmdk").write_text("# Disk DescriptorFile\nversion=1\n")

        results = find_vmdk_files(tmp_path)
        names = [p.name for p in results]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# VMDK_SPARSE_MAGIC constant
# ---------------------------------------------------------------------------


class TestVMDKSparsemagic:
    """Verify the VMDK sparse magic constant."""

    def test_magic_value(self) -> None:
        """VMDK_SPARSE_MAGIC should be 0x564D444B (little-endian 'KDMV')."""
        assert VMDK_SPARSE_MAGIC == 0x564D444B

    def test_magic_to_bytes(self) -> None:
        """Packing the magic as little-endian should yield 'KDMV'."""
        raw = struct.pack("<I", VMDK_SPARSE_MAGIC)
        assert raw == b"KDMV"


# ---------------------------------------------------------------------------
# VMDKType enum
# ---------------------------------------------------------------------------


class TestVMDKTypeEnum:
    """Tests for the VMDKType enumeration."""

    def test_vmdk_type_members(self) -> None:
        """VMDKType should contain FLAT, SPARSE, SESPARSE, STREAM_OPTIMIZED,
        and UNKNOWN."""
        members = set(VMDKType.__members__.keys())
        expected = {"FLAT", "SPARSE", "SESPARSE", "STREAM_OPTIMIZED", "UNKNOWN"}
        assert expected.issubset(members)

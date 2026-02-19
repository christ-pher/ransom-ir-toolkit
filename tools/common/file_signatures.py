"""
File signature (magic bytes) database for data carving from partially-encrypted VMDK files.

When ransomware encrypts virtual disk images, it often leaves regions unencrypted --
either due to intermittent encryption strategies, partial encryption before interruption,
or the encryption skipping unallocated / low-priority disk areas. This module provides
a catalog of well-known file signatures (magic bytes) used to identify and carve
recoverable files from those unencrypted regions.

Each signature includes the magic byte sequence, expected offset, optional footer marker,
and size hints to support bounded extraction during carving passes.

Usage:
    from tools.common.file_signatures import SIGNATURES, find_signatures

    with open("flat.vmdk", "rb") as f:
        chunk = f.read(1_048_576)
        for abs_offset, sig in find_signatures(chunk, offset=0):
            print(f"Found {sig.name} at offset 0x{abs_offset:08x}")
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FileSignature:
    """Describes a file type by its magic byte signature and carving metadata."""

    name: str
    """Human-readable file type name (e.g. 'PDF', 'JPEG', 'NTFS MFT')."""

    category: str
    """Broad classification: 'document', 'image', 'archive', 'filesystem', 'database',
    'email', 'windows', 'virtualization'."""

    magic: bytes
    """The magic byte sequence that identifies the file type."""

    extension: str
    """Canonical file extension including the leading dot (e.g. '.pdf')."""

    offset: int = 0
    """Byte offset from the start of the file where *magic* appears.  Usually 0."""

    max_size: int | None = None
    """Upper-bound estimate of file size in bytes for carving.  ``None`` means
    unknown / unbounded."""

    footer: bytes | None = None
    """Optional end-of-file marker.  When present, carving can search forward from the
    header to the footer for precise extraction."""


# ---------------------------------------------------------------------------
# Signature catalogue
# ---------------------------------------------------------------------------

SIGNATURES: list[FileSignature] = [
    # ------------------------------------------------------------------
    # Documents
    # ------------------------------------------------------------------
    FileSignature(
        name="PDF",
        category="document",
        magic=b"%PDF",
        extension=".pdf",
        max_size=500_000_000,          # 500 MB upper bound
        footer=b"%%EOF",
    ),
    FileSignature(
        name="DOCX",
        category="document",
        magic=b"PK\x03\x04",
        extension=".docx",
        max_size=100_000_000,          # 100 MB
        footer=b"PK\x05\x06",         # End-of-central-directory record
    ),
    FileSignature(
        name="XLSX",
        category="document",
        magic=b"PK\x03\x04",
        extension=".xlsx",
        max_size=200_000_000,
        footer=b"PK\x05\x06",
    ),
    FileSignature(
        name="PPTX",
        category="document",
        magic=b"PK\x03\x04",
        extension=".pptx",
        max_size=500_000_000,
        footer=b"PK\x05\x06",
    ),
    FileSignature(
        name="RTF",
        category="document",
        magic=b"{\\rtf",
        extension=".rtf",
        max_size=50_000_000,           # 50 MB
        footer=b"}",
    ),

    # ------------------------------------------------------------------
    # Images
    # ------------------------------------------------------------------
    FileSignature(
        name="JPEG",
        category="image",
        magic=b"\xff\xd8\xff",
        extension=".jpg",
        max_size=50_000_000,
        footer=b"\xff\xd9",
    ),
    FileSignature(
        name="PNG",
        category="image",
        magic=b"\x89PNG\r\n\x1a\n",
        extension=".png",
        max_size=50_000_000,
        footer=b"IEND\xae\x42\x60\x82",
    ),
    FileSignature(
        name="GIF87a",
        category="image",
        magic=b"GIF87a",
        extension=".gif",
        max_size=20_000_000,
        footer=b"\x3b",
    ),
    FileSignature(
        name="GIF89a",
        category="image",
        magic=b"GIF89a",
        extension=".gif",
        max_size=20_000_000,
        footer=b"\x3b",
    ),
    FileSignature(
        name="BMP",
        category="image",
        magic=b"BM",
        extension=".bmp",
        max_size=50_000_000,
    ),
    FileSignature(
        name="TIFF (little-endian)",
        category="image",
        magic=b"\x49\x49\x2a\x00",
        extension=".tiff",
        max_size=500_000_000,
    ),
    FileSignature(
        name="TIFF (big-endian)",
        category="image",
        magic=b"\x4d\x4d\x00\x2a",
        extension=".tiff",
        max_size=500_000_000,
    ),

    # ------------------------------------------------------------------
    # Archives
    # ------------------------------------------------------------------
    FileSignature(
        name="ZIP",
        category="archive",
        magic=b"PK\x03\x04",
        extension=".zip",
        max_size=4_000_000_000,        # 4 GB
        footer=b"PK\x05\x06",
    ),
    FileSignature(
        name="7-Zip",
        category="archive",
        magic=b"\x37\x7a\xbc\xaf\x27\x1c",
        extension=".7z",
        max_size=4_000_000_000,
    ),
    FileSignature(
        name="RAR",
        category="archive",
        magic=b"\x52\x61\x72\x21",
        extension=".rar",
        max_size=4_000_000_000,
    ),
    FileSignature(
        name="GZIP",
        category="archive",
        magic=b"\x1f\x8b",
        extension=".gz",
        max_size=4_000_000_000,
    ),
    FileSignature(
        name="TAR",
        category="archive",
        magic=b"ustar",
        extension=".tar",
        offset=257,
        max_size=4_000_000_000,
    ),

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    FileSignature(
        name="SQLite",
        category="database",
        magic=b"SQLite format 3\x00",
        extension=".sqlite",
        max_size=1_000_000_000,        # 1 GB
    ),

    # ------------------------------------------------------------------
    # Email
    # ------------------------------------------------------------------
    FileSignature(
        name="Outlook PST",
        category="email",
        magic=b"!BDN",
        extension=".pst",
        max_size=50_000_000_000,       # 50 GB
    ),
    FileSignature(
        name="EML / MBOX",
        category="email",
        magic=b"From ",
        extension=".eml",
        max_size=100_000_000,
    ),

    # ------------------------------------------------------------------
    # Filesystem structures
    # ------------------------------------------------------------------
    FileSignature(
        name="NTFS MFT entry",
        category="filesystem",
        magic=b"\x46\x49\x4c\x45",    # FILE (FILE0 record)
        extension=".mft",
        max_size=4096,                 # Typically one MFT record = 1024 or 4096 bytes
    ),
    FileSignature(
        name="ext4 superblock",
        category="filesystem",
        magic=b"\x53\xef",
        extension=".superblock",
        offset=0x38,
        max_size=4096,
    ),
    FileSignature(
        name="NTFS boot sector",
        category="filesystem",
        magic=b"\xeb\x52\x90NTFS",
        extension=".ntfs",
        max_size=8192,
    ),

    # ------------------------------------------------------------------
    # Windows artifacts
    # ------------------------------------------------------------------
    FileSignature(
        name="Windows Registry hive",
        category="windows",
        magic=b"regf",
        extension=".reg",
        max_size=500_000_000,
    ),
    FileSignature(
        name="PE executable",
        category="windows",
        magic=b"MZ",
        extension=".exe",
        max_size=500_000_000,
    ),
    FileSignature(
        name="Windows EVTX",
        category="windows",
        magic=b"ElfFile\x00",
        extension=".evtx",
        max_size=100_000_000,
    ),

    # ------------------------------------------------------------------
    # Virtualization
    # ------------------------------------------------------------------
    FileSignature(
        name="VMDK sparse header",
        category="virtualization",
        magic=b"KDMV",
        extension=".vmdk",
        max_size=None,                 # Unbounded; virtual disks vary wildly
    ),
    FileSignature(
        name="VHD footer",
        category="virtualization",
        magic=b"conectix",
        extension=".vhd",
        max_size=None,
    ),
]


# ---------------------------------------------------------------------------
# Pre-computed lookup structures (built once at import time)
# ---------------------------------------------------------------------------

# Signatures grouped by the offset at which their magic bytes appear.
_sigs_by_offset: dict[int, list[FileSignature]] = {}
for _sig in SIGNATURES:
    _sigs_by_offset.setdefault(_sig.offset, []).append(_sig)

# Unique offsets sorted ascending so scans proceed in a deterministic order.
_offsets_sorted: list[int] = sorted(_sigs_by_offset)


# ---------------------------------------------------------------------------
# Public query helpers
# ---------------------------------------------------------------------------

def find_signatures(data: bytes, offset: int = 0) -> list[tuple[int, FileSignature]]:
    """Scan *data* for every occurrence of every known signature.

    Parameters
    ----------
    data:
        Raw bytes to scan -- typically a chunk read from a VMDK flat extent.
    offset:
        The absolute byte offset of the beginning of *data* within the larger
        file.  This value is added to each local match position so that the
        returned offsets are absolute.

    Returns
    -------
    list[tuple[int, FileSignature]]
        Each element is ``(absolute_offset, signature)`` sorted in ascending
        order of absolute offset.  When multiple signatures match at the same
        position (e.g. ZIP/DOCX/XLSX all share ``PK\\x03\\x04``), all of them
        are returned.
    """
    data_len: int = len(data)
    hits: list[tuple[int, FileSignature]] = []

    for sig_offset in _offsets_sorted:
        for sig in _sigs_by_offset[sig_offset]:
            magic: bytes = sig.magic
            magic_len: int = len(magic)

            # We need at least sig_offset bytes *before* the magic inside
            # a candidate file.  When scanning a raw buffer the magic will
            # appear at ``local_pos + sig_offset`` within the candidate
            # file boundary, but in a flat byte stream we scan for the
            # magic itself.  For offset-0 signatures we scan directly;
            # for non-zero offsets (e.g. TAR "ustar" at 257) we look for
            # the magic at any position and report the hit rewound by
            # *sig_offset* so the caller gets the start of the file.
            search_start: int = 0
            while search_start <= data_len - magic_len:
                pos: int = data.find(magic, search_start)
                if pos == -1:
                    break

                # The candidate file would start at ``pos - sig.offset``
                # within *data*.
                file_start_local: int = pos - sig.offset
                if file_start_local >= 0:
                    hits.append((offset + file_start_local, sig))

                search_start = pos + 1

    hits.sort(key=lambda h: h[0])
    return hits


def find_signature_at(data: bytes) -> FileSignature | None:
    """Check whether *data* begins with a known file signature.

    Only signatures with ``offset == 0`` are considered (the most common
    case).  Returns the *first* matching signature or ``None``.

    For signatures that have a non-zero offset (e.g. TAR at offset 257),
    this function will **also** check if the magic bytes are present at the
    expected offset within *data*.
    """
    # Fast path: check offset-0 signatures first (most common).
    for sig in _sigs_by_offset.get(0, []):
        if data[:len(sig.magic)] == sig.magic:
            return sig

    # Slower path: check signatures at non-zero offsets.
    for sig_offset in _offsets_sorted:
        if sig_offset == 0:
            continue
        if sig_offset >= len(data):
            continue
        for sig in _sigs_by_offset[sig_offset]:
            end: int = sig_offset + len(sig.magic)
            if end <= len(data) and data[sig_offset:end] == sig.magic:
                return sig

    return None


def get_signatures_by_category(category: str) -> list[FileSignature]:
    """Return all signatures belonging to *category* (case-insensitive).

    Parameters
    ----------
    category:
        One of ``'document'``, ``'image'``, ``'archive'``, ``'filesystem'``,
        ``'database'``, ``'email'``, ``'windows'``, ``'virtualization'``.

    Returns
    -------
    list[FileSignature]
        Matching signatures in the same order they appear in :data:`SIGNATURES`.
    """
    cat_lower: str = category.lower()
    return [sig for sig in SIGNATURES if sig.category == cat_lower]

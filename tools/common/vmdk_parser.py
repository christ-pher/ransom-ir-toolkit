"""VMDK descriptor and sparse-header parser for ransomware incident response.

This module parses VMware Virtual Machine Disk (VMDK) metadata so that
downstream tools -- particularly the entropy analyser -- can locate the
actual data regions that need to be scanned for encryption artefacts.

VMDK Types
----------
VMware uses several on-disk layouts, and knowing the layout is essential
before running entropy analysis:

* **Flat (monolithicFlat / twoGbMaxExtentFlat)** --
  The VMDK file is a small *text descriptor* that references one or more
  companion ``*-flat.vmdk`` files containing raw disk data.  Entropy
  analysis runs directly against those flat extent files because they
  contain an unadorned byte-for-byte copy of the virtual disk.

* **Sparse (monolithicSparse / twoGbMaxExtentSparse)** --
  The VMDK file is a *binary container* with a 512-byte sparse header
  followed by grain tables, grain directories, and compressed/
  uncompressed grains.  The header must be parsed first so that the
  entropy analyser can skip metadata regions and only measure grains.

* **SE Sparse (seSparse)** --
  An improved sparse format used by ESXi 6.5+ for snapshots.  Uses a
  different on-disk layout with space-efficient grain tables.

* **Stream-optimised (streamOptimized)** --
  Designed for OVA/OVF export.  Grains are individually compressed
  (deflate) and the grain table is appended as a footer.  Entropy
  analysis must decompress grains before measuring.

Distinguishing these types is critical because flat extents can be
scanned linearly for high-entropy (encrypted) regions, whereas sparse
files require grain-level parsing to avoid measuring metadata as
"encrypted" data (grain tables and directories have high entropy but
are not ciphertext).

Mario / eMario ransomware encrypts VMDK flat extents in place and
sometimes renames or creates companion ``.emario`` marker files.  The
``is_encrypted_vmdk`` heuristic on :class:`VMDKInfo` checks for the
presence of such marker files adjacent to the VMDK.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

from tools.common.safe_io import SafeReader, validate_evidence_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VMDK_SPARSE_MAGIC: int = 0x564D444B  # "KDMV" in little-endian

_SECTOR_SIZE: int = 512

# struct format for the first 512 bytes of a sparse VMDK header.
# Fields (all little-endian):
#   I  magicNumber          (4)
#   I  version              (4)
#   I  flags                (4)
#   Q  capacity             (8)
#   Q  grainSize            (8)
#   Q  descriptorOffset     (8)
#   Q  descriptorSize       (8)
#   I  numGTEsPerGT         (4)
#   Q  rgdOffset            (8)
#   Q  gdOffset             (8)
#   Q  overHead             (8)
#   B  uncleanShutdown      (1)
#   c  singleEndLineChar    (1)
#   c  nonEndLineChar       (1)
#   c  doubleEndLineChar1   (1)  \
#   c  doubleEndLineChar2   (1)  / treated as two separate chars
#   H  compressAlgorithm    (2)
# Total consumed: 4+4+4+8+8+8+8+4+8+8+8+1+1+1+1+1+2 = 80 bytes
# The remaining bytes up to 512 are padding (ignored).
_SPARSE_HEADER_FMT: str = "<IIIQQQQIQQQBccccH"
_SPARSE_HEADER_SIZE: int = struct.calcsize(_SPARSE_HEADER_FMT)

# Regex patterns for descriptor parsing.
_RE_EXTENT_LINE = re.compile(
    r"^(RW|RDONLY|NOACCESS)\s+"     # access mode
    r"(\d+)\s+"                      # size in sectors
    r"(FLAT|SPARSE|ZERO|SESPARSE|VMFS|VMFSSPARSE)\s+"  # extent type
    r'"([^"]+)"'                     # filename (quoted)
    r"(?:\s+(\d+))?"                 # optional offset for flat extents
    r"\s*$",
    re.MULTILINE,
)

_RE_KV_LINE = re.compile(
    r'^(\w+)\s*=\s*"?([^"\n]*)"?\s*$',
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class VMDKType(Enum):
    """Enumeration of VMDK on-disk layout types."""

    FLAT = auto()
    SPARSE = auto()
    SESPARSE = auto()
    STREAM_OPTIMIZED = auto()
    UNKNOWN = auto()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SparseHeader:
    """Parsed representation of the 512-byte sparse VMDK header.

    All multi-byte integers are stored little-endian on disk per the
    VMware specification.

    Attributes
    ----------
    magic:
        Must equal :data:`VMDK_SPARSE_MAGIC` (``0x564D444B``).
    version:
        Header version (typically 1 or 3).
    flags:
        Bitmask of feature flags.
    capacity_sectors:
        Virtual disk capacity in sectors.
    grain_size_sectors:
        Size of each grain in sectors (commonly 128 = 64 KiB).
    descriptor_offset_sectors:
        Sector offset to the embedded descriptor.
    descriptor_size_sectors:
        Size of the embedded descriptor region in sectors.
    num_gtes_per_gt:
        Number of grain-table entries per grain table (commonly 512).
    rgd_offset_sectors:
        Sector offset to the redundant grain directory.
    gd_offset_sectors:
        Sector offset to the primary grain directory.
    overhead_sectors:
        Total metadata overhead in sectors before data grains begin.
    unclean_shutdown:
        ``True`` if the VMDK was not cleanly closed.
    single_end_line_char:
        Newline detection byte (``\\n``).
    non_end_line_char:
        Non-newline detection byte (``\\x20``).
    double_end_line_chars:
        Two-byte newline detection sequence (``\\r\\n``).
    compress_algorithm:
        Compression algorithm identifier (0 = none, 1 = deflate).
    """

    magic: int
    version: int
    flags: int
    capacity_sectors: int
    grain_size_sectors: int
    descriptor_offset_sectors: int
    descriptor_size_sectors: int
    num_gtes_per_gt: int
    rgd_offset_sectors: int
    gd_offset_sectors: int
    overhead_sectors: int
    unclean_shutdown: bool
    single_end_line_char: bytes
    non_end_line_char: bytes
    double_end_line_chars: bytes
    compress_algorithm: int


@dataclass(frozen=True, slots=True)
class VMDKExtent:
    """A single extent entry from a VMDK descriptor.

    Attributes
    ----------
    access:
        Access mode string (``"RW"``, ``"RDONLY"``, or ``"NOACCESS"``).
    size_sectors:
        Extent size in 512-byte sectors.
    extent_type:
        On-disk format: ``"FLAT"``, ``"SPARSE"``, ``"ZERO"``,
        ``"SESPARSE"``, ``"VMFS"``, or ``"VMFSSPARSE"``.
    filename:
        Filename of the extent data file (relative to the descriptor).
    offset_sectors:
        For flat extents, the byte-offset (in sectors) into the flat
        file where this extent's data begins.  Zero for sparse extents.
    """

    access: str
    size_sectors: int
    extent_type: str
    filename: str
    offset_sectors: int


@dataclass(frozen=True, slots=True)
class VMDKDescriptor:
    """Parsed VMDK text descriptor.

    The descriptor is either a standalone ``.vmdk`` text file (for flat
    layouts) or embedded within the metadata area of a sparse VMDK.

    Attributes
    ----------
    raw_text:
        The unmodified descriptor text.
    create_type:
        The ``createType`` value (e.g. ``"monolithicFlat"``,
        ``"twoGbMaxExtentSparse"``, ``"streamOptimized"``).
    extents:
        Ordered list of extent entries.
    disk_size_bytes:
        Total virtual disk size in bytes, calculated by summing all
        extent sizes (in sectors) and multiplying by 512.
    parent_filename:
        For delta/snapshot VMDKs, the ``parentFileNameHint`` pointing
        to the parent disk.  ``None`` for base disks.
    cid:
        Content identifier (hex string) used for parent-child chain
        validation.
    parent_cid:
        Parent content identifier.  ``"ffffffff"`` for base disks.
    """

    raw_text: str
    create_type: str
    extents: list[VMDKExtent]
    disk_size_bytes: int
    parent_filename: str | None
    cid: str | None
    parent_cid: str | None


@dataclass(frozen=True, slots=True)
class VMDKInfo:
    """Top-level analysis result for a single VMDK file.

    Attributes
    ----------
    path:
        Resolved filesystem path to the ``.vmdk`` file.
    vmdk_type:
        Detected on-disk layout.
    descriptor:
        Parsed descriptor (``None`` if the descriptor could not be
        extracted or the file is of an unknown type).
    sparse_header:
        Parsed sparse header (``None`` for flat VMDKs).
    flat_extents:
        Resolved paths to the flat data files referenced by the
        descriptor.  Empty for sparse VMDKs.
    total_disk_size:
        Virtual disk size in bytes.
    is_encrypted_vmdk:
        Heuristic flag: ``True`` if companion ``.emario`` marker files
        exist adjacent to this VMDK, suggesting Mario/eMario ransomware
        encryption.
    """

    path: Path
    vmdk_type: VMDKType
    descriptor: VMDKDescriptor | None
    sparse_header: SparseHeader | None
    flat_extents: list[Path] = field(default_factory=list)
    total_disk_size: int = 0
    is_encrypted_vmdk: bool = False


# ---------------------------------------------------------------------------
# Parsing functions
# ---------------------------------------------------------------------------


def parse_sparse_header(data: bytes) -> SparseHeader:
    """Parse the 512-byte sparse VMDK header from raw bytes.

    Parameters
    ----------
    data:
        At least :data:`_SPARSE_HEADER_SIZE` bytes from the beginning
        of a sparse VMDK file.

    Returns
    -------
    SparseHeader
        Populated header structure.

    Raises
    ------
    ValueError
        If *data* is too short or the magic number does not match.
    """
    if len(data) < _SPARSE_HEADER_SIZE:
        raise ValueError(
            f"Sparse header requires at least {_SPARSE_HEADER_SIZE} bytes, "
            f"got {len(data)}"
        )

    fields = struct.unpack_from(_SPARSE_HEADER_FMT, data, 0)

    (
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
        unclean_shutdown_byte,
        single_end_line_char,
        non_end_line_char,
        double_end_line_char1,
        double_end_line_char2,
        compress_algorithm,
    ) = fields

    if magic != VMDK_SPARSE_MAGIC:
        raise ValueError(
            f"Invalid sparse VMDK magic: 0x{magic:08X} "
            f"(expected 0x{VMDK_SPARSE_MAGIC:08X})"
        )

    header = SparseHeader(
        magic=magic,
        version=version,
        flags=flags,
        capacity_sectors=capacity_sectors,
        grain_size_sectors=grain_size_sectors,
        descriptor_offset_sectors=descriptor_offset_sectors,
        descriptor_size_sectors=descriptor_size_sectors,
        num_gtes_per_gt=num_gtes_per_gt,
        rgd_offset_sectors=rgd_offset_sectors,
        gd_offset_sectors=gd_offset_sectors,
        overhead_sectors=overhead_sectors,
        unclean_shutdown=bool(unclean_shutdown_byte),
        single_end_line_char=single_end_line_char,
        non_end_line_char=non_end_line_char,
        double_end_line_chars=double_end_line_char1 + double_end_line_char2,
        compress_algorithm=compress_algorithm,
    )

    logger.debug(
        "Parsed sparse header: version=%d capacity=%d sectors "
        "grain_size=%d sectors overhead=%d sectors compress=%d",
        header.version,
        header.capacity_sectors,
        header.grain_size_sectors,
        header.overhead_sectors,
        header.compress_algorithm,
    )
    return header


def parse_descriptor(text: str) -> VMDKDescriptor:
    """Parse a VMDK text descriptor into a structured representation.

    Parameters
    ----------
    text:
        The raw descriptor text.  May originate from a standalone
        ``.vmdk`` file or from the embedded descriptor region of a
        sparse VMDK.

    Returns
    -------
    VMDKDescriptor
        Parsed descriptor with extents and metadata.
    """
    # Extract key-value pairs.
    kv: dict[str, str] = {}
    for match in _RE_KV_LINE.finditer(text):
        key, value = match.group(1), match.group(2).strip()
        kv[key] = value

    create_type: str = kv.get("createType", "unknown")
    parent_filename: str | None = kv.get("parentFileNameHint") or None
    cid: str | None = kv.get("CID") or None
    parent_cid: str | None = kv.get("parentCID") or None

    # Parse extent lines.
    extents: list[VMDKExtent] = []
    for match in _RE_EXTENT_LINE.finditer(text):
        access = match.group(1)
        size_sectors = int(match.group(2))
        extent_type = match.group(3)
        filename = match.group(4)
        offset_str = match.group(5)
        offset_sectors = int(offset_str) if offset_str is not None else 0

        extents.append(
            VMDKExtent(
                access=access,
                size_sectors=size_sectors,
                extent_type=extent_type,
                filename=filename,
                offset_sectors=offset_sectors,
            )
        )

    # Total virtual disk size from all extents.
    disk_size_bytes = sum(e.size_sectors for e in extents) * _SECTOR_SIZE

    descriptor = VMDKDescriptor(
        raw_text=text,
        create_type=create_type,
        extents=extents,
        disk_size_bytes=disk_size_bytes,
        parent_filename=parent_filename,
        cid=cid,
        parent_cid=parent_cid,
    )

    logger.debug(
        "Parsed descriptor: createType=%s extents=%d disk_size=%d bytes "
        "parent=%s cid=%s parentCID=%s",
        descriptor.create_type,
        len(descriptor.extents),
        descriptor.disk_size_bytes,
        descriptor.parent_filename,
        descriptor.cid,
        descriptor.parent_cid,
    )
    return descriptor


def find_flat_extents(
    descriptor_path: Path, descriptor: VMDKDescriptor
) -> list[Path]:
    """Resolve extent filenames to absolute paths relative to the descriptor.

    Only extent entries whose ``extent_type`` is ``"FLAT"`` are resolved,
    since sparse extents are contained within the VMDK file itself.

    Parameters
    ----------
    descriptor_path:
        Path to the ``.vmdk`` descriptor file.  Extent filenames are
        resolved relative to this file's parent directory.
    descriptor:
        Parsed descriptor containing extent entries.

    Returns
    -------
    list[Path]
        Resolved paths to flat extent files that exist on disk.  Extents
        whose files cannot be found are logged as warnings and omitted.
    """
    base_dir = descriptor_path.parent
    flat_paths: list[Path] = []

    for extent in descriptor.extents:
        if extent.extent_type != "FLAT":
            continue

        extent_path = base_dir / extent.filename
        resolved = extent_path.resolve()

        if resolved.exists():
            flat_paths.append(resolved)
            logger.debug("Resolved flat extent: %s", resolved)
        else:
            logger.warning(
                "Flat extent file not found: %s (referenced by %s)",
                resolved,
                descriptor_path,
            )

    return flat_paths


def detect_vmdk_type(path: Path) -> VMDKType:
    """Detect the VMDK type by examining the first bytes of the file.

    Parameters
    ----------
    path:
        Path to the ``.vmdk`` file.  Must be a validated evidence path.

    Returns
    -------
    VMDKType
        The detected type.  Falls back to :attr:`VMDKType.UNKNOWN` if
        the format cannot be determined.
    """
    with SafeReader(path) as reader:
        # Read enough for magic detection and a quick peek at content.
        header_bytes = reader.read_chunk(0, _SECTOR_SIZE)

    if len(header_bytes) < 4:
        logger.warning("File too small to identify VMDK type: %s", path)
        return VMDKType.UNKNOWN

    # Check for sparse magic (little-endian "KDMV").
    magic = struct.unpack_from("<I", header_bytes, 0)[0]
    if magic == VMDK_SPARSE_MAGIC:
        # Distinguish between plain sparse and stream-optimised by
        # checking the flags field (bit 16 = stream-optimised markers).
        # Also peek at the version to detect SE sparse (version 3).
        version = struct.unpack_from("<I", header_bytes, 4)[0]
        flags = struct.unpack_from("<I", header_bytes, 8)[0]

        if version == 3:
            logger.debug("Detected VMDK type: SESPARSE (%s)", path)
            return VMDKType.SESPARSE

        # Bit 16 of flags indicates stream-optimised grain markers.
        if flags & (1 << 16):
            logger.debug("Detected VMDK type: STREAM_OPTIMIZED (%s)", path)
            return VMDKType.STREAM_OPTIMIZED

        logger.debug("Detected VMDK type: SPARSE (%s)", path)
        return VMDKType.SPARSE

    # If the file starts with printable ASCII, it is likely a text
    # descriptor (flat VMDK).  Check for the characteristic comment or
    # version line that opens every VMware descriptor.
    try:
        text_preview = header_bytes.decode("ascii", errors="strict")
    except (UnicodeDecodeError, ValueError):
        logger.warning("Cannot identify VMDK type for: %s", path)
        return VMDKType.UNKNOWN

    if "# Disk DescriptorFile" in text_preview or "version=" in text_preview:
        logger.debug("Detected VMDK type: FLAT (text descriptor) (%s)", path)
        return VMDKType.FLAT

    logger.warning("Cannot identify VMDK type for: %s", path)
    return VMDKType.UNKNOWN


def _check_emario_markers(vmdk_path: Path) -> bool:
    """Check whether ``.emario`` companion files exist near the VMDK.

    Mario / eMario ransomware typically creates marker files alongside
    or in place of the original VMDK extents.  This heuristic checks
    for:
    - ``<vmdk_path>.emario``
    - Any ``.emario`` file in the same directory sharing the VM name
      prefix.

    Parameters
    ----------
    vmdk_path:
        Resolved path to the ``.vmdk`` file.

    Returns
    -------
    bool
        ``True`` if at least one ``.emario`` marker file is found.
    """
    # Direct companion: vm-flat.vmdk.emario
    if vmdk_path.with_suffix(vmdk_path.suffix + ".emario").exists():
        return True

    # Scan the directory for .emario files sharing the stem prefix.
    stem = vmdk_path.stem.split("-")[0] if "-" in vmdk_path.stem else vmdk_path.stem
    parent = vmdk_path.parent
    try:
        for sibling in parent.iterdir():
            if sibling.suffix == ".emario" and sibling.stem.startswith(stem):
                return True
    except OSError:
        logger.debug("Could not scan directory %s for .emario files", parent)

    return False


def find_vmdk_files(directory: Path) -> list[Path]:
    """Scan a directory (non-recursively) for all ``.vmdk`` files.

    Parameters
    ----------
    directory:
        Directory to scan.

    Returns
    -------
    list[Path]
        Sorted list of resolved paths to ``.vmdk`` files found in
        *directory*.

    Raises
    ------
    FileNotFoundError
        If *directory* does not exist.
    ValueError
        If *directory* is not a directory.
    """
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(f"Directory does not exist: {directory}")
    if not directory.is_dir():
        raise ValueError(f"Path is not a directory: {directory}")

    vmdk_files: list[Path] = []
    for entry in sorted(directory.iterdir()):
        if entry.is_file() and entry.suffix.lower() == ".vmdk":
            vmdk_files.append(entry.resolve())

    logger.info("Found %d VMDK file(s) in %s", len(vmdk_files), directory)
    return vmdk_files


def parse_vmdk(path: Path) -> VMDKInfo:
    """Parse a VMDK file and return a comprehensive analysis result.

    This is the main entry point.  It detects the VMDK type, parses
    the sparse header and/or text descriptor as appropriate, resolves
    flat extent paths, and checks for ransomware encryption markers.

    Parameters
    ----------
    path:
        Path to the ``.vmdk`` file.

    Returns
    -------
    VMDKInfo
        Complete analysis result.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If *path* is not a regular file or is unreadable.
    """
    resolved_path = validate_evidence_path(path)

    vmdk_type = detect_vmdk_type(resolved_path)
    descriptor: VMDKDescriptor | None = None
    sparse_header: SparseHeader | None = None
    flat_extents: list[Path] = []
    total_disk_size: int = 0

    if vmdk_type == VMDKType.SPARSE or vmdk_type == VMDKType.STREAM_OPTIMIZED:
        # Binary sparse file: parse header, then extract embedded descriptor.
        with SafeReader(resolved_path) as reader:
            header_data = reader.read_chunk(0, _SECTOR_SIZE)
            sparse_header = parse_sparse_header(header_data)

            # Read the embedded descriptor if present.
            if sparse_header.descriptor_offset_sectors > 0 and sparse_header.descriptor_size_sectors > 0:
                desc_offset = sparse_header.descriptor_offset_sectors * _SECTOR_SIZE
                desc_size = sparse_header.descriptor_size_sectors * _SECTOR_SIZE
                desc_data = reader.read_chunk(desc_offset, desc_size)
                # The descriptor is null-terminated ASCII text.
                desc_text = desc_data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
                if desc_text.strip():
                    descriptor = parse_descriptor(desc_text)

        if descriptor is not None:
            total_disk_size = descriptor.disk_size_bytes
        else:
            # Fall back to the capacity from the sparse header.
            total_disk_size = sparse_header.capacity_sectors * _SECTOR_SIZE

    elif vmdk_type == VMDKType.SESPARSE:
        # SE sparse: parse header for basic info.
        with SafeReader(resolved_path) as reader:
            header_data = reader.read_chunk(0, _SECTOR_SIZE)
            sparse_header = parse_sparse_header(header_data)

            if sparse_header.descriptor_offset_sectors > 0 and sparse_header.descriptor_size_sectors > 0:
                desc_offset = sparse_header.descriptor_offset_sectors * _SECTOR_SIZE
                desc_size = sparse_header.descriptor_size_sectors * _SECTOR_SIZE
                desc_data = reader.read_chunk(desc_offset, desc_size)
                desc_text = desc_data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
                if desc_text.strip():
                    descriptor = parse_descriptor(desc_text)

        if descriptor is not None:
            total_disk_size = descriptor.disk_size_bytes
        else:
            total_disk_size = sparse_header.capacity_sectors * _SECTOR_SIZE

    elif vmdk_type == VMDKType.FLAT:
        # Text descriptor file: read and parse entirely as text.
        with SafeReader(resolved_path) as reader:
            raw = reader.read_chunk(0, reader.get_size())
            desc_text = raw.decode("ascii", errors="replace")

        descriptor = parse_descriptor(desc_text)
        flat_extents = find_flat_extents(resolved_path, descriptor)
        total_disk_size = descriptor.disk_size_bytes

    else:
        logger.warning("Unknown VMDK type for %s; limited analysis available", resolved_path)

    is_encrypted = _check_emario_markers(resolved_path)

    # Also check flat extent paths for .emario markers.
    if not is_encrypted:
        for extent_path in flat_extents:
            if _check_emario_markers(extent_path):
                is_encrypted = True
                break

    info = VMDKInfo(
        path=resolved_path,
        vmdk_type=vmdk_type,
        descriptor=descriptor,
        sparse_header=sparse_header,
        flat_extents=flat_extents,
        total_disk_size=total_disk_size,
        is_encrypted_vmdk=is_encrypted,
    )

    logger.info(
        "VMDK analysis complete: %s type=%s size=%d bytes "
        "flat_extents=%d encrypted=%s",
        info.path,
        info.vmdk_type.name,
        info.total_disk_size,
        len(info.flat_extents),
        info.is_encrypted_vmdk,
    )
    return info

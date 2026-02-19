"""Babuk/Mario ransomware file format structures.

Mario ransomware is derived from leaked Babuk source code. It encrypts
files and appends a per-file Curve25519 ephemeral public key as a 32-byte
footer. Encrypted files are renamed with ``.emario`` or ``.omario``
extensions depending on the campaign variant.

This module defines the binary layout constants, data structures, and
extraction helpers needed to parse and classify Mario-encrypted files.

Version heuristics
------------------
Two major Mario variants have been observed in the wild:

- **Older linear**: Encrypts the entire file contents sequentially using
  Sosemanuk. All regions exhibit high entropy (~8.0 bits/byte).

- **Newer intermittent**: Applies sparse/intermittent encryption with a
  dual-key scheme. Files below 8 GiB are fully encrypted; files at or
  above 8 GiB have alternating encrypted and plaintext regions. Entropy
  sampling at multiple offsets reveals a mix of high and low values.

Designed for Python 3.10+ with no external dependencies beyond the
project's common modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from tools.common.entropy import calculate_entropy, classify_entropy
from tools.common.safe_io import SafeReader

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BABUK_KEY_SIZE: int = 32
"""Curve25519 public key size in bytes."""

EMARIO_EXTENSIONS: tuple[str, ...] = (".emario", ".omario")
"""File extensions used by Mario ransomware variants."""

BABUK_FOOTER_SIZE: int = 32
"""Size of the per-file encrypted key appended to each victim file."""

_8GB: int = 8_589_934_592
"""Threshold (in bytes) above which the newer intermittent variant applies
sparse encryption rather than full-file encryption."""

_HEADER_SAMPLE_SIZE: int = 4096
"""Number of bytes sampled from the file header for entropy analysis."""

_HIGH_ENTROPY_THRESHOLD: float = 7.9
"""Entropy value (bits/byte) at or above which a region is considered
encrypted (Sosemanuk cipher output)."""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BabukFooter:
    """Parsed Babuk-style footer containing the per-file ephemeral key.

    In the Babuk/Mario scheme each encrypted file has a unique Curve25519
    ephemeral public key written as the final 32 bytes. The corresponding
    private key was used (together with the attacker's static key) in an
    ECDH exchange to derive the Sosemanuk file-encryption key and is then
    discarded.

    Attributes
    ----------
    file_path:
        Path of the encrypted file this footer was extracted from.
    file_size:
        Total size of the encrypted file in bytes (including the footer).
    per_file_pubkey:
        Raw 32-byte Curve25519 ephemeral public key.
    pubkey_hex:
        Hexadecimal string representation of *per_file_pubkey*.
    """

    file_path: Path
    file_size: int
    per_file_pubkey: bytes
    pubkey_hex: str


class MarioVersion(Enum):
    """Detected Mario ransomware encryption variant."""

    OLDER_LINEAR = "older_linear"
    """Linear full-file encryption -- simpler, earlier variant."""

    NEWER_INTERMITTENT = "newer_intermittent"
    """Intermittent/sparse encryption with dual-key scheme and 8 GiB
    threshold -- newer, more sophisticated variant."""

    UNKNOWN = "unknown"
    """Version could not be determined from the available heuristics."""


@dataclass(slots=True)
class MarioFileInfo:
    """Aggregated analysis results for a single Mario-encrypted file.

    Attributes
    ----------
    file_path:
        Path to the encrypted file.
    file_size:
        Total file size in bytes.
    extension:
        The ransomware extension (``.emario`` or ``.omario``).
    footer:
        Parsed :class:`BabukFooter` containing the per-file key.
    estimated_version:
        Heuristic version classification.
    encryption_ratio:
        Fraction of sampled blocks classified as encrypted (0.0--1.0),
        or ``None`` if entropy sampling was not performed.
    header_entropy:
        Shannon entropy of the first 4 KiB of the file.
    notes:
        Free-form analysis observations collected during detection.
    """

    file_path: Path
    file_size: int
    extension: str
    footer: BabukFooter
    estimated_version: MarioVersion
    encryption_ratio: float | None = None
    header_entropy: float = 0.0
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Footer extraction
# ---------------------------------------------------------------------------


def extract_babuk_footer(reader: SafeReader) -> BabukFooter:
    """Read the Babuk-style footer from an open evidence file.

    The last :data:`BABUK_FOOTER_SIZE` bytes of the file are interpreted
    as a Curve25519 per-file ephemeral public key.

    Parameters
    ----------
    reader:
        An open :class:`SafeReader` positioned on the encrypted file.

    Returns
    -------
    BabukFooter
        Parsed footer data.

    Raises
    ------
    ValueError
        If the file is too small to contain a valid footer.
    """
    file_size = reader.get_size()
    if file_size < BABUK_FOOTER_SIZE:
        raise ValueError(
            f"File too small ({file_size} bytes) to contain a "
            f"{BABUK_FOOTER_SIZE}-byte Babuk footer: {reader.path}"
        )

    tail = reader.read_tail(BABUK_FOOTER_SIZE)
    footer = BabukFooter(
        file_path=reader.path,
        file_size=file_size,
        per_file_pubkey=tail,
        pubkey_hex=tail.hex(),
    )
    logger.info(
        "Extracted Babuk footer from %s: pubkey=%s",
        reader.path,
        footer.pubkey_hex,
    )
    return footer


# ---------------------------------------------------------------------------
# Version detection heuristics
# ---------------------------------------------------------------------------


def _sample_entropy_at(reader: SafeReader, offset: int) -> float:
    """Read a sample at *offset* and return its Shannon entropy."""
    data = reader.read_chunk(offset, _HEADER_SAMPLE_SIZE)
    if not data:
        return 0.0
    return calculate_entropy(data)


def detect_mario_version(
    reader: SafeReader,
    file_size: int,
) -> tuple[MarioVersion, list[str]]:
    """Determine the Mario ransomware variant using entropy heuristics.

    For files smaller than 8 GiB both variants fully encrypt, so the
    version is inferred from the header entropy pattern alone. For files
    at or above 8 GiB, multiple sample points are probed:

    * If **all** samples show high entropy the older linear variant
      (which encrypts everything) is indicated.
    * If a **mix** of high and low entropy samples is found the newer
      intermittent variant is indicated.

    Parameters
    ----------
    reader:
        An open :class:`SafeReader` on the encrypted file.
    file_size:
        Total file size in bytes (must match ``reader.get_size()``).

    Returns
    -------
    tuple[MarioVersion, list[str]]
        The estimated version and a list of human-readable reasoning
        notes explaining the classification.
    """
    notes: list[str] = []

    # -- Small-file fast path -----------------------------------------------
    if file_size < _8GB:
        notes.append(
            f"File size ({file_size:,} bytes) is below 8 GiB threshold; "
            f"both variants fully encrypt files this size."
        )

        # Even though we cannot definitively distinguish the variant for
        # small files, the header entropy still provides a sanity check.
        header_ent = _sample_entropy_at(reader, 0)
        classification = classify_entropy(header_ent)
        notes.append(
            f"Header entropy: {header_ent:.4f} bits/byte "
            f"({classification})."
        )

        if classification == "encrypted":
            notes.append(
                "File appears fully encrypted as expected for either variant."
            )
            return MarioVersion.UNKNOWN, notes

        notes.append(
            "Header entropy is unexpectedly low -- file may be partially "
            "encrypted or corrupted."
        )
        return MarioVersion.UNKNOWN, notes

    # -- Large-file multi-point sampling ------------------------------------
    notes.append(
        f"File size ({file_size:,} bytes) meets or exceeds 8 GiB threshold; "
        f"sampling entropy at multiple offsets."
    )

    # Compute safe content size (excluding the footer).
    content_size = file_size - BABUK_FOOTER_SIZE

    # Sample at start, 25%, 50%, 75%, and near end of the content region.
    sample_fractions = [0.0, 0.25, 0.50, 0.75]
    sample_offsets: list[int] = [
        int(content_size * frac) for frac in sample_fractions
    ]
    # "Near end" -- back off one sample width from the content boundary.
    near_end = max(content_size - _HEADER_SAMPLE_SIZE, 0)
    if near_end not in sample_offsets:
        sample_offsets.append(near_end)

    high_count = 0
    low_count = 0

    for offset in sample_offsets:
        ent = _sample_entropy_at(reader, offset)
        classification = classify_entropy(ent)
        is_high = classification == "encrypted"

        if is_high:
            high_count += 1
        else:
            low_count += 1

        notes.append(
            f"  offset {offset:>14,}: entropy={ent:.4f} "
            f"({classification})"
        )

    total_samples = high_count + low_count
    notes.append(
        f"High-entropy samples: {high_count}/{total_samples}, "
        f"low-entropy samples: {low_count}/{total_samples}."
    )

    if low_count == 0:
        # All samples are high entropy -- consistent with full-file
        # (linear) encryption.
        notes.append(
            "All sampled regions are encrypted -> consistent with "
            "older linear variant."
        )
        return MarioVersion.OLDER_LINEAR, notes

    if high_count > 0 and low_count > 0:
        # Mixed entropy -- hallmark of intermittent encryption.
        notes.append(
            "Mix of encrypted and unencrypted regions -> consistent with "
            "newer intermittent variant."
        )
        return MarioVersion.NEWER_INTERMITTENT, notes

    # All samples low -- unusual.  Possibly not actually encrypted content
    # before the footer, or an unrecognised variant.
    notes.append(
        "No high-entropy regions detected in sampled offsets -- cannot "
        "determine version."
    )
    return MarioVersion.UNKNOWN, notes


# ---------------------------------------------------------------------------
# File discovery helpers
# ---------------------------------------------------------------------------


def is_emario_file(path: Path) -> bool:
    """Return ``True`` if *path* has a Mario ransomware extension.

    Checks against :data:`EMARIO_EXTENSIONS` (``.emario``, ``.omario``).

    Parameters
    ----------
    path:
        Filesystem path to check (need not exist).

    Returns
    -------
    bool
    """
    return path.suffix.lower() in EMARIO_EXTENSIONS


def find_emario_files(directory: Path) -> list[Path]:
    """Recursively find all Mario-encrypted files in *directory*.

    Searches for files whose extension matches :data:`EMARIO_EXTENSIONS`.

    Parameters
    ----------
    directory:
        Root directory to search.

    Returns
    -------
    list[Path]
        Sorted list of matching file paths.

    Raises
    ------
    FileNotFoundError
        If *directory* does not exist.
    NotADirectoryError
        If *directory* is not a directory.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"Directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    results: list[Path] = []
    for ext in EMARIO_EXTENSIONS:
        results.extend(directory.rglob(f"*{ext}"))

    results.sort()
    logger.info(
        "Found %d .emario/.omario files in %s", len(results), directory
    )
    return results

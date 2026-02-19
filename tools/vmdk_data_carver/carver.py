"""VMDK Data Carver -- extract recoverable files from unencrypted VMDK regions.

This module identifies and extracts intact files from plaintext (unencrypted)
regions within VMDK disk images that have been partially encrypted by
ransomware.  It works in tandem with the entropy analyzer: the analyzer
classifies each region of the VMDK as encrypted, compressed, plaintext, or
zeroed, and the carver uses those boundaries to focus signature scanning on
the regions most likely to contain recoverable data.

Workflow:
    1.  Load the entropy analysis JSON (produced by the VMDK entropy analyzer)
        to obtain the list of plaintext/compressed region boundaries.
    2.  For each recoverable region, scan for known file signatures (magic
        bytes) using the shared signature catalogue.
    3.  For every signature hit, extract the data from the signature offset to
        an estimated end boundary (footer marker, max-size hint, or region
        end -- whichever comes first).
    4.  Validate the carved data: verify that its entropy is consistent with
        plaintext or compressed content (not encrypted noise).
    5.  Save each valid file to the output directory with a deterministic
        name derived from its absolute offset and file type.

The module can also generate a ddrescue-format skip map so that external
recovery tools (PhotoRec, TestDisk) can restrict their scans to the
unencrypted regions.

Designed for Python 3.10+ with ``rich`` for progress display.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.common.entropy import (
    COMPRESSED,
    ENCRYPTED,
    PLAINTEXT,
    ZEROED,
    calculate_entropy,
    classify_entropy,
)
from tools.common.file_signatures import (
    FileSignature,
    SIGNATURES,
    find_signatures,
    find_signature_at,
    get_signatures_by_category,
)
from tools.common.report import (
    create_progress,
    format_bytes,
    print_banner,
    print_finding,
    print_summary,
    write_json_report,
    write_markdown_report,
    ReportSection,
)
from tools.common.safe_io import SafeReader, ensure_output_dir, validate_evidence_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entropy threshold for carved-data validation.  Carved content whose
# entropy exceeds this value is likely encrypted noise that happened to
# start with bytes matching a known signature.
# ---------------------------------------------------------------------------

_CARVED_ENTROPY_CEILING: float = 7.9


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CarveConfig:
    """Configuration knobs for the data carving process."""

    min_file_size: int = 512
    """Minimum size (bytes) for a carved file to be kept.  Smaller extractions
    are discarded as likely false positives."""

    max_file_size: int = 100 * 1024 * 1024  # 100 MiB
    """Maximum size (bytes) to extract for a single carved file.  Prevents
    runaway reads when no footer is found."""

    scan_chunk_size: int = 65536  # 64 KiB
    """Chunk size used when reading region data for signature scanning."""

    categories: list[str] | None = None
    """When set, only file signatures belonging to these categories are
    considered (e.g. ``['document', 'image']``).  ``None`` means all
    categories."""


@dataclass(slots=True)
class CarvedFile:
    """Metadata for a single file extracted from the VMDK."""

    signature: FileSignature
    """The file signature that triggered extraction."""

    offset: int
    """Absolute byte offset within the source VMDK where the file begins."""

    size: int
    """Size of the extracted file in bytes."""

    output_path: Path | None
    """Filesystem path where the carved file was saved, or ``None`` if it
    was not written (e.g. validation failed, dry-run mode)."""

    entropy: float
    """Shannon entropy of the carved data -- a sanity check to confirm the
    content is genuinely plaintext/compressed rather than encrypted noise."""

    valid: bool
    """Whether the carved file passed basic validation checks."""


@dataclass(slots=True)
class CarveResult:
    """Aggregate statistics for a complete carving run."""

    source_path: Path
    """Path to the VMDK that was carved."""

    analysis_file: Path | None
    """Path to the entropy analysis JSON used (may be ``None``)."""

    regions_scanned: int
    """Number of plaintext/compressed regions that were scanned."""

    bytes_scanned: int
    """Total bytes read during signature scanning."""

    files_found: int
    """Number of file signatures detected (before validation)."""

    files_carved: int
    """Number of files that passed validation and were saved."""

    carved_files: list[CarvedFile]
    """Per-file detail records."""

    skip_map_path: Path | None
    """Path to an optional ddrescue skip map that was generated."""

    duration_seconds: float
    """Wall-clock time of the carving operation."""


# ---------------------------------------------------------------------------
# Core carver
# ---------------------------------------------------------------------------


class VMDKDataCarver:
    """Extract recoverable files from unencrypted VMDK regions.

    Parameters
    ----------
    config:
        Optional :class:`CarveConfig`.  Defaults are used when ``None``.
    """

    def __init__(self, config: CarveConfig | None = None) -> None:
        self._config: CarveConfig = config or CarveConfig()

    # -- public entry point -------------------------------------------------

    def carve(
        self,
        vmdk_path: Path,
        analysis_json: Path | None,
        output_dir: Path,
    ) -> CarveResult:
        """Scan a VMDK for file signatures and extract recoverable files.

        Parameters
        ----------
        vmdk_path:
            Path to the (flat) VMDK evidence file.
        analysis_json:
            Path to the entropy analysis JSON produced by the VMDK entropy
            analyzer.  When provided, only plaintext and compressed regions
            are scanned.  When ``None``, the entire file is scanned (much
            slower, with more false positives).
        output_dir:
            Directory where carved files are written.  Created if it does
            not exist.

        Returns
        -------
        CarveResult
            Aggregate statistics and per-file metadata.
        """
        start_time = time.monotonic()

        vmdk_resolved = validate_evidence_path(vmdk_path)
        out_resolved = ensure_output_dir(output_dir, evidence_path=vmdk_resolved)

        # Determine regions to scan.
        if analysis_json is not None:
            regions = self._load_analysis(analysis_json)
            logger.info(
                "Loaded %d recoverable regions from analysis: %s",
                len(regions),
                analysis_json,
            )
        else:
            logger.warning(
                "No analysis file provided -- scanning entire VMDK. "
                "This is significantly slower and may produce more false positives."
            )
            regions = None  # Signals full-file scan.

        carved_files: list[CarvedFile] = []
        files_found = 0
        bytes_scanned = 0
        regions_scanned = 0

        with SafeReader(vmdk_resolved) as reader:
            if regions is None:
                # Full-file scan: treat the whole file as a single region.
                file_size = reader.get_size()
                scan_regions = [{"start_offset": 0, "end_offset": file_size}]
            else:
                scan_regions = regions

            total_scan_bytes = sum(
                r["end_offset"] - r["start_offset"] for r in scan_regions
            )

            progress = create_progress("Carving")
            with progress:
                task_id = progress.add_task(
                    "Scanning regions", total=total_scan_bytes
                )

                for region in scan_regions:
                    r_start: int = region["start_offset"]
                    r_end: int = region["end_offset"]
                    regions_scanned += 1

                    logger.info(
                        "Scanning region 0x%012x -- 0x%012x (%s)",
                        r_start,
                        r_end,
                        format_bytes(r_end - r_start),
                    )

                    sig_hits = self._scan_region(reader, r_start, r_end)
                    files_found += len(sig_hits)
                    bytes_scanned += r_end - r_start

                    for abs_offset, sig in sig_hits:
                        carved = self._extract_file(
                            reader, abs_offset, sig, r_end, out_resolved
                        )
                        if carved is not None:
                            carved_files.append(carved)

                    progress.update(task_id, advance=r_end - r_start)

        elapsed = time.monotonic() - start_time

        result = CarveResult(
            source_path=vmdk_resolved,
            analysis_file=Path(analysis_json) if analysis_json else None,
            regions_scanned=regions_scanned,
            bytes_scanned=bytes_scanned,
            files_found=files_found,
            files_carved=sum(1 for cf in carved_files if cf.valid),
            carved_files=carved_files,
            skip_map_path=None,
            duration_seconds=round(elapsed, 2),
        )

        logger.info(
            "Carving complete: %d files found, %d carved in %.2fs",
            result.files_found,
            result.files_carved,
            result.duration_seconds,
        )

        return result

    # -- analysis loader ----------------------------------------------------

    def _load_analysis(self, json_path: Path) -> list[dict]:
        """Load entropy analysis JSON and return plaintext/compressed regions.

        The analysis JSON is expected to contain a ``"regions"`` key whose
        value is a list of objects with ``start_offset``, ``end_offset``, and
        ``classification`` fields.

        Parameters
        ----------
        json_path:
            Path to the entropy analysis JSON file.

        Returns
        -------
        list[dict]
            Region dicts filtered to only plaintext and compressed regions,
            sorted by ``start_offset``.
        """
        path = Path(json_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"Analysis JSON not found: {path}"
            )

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        raw_regions = data.get("regions", [])
        if not raw_regions:
            logger.warning("Analysis JSON contains no regions: %s", path)
            return []

        # Keep only regions that are likely to contain recoverable data.
        recoverable = [
            r
            for r in raw_regions
            if r.get("classification") in (PLAINTEXT, COMPRESSED)
        ]

        # Sort by start offset for deterministic, sequential scanning.
        recoverable.sort(key=lambda r: r["start_offset"])

        logger.info(
            "Analysis: %d total regions, %d recoverable (plaintext/compressed)",
            len(raw_regions),
            len(recoverable),
        )

        return recoverable

    # -- region scanner -----------------------------------------------------

    def _scan_region(
        self,
        reader: SafeReader,
        start: int,
        end: int,
    ) -> list[tuple[int, FileSignature]]:
        """Scan a byte region for known file signatures.

        The region is read in overlapping chunks (overlap equals the length
        of the longest magic sequence) so that signatures straddling chunk
        boundaries are not missed.

        Parameters
        ----------
        reader:
            Open :class:`SafeReader` positioned on the VMDK.
        start:
            Absolute start offset of the region.
        end:
            Absolute end offset (exclusive) of the region.

        Returns
        -------
        list[tuple[int, FileSignature]]
            ``(absolute_offset, signature)`` pairs, sorted by offset.
        """
        chunk_size = self._config.scan_chunk_size
        categories = self._config.categories

        # Determine the maximum magic length so we can overlap reads.
        if categories:
            sigs_in_scope = []
            for cat in categories:
                sigs_in_scope.extend(get_signatures_by_category(cat))
        else:
            sigs_in_scope = SIGNATURES

        max_magic_len = max(
            (len(sig.magic) + sig.offset for sig in sigs_in_scope), default=8
        )
        overlap = max_magic_len

        all_hits: list[tuple[int, FileSignature]] = []
        seen_offsets: set[int] = set()

        offset = start
        while offset < end:
            read_size = min(chunk_size, end - offset)
            data = reader.read_chunk(offset, read_size)
            if not data:
                break

            hits = find_signatures(data, offset=offset)

            # Filter by category if configured.
            if categories:
                cat_lower = {c.lower() for c in categories}
                hits = [
                    (off, sig) for off, sig in hits if sig.category in cat_lower
                ]

            for abs_off, sig in hits:
                if abs_off not in seen_offsets:
                    seen_offsets.add(abs_off)
                    all_hits.append((abs_off, sig))

            # Advance with overlap to avoid missing cross-boundary signatures.
            advance = len(data) - overlap
            if advance <= 0:
                # Chunk is smaller than overlap -- just move past it.
                break
            offset += advance

        all_hits.sort(key=lambda h: h[0])
        logger.debug(
            "Region 0x%012x--0x%012x: found %d signature hits",
            start,
            end,
            len(all_hits),
        )
        return all_hits

    # -- file extraction ----------------------------------------------------

    def _extract_file(
        self,
        reader: SafeReader,
        offset: int,
        sig: FileSignature,
        region_end: int,
        output_dir: Path,
    ) -> CarvedFile | None:
        """Extract a single carved file from the VMDK.

        Parameters
        ----------
        reader:
            Open :class:`SafeReader` for the VMDK.
        offset:
            Absolute offset where the file signature was found.
        sig:
            The matched :class:`FileSignature`.
        region_end:
            End boundary of the containing plaintext region (exclusive).
        output_dir:
            Directory where the carved file will be saved.

        Returns
        -------
        CarvedFile | None
            Metadata for the carved file, or ``None`` if the extraction
            failed or the file was below the minimum size threshold.
        """
        estimated_size = self._estimate_file_size(reader, offset, sig, region_end)

        if estimated_size < self._config.min_file_size:
            logger.debug(
                "Skipping %s at 0x%012x: estimated size %d < min %d",
                sig.name,
                offset,
                estimated_size,
                self._config.min_file_size,
            )
            return None

        # Read the carved data.
        data = reader.read_chunk(offset, estimated_size)
        if len(data) < self._config.min_file_size:
            logger.debug(
                "Skipping %s at 0x%012x: read only %d bytes (< min %d)",
                sig.name,
                offset,
                len(data),
                self._config.min_file_size,
            )
            return None

        # Validate: check entropy to confirm this is not encrypted noise.
        ent = calculate_entropy(data)
        classification = classify_entropy(ent)
        is_valid = classification in (PLAINTEXT, COMPRESSED)

        if not is_valid:
            logger.info(
                "Carved %s at 0x%012x failed entropy check: %.4f (%s) -- skipping",
                sig.name,
                offset,
                ent,
                classification,
            )
            return CarvedFile(
                signature=sig,
                offset=offset,
                size=len(data),
                output_path=None,
                entropy=round(ent, 4),
                valid=False,
            )

        # Build output filename: {offset_hex}_{name}{extension}
        safe_name = sig.name.replace(" ", "_").replace("/", "-")
        filename = f"{offset:012x}_{safe_name}{sig.extension}"
        out_path = output_dir / filename

        out_path.write_bytes(data)
        logger.info(
            "Carved %s at 0x%012x -> %s (%s, entropy=%.4f)",
            sig.name,
            offset,
            out_path,
            format_bytes(len(data)),
            ent,
        )

        return CarvedFile(
            signature=sig,
            offset=offset,
            size=len(data),
            output_path=out_path,
            entropy=round(ent, 4),
            valid=True,
        )

    # -- size estimation ----------------------------------------------------

    def _estimate_file_size(
        self,
        reader: SafeReader,
        offset: int,
        sig: FileSignature,
        region_end: int,
    ) -> int:
        """Estimate the size of a file starting at *offset*.

        The estimate uses a cascade of strategies:
            1. If the signature has a footer marker, search forward for it.
            2. If the signature has a ``max_size`` hint, use that.
            3. Fall back to the configured ``max_file_size``.

        The result is always clamped to the region boundary.

        Parameters
        ----------
        reader:
            Open :class:`SafeReader` for the VMDK.
        offset:
            Absolute offset where the file starts.
        sig:
            The matched :class:`FileSignature`.
        region_end:
            End of the containing region (exclusive).

        Returns
        -------
        int
            Estimated file size in bytes.
        """
        max_allowed = min(self._config.max_file_size, region_end - offset)

        if sig.max_size is not None:
            max_allowed = min(max_allowed, sig.max_size)

        if max_allowed <= 0:
            return 0

        # Strategy 1: search for the footer marker within the allowed range.
        if sig.footer is not None:
            footer_len = len(sig.footer)
            search_size = max_allowed
            # Read the potential file content in one go for footer search.
            data = reader.read_chunk(offset, search_size)
            if data:
                # Search for the footer; take the LAST occurrence to handle
                # formats where the footer byte(s) may appear in content
                # (e.g. '}' in RTF, 0x3b in GIF).
                footer_pos = data.rfind(sig.footer)
                if footer_pos >= 0:
                    size = footer_pos + footer_len
                    if size >= self._config.min_file_size:
                        logger.debug(
                            "Footer found for %s at offset 0x%012x: "
                            "footer at +0x%x, size=%d",
                            sig.name,
                            offset,
                            footer_pos,
                            size,
                        )
                        return size

        # Strategy 2 / 3: use max_size from signature or config limit.
        return max_allowed

    # -- skip map generation ------------------------------------------------

    def generate_skip_map(
        self,
        vmdk_path: Path,
        analysis_json: Path,
        output_path: Path,
    ) -> Path:
        """Generate a ddrescue-format skip map for PhotoRec / TestDisk.

        The skip map marks each region from the entropy analysis as either
        recoverable (``+``) or non-recoverable (``-``).  External tools
        that support ddrescue map files can use this to skip encrypted
        regions entirely, dramatically reducing scan time.

        Format (one region per line)::

            # VMDK Data Carver skip map
            # Source: /path/to/file.vmdk
            # Analysis: /path/to/analysis.json
            offset  size  status

        Where *offset* and *size* are in bytes (decimal) and *status* is
        ``+`` (good / plaintext) or ``-`` (bad / encrypted / zeroed).

        Parameters
        ----------
        vmdk_path:
            Path to the VMDK evidence file (used for the header comment).
        analysis_json:
            Path to the entropy analysis JSON.
        output_path:
            Destination file for the skip map.

        Returns
        -------
        Path
            The resolved path to the written skip map file.
        """
        vmdk_resolved = validate_evidence_path(vmdk_path)
        regions = self._load_analysis_all(analysis_json)

        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = [
            "# VMDK Data Carver skip map",
            f"# Source: {vmdk_resolved}",
            f"# Analysis: {Path(analysis_json).resolve()}",
            "#",
            "# Format: offset  size  status",
            "#   +  recoverable (plaintext/compressed)",
            "#   -  non-recoverable (encrypted/zeroed)",
            "",
        ]

        for region in regions:
            r_start = region["start_offset"]
            r_end = region["end_offset"]
            classification = region.get("classification", "")
            size = r_end - r_start

            if classification in (PLAINTEXT, COMPRESSED):
                status = "+"
            else:
                status = "-"

            lines.append(f"{r_start}  {size}  {status}")

        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        logger.info("Skip map written: %s (%d regions)", out, len(regions))
        return out

    def _load_analysis_all(self, json_path: Path) -> list[dict]:
        """Load all regions from the analysis JSON (not filtered).

        Unlike :meth:`_load_analysis`, this returns every region including
        encrypted and zeroed ones, which is needed for the skip map.

        Parameters
        ----------
        json_path:
            Path to the entropy analysis JSON.

        Returns
        -------
        list[dict]
            All region dicts, sorted by ``start_offset``.
        """
        path = Path(json_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"Analysis JSON not found: {path}"
            )

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        raw_regions = data.get("regions", [])
        raw_regions.sort(key=lambda r: r["start_offset"])
        return raw_regions

"""Two-pass entropy scanning engine for Mario ransomware-encrypted VMDK files.

This module implements a coarse-then-fine entropy analysis strategy to
efficiently map encrypted versus unencrypted regions in large VMDK files:

    Pass 1 (Coarse):  Scan the entire file with 1 MiB blocks to build a
                      fast overview of entropy distribution.

    Pass 2 (Fine):    Re-scan only the boundary regions (where the
                      classification changes between adjacent coarse blocks)
                      using 4 KiB blocks for precise boundary location.

    Merge:            Combine both passes into a contiguous list of
                      RegionInfo objects that map every byte of the file
                      to an encryption classification.

The two-pass approach is critical for incident response on 100 GB+ VMDK
images: a full 4 KiB scan would be prohibitively slow, while a 1 MiB-only
scan misses boundary details needed for data carving.
"""

from __future__ import annotations

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
    EntropyResult,
    calculate_entropy,
    classify_entropy,
)
from tools.common.report import create_progress, format_bytes
from tools.common.safe_io import SafeReader, validate_evidence_path
from tools.common.vmdk_parser import find_evidence_files, find_vmdk_files

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ScanConfig:
    """Configuration for the two-pass entropy scanner.

    Attributes
    ----------
    coarse_block_size:
        Block size in bytes for pass 1 (fast overview).
        Default is 1 MiB (1,048,576 bytes).
    fine_block_size:
        Block size in bytes for pass 2 (boundary precision).
        Default is 4 KiB (4,096 bytes).
    entropy_threshold:
        Shannon entropy threshold (bits/byte) above which a block is
        classified as encrypted.  Default 7.9 cleanly separates
        Sosemanuk cipher output (~8.0) from compressed data (~7.0-7.8).
    boundary_margin:
        Number of coarse blocks on each side of a detected boundary to
        include in the fine-scan pass.  Increasing this value improves
        boundary accuracy at the cost of longer scan time.
    """

    coarse_block_size: int = 1_048_576  # 1 MiB
    fine_block_size: int = 4_096        # 4 KiB
    entropy_threshold: float = 7.9
    boundary_margin: int = 5


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RegionInfo:
    """A contiguous file region sharing a single entropy classification.

    Adjacent blocks with the same classification are merged into a single
    RegionInfo to produce a compact map of encrypted vs. recoverable data.

    Attributes
    ----------
    start_offset:
        Byte offset where this region begins.
    end_offset:
        Byte offset one past the last byte of this region.
    classification:
        One of ``"encrypted"``, ``"compressed"``, ``"plaintext"``,
        or ``"zeroed"``.
    avg_entropy:
        Mean Shannon entropy across all blocks within this region.
    min_entropy:
        Minimum Shannon entropy observed in this region.
    max_entropy:
        Maximum Shannon entropy observed in this region.
    """

    start_offset: int
    end_offset: int
    classification: str
    avg_entropy: float
    min_entropy: float
    max_entropy: float

    @property
    def size(self) -> int:
        """Total size of this region in bytes."""
        return self.end_offset - self.start_offset


@dataclass(slots=True)
class AnalysisResult:
    """Complete result from a two-pass entropy analysis of a single file.

    Attributes
    ----------
    file_path:
        Resolved path to the analysed file.
    file_size:
        Total file size in bytes.
    scan_config:
        The :class:`ScanConfig` used for this analysis.
    coarse_results:
        Per-block entropy measurements from pass 1.
    fine_results:
        Per-block entropy measurements from pass 2 (boundary regions only).
    regions:
        Merged contiguous regions with uniform classification.
    scan_duration_seconds:
        Wall-clock time for the complete two-pass scan.
    """

    file_path: Path
    file_size: int
    scan_config: ScanConfig
    coarse_results: list[EntropyResult] = field(default_factory=list)
    fine_results: list[EntropyResult] = field(default_factory=list)
    regions: list[RegionInfo] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def total_encrypted(self) -> int:
        """Total bytes classified as encrypted."""
        return sum(r.size for r in self.regions if r.classification == ENCRYPTED)

    @property
    def total_plaintext(self) -> int:
        """Total bytes NOT classified as encrypted.

        This includes plaintext, compressed, and zeroed regions -- all of
        which may contain recoverable data.
        """
        return sum(r.size for r in self.regions if r.classification != ENCRYPTED)

    @property
    def recovery_percentage(self) -> float:
        """Percentage of the file that is potentially recoverable."""
        if self.file_size == 0:
            return 0.0
        return (self.total_plaintext / self.file_size) * 100.0

    @property
    def encrypted_percentage(self) -> float:
        """Percentage of the file classified as encrypted."""
        if self.file_size == 0:
            return 0.0
        return (self.total_encrypted / self.file_size) * 100.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize the analysis result to a JSON-compatible dictionary."""
        return {
            "file_path": str(self.file_path),
            "file_size": self.file_size,
            "scan_config": {
                "coarse_block_size": self.scan_config.coarse_block_size,
                "fine_block_size": self.scan_config.fine_block_size,
                "entropy_threshold": self.scan_config.entropy_threshold,
                "boundary_margin": self.scan_config.boundary_margin,
            },
            "coarse_results": [
                {
                    "offset": r.offset,
                    "size": r.size,
                    "entropy": round(r.entropy, 6),
                    "classification": r.classification,
                }
                for r in self.coarse_results
            ],
            "fine_results": [
                {
                    "offset": r.offset,
                    "size": r.size,
                    "entropy": round(r.entropy, 6),
                    "classification": r.classification,
                }
                for r in self.fine_results
            ],
            "regions": [
                {
                    "start_offset": r.start_offset,
                    "end_offset": r.end_offset,
                    "size": r.size,
                    "classification": r.classification,
                    "avg_entropy": round(r.avg_entropy, 6),
                    "min_entropy": round(r.min_entropy, 6),
                    "max_entropy": round(r.max_entropy, 6),
                }
                for r in self.regions
            ],
            "summary": {
                "total_encrypted": self.total_encrypted,
                "total_plaintext": self.total_plaintext,
                "recovery_percentage": round(self.recovery_percentage, 2),
                "encrypted_percentage": round(self.encrypted_percentage, 2),
                "scan_duration_seconds": round(self.scan_duration_seconds, 3),
            },
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class VMDKEntropyAnalyzer:
    """Two-pass entropy scanner for VMDK files.

    Usage::

        analyzer = VMDKEntropyAnalyzer()
        result = analyzer.scan(Path("/evidence/server-flat.vmdk"))
        print(f"Recovery potential: {result.recovery_percentage:.1f}%")
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    # -- public API ---------------------------------------------------------

    def scan(self, file_path: Path, skip_fine_scan: bool = False) -> AnalysisResult:
        """Run a full two-pass entropy scan on a single file.

        Parameters
        ----------
        file_path:
            Path to the VMDK (or flat extent) file to analyse.
        skip_fine_scan:
            If ``True``, skip pass 2 and produce regions from the coarse
            scan only.  Useful for a quick overview of very large files.

        Returns
        -------
        AnalysisResult
            Complete analysis including per-block entropy and merged regions.
        """
        resolved = validate_evidence_path(file_path)
        logger.info("Starting two-pass entropy scan: %s", resolved)
        start_time = time.monotonic()

        with SafeReader(resolved) as reader:
            file_size = reader.get_size()

            # Pass 1: Coarse scan
            logger.info(
                "Pass 1: Coarse scan with %s blocks",
                format_bytes(self.config.coarse_block_size),
            )
            coarse_results = self._coarse_scan(reader)
            logger.info(
                "Pass 1 complete: %d blocks scanned", len(coarse_results)
            )

            # Pass 2: Fine scan at boundaries
            fine_results: list[EntropyResult] = []
            if not skip_fine_scan and len(coarse_results) > 1:
                boundaries = self._find_boundaries(coarse_results)
                if boundaries:
                    logger.info(
                        "Pass 2: Fine scan with %s blocks at %d boundary region(s)",
                        format_bytes(self.config.fine_block_size),
                        len(boundaries),
                    )
                    fine_results = self._fine_scan(reader, boundaries, coarse_results)
                    logger.info(
                        "Pass 2 complete: %d fine blocks scanned",
                        len(fine_results),
                    )
                else:
                    logger.info(
                        "Pass 2: No boundaries detected, skipping fine scan"
                    )
            elif skip_fine_scan:
                logger.info("Pass 2: Fine scan skipped by user request")

        # Merge into contiguous regions
        regions = self._merge_regions(coarse_results, fine_results)
        elapsed = time.monotonic() - start_time

        logger.info(
            "Scan complete: %d regions, %.1f%% encrypted, %.1fs",
            len(regions),
            sum(r.size for r in regions if r.classification == ENCRYPTED)
            / max(file_size, 1)
            * 100,
            elapsed,
        )

        return AnalysisResult(
            file_path=resolved,
            file_size=file_size,
            scan_config=self.config,
            coarse_results=coarse_results,
            fine_results=fine_results,
            regions=regions,
            scan_duration_seconds=elapsed,
        )

    def batch_scan(
        self, directory: Path, skip_fine_scan: bool = False
    ) -> list[AnalysisResult]:
        """Scan all evidence files in a directory.

        Finds VMDKs, Veeam backup files (.vbk/.vib/.vrb), and
        Mario-encrypted files (.emario/.omario).

        Parameters
        ----------
        directory:
            Directory to scan for evidence files.
        skip_fine_scan:
            If ``True``, skip fine boundary scanning on all files.

        Returns
        -------
        list[AnalysisResult]
            One result per evidence file found.
        """
        evidence_files = find_evidence_files(directory)
        if not evidence_files:
            logger.warning("No evidence files found in %s", directory)
            return []

        logger.info(
            "Batch scan: %d evidence file(s) in %s",
            len(evidence_files),
            directory,
        )
        results: list[AnalysisResult] = []
        for file_path in evidence_files:
            try:
                result = self.scan(file_path, skip_fine_scan=skip_fine_scan)
                results.append(result)
            except Exception:
                logger.exception("Failed to scan %s", file_path)

        return results

    # -- pass 1: coarse scan ------------------------------------------------

    def _coarse_scan(self, reader: SafeReader) -> list[EntropyResult]:
        """Scan the file with coarse blocks and a rich progress bar.

        Parameters
        ----------
        reader:
            An open :class:`SafeReader` context.

        Returns
        -------
        list[EntropyResult]
            One result per coarse block.
        """
        file_size = reader.get_size()
        block_size = self.config.coarse_block_size
        threshold = self.config.entropy_threshold
        total_blocks = (file_size + block_size - 1) // block_size
        results: list[EntropyResult] = []

        try:
            progress = create_progress("Coarse scan")
            with progress:
                task = progress.add_task("Scanning", total=total_blocks)
                for offset, chunk in reader.iter_chunks(block_size):
                    ent = calculate_entropy(chunk)
                    cls = classify_entropy(ent, threshold)
                    results.append(
                        EntropyResult(
                            offset=offset,
                            size=len(chunk),
                            entropy=ent,
                            classification=cls,
                        )
                    )
                    progress.update(task, advance=1)
        except RuntimeError:
            # rich not available -- fall back to plain iteration with logging
            logger.info("Progress bars unavailable; scanning without visual feedback")
            block_count = 0
            for offset, chunk in reader.iter_chunks(block_size):
                ent = calculate_entropy(chunk)
                cls = classify_entropy(ent, threshold)
                results.append(
                    EntropyResult(
                        offset=offset,
                        size=len(chunk),
                        entropy=ent,
                        classification=cls,
                    )
                )
                block_count += 1
                if block_count % 100 == 0:
                    logger.info(
                        "Coarse scan progress: %d / %d blocks",
                        block_count,
                        total_blocks,
                    )

        return results

    # -- boundary detection -------------------------------------------------

    def _find_boundaries(self, results: list[EntropyResult]) -> list[int]:
        """Find indices where the classification changes between adjacent blocks.

        Parameters
        ----------
        results:
            Ordered list of coarse-scan :class:`EntropyResult` objects.

        Returns
        -------
        list[int]
            Indices into *results* where ``results[i].classification``
            differs from ``results[i-1].classification``.
        """
        boundaries: list[int] = []
        for i in range(1, len(results)):
            if results[i].classification != results[i - 1].classification:
                boundaries.append(i)
                logger.debug(
                    "Boundary at index %d: %s -> %s (offset %d)",
                    i,
                    results[i - 1].classification,
                    results[i].classification,
                    results[i].offset,
                )
        return boundaries

    # -- pass 2: fine scan at boundaries ------------------------------------

    def _fine_scan(
        self,
        reader: SafeReader,
        boundaries: list[int],
        coarse_results: list[EntropyResult],
    ) -> list[EntropyResult]:
        """Re-scan boundary regions with fine-grained blocks.

        For each boundary index, a window of ``boundary_margin`` coarse
        blocks on each side is re-scanned at the fine block size.

        Parameters
        ----------
        reader:
            An open :class:`SafeReader` context.
        boundaries:
            Indices into *coarse_results* where classification changes.
        coarse_results:
            The full coarse-scan results (needed to compute scan windows).

        Returns
        -------
        list[EntropyResult]
            Fine-grained results for all boundary regions, sorted by offset.
        """
        file_size = reader.get_size()
        fine_block = self.config.fine_block_size
        threshold = self.config.entropy_threshold
        margin = self.config.boundary_margin
        num_coarse = len(coarse_results)

        # Build the set of (start_offset, end_offset) ranges to rescan.
        # Overlapping ranges from nearby boundaries are merged.
        raw_ranges: list[tuple[int, int]] = []
        for boundary_idx in boundaries:
            lo = max(0, boundary_idx - margin)
            hi = min(num_coarse - 1, boundary_idx + margin)
            start = coarse_results[lo].offset
            end = coarse_results[hi].offset + coarse_results[hi].size
            end = min(end, file_size)
            raw_ranges.append((start, end))

        # Merge overlapping ranges
        merged_ranges: list[tuple[int, int]] = []
        for start, end in sorted(raw_ranges):
            if merged_ranges and start <= merged_ranges[-1][1]:
                merged_ranges[-1] = (
                    merged_ranges[-1][0],
                    max(merged_ranges[-1][1], end),
                )
            else:
                merged_ranges.append((start, end))

        logger.info(
            "Fine scan covers %d merged range(s) totalling %s",
            len(merged_ranges),
            format_bytes(sum(e - s for s, e in merged_ranges)),
        )

        # Scan each merged range at fine granularity
        fine_results: list[EntropyResult] = []
        for range_start, range_end in merged_ranges:
            offset = range_start
            while offset < range_end:
                read_size = min(fine_block, range_end - offset)
                chunk = reader.read_chunk(offset, read_size)
                if not chunk:
                    break
                ent = calculate_entropy(chunk)
                cls = classify_entropy(ent, threshold)
                fine_results.append(
                    EntropyResult(
                        offset=offset,
                        size=len(chunk),
                        entropy=ent,
                        classification=cls,
                    )
                )
                offset += len(chunk)

        # Sort by offset for deterministic merging
        fine_results.sort(key=lambda r: r.offset)
        return fine_results

    # -- merge passes into regions ------------------------------------------

    def _merge_regions(
        self,
        coarse: list[EntropyResult],
        fine: list[EntropyResult],
    ) -> list[RegionInfo]:
        """Combine coarse and fine results into contiguous classified regions.

        Where fine-scan data is available it takes precedence over coarse
        data (since it provides higher resolution).  Adjacent blocks with
        the same classification are merged into a single :class:`RegionInfo`.

        Parameters
        ----------
        coarse:
            Pass 1 results covering the entire file.
        fine:
            Pass 2 results covering boundary regions only (may be empty).

        Returns
        -------
        list[RegionInfo]
            Contiguous, non-overlapping regions covering the full file.
        """
        if not coarse:
            return []

        # Build a sorted list of (offset, size, entropy, classification)
        # using fine results to override coarse results where they overlap.
        # Strategy: collect all fine-scan ranges, then for each coarse block,
        # either use the fine data (if the coarse block is fully covered) or
        # the coarse data.

        # Index fine results by their offset for quick lookup
        fine_by_offset: dict[int, EntropyResult] = {r.offset: r for r in fine}
        fine_offsets = set(fine_by_offset.keys())

        # Determine which coarse blocks are covered by fine-scan data
        fine_ranges: list[tuple[int, int]] = []
        if fine:
            # Rebuild the continuous ranges from fine results
            range_start = fine[0].offset
            range_end = fine[0].offset + fine[0].size
            for fr in fine[1:]:
                if fr.offset <= range_end:
                    range_end = max(range_end, fr.offset + fr.size)
                else:
                    fine_ranges.append((range_start, range_end))
                    range_start = fr.offset
                    range_end = fr.offset + fr.size
            fine_ranges.append((range_start, range_end))

        def _is_covered_by_fine(offset: int, size: int) -> bool:
            """Check if a coarse block is fully within a fine-scan range."""
            block_end = offset + size
            for fs, fe in fine_ranges:
                if offset >= fs and block_end <= fe:
                    return True
            return False

        # Build the unified block list
        blocks: list[EntropyResult] = []

        for cr in coarse:
            if fine_ranges and _is_covered_by_fine(cr.offset, cr.size):
                # Use fine blocks that fall within this coarse block's span
                for fr in fine:
                    if fr.offset >= cr.offset and fr.offset < cr.offset + cr.size:
                        blocks.append(fr)
            else:
                blocks.append(cr)

        # Also include fine blocks that may extend beyond coarse block
        # boundaries (already included via the loop above in most cases).
        # Ensure no duplicates by tracking offsets.
        seen_offsets: set[int] = {b.offset for b in blocks}
        for fr in fine:
            if fr.offset not in seen_offsets:
                blocks.append(fr)
                seen_offsets.add(fr.offset)

        # Sort by offset
        blocks.sort(key=lambda b: b.offset)

        if not blocks:
            return []

        # Merge adjacent blocks with the same classification
        regions: list[RegionInfo] = []
        current_start = blocks[0].offset
        current_end = blocks[0].offset + blocks[0].size
        current_cls = blocks[0].classification
        entropies: list[float] = [blocks[0].entropy]

        for block in blocks[1:]:
            if block.classification == current_cls:
                # Extend the current region
                current_end = block.offset + block.size
                entropies.append(block.entropy)
            else:
                # Finalize the current region and start a new one
                regions.append(
                    RegionInfo(
                        start_offset=current_start,
                        end_offset=current_end,
                        classification=current_cls,
                        avg_entropy=sum(entropies) / len(entropies),
                        min_entropy=min(entropies),
                        max_entropy=max(entropies),
                    )
                )
                current_start = block.offset
                current_end = block.offset + block.size
                current_cls = block.classification
                entropies = [block.entropy]

        # Finalize the last region
        regions.append(
            RegionInfo(
                start_offset=current_start,
                end_offset=current_end,
                classification=current_cls,
                avg_entropy=sum(entropies) / len(entropies),
                min_entropy=min(entropies),
                max_entropy=max(entropies),
            )
        )

        logger.info("Merged into %d contiguous region(s)", len(regions))
        return regions

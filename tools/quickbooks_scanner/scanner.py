"""QuickBooks content search engine.

Scans plaintext regions of encrypted evidence files for QuickBooks
indicator strings.  The main QuickBooks company file (.QBW) uses the
Pervasive PSQL / Btrieve database format which has no universal magic
number, so magic-byte carving alone cannot find it.  This scanner
searches for characteristic strings that appear in QB data files.

Workflow:
    1.  Optionally load an entropy analysis JSON to restrict scanning
        to plaintext / compressed regions (much faster).
    2.  Read regions in 1 MiB chunks, searching each chunk for QB
        indicator patterns.
    3.  Record every hit with offset, pattern matched, and surrounding
        context bytes.
    4.  Optionally extract a configurable window around each hit for
        manual inspection.

Designed for Python 3.10+.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.report import format_bytes, write_json_report
from tools.common.safe_io import SafeReader, ensure_output_dir, validate_evidence_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# QuickBooks indicator patterns
# ---------------------------------------------------------------------------

QB_INDICATORS: list[tuple[bytes, str]] = [
    (b"Intuit", "Intuit company marker"),
    (b"QuickBooks", "QuickBooks product string"),
    (b"QBFS", "QuickBooks filesystem marker"),
    (b".QBW", "QBW filename reference"),
    (b".qbw", "QBW filename reference (lowercase)"),
    (b".TLG", "Transaction log reference"),
    (b".tlg", "Transaction log reference (lowercase)"),
    (b".QBB", "QBB backup reference"),
    (b".qbb", "QBB backup reference (lowercase)"),
]

_SCAN_CHUNK_SIZE: int = 1_048_576  # 1 MiB
_CONTEXT_BYTES: int = 64  # bytes before and after each hit for context


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class QBHit:
    """A single QuickBooks indicator hit within the evidence file."""

    offset: int
    """Absolute byte offset of the matched pattern."""

    pattern: str
    """The indicator pattern that was matched."""

    description: str
    """Human-readable description of what this pattern means."""

    context_before: bytes
    """Raw bytes immediately before the match (up to CONTEXT_BYTES)."""

    context_after: bytes
    """Raw bytes immediately after the match (up to CONTEXT_BYTES)."""

    region_start: int | None = None
    """Start offset of the containing entropy region, if known."""

    region_end: int | None = None
    """End offset of the containing entropy region, if known."""


@dataclass(slots=True)
class ScanResult:
    """Aggregate result from a QuickBooks content scan."""

    source_path: Path
    """Path to the scanned evidence file."""

    analysis_file: Path | None
    """Path to the entropy analysis JSON used, if any."""

    hits: list[QBHit] = field(default_factory=list)
    """All indicator hits found."""

    regions_scanned: int = 0
    """Number of regions scanned."""

    bytes_scanned: int = 0
    """Total bytes read during the scan."""

    duration_seconds: float = 0.0
    """Wall-clock time for the scan."""

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "source_path": str(self.source_path),
            "analysis_file": str(self.analysis_file) if self.analysis_file else None,
            "total_hits": len(self.hits),
            "regions_scanned": self.regions_scanned,
            "bytes_scanned": self.bytes_scanned,
            "duration_seconds": round(self.duration_seconds, 3),
            "hits": [
                {
                    "offset": h.offset,
                    "offset_hex": f"0x{h.offset:012x}",
                    "pattern": h.pattern,
                    "description": h.description,
                    "context_before": h.context_before.hex(),
                    "context_after": h.context_after.hex(),
                    "region_start": h.region_start,
                    "region_end": h.region_end,
                }
                for h in self.hits
            ],
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class QuickBooksScanner:
    """Search evidence files for QuickBooks content indicators."""

    def search(
        self,
        file_path: Path,
        analysis_json: Path | None = None,
        output_dir: Path | None = None,
    ) -> ScanResult:
        """Scan an evidence file for QuickBooks indicator strings.

        Parameters
        ----------
        file_path:
            Path to the evidence file (.emario, .vbk, etc.).
        analysis_json:
            Optional entropy analysis JSON.  When provided, only
            plaintext/compressed regions are scanned.
        output_dir:
            Optional directory for saving the hit report JSON.

        Returns
        -------
        ScanResult
            All hits found with context.
        """
        resolved = validate_evidence_path(file_path)
        start_time = time.monotonic()

        regions = None
        if analysis_json is not None:
            regions = self._load_analysis(analysis_json)
            logger.info(
                "Loaded %d recoverable regions from %s",
                len(regions),
                analysis_json,
            )

        hits: list[QBHit] = []
        bytes_scanned = 0
        regions_scanned = 0

        with SafeReader(resolved) as reader:
            if regions is None:
                file_size = reader.get_size()
                scan_regions = [
                    {"start_offset": 0, "end_offset": file_size,
                     "classification": "full_scan"}
                ]
            else:
                scan_regions = regions

            for region in scan_regions:
                r_start: int = region["start_offset"]
                r_end: int = region["end_offset"]
                regions_scanned += 1

                region_hits = self._scan_region(
                    reader, r_start, r_end
                )
                for h in region_hits:
                    h.region_start = r_start
                    h.region_end = r_end
                hits.extend(region_hits)
                bytes_scanned += r_end - r_start

        elapsed = time.monotonic() - start_time

        result = ScanResult(
            source_path=resolved,
            analysis_file=Path(analysis_json) if analysis_json else None,
            hits=hits,
            regions_scanned=regions_scanned,
            bytes_scanned=bytes_scanned,
            duration_seconds=elapsed,
        )

        if output_dir is not None:
            out = ensure_output_dir(output_dir, evidence_path=resolved)
            report_name = f"{resolved.name}_qb_hits.json"
            write_json_report(out / report_name, result.to_dict())
            logger.info("Hit report saved: %s", out / report_name)

        logger.info(
            "QB scan complete: %d hits in %s (%s scanned in %.1fs)",
            len(hits),
            resolved.name,
            format_bytes(bytes_scanned),
            elapsed,
        )

        return result

    def extract(
        self,
        file_path: Path,
        output_dir: Path,
        analysis_json: Path | None = None,
        window: int = 10 * 1024 * 1024,  # 10 MiB
    ) -> ScanResult:
        """Search for QB hits and extract data windows around each one.

        Parameters
        ----------
        file_path:
            Path to the evidence file.
        output_dir:
            Directory where extracted windows are saved.
        analysis_json:
            Optional entropy analysis JSON.
        window:
            Number of bytes to extract before and after each hit.

        Returns
        -------
        ScanResult
            Same as :meth:`search`, but extracted windows are saved to disk.
        """
        result = self.search(file_path, analysis_json, output_dir)

        if not result.hits:
            logger.info("No QB hits found — nothing to extract")
            return result

        resolved = validate_evidence_path(file_path)
        out = ensure_output_dir(output_dir, evidence_path=resolved)

        with SafeReader(resolved) as reader:
            file_size = reader.get_size()

            for i, hit in enumerate(result.hits):
                extract_start = max(0, hit.offset - window)
                extract_end = min(file_size, hit.offset + len(hit.pattern.encode()) + window)
                extract_size = extract_end - extract_start

                data = reader.read_chunk(extract_start, extract_size)
                out_name = (
                    f"qb_extract_{i:04d}_0x{hit.offset:012x}"
                    f"_{hit.pattern.replace('.', '').replace(' ', '_')}.bin"
                )
                out_path = out / out_name
                out_path.write_bytes(data)
                logger.info(
                    "Extracted %s around hit at 0x%012x -> %s",
                    format_bytes(len(data)),
                    hit.offset,
                    out_path,
                )

        return result

    # -- internal helpers ---------------------------------------------------

    def _scan_region(
        self,
        reader: SafeReader,
        start: int,
        end: int,
    ) -> list[QBHit]:
        """Scan a byte region for QB indicator patterns."""
        hits: list[QBHit] = []
        # Overlap chunks by max indicator length to avoid missing cross-boundary hits
        max_pattern_len = max(len(p) for p, _ in QB_INDICATORS)
        overlap = max_pattern_len + _CONTEXT_BYTES
        seen_offsets: set[tuple[int, str]] = set()

        offset = start
        while offset < end:
            read_size = min(_SCAN_CHUNK_SIZE, end - offset)
            data = reader.read_chunk(offset, read_size)
            if not data:
                break

            for pattern, description in QB_INDICATORS:
                search_start = 0
                while True:
                    pos = data.find(pattern, search_start)
                    if pos == -1:
                        break

                    abs_offset = offset + pos
                    key = (abs_offset, pattern.decode("ascii", errors="replace"))

                    if key not in seen_offsets:
                        seen_offsets.add(key)

                        ctx_before_start = max(0, pos - _CONTEXT_BYTES)
                        ctx_after_end = min(len(data), pos + len(pattern) + _CONTEXT_BYTES)

                        hits.append(QBHit(
                            offset=abs_offset,
                            pattern=pattern.decode("ascii", errors="replace"),
                            description=description,
                            context_before=data[ctx_before_start:pos],
                            context_after=data[pos + len(pattern):ctx_after_end],
                        ))

                    search_start = pos + 1

            advance = len(data) - overlap
            if advance <= 0:
                break
            offset += advance

        hits.sort(key=lambda h: h.offset)
        return hits

    def _load_analysis(self, json_path: Path) -> list[dict]:
        """Load entropy analysis JSON and return plaintext/compressed regions."""
        path = Path(json_path)
        if not path.is_file():
            raise FileNotFoundError(f"Analysis JSON not found: {path}")

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        raw_regions = data.get("regions", [])
        recoverable = [
            r for r in raw_regions
            if r.get("classification") in ("plaintext", "compressed")
        ]
        recoverable.sort(key=lambda r: r["start_offset"])
        return recoverable

"""Tests for tools.quickbooks_scanner -- QuickBooks content detection.

Covers the QuickBooksScanner search and extraction logic using
synthetic evidence files with embedded QuickBooks indicator strings.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from tools.quickbooks_scanner.scanner import (
    QB_INDICATORS,
    QBHit,
    QuickBooksScanner,
    ScanResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def scanner() -> QuickBooksScanner:
    return QuickBooksScanner()


@pytest.fixture()
def evidence_with_qb(tmp_path: Path) -> Path:
    """Create a synthetic evidence file containing QuickBooks indicators."""
    data = bytearray(1_000_000)  # 1 MB of zeroes

    # Embed QB indicators at known offsets
    data[1000:1006] = b"Intuit"
    data[2000:2010] = b"QuickBooks"
    data[5000:5004] = b"QBFS"
    data[10000:10004] = b".QBW"
    data[20000:20004] = b".TLG"
    data[50000:50004] = b".QBB"

    file_path = tmp_path / "test_vm.vmdk.emario"
    file_path.write_bytes(bytes(data))
    return file_path


@pytest.fixture()
def evidence_no_qb(tmp_path: Path) -> Path:
    """Create a synthetic evidence file with no QuickBooks indicators."""
    data = b"\x00" * 100_000
    file_path = tmp_path / "clean.vmdk.emario"
    file_path.write_bytes(data)
    return file_path


@pytest.fixture()
def analysis_json(tmp_path: Path) -> Path:
    """Create a synthetic entropy analysis JSON with two regions."""
    analysis = {
        "file_path": "/fake/path.emario",
        "file_size": 1_000_000,
        "regions": [
            {
                "start_offset": 0,
                "end_offset": 100_000,
                "classification": "plaintext",
                "avg_entropy": 2.5,
                "min_entropy": 0.0,
                "max_entropy": 4.0,
            },
            {
                "start_offset": 100_000,
                "end_offset": 500_000,
                "classification": "encrypted",
                "avg_entropy": 7.95,
                "min_entropy": 7.9,
                "max_entropy": 8.0,
            },
            {
                "start_offset": 500_000,
                "end_offset": 1_000_000,
                "classification": "plaintext",
                "avg_entropy": 3.0,
                "min_entropy": 1.0,
                "max_entropy": 5.0,
            },
        ],
    }
    json_path = tmp_path / "analysis.json"
    json_path.write_text(json.dumps(analysis), encoding="utf-8")
    return json_path


# ---------------------------------------------------------------------------
# Scanner search tests
# ---------------------------------------------------------------------------


class TestQuickBooksScanner:
    """Test the QuickBooks content scanner."""

    def test_find_intuit_string(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Scanner should find 'Intuit' indicator in synthetic data."""
        result = scanner.search(evidence_with_qb)
        patterns = [h.pattern for h in result.hits]
        assert "Intuit" in patterns

    def test_find_quickbooks_string(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Scanner should find 'QuickBooks' indicator."""
        result = scanner.search(evidence_with_qb)
        patterns = [h.pattern for h in result.hits]
        assert "QuickBooks" in patterns

    def test_find_qbfs_string(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Scanner should find 'QBFS' filesystem marker."""
        result = scanner.search(evidence_with_qb)
        patterns = [h.pattern for h in result.hits]
        assert "QBFS" in patterns

    def test_find_qbw_reference(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Scanner should find .QBW filename reference."""
        result = scanner.search(evidence_with_qb)
        patterns = [h.pattern for h in result.hits]
        assert ".QBW" in patterns

    def test_find_tlg_reference(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Scanner should find .TLG transaction log reference."""
        result = scanner.search(evidence_with_qb)
        patterns = [h.pattern for h in result.hits]
        assert ".TLG" in patterns

    def test_no_hits_in_clean_data(
        self, scanner: QuickBooksScanner, evidence_no_qb: Path
    ) -> None:
        """Scanner should find zero hits in data with no QB indicators."""
        result = scanner.search(evidence_no_qb)
        assert len(result.hits) == 0

    def test_hit_offsets_are_correct(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Hit offsets should correspond to where indicators were placed."""
        result = scanner.search(evidence_with_qb)
        offset_map = {h.pattern: h.offset for h in result.hits}
        assert offset_map.get("Intuit") == 1000
        assert offset_map.get("QuickBooks") == 2000
        assert offset_map.get("QBFS") == 5000
        assert offset_map.get(".QBW") == 10000

    def test_hit_has_context(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Each hit should include context bytes around the match."""
        result = scanner.search(evidence_with_qb)
        for hit in result.hits:
            # Context may be shorter at file boundaries but should exist
            assert isinstance(hit.context_before, bytes)
            assert isinstance(hit.context_after, bytes)


# ---------------------------------------------------------------------------
# Region-bounded scanning
# ---------------------------------------------------------------------------


class TestScannerWithAnalysis:
    """Test that the scanner respects entropy analysis region boundaries."""

    def test_respects_region_boundaries(
        self,
        scanner: QuickBooksScanner,
        evidence_with_qb: Path,
        analysis_json: Path,
    ) -> None:
        """Hits in encrypted regions should be excluded when analysis is used.

        The analysis defines 0-100K and 500K-1M as plaintext.
        Indicators at offsets 1K, 2K, 5K, 10K, 20K, 50K are in the first
        plaintext region. No indicators are in the 500K-1M region.
        """
        result = scanner.search(evidence_with_qb, analysis_json=analysis_json)
        # All embedded indicators are within the first plaintext region (0-100K)
        for hit in result.hits:
            assert hit.offset < 100_000, (
                f"Hit at {hit.offset} should be within plaintext region"
            )

    def test_regions_scanned_count(
        self,
        scanner: QuickBooksScanner,
        evidence_with_qb: Path,
        analysis_json: Path,
    ) -> None:
        """Only plaintext/compressed regions should be scanned."""
        result = scanner.search(evidence_with_qb, analysis_json=analysis_json)
        # Analysis has 2 plaintext regions, 1 encrypted
        assert result.regions_scanned == 2


# ---------------------------------------------------------------------------
# Hit reporting
# ---------------------------------------------------------------------------


class TestScanResultSerialization:
    """Test that scan results serialize correctly."""

    def test_to_dict_structure(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """to_dict should produce a well-formed JSON-compatible dictionary."""
        result = scanner.search(evidence_with_qb)
        d = result.to_dict()

        assert "source_path" in d
        assert "total_hits" in d
        assert "hits" in d
        assert isinstance(d["hits"], list)
        assert d["total_hits"] == len(d["hits"])

    def test_hit_dict_has_hex_offset(
        self, scanner: QuickBooksScanner, evidence_with_qb: Path
    ) -> None:
        """Each hit dict should include a hex-formatted offset."""
        result = scanner.search(evidence_with_qb)
        d = result.to_dict()
        if d["hits"]:
            assert "offset_hex" in d["hits"][0]
            assert d["hits"][0]["offset_hex"].startswith("0x")

    def test_json_report_written(
        self,
        scanner: QuickBooksScanner,
        evidence_with_qb: Path,
    ) -> None:
        """When output_dir is provided, a JSON report should be written."""
        # Output must be outside the evidence tree (safe_io requirement)
        with tempfile.TemporaryDirectory() as output_dir:
            result = scanner.search(evidence_with_qb, output_dir=Path(output_dir))

            json_files = list(Path(output_dir).glob("*_qb_hits.json"))
            assert len(json_files) == 1

            with open(json_files[0], "r") as f:
                data = json.load(f)
            assert data["total_hits"] == len(result.hits)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


class TestQuickBooksExtraction:
    """Test the extraction of data windows around QB hits."""

    def test_extract_creates_bin_files(
        self,
        scanner: QuickBooksScanner,
        evidence_with_qb: Path,
    ) -> None:
        """extract should create .bin files around each hit."""
        # Output must be outside the evidence tree (safe_io requirement)
        with tempfile.TemporaryDirectory() as output_dir:
            result = scanner.extract(
                evidence_with_qb,
                output_dir=Path(output_dir),
                window=1024,  # Small window for testing
            )

            assert len(result.hits) > 0
            bin_files = list(Path(output_dir).glob("qb_extract_*.bin"))
            assert len(bin_files) == len(result.hits)

    def test_extract_window_size(
        self,
        scanner: QuickBooksScanner,
        evidence_with_qb: Path,
    ) -> None:
        """Extracted files should respect the window parameter."""
        # Output must be outside the evidence tree (safe_io requirement)
        with tempfile.TemporaryDirectory() as output_dir:
            window = 512
            scanner.extract(
                evidence_with_qb,
                output_dir=Path(output_dir),
                window=window,
            )

            bin_files = list(Path(output_dir).glob("qb_extract_*.bin"))
            for bf in bin_files:
                # Each file should be at most 2*window + pattern_len
                # (window before + pattern + window after)
                assert bf.stat().st_size <= 2 * window + 20

"""Emario Header Analyzer -- core analysis engine.

Provides :class:`EmarioAnalyzer`, the main entry point for examining
``.emario`` / ``.omario`` files produced by Mario ransomware (a Babuk
derivative). The analyzer extracts the per-file Curve25519 ephemeral
public key from the Babuk-style footer, computes entropy metrics, and
applies heuristics to classify the ransomware variant.

Designed for Python 3.10+ with ``rich`` (optional, for progress bars).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from tools.common.entropy import calculate_entropy, classify_entropy
from tools.common.report import create_progress
from tools.common.safe_io import SafeReader

from .babuk_format import (
    BABUK_FOOTER_SIZE,
    MarioFileInfo,
    MarioVersion,
    _HEADER_SAMPLE_SIZE,
    detect_mario_version,
    extract_babuk_footer,
    find_emario_files,
)

logger = logging.getLogger(__name__)


class EmarioAnalyzer:
    """Analyze Mario ransomware encrypted files.

    Usage::

        analyzer = EmarioAnalyzer()
        info = analyzer.analyze_file(Path("/evidence/document.pdf.emario"))
        print(info.footer.pubkey_hex)
        print(info.estimated_version)
    """

    # ------------------------------------------------------------------
    # Single-file analysis
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: Path) -> MarioFileInfo:
        """Perform a full analysis of a single Mario-encrypted file.

        Steps:

        1. Open the file with :class:`SafeReader`.
        2. Extract the Babuk footer (per-file Curve25519 public key).
        3. Calculate the Shannon entropy of the first 4 KiB.
        4. Apply version-detection heuristics.
        5. Compute an approximate encryption ratio from sampled regions.

        Parameters
        ----------
        file_path:
            Path to an ``.emario`` or ``.omario`` file.

        Returns
        -------
        MarioFileInfo
            Aggregated analysis results.

        Raises
        ------
        ValueError
            If the file is too small, or the path fails evidence
            validation.
        """
        file_path = Path(file_path)

        with SafeReader(file_path) as reader:
            file_size = reader.get_size()

            # 1. Extract footer ------------------------------------------
            footer = extract_babuk_footer(reader)

            # 2. Header entropy ------------------------------------------
            header_data = reader.read_chunk(0, _HEADER_SAMPLE_SIZE)
            header_entropy = calculate_entropy(header_data)

            # 3. Version detection ---------------------------------------
            version, notes = detect_mario_version(reader, file_size)

            # 4. Encryption ratio estimate --------------------------------
            encryption_ratio = self._estimate_encryption_ratio(
                reader, file_size
            )

        info = MarioFileInfo(
            file_path=file_path,
            file_size=file_size,
            extension=file_path.suffix.lower(),
            footer=footer,
            estimated_version=version,
            encryption_ratio=encryption_ratio,
            header_entropy=header_entropy,
            notes=notes,
        )
        logger.info(
            "Analysis complete: %s  version=%s  entropy=%.4f  key=%s",
            file_path.name,
            version.value,
            header_entropy,
            footer.pubkey_hex[:16] + "...",
        )
        return info

    # ------------------------------------------------------------------
    # Batch / directory analysis
    # ------------------------------------------------------------------

    def analyze_directory(self, directory: Path) -> list[MarioFileInfo]:
        """Analyze every ``.emario`` / ``.omario`` file under *directory*.

        Displays a ``rich`` progress bar when the library is available.

        Parameters
        ----------
        directory:
            Root directory to scan recursively.

        Returns
        -------
        list[MarioFileInfo]
            Results for each file, in discovery order.
        """
        targets = find_emario_files(directory)
        if not targets:
            logger.warning("No .emario/.omario files found in %s", directory)
            return []

        results: list[MarioFileInfo] = []

        try:
            progress = create_progress(description="Analyzing files")
        except RuntimeError:
            # rich is not installed -- fall back to simple loop.
            progress = None

        if progress is not None:
            with progress:
                task = progress.add_task("Analyzing", total=len(targets))
                for path in targets:
                    try:
                        info = self.analyze_file(path)
                        results.append(info)
                    except Exception as exc:
                        logger.error("Failed to analyze %s: %s", path, exc)
                    progress.advance(task)
        else:
            for idx, path in enumerate(targets, 1):
                print(f"  [{idx}/{len(targets)}] {path.name}")
                try:
                    info = self.analyze_file(path)
                    results.append(info)
                except Exception as exc:
                    logger.error("Failed to analyze %s: %s", path, exc)

        return results

    # ------------------------------------------------------------------
    # Grouping / comparison helpers
    # ------------------------------------------------------------------

    @staticmethod
    def group_by_session(
        results: list[MarioFileInfo],
    ) -> dict[str, list[MarioFileInfo]]:
        """Group analysed files by per-file public key.

        In the Babuk scheme every file receives a unique ephemeral key,
        so each group should contain exactly one file. If a key appears
        more than once it signals a possible implementation bug in the
        ransomware (key reuse), which is a significant finding for
        incident response because it may make decryption feasible.

        Parameters
        ----------
        results:
            List of :class:`MarioFileInfo` objects to group.

        Returns
        -------
        dict[str, list[MarioFileInfo]]
            Mapping of public-key hex string to the files sharing that
            key.
        """
        groups: dict[str, list[MarioFileInfo]] = defaultdict(list)
        for info in results:
            groups[info.footer.pubkey_hex].append(info)
        return dict(groups)

    @staticmethod
    def compare_keys(results: list[MarioFileInfo]) -> dict:
        """Produce key-reuse and version statistics across a file set.

        Parameters
        ----------
        results:
            Analysed file results.

        Returns
        -------
        dict
            Dictionary with the following keys:

            - **total_files** (*int*): Number of files analysed.
            - **unique_keys** (*int*): Number of distinct per-file keys.
            - **reused_keys** (*dict[str, list[Path]]*): Keys observed
              more than once, mapped to the list of file paths sharing
              that key.
            - **versions_seen** (*dict[str, int]*): Count of files per
              detected :class:`MarioVersion`.
        """
        key_to_paths: dict[str, list[Path]] = defaultdict(list)
        version_counts: dict[str, int] = defaultdict(int)

        for info in results:
            key_to_paths[info.footer.pubkey_hex].append(info.file_path)
            version_counts[info.estimated_version.value] += 1

        reused = {
            key: paths
            for key, paths in key_to_paths.items()
            if len(paths) > 1
        }

        return {
            "total_files": len(results),
            "unique_keys": len(key_to_paths),
            "reused_keys": reused,
            "versions_seen": dict(version_counts),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_encryption_ratio(
        reader: SafeReader,
        file_size: int,
        num_samples: int = 20,
    ) -> float | None:
        """Estimate the fraction of the file that is encrypted.

        Takes *num_samples* evenly spaced 4 KiB samples across the file
        content (excluding the footer) and classifies each by entropy.

        Parameters
        ----------
        reader:
            Open :class:`SafeReader` for the file.
        file_size:
            Total file size in bytes.
        num_samples:
            Number of sample points. Clamped to available content.

        Returns
        -------
        float | None
            Ratio of encrypted samples (0.0--1.0), or ``None`` if the
            file is too small to sample meaningfully.
        """
        content_size = file_size - BABUK_FOOTER_SIZE
        if content_size < _HEADER_SAMPLE_SIZE:
            return None

        # Clamp samples so we don't exceed available content.
        actual_samples = min(num_samples, max(1, content_size // _HEADER_SAMPLE_SIZE))
        step = content_size // actual_samples

        encrypted_count = 0
        for i in range(actual_samples):
            offset = i * step
            data = reader.read_chunk(offset, _HEADER_SAMPLE_SIZE)
            if not data:
                continue
            ent = calculate_entropy(data)
            if classify_entropy(ent) == "encrypted":
                encrypted_count += 1

        return encrypted_count / actual_samples

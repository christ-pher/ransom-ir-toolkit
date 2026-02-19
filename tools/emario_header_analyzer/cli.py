"""CLI entry point for the Emario Header Analyzer.

Provides three sub-commands:

- **analyze** -- Examine a single ``.emario`` / ``.omario`` file.
- **batch**   -- Scan an entire directory and produce aggregate reports.
- **keys**    -- Key-reuse and session analysis across a directory.

Usage examples::

    python -m tools.emario_header_analyzer.cli analyze evidence/doc.pdf.emario
    python -m tools.emario_header_analyzer.cli batch evidence/ --output-dir reports/
    python -m tools.emario_header_analyzer.cli keys evidence/ --output keys.json

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tools.common.report import (
    ReportSection,
    format_bytes,
    print_banner,
    print_finding,
    print_summary,
    timestamp,
    write_json_report,
    write_markdown_report,
)

from .analyzer import EmarioAnalyzer
from .babuk_format import MarioFileInfo, MarioVersion

logger = logging.getLogger(__name__)

_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _file_info_to_dict(info: MarioFileInfo) -> dict:
    """Convert a :class:`MarioFileInfo` to a JSON-friendly dictionary."""
    return {
        "file_path": str(info.file_path),
        "file_size": info.file_size,
        "file_size_human": format_bytes(info.file_size),
        "extension": info.extension,
        "per_file_pubkey": info.footer.pubkey_hex,
        "estimated_version": info.estimated_version.value,
        "encryption_ratio": info.encryption_ratio,
        "header_entropy": round(info.header_entropy, 4),
        "notes": info.notes,
    }


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _cmd_analyze(args: argparse.Namespace) -> int:
    """Handle the ``analyze`` sub-command (single file)."""
    file_path = Path(args.file_path)
    analyzer = EmarioAnalyzer()

    try:
        info = analyzer.analyze_file(file_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # -- Terminal output ----------------------------------------------------
    print_finding(
        f"File: {info.file_path.name}",
        {
            "Path": str(info.file_path),
            "Size": f"{info.file_size:,} bytes ({format_bytes(info.file_size)})",
            "Extension": info.extension,
        },
    )
    print_finding(
        "Babuk Footer (per-file public key)",
        {
            "Public key (hex)": info.footer.pubkey_hex,
        },
    )
    print_finding(
        "Version Detection",
        {
            "Estimated version": info.estimated_version.value,
            "Header entropy": f"{info.header_entropy:.4f} bits/byte",
            "Encryption ratio": (
                f"{info.encryption_ratio:.1%}"
                if info.encryption_ratio is not None
                else "N/A"
            ),
        },
    )

    if info.notes:
        print_finding(
            "Analysis Notes",
            {f"[{i + 1}]": note for i, note in enumerate(info.notes)},
        )

    # -- Optional JSON output -----------------------------------------------
    if args.output:
        data = {
            "tool": "emario_header_analyzer",
            "version": _VERSION,
            "timestamp": timestamp(),
            "result": _file_info_to_dict(info),
        }
        write_json_report(Path(args.output), data)
        print(f"\nJSON report written to: {args.output}")

    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    """Handle the ``batch`` sub-command (directory scan)."""
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: Not a directory: {directory}", file=sys.stderr)
        return 1

    analyzer = EmarioAnalyzer()
    results = analyzer.analyze_directory(directory)

    if not results:
        print("No .emario/.omario files found.")
        return 0

    # -- Summary table ------------------------------------------------------
    version_counts: dict[str, int] = {}
    for info in results:
        ver = info.estimated_version.value
        version_counts[ver] = version_counts.get(ver, 0) + 1

    total_size = sum(info.file_size for info in results)
    print_summary(
        "Batch Analysis Summary",
        {
            "Total files": len(results),
            "Total size": format_bytes(total_size),
            "Extensions": ", ".join(
                sorted({info.extension for info in results})
            ),
        },
    )

    print_finding(
        "Version Distribution",
        version_counts,
    )

    # -- Key analysis -------------------------------------------------------
    key_stats = analyzer.compare_keys(results)
    key_details: dict[str, str] = {
        "Unique keys": str(key_stats["unique_keys"]),
        "Reused keys": str(len(key_stats["reused_keys"])),
    }
    if key_stats["reused_keys"]:
        key_details["WARNING"] = (
            "Key reuse detected! This may indicate a ransomware "
            "implementation bug exploitable for decryption."
        )
    print_finding(
        "Key Analysis",
        key_details,
        severity="critical" if key_stats["reused_keys"] else "info",
    )

    # -- Per-file details ---------------------------------------------------
    for info in results:
        print_finding(
            info.file_path.name,
            {
                "Size": format_bytes(info.file_size),
                "Version": info.estimated_version.value,
                "Entropy": f"{info.header_entropy:.4f}",
                "Key": info.footer.pubkey_hex[:16] + "...",
            },
        )

    # -- File reports -------------------------------------------------------
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        report_data = {
            "tool": "emario_header_analyzer",
            "version": _VERSION,
            "timestamp": timestamp(),
            "directory": str(directory),
            "summary": {
                "total_files": len(results),
                "total_size": total_size,
                "total_size_human": format_bytes(total_size),
                "version_distribution": version_counts,
                "key_analysis": key_stats,
            },
            "files": [_file_info_to_dict(info) for info in results],
        }

        formats = [f.strip().lower() for f in args.format.split(",")]

        if "json" in formats:
            json_path = output_dir / "emario_analysis.json"
            write_json_report(json_path, report_data)
            print(f"\nJSON report: {json_path}")

        if "markdown" in formats or "md" in formats:
            md_path = output_dir / "emario_analysis.md"
            sections = _build_markdown_sections(results, key_stats, version_counts)
            write_markdown_report(
                md_path,
                "Emario Header Analysis Report",
                sections,
            )
            print(f"Markdown report: {md_path}")

        if "text" in formats:
            # Text output is the terminal output already printed above.
            print("\n(Text report was displayed above.)")

    return 0


def _cmd_keys(args: argparse.Namespace) -> int:
    """Handle the ``keys`` sub-command (key comparison)."""
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: Not a directory: {directory}", file=sys.stderr)
        return 1

    analyzer = EmarioAnalyzer()
    results = analyzer.analyze_directory(directory)

    if not results:
        print("No .emario/.omario files found.")
        return 0

    key_stats = analyzer.compare_keys(results)

    # -- Terminal output ----------------------------------------------------
    print_summary(
        "Key Comparison",
        {
            "Total files analysed": key_stats["total_files"],
            "Unique per-file keys": key_stats["unique_keys"],
            "Reused keys": len(key_stats["reused_keys"]),
        },
    )

    print_finding(
        "Version Distribution",
        key_stats["versions_seen"],
    )

    if key_stats["reused_keys"]:
        print_finding(
            "KEY REUSE DETECTED",
            {
                "Reused key count": len(key_stats["reused_keys"]),
                "Detail": (
                    "One or more per-file ephemeral keys appear on "
                    "multiple files. In the Babuk/Mario scheme each file "
                    "should receive a unique key. Reuse suggests a "
                    "ransomware implementation bug that may make "
                    "decryption possible."
                ),
            },
            severity="critical",
        )
        for key_hex, paths in key_stats["reused_keys"].items():
            print_finding(
                f"Reused key: {key_hex[:16]}...",
                {f"File {i + 1}": str(p) for i, p in enumerate(paths)},
                severity="warning",
            )
    else:
        print_finding(
            "No key reuse detected",
            {
                "Result": (
                    "All per-file keys are unique, consistent with a "
                    "correct Babuk ECDH implementation."
                ),
            },
        )

    # Group display
    groups = analyzer.group_by_session(results)
    print_summary(
        "Session Groups (by per-file key)",
        {
            "Groups": len(groups),
            "Single-file groups": sum(
                1 for g in groups.values() if len(g) == 1
            ),
            "Multi-file groups": sum(
                1 for g in groups.values() if len(g) > 1
            ),
        },
    )

    # -- Optional JSON output -----------------------------------------------
    if args.output:
        # Convert Path objects to strings for JSON serialisation.
        serialisable_reused = {
            k: [str(p) for p in v]
            for k, v in key_stats["reused_keys"].items()
        }
        data = {
            "tool": "emario_header_analyzer",
            "version": _VERSION,
            "command": "keys",
            "timestamp": timestamp(),
            "directory": str(directory),
            "total_files": key_stats["total_files"],
            "unique_keys": key_stats["unique_keys"],
            "reused_keys": serialisable_reused,
            "versions_seen": key_stats["versions_seen"],
        }
        write_json_report(Path(args.output), data)
        print(f"\nJSON report written to: {args.output}")

    return 0


# ---------------------------------------------------------------------------
# Markdown report builder
# ---------------------------------------------------------------------------


def _build_markdown_sections(
    results: list[MarioFileInfo],
    key_stats: dict,
    version_counts: dict[str, int],
) -> list[ReportSection]:
    """Build :class:`ReportSection` objects for a batch Markdown report."""
    sections: list[ReportSection] = []

    # Overview
    sections.append(
        ReportSection(
            title="Overview",
            content={
                "Total files": str(len(results)),
                "Total size": format_bytes(
                    sum(i.file_size for i in results)
                ),
                "Extensions": ", ".join(
                    sorted({i.extension for i in results})
                ),
            },
            level=2,
        )
    )

    # Version distribution
    sections.append(
        ReportSection(
            title="Version Distribution",
            content={v: str(c) for v, c in version_counts.items()},
            level=2,
        )
    )

    # Key analysis
    key_notes: list[str] = [
        f"Unique keys: {key_stats['unique_keys']}",
        f"Reused keys: {len(key_stats['reused_keys'])}",
    ]
    if key_stats["reused_keys"]:
        key_notes.append(
            "WARNING: Key reuse detected -- possible ransomware "
            "implementation bug."
        )
        for key_hex, paths in key_stats["reused_keys"].items():
            key_notes.append(
                f"Key {key_hex[:16]}... reused across "
                f"{len(paths)} files."
            )
    sections.append(
        ReportSection(title="Key Analysis", content=key_notes, level=2)
    )

    # Per-file details
    for info in results:
        sections.append(
            ReportSection(
                title=info.file_path.name,
                content={
                    "Path": str(info.file_path),
                    "Size": f"{info.file_size:,} bytes ({format_bytes(info.file_size)})",
                    "Extension": info.extension,
                    "Per-file key": info.footer.pubkey_hex,
                    "Estimated version": info.estimated_version.value,
                    "Header entropy": f"{info.header_entropy:.4f} bits/byte",
                    "Encryption ratio": (
                        f"{info.encryption_ratio:.1%}"
                        if info.encryption_ratio is not None
                        else "N/A"
                    ),
                },
                level=3,
            )
        )

    return sections


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser with sub-commands."""
    parser = argparse.ArgumentParser(
        prog="emario_header_analyzer",
        description=(
            "Analyze .emario/.omario encrypted file headers to determine "
            "Mario ransomware version and extract cryptographic metadata."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- analyze (single file) ---------------------------------------------
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a single .emario/.omario file.",
    )
    p_analyze.add_argument(
        "file_path",
        help="Path to the encrypted file.",
    )
    p_analyze.add_argument(
        "--output",
        default=None,
        help="Optional path to write a JSON report.",
    )

    # -- batch (directory) -------------------------------------------------
    p_batch = subparsers.add_parser(
        "batch",
        help="Analyze all .emario/.omario files in a directory.",
    )
    p_batch.add_argument(
        "directory",
        help="Root directory to scan recursively.",
    )
    p_batch.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write report files into.",
    )
    p_batch.add_argument(
        "--format",
        default="text,json",
        help=(
            "Comma-separated report formats: text, json, markdown. "
            "Default: text,json"
        ),
    )

    # -- keys (key analysis) -----------------------------------------------
    p_keys = subparsers.add_parser(
        "keys",
        help="Key comparison and session analysis.",
    )
    p_keys.add_argument(
        "directory",
        help="Root directory to scan recursively.",
    )
    p_keys.add_argument(
        "--output",
        default=None,
        help="Optional path to write a JSON key-analysis report.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point."""
    print_banner("Emario Header Analyzer", version=_VERSION)

    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging.
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s",
    )

    # Dispatch to the appropriate handler.
    handlers = {
        "analyze": _cmd_analyze,
        "batch": _cmd_batch,
        "keys": _cmd_keys,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

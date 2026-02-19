"""CLI entry point for the VMDK Entropy Analyzer.

Provides three sub-commands for scanning Mario ransomware-encrypted VMDK
files and generating entropy map reports:

    scan    Analyse a single VMDK file with two-pass entropy scanning.
    batch   Analyse all VMDK files in a directory.
    report  Regenerate reports from a previously saved JSON analysis.

Usage examples::

    # Scan a single file, generate all report formats
    python -m tools.vmdk_entropy_analyzer.cli scan /evidence/server-flat.vmdk \\
        --output-dir /reports

    # Fast coarse-only scan of a very large image
    python -m tools.vmdk_entropy_analyzer.cli scan /evidence/huge-flat.vmdk \\
        --no-fine-scan --format text

    # Batch scan a directory
    python -m tools.vmdk_entropy_analyzer.cli batch /evidence/vmdk/ \\
        --output-dir /reports

    # Regenerate HTML from a saved JSON analysis
    python -m tools.vmdk_entropy_analyzer.cli report /reports/analysis.json \\
        --format html --output-dir /reports/html
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from tools.common.entropy import EntropyResult
from tools.common.report import (
    format_bytes,
    format_duration,
    format_percent,
    print_banner,
    print_finding,
    print_summary,
)

from .analyzer import AnalysisResult, RegionInfo, ScanConfig, VMDKEntropyAnalyzer
from .visualizer import render_text_map, save_report

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle the ``scan`` sub-command."""
    file_path = Path(args.file_path)

    config = ScanConfig(
        coarse_block_size=args.block_size,
        fine_block_size=args.fine_block_size,
        entropy_threshold=args.threshold,
    )

    analyzer = VMDKEntropyAnalyzer(config)
    result = analyzer.scan(file_path, skip_fine_scan=args.no_fine_scan)

    # Print text map to terminal
    print(render_text_map(result))

    # Print summary
    _print_result_summary(result)

    # Save reports if output dir specified
    if args.output_dir:
        saved = save_report(result, Path(args.output_dir), formats=args.format)
        for path in saved:
            print(f"  Report saved: {path}")

    return 0


def _handle_batch(args: argparse.Namespace) -> int:
    """Handle the ``batch`` sub-command."""
    directory = Path(args.directory)
    output_dir = Path(args.output_dir)

    config = ScanConfig(
        coarse_block_size=args.block_size,
        fine_block_size=args.fine_block_size,
        entropy_threshold=args.threshold,
    )

    analyzer = VMDKEntropyAnalyzer(config)
    results = analyzer.batch_scan(directory, skip_fine_scan=args.no_fine_scan)

    if not results:
        print_finding(
            "No evidence files found",
            {"Directory": str(directory),
             "Searched": ".vmdk, .vbk, .vib, .vrb, .emario, .omario"},
            severity="warning",
        )
        return 1

    for result in results:
        print(render_text_map(result))
        _print_result_summary(result)
        saved = save_report(result, output_dir, formats=args.format)
        for path in saved:
            print(f"  Report saved: {path}")
        print()

    # Aggregate summary
    total_encrypted = sum(r.total_encrypted for r in results)
    total_size = sum(r.file_size for r in results)
    total_plaintext = sum(r.total_plaintext for r in results)
    total_duration = sum(r.scan_duration_seconds for r in results)

    print_summary(
        "Batch Scan Summary",
        {
            "Files scanned": len(results),
            "Total file size": format_bytes(total_size),
            "Total encrypted": format_bytes(total_encrypted),
            "Total recoverable": format_bytes(total_plaintext),
            "Overall recovery": format_percent(total_plaintext, total_size),
            "Total scan time": format_duration(total_duration),
        },
    )

    return 0


def _handle_report(args: argparse.Namespace) -> int:
    """Handle the ``report`` sub-command.

    Reads a previously saved JSON analysis and regenerates reports in the
    requested formats.
    """
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"Error: JSON file not found: {json_path}", file=sys.stderr)
        return 1

    with open(json_path, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    # Reconstruct the AnalysisResult from JSON data
    result = _result_from_dict(data)

    # Print text map to terminal
    print(render_text_map(result))
    _print_result_summary(result)

    # Save reports
    output_dir = Path(args.output_dir) if args.output_dir else json_path.parent
    saved = save_report(result, output_dir, formats=args.format)
    for path in saved:
        print(f"  Report saved: {path}")

    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_result_summary(result: AnalysisResult) -> None:
    """Print a concise summary of a scan result to the terminal."""
    # Classification-specific findings
    region_counts: dict[str, int] = {}
    region_sizes: dict[str, int] = {}
    for region in result.regions:
        region_counts[region.classification] = (
            region_counts.get(region.classification, 0) + 1
        )
        region_sizes[region.classification] = (
            region_sizes.get(region.classification, 0) + region.size
        )

    if result.total_encrypted > 0:
        print_finding(
            "Encrypted regions detected",
            {
                "Encrypted regions": region_counts.get("encrypted", 0),
                "Encrypted size": format_bytes(result.total_encrypted),
                "Encrypted percentage": f"{result.encrypted_percentage:.1f}%",
            },
            severity="critical",
        )

    if result.total_plaintext > 0:
        print_finding(
            "Recoverable data found",
            {
                "Recoverable size": format_bytes(result.total_plaintext),
                "Recovery percentage": f"{result.recovery_percentage:.1f}%",
            },
            severity="info",
        )

    print_summary(
        f"Analysis: {result.file_path.name}",
        {
            "File size": format_bytes(result.file_size),
            "Encrypted": f"{format_bytes(result.total_encrypted)} ({result.encrypted_percentage:.1f}%)",
            "Recoverable": f"{format_bytes(result.total_plaintext)} ({result.recovery_percentage:.1f}%)",
            "Regions": len(result.regions),
            "Scan time": format_duration(result.scan_duration_seconds),
        },
    )


def _result_from_dict(data: dict[str, Any]) -> AnalysisResult:
    """Reconstruct an AnalysisResult from a JSON-deserialized dictionary.

    Parameters
    ----------
    data:
        Dictionary matching the schema produced by
        :meth:`AnalysisResult.to_dict`.

    Returns
    -------
    AnalysisResult
        Reconstructed result suitable for report generation.
    """
    config_data = data.get("scan_config", {})
    config = ScanConfig(
        coarse_block_size=config_data.get("coarse_block_size", 1_048_576),
        fine_block_size=config_data.get("fine_block_size", 4096),
        entropy_threshold=config_data.get("entropy_threshold", 7.9),
        boundary_margin=config_data.get("boundary_margin", 5),
    )

    coarse_results = [
        EntropyResult(
            offset=r["offset"],
            size=r["size"],
            entropy=r["entropy"],
            classification=r["classification"],
        )
        for r in data.get("coarse_results", [])
    ]

    fine_results = [
        EntropyResult(
            offset=r["offset"],
            size=r["size"],
            entropy=r["entropy"],
            classification=r["classification"],
        )
        for r in data.get("fine_results", [])
    ]

    regions = [
        RegionInfo(
            start_offset=r["start_offset"],
            end_offset=r["end_offset"],
            classification=r["classification"],
            avg_entropy=r["avg_entropy"],
            min_entropy=r["min_entropy"],
            max_entropy=r["max_entropy"],
        )
        for r in data.get("regions", [])
    ]

    summary = data.get("summary", {})

    return AnalysisResult(
        file_path=Path(data.get("file_path", "unknown")),
        file_size=data.get("file_size", 0),
        scan_config=config,
        coarse_results=coarse_results,
        fine_results=fine_results,
        regions=regions,
        scan_duration_seconds=summary.get("scan_duration_seconds", 0.0),
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with sub-commands."""
    parser = argparse.ArgumentParser(
        prog="vmdk_entropy_analyzer",
        description=(
            "VMDK Entropy Analyzer -- map encrypted vs. unencrypted regions "
            "in Mario ransomware-encrypted VMDK files using two-pass "
            "entropy scanning."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- scan ---------------------------------------------------------------
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a single VMDK file.",
    )
    scan_parser.add_argument(
        "file_path",
        help="Path to the VMDK file to analyse.",
    )
    scan_parser.add_argument(
        "--block-size",
        type=int,
        default=1_048_576,
        help="Coarse block size in bytes (default: 1048576 = 1 MiB).",
    )
    scan_parser.add_argument(
        "--fine-block-size",
        type=int,
        default=4096,
        help="Fine block size in bytes (default: 4096 = 4 KiB).",
    )
    scan_parser.add_argument(
        "--threshold",
        type=float,
        default=7.9,
        help="Entropy threshold for encrypted classification (default: 7.9).",
    )
    scan_parser.add_argument(
        "--output-dir",
        help="Output directory for reports.",
    )
    scan_parser.add_argument(
        "--format",
        nargs="+",
        default=["text", "html", "json"],
        choices=["text", "html", "json"],
        help="Report formats to generate (default: text html json).",
    )
    scan_parser.add_argument(
        "--no-fine-scan",
        action="store_true",
        help="Skip the fine boundary scan for faster results.",
    )

    # -- batch --------------------------------------------------------------
    batch_parser = subparsers.add_parser(
        "batch",
        help="Scan all evidence files in a directory (VMDKs, Veeam backups, Mario-encrypted).",
    )
    batch_parser.add_argument(
        "directory",
        help="Directory containing evidence files to analyse (.vmdk, .vbk, .vib, .vrb, .emario, .omario).",
    )
    batch_parser.add_argument(
        "--output-dir",
        required=True,
        help="Output directory for reports (required).",
    )
    batch_parser.add_argument(
        "--block-size",
        type=int,
        default=1_048_576,
        help="Coarse block size in bytes (default: 1048576 = 1 MiB).",
    )
    batch_parser.add_argument(
        "--fine-block-size",
        type=int,
        default=4096,
        help="Fine block size in bytes (default: 4096 = 4 KiB).",
    )
    batch_parser.add_argument(
        "--threshold",
        type=float,
        default=7.9,
        help="Entropy threshold for encrypted classification (default: 7.9).",
    )
    batch_parser.add_argument(
        "--format",
        nargs="+",
        default=["text", "html", "json"],
        choices=["text", "html", "json"],
        help="Report formats to generate (default: text html json).",
    )
    batch_parser.add_argument(
        "--no-fine-scan",
        action="store_true",
        help="Skip the fine boundary scan for faster results.",
    )

    # -- report -------------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report",
        help="Generate reports from a saved JSON analysis.",
    )
    report_parser.add_argument(
        "json_file",
        help="Path to a previously saved JSON analysis file.",
    )
    report_parser.add_argument(
        "--output-dir",
        help="Output directory for reports (default: same directory as JSON file).",
    )
    report_parser.add_argument(
        "--format",
        nargs="+",
        default=["text", "html", "json"],
        choices=["text", "html", "json"],
        help="Report formats to generate (default: text html json).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """CLI entry point for the VMDK Entropy Analyzer."""
    print_banner("VMDK Entropy Analyzer")

    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "scan": _handle_scan,
        "batch": _handle_batch,
        "report": _handle_report,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        logger.exception("Unexpected error during analysis")
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

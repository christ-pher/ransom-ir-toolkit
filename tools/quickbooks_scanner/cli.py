"""CLI entry point for the QuickBooks Content Scanner.

Provides two sub-commands:

``search``
    Scan an evidence file for QuickBooks indicator strings and report hits.

``extract``
    Search for QB hits and extract data windows around each one for manual
    inspection.

Usage examples::

    # Scan with entropy analysis guidance
    python -m tools.quickbooks_scanner.cli search /path/to/file.emario \\
        --analysis-file /output/entropy_results/file.json \\
        --output-dir /output/qb_hits/

    # Scan without analysis (searches entire file)
    python -m tools.quickbooks_scanner.cli search /path/to/file.vbk.emario \\
        --output-dir /output/qb_hits/

    # Extract regions around QB hits
    python -m tools.quickbooks_scanner.cli extract /path/to/file.emario \\
        --analysis-file /output/entropy_results/file.json \\
        --output-dir /output/qb_extracted/ \\
        --window 10M

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tools.common.report import format_bytes, print_banner, print_finding, print_summary

from .scanner import QuickBooksScanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Size parsing
# ---------------------------------------------------------------------------

def _parse_size(s: str) -> int:
    """Parse a human-readable size string (e.g. '10M', '1G', '512K') to bytes."""
    s = s.strip().upper()
    multipliers = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if s[-1] in multipliers:
        return int(float(s[:-1]) * multipliers[s[-1]])
    return int(s)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _handle_search(args: argparse.Namespace) -> int:
    """Handle the ``search`` sub-command."""
    scanner = QuickBooksScanner()

    try:
        result = scanner.search(
            file_path=Path(args.file_path),
            analysis_json=Path(args.analysis_file) if args.analysis_file else None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except FileNotFoundError as exc:
        print_finding("File not found", {"Error": str(exc)}, severity="critical")
        return 1
    except ValueError as exc:
        print_finding("Validation error", {"Error": str(exc)}, severity="critical")
        return 1

    if result.hits:
        # Group hits by pattern for summary
        pattern_counts: dict[str, int] = {}
        for hit in result.hits:
            pattern_counts[hit.pattern] = pattern_counts.get(hit.pattern, 0) + 1

        print_finding(
            f"QuickBooks data indicators found: {len(result.hits)} hits",
            {p: f"{c} occurrences" for p, c in sorted(pattern_counts.items())},
            severity="info",
        )

        # Show first few hits with context
        for hit in result.hits[:10]:
            ctx = hit.context_after[:32]
            printable = ctx.decode("ascii", errors="replace")
            print_finding(
                f"Hit: {hit.pattern}",
                {
                    "Offset": f"0x{hit.offset:012x}",
                    "Description": hit.description,
                    "Context (after)": repr(printable),
                },
                severity="info",
            )

        if len(result.hits) > 10:
            print(f"  ... and {len(result.hits) - 10} more hits (see JSON report)")
            print()
    else:
        print_finding(
            "No QuickBooks indicators found",
            {"File": str(result.source_path)},
            severity="warning",
        )

    print_summary("QuickBooks Scan Results", {
        "Source": str(result.source_path),
        "Analysis file": str(result.analysis_file) if result.analysis_file else "None (full scan)",
        "Regions scanned": str(result.regions_scanned),
        "Bytes scanned": format_bytes(result.bytes_scanned),
        "QB hits": str(len(result.hits)),
        "Duration": f"{result.duration_seconds:.2f}s",
    })

    return 0


def _handle_extract(args: argparse.Namespace) -> int:
    """Handle the ``extract`` sub-command."""
    window = _parse_size(args.window)

    scanner = QuickBooksScanner()

    try:
        result = scanner.extract(
            file_path=Path(args.file_path),
            output_dir=Path(args.output_dir),
            analysis_json=Path(args.analysis_file) if args.analysis_file else None,
            window=window,
        )
    except FileNotFoundError as exc:
        print_finding("File not found", {"Error": str(exc)}, severity="critical")
        return 1
    except ValueError as exc:
        print_finding("Validation error", {"Error": str(exc)}, severity="critical")
        return 1

    print_summary("QuickBooks Extraction Results", {
        "Source": str(result.source_path),
        "QB hits": str(len(result.hits)),
        "Window size": format_bytes(window),
        "Output dir": str(args.output_dir),
        "Duration": f"{result.duration_seconds:.2f}s",
    })

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with sub-commands."""
    parser = argparse.ArgumentParser(
        prog="qb-scan",
        description=(
            "QuickBooks Content Scanner -- search encrypted evidence files "
            "for QuickBooks data indicators (Intuit, QBFS, .QBW references, etc.)."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- search -------------------------------------------------------------
    search_parser = subparsers.add_parser(
        "search",
        help="Scan for QuickBooks indicators in an evidence file.",
    )
    search_parser.add_argument(
        "file_path",
        help="Path to the evidence file to scan.",
    )
    search_parser.add_argument(
        "--analysis-file",
        default=None,
        help=(
            "Path to entropy analysis JSON.  When provided, only plaintext/"
            "compressed regions are scanned.  Highly recommended."
        ),
    )
    search_parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for saving the hit report JSON.",
    )

    # -- extract ------------------------------------------------------------
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract data windows around QB hits for manual inspection.",
    )
    extract_parser.add_argument(
        "file_path",
        help="Path to the evidence file to scan.",
    )
    extract_parser.add_argument(
        "--analysis-file",
        default=None,
        help="Path to entropy analysis JSON.",
    )
    extract_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory for extracted data windows.",
    )
    extract_parser.add_argument(
        "--window",
        default="10M",
        help="Size of extraction window around each hit (default: 10M).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the QuickBooks Content Scanner."""
    print_banner("QuickBooks Content Scanner")

    parser = _build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    handlers = {
        "search": _handle_search,
        "extract": _handle_extract,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        sys.exit(handler(args))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during scan")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

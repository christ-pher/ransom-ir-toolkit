"""Command-line interface for the VMDK Data Carver.

Provides two sub-commands:

``carve``
    Scan a VMDK file for known file signatures in unencrypted regions and
    extract recoverable files to an output directory.

``skip-map``
    Generate a ddrescue-format skip map from an entropy analysis JSON so
    that external tools (PhotoRec, TestDisk) can restrict their scans to
    the plaintext regions.

Usage examples::

    # Carve with entropy analysis guidance (recommended)
    python -m tools.vmdk_data_carver.cli carve disk-flat.vmdk \\
        --analysis-file analysis.json --output-dir ./carved

    # Carve the whole file without analysis (slower, more false positives)
    python -m tools.vmdk_data_carver.cli carve disk-flat.vmdk \\
        --output-dir ./carved

    # Generate a skip map for PhotoRec
    python -m tools.vmdk_data_carver.cli skip-map disk-flat.vmdk \\
        --analysis-file analysis.json --output skip_map.txt

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tools.common.report import format_bytes, print_banner, print_finding, print_summary
from tools.vmdk_data_carver.carver import CarveConfig, VMDKDataCarver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with ``carve`` and ``skip-map`` sub-commands."""

    parser = argparse.ArgumentParser(
        prog="vmdk-data-carver",
        description=(
            "Extract recoverable files from unencrypted VMDK regions "
            "identified by the entropy analyzer."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debug-level logging.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- carve sub-command ------------------------------------------------

    carve_parser = subparsers.add_parser(
        "carve",
        help="Extract files from a VMDK.",
        description=(
            "Scan a VMDK for known file signatures within unencrypted "
            "regions and extract each match to the output directory."
        ),
    )
    carve_parser.add_argument(
        "vmdk_path",
        type=Path,
        help="Path to the (flat) VMDK evidence file.",
    )
    carve_parser.add_argument(
        "--analysis-file",
        type=Path,
        default=None,
        help=(
            "Path to the entropy analyzer JSON output.  When provided, only "
            "plaintext/compressed regions are scanned.  Highly recommended."
        ),
    )
    carve_parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory where carved files will be saved.",
    )
    carve_parser.add_argument(
        "--min-size",
        type=int,
        default=512,
        metavar="BYTES",
        help="Minimum carved file size in bytes (default: 512).",
    )
    carve_parser.add_argument(
        "--max-size",
        type=int,
        default=100 * 1024 * 1024,
        metavar="BYTES",
        help="Maximum carved file size in bytes (default: 100 MiB).",
    )
    carve_parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        metavar="CAT",
        help=(
            "Restrict carving to specific file categories.  "
            "Options: document, image, archive, database, email, "
            "filesystem, windows, virtualization."
        ),
    )

    # ---- skip-map sub-command ---------------------------------------------

    skipmap_parser = subparsers.add_parser(
        "skip-map",
        help="Generate a PhotoRec/ddrescue skip map.",
        description=(
            "Produce a ddrescue-format skip map from entropy analysis results "
            "so that PhotoRec or TestDisk can focus on recoverable regions."
        ),
    )
    skipmap_parser.add_argument(
        "vmdk_path",
        type=Path,
        help="Path to the (flat) VMDK evidence file.",
    )
    skipmap_parser.add_argument(
        "--analysis-file",
        type=Path,
        required=True,
        help="Path to the entropy analyzer JSON output (required).",
    )
    skipmap_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output file path for the skip map.",
    )

    return parser


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def _handle_carve(args: argparse.Namespace) -> int:
    """Execute the ``carve`` sub-command.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on error.
    """
    config = CarveConfig(
        min_file_size=args.min_size,
        max_file_size=args.max_size,
        categories=args.categories,
    )

    carver = VMDKDataCarver(config=config)

    try:
        result = carver.carve(
            vmdk_path=args.vmdk_path,
            analysis_json=args.analysis_file,
            output_dir=args.output_dir,
        )
    except FileNotFoundError as exc:
        print_finding(
            "File not found",
            {"Error": str(exc)},
            severity="critical",
        )
        return 1
    except ValueError as exc:
        print_finding(
            "Validation error",
            {"Error": str(exc)},
            severity="critical",
        )
        return 1

    # Display per-file findings for carved files.
    valid_files = [cf for cf in result.carved_files if cf.valid]
    invalid_files = [cf for cf in result.carved_files if not cf.valid]

    for cf in valid_files:
        print_finding(
            f"Carved: {cf.signature.name}",
            {
                "Offset": f"0x{cf.offset:012x}",
                "Size": format_bytes(cf.size),
                "Entropy": f"{cf.entropy:.4f}",
                "Output": str(cf.output_path),
            },
            severity="info",
        )

    if invalid_files:
        print_finding(
            f"Skipped {len(invalid_files)} files (failed entropy validation)",
            {
                "Reason": "Entropy too high -- likely encrypted noise matching a signature",
                "Threshold": f"< {7.9:.1f} bits/byte",
            },
            severity="warning",
        )

    # Summary.
    total_bytes_recovered = sum(cf.size for cf in valid_files)
    print_summary("Carving Results", {
        "Source": str(result.source_path),
        "Analysis file": str(result.analysis_file) if result.analysis_file else "None (full scan)",
        "Regions scanned": str(result.regions_scanned),
        "Bytes scanned": format_bytes(result.bytes_scanned),
        "Signatures found": str(result.files_found),
        "Files carved": str(result.files_carved),
        "Total recovered": format_bytes(total_bytes_recovered),
        "Duration": f"{result.duration_seconds:.2f}s",
    })

    return 0


def _handle_skip_map(args: argparse.Namespace) -> int:
    """Execute the ``skip-map`` sub-command.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on error.
    """
    carver = VMDKDataCarver()

    try:
        out_path = carver.generate_skip_map(
            vmdk_path=args.vmdk_path,
            analysis_json=args.analysis_file,
            output_path=args.output,
        )
    except FileNotFoundError as exc:
        print_finding(
            "File not found",
            {"Error": str(exc)},
            severity="critical",
        )
        return 1
    except ValueError as exc:
        print_finding(
            "Validation error",
            {"Error": str(exc)},
            severity="critical",
        )
        return 1

    print_summary("Skip Map Generated", {
        "Output": str(out_path),
        "VMDK": str(args.vmdk_path),
        "Analysis": str(args.analysis_file),
    })

    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the VMDK Data Carver."""

    print_banner("VMDK Data Carver")

    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging.
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    command = args.command
    if command == "carve":
        exit_code = _handle_carve(args)
    elif command == "skip-map":
        exit_code = _handle_skip_map(args)
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

"""CLI entry point for the QuickBooks File Validator.

Validates carved QuickBooks files (.qbb, .iif, .ofx) from carve-vmdk
output, classifying real QB data and filtering false positives.

Usage::

    python -m tools.qb_validator /output/carved_files/ \\
        --output-dir /output/validated_qb/

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from tools.common.report import format_bytes, print_banner, print_finding, print_summary

from .validator import validate_directory

logger = logging.getLogger(__name__)


def _handle_validate(args: argparse.Namespace) -> int:
    """Run validation on the input directory."""
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.is_dir():
        print_finding("Input not found", {"Error": f"Not a directory: {input_dir}"}, severity="critical")
        return 1

    results = validate_directory(input_dir, output_dir)

    if not results:
        print_finding("No files found", {"Directory": str(input_dir)}, severity="warning")
        return 0

    # Print per-file results
    for r in results:
        severity = "info" if r.valid else "warning"
        details = {
            "Classification": r.classification,
            "Size": format_bytes(r.size),
        }
        if r.valid and r.output_path:
            details["Copied to"] = str(r.output_path)
        if "qbw_file" in r.details:
            details["QBW inside"] = r.details["qbw_file"]
            details["QBW size"] = format_bytes(r.details["qbw_size"])
        if "contents" in r.details:
            details["Contents"] = f"{len(r.details['contents'])} entries"
        if "error" in r.details:
            details["Error"] = r.details["error"]

        label = "VALID" if r.valid else "SKIP"
        print_finding(f"[{label}] {r.path.name}", details, severity=severity)

    # Summary
    valid_count = sum(1 for r in results if r.valid)
    by_class: dict[str, int] = {}
    for r in results:
        by_class[r.classification] = by_class.get(r.classification, 0) + 1

    summary_stats = {
        "Input directory": str(input_dir),
        "Output directory": str(output_dir),
        "Total files scanned": str(len(results)),
        "Valid QB files": str(valid_count),
    }
    for cls, count in sorted(by_class.items()):
        summary_stats[cls] = str(count)

    print_summary("QuickBooks Validation Results", summary_stats)

    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="qb-validate",
        description=(
            "QuickBooks File Validator -- validate carved files from "
            "carve-vmdk output, separating real QuickBooks data from "
            "false positives (Office docs, JARs, corrupt ZIPs)."
        ),
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing carved files to validate.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help=(
            "Directory for validated output.  Valid files are copied "
            "into qbb/, iif/, ofx/ subdirectories."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    return parser


def main() -> None:
    """CLI entry point for the QuickBooks File Validator."""
    print_banner("QuickBooks File Validator")

    parser = _build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        sys.exit(_handle_validate(args))
    except KeyboardInterrupt:
        print("\nValidation interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during validation")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

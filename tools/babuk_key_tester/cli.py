"""CLI entry point for the Babuk Key Tester tool.

Tests known Babuk/Mario ECDH private keys against encrypted files to
determine if any of the keys can decrypt the target.  This is a
low-probability but zero-cost test: if any key matches, the file can
be fully recovered.

Usage::

    # Test a single file
    python -m tools.babuk_key_tester.cli test /evidence/file.emario

    # Batch test a directory
    python -m tools.babuk_key_tester.cli batch /evidence/encrypted/ \\
        --output-dir /output/results/ --stop-on-match

    # Test with custom keys
    python -m tools.babuk_key_tester.cli test /evidence/file.emario \\
        --keys /path/to/custom_keys.json --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from tools.common.report import (
    print_banner,
    print_finding,
    print_summary,
    write_json_report,
    format_bytes,
    timestamp,
)
from tools.babuk_key_tester.key_tester import BabukKeyTester, TestResult
from tools.babuk_key_tester.known_keys import get_all_keys

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------


def _load_custom_keys(keys_path: Path) -> list[dict]:
    """Load keys from a JSON file.

    Expected format: a JSON array of objects, each with ``name`` (str)
    and ``private_key`` (hex string, 64 chars).  Optional fields:
    ``source`` and ``notes``.

    Parameters
    ----------
    keys_path:
        Path to the JSON file.

    Returns
    -------
    list[dict]
        Keys in the internal format (``private_key`` as bytes).
    """
    with open(keys_path, "r", encoding="utf-8") as f:
        raw_keys = json.load(f)

    keys: list[dict] = []
    for entry in raw_keys:
        keys.append({
            "name": entry["name"],
            "private_key": bytes.fromhex(entry["private_key"]),
            "source": entry.get("source", "custom"),
            "notes": entry.get("notes", ""),
        })
    return keys


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _cmd_test(args: argparse.Namespace) -> int:
    """Handle the 'test' subcommand: test keys against a single file."""
    file_path = Path(args.file_path)

    if not file_path.exists():
        print(f"Error: file not found: {file_path}")
        return 1

    # Load keys.
    if args.keys:
        keys = _load_custom_keys(Path(args.keys))
        print(f"Loaded {len(keys)} custom keys from {args.keys}")
    else:
        keys = get_all_keys()
        print(f"Using {len(keys)} built-in known keys")

    tester = BabukKeyTester(keys=keys)
    print(f"\nTesting: {file_path}")
    print(f"File size: {format_bytes(file_path.stat().st_size)}")
    print("-" * 72)

    results = tester.test_file(file_path)

    # Display results.
    matches = 0
    for result in results:
        if args.verbose or result.success:
            _print_result(result, verbose=args.verbose)
        if result.success:
            matches += 1

    # Summary.
    print()
    print_summary("Key Test Results", {
        "File": str(file_path),
        "Keys tested": len(results),
        "Matches found": matches,
        "Best confidence": f"{results[0].confidence:.1%}" if results else "N/A",
        "Timestamp": timestamp(),
    })

    # Write JSON output if requested.
    if args.output:
        report_data = {
            "tool": "babuk_key_tester",
            "timestamp": timestamp(),
            "file": str(file_path),
            "keys_tested": len(results),
            "matches": matches,
            "results": [_result_to_dict(r) for r in results],
        }
        write_json_report(Path(args.output), report_data)
        print(f"\nJSON report written to: {args.output}")

    if matches > 0:
        print(
            f"\n*** {matches} POTENTIAL KEY MATCH(ES) FOUND! ***"
        )
        print("Review the results above carefully. A match means the file")
        print("may be decryptable with the corresponding key.")

    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    """Handle the 'batch' subcommand: test all .emario files in a directory."""
    directory = Path(args.directory)

    if not directory.exists():
        print(f"Error: directory not found: {directory}")
        return 1
    if not directory.is_dir():
        print(f"Error: not a directory: {directory}")
        return 1

    # Load keys.
    if args.keys:
        keys = _load_custom_keys(Path(args.keys))
        print(f"Loaded {len(keys)} custom keys from {args.keys}")
    else:
        keys = get_all_keys()
        print(f"Using {len(keys)} built-in known keys")

    tester = BabukKeyTester(keys=keys)

    print(f"\nScanning directory: {directory}")
    print("-" * 72)

    all_results = tester.test_directory(directory)

    total_files = len(all_results)
    total_tests = sum(len(r) for r in all_results.values())
    total_matches = 0
    matched_files: list[str] = []

    for file_str, results in all_results.items():
        file_matches = sum(1 for r in results if r.success)
        if file_matches > 0:
            total_matches += file_matches
            matched_files.append(file_str)

            print(f"\n  FILE: {file_str}")
            for r in results:
                if r.success:
                    _print_result(r, verbose=True, indent=4)

            if args.stop_on_match:
                print("\n  --stop-on-match: halting after first match.")
                break
        else:
            print(f"  {file_str}: no matches ({len(results)} keys tested)")

    # Summary.
    print()
    print_summary("Batch Key Test Results", {
        "Directory": str(directory),
        "Files tested": total_files,
        "Total key tests": total_tests,
        "Files with matches": len(matched_files),
        "Total matches": total_matches,
        "Timestamp": timestamp(),
    })

    # Write per-file JSON reports if output-dir specified.
    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        summary_data = {
            "tool": "babuk_key_tester",
            "mode": "batch",
            "timestamp": timestamp(),
            "directory": str(directory),
            "files_tested": total_files,
            "total_key_tests": total_tests,
            "matches": total_matches,
            "matched_files": matched_files,
            "file_results": {
                fp: [_result_to_dict(r) for r in results]
                for fp, results in all_results.items()
            },
        }
        report_path = out_dir / "babuk_key_test_results.json"
        write_json_report(report_path, summary_data)
        print(f"\nBatch report written to: {report_path}")

    if total_matches > 0:
        print(
            f"\n*** {total_matches} POTENTIAL KEY MATCH(ES) ACROSS "
            f"{len(matched_files)} FILE(S)! ***"
        )
        print("This is a significant finding. Review matches and attempt")
        print("full-file decryption with the matching keys.")

    return 0


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _print_result(
    result: TestResult, verbose: bool = False, indent: int = 2
) -> None:
    """Print a single test result to the terminal."""
    prefix = " " * indent
    status = "MATCH" if result.success else "no match"

    if result.success:
        print_finding(
            f"Key Match: {result.key_name}",
            {
                "File": str(result.file_path),
                "Confidence": f"{result.confidence:.1%}",
                "Signature": result.signature_match or "none",
                "Entropy": (
                    f"{result.decrypted_entropy:.4f}"
                    if result.decrypted_entropy is not None
                    else "N/A"
                ),
                "Key (hex)": result.key_hex[:16] + "...",
            },
            severity="critical" if result.confidence >= 0.7 else "warning",
        )
    elif verbose:
        details = {
            "Status": status,
            "Confidence": f"{result.confidence:.1%}",
        }
        if result.decrypted_entropy is not None:
            details["Entropy"] = f"{result.decrypted_entropy:.4f}"
        if result.error:
            details["Error"] = result.error

        print(f"{prefix}{result.key_name}: {status} ({result.confidence:.1%})")
        if result.error:
            print(f"{prefix}  error: {result.error}")


def _result_to_dict(result: TestResult) -> dict:
    """Convert a TestResult to a JSON-serialisable dict."""
    d = {
        "file_path": str(result.file_path),
        "key_name": result.key_name,
        "key_hex": result.key_hex,
        "success": result.success,
        "confidence": result.confidence,
        "signature_match": result.signature_match,
        "decrypted_entropy": result.decrypted_entropy,
        "error": result.error,
    }
    if result.decrypted_preview is not None:
        # Store the first 64 bytes as hex for the report (not the full 512).
        d["decrypted_preview_hex"] = result.decrypted_preview[:64].hex()
    return d


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="babuk_key_tester",
        description=(
            "Test known Babuk/Mario ECDH private keys against encrypted "
            "files.  Low probability but zero cost -- if a key matches, "
            "the file can be fully decrypted."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- test subcommand ----------------------------------------------------
    test_parser = subparsers.add_parser(
        "test",
        help="Test keys against a single encrypted file.",
    )
    test_parser.add_argument(
        "file_path",
        help="Path to the .emario / .omario encrypted file.",
    )
    test_parser.add_argument(
        "--keys",
        metavar="JSON_FILE",
        help="Path to a custom keys JSON file.",
    )
    test_parser.add_argument(
        "--output",
        metavar="JSON_FILE",
        help="Write results as a JSON report to this path.",
    )
    test_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show details for every key test (not just matches).",
    )

    # -- batch subcommand ---------------------------------------------------
    batch_parser = subparsers.add_parser(
        "batch",
        help="Test keys against all .emario files in a directory.",
    )
    batch_parser.add_argument(
        "directory",
        help="Directory to scan recursively for .emario / .omario files.",
    )
    batch_parser.add_argument(
        "--keys",
        metavar="JSON_FILE",
        help="Path to a custom keys JSON file.",
    )
    batch_parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Output directory for JSON result files.",
    )
    batch_parser.add_argument(
        "--stop-on-match",
        action="store_true",
        help="Stop testing remaining keys/files after the first match.",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the Babuk Key Tester."""
    print_banner("Babuk Key Tester")

    parser = build_parser()
    args = parser.parse_args()

    # Configure logging.
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    if args.command == "test":
        rc = _cmd_test(args)
    elif args.command == "batch":
        rc = _cmd_batch(args)
    else:
        parser.print_help()
        rc = 1

    sys.exit(rc)


if __name__ == "__main__":
    main()

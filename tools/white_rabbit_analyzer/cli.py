"""White Rabbit Analyzer -- CLI entry point.

Provides a command-line interface for parsing White Rabbit ransomware
artifacts, extracting IOCs, and optionally analysing PE binary samples.

Commands
--------
- **parse** -- Parse ransom notes in a directory and generate reports.
- **binary** -- Analyse a PE binary sample (requires ``pefile``).
- **iocs** -- Extract and consolidate IOCs into a single output file.

Usage::

    python -m tools.white_rabbit_analyzer.cli parse /evidence/notes/
    python -m tools.white_rabbit_analyzer.cli binary /evidence/sample.exe
    python -m tools.white_rabbit_analyzer.cli iocs /evidence/notes/ --format json

Designed for Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from tools.common.report import (
    format_bytes,
    print_banner,
    print_finding,
    print_summary,
)

from .binary_analyzer import BinaryAnalyzer
from .ioc_generator import IOCGenerator
from .note_parser import NoteParser

logger = logging.getLogger(__name__)

_VERSION = "1.0.0"
_ALL_FORMATS = ("markdown", "csv", "json", "yara")


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def _cmd_parse(args: argparse.Namespace) -> int:
    """Handle the ``parse`` sub-command.

    Parse ransom notes in a directory, print findings, and export
    reports in the requested formats.
    """
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1

    output_dir = Path(args.output_dir) if args.output_dir else directory / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    parser = NoteParser()
    notes = parser.parse_directory(directory)

    if not notes:
        print("No ransom notes found.")
        return 0

    # Print per-note findings.
    for note in notes:
        severity = "critical" if note.btc_addresses or note.onion_urls else "info"
        details: dict[str, object] = {
            "File": str(note.file_path),
        }
        if note.victim_id:
            details["Victim ID"] = note.victim_id
        if note.emails:
            details["Emails"] = ", ".join(note.emails)
        if note.onion_urls:
            details["Onion URLs"] = ", ".join(note.onion_urls)
        if note.btc_addresses:
            details["BTC Addresses"] = ", ".join(note.btc_addresses)
        if note.tox_ids:
            details["TOX IDs"] = ", ".join(note.tox_ids)
        if note.deadlines:
            details["Deadlines"] = ", ".join(note.deadlines)
        if note.claimed_file_count is not None:
            details["Claimed Files"] = note.claimed_file_count
        if note.claimed_data_size:
            details["Claimed Data Size"] = note.claimed_data_size

        print_finding(f"Ransom Note: {note.file_path.name}", details, severity)

    # Generate consolidated IOC report.
    generator = IOCGenerator()
    report = generator.generate_report(notes)

    print_summary("IOC Extraction Summary", {
        "Notes Parsed": report.total_notes_parsed,
        "Unique Emails": report.summary.get("emails", 0),
        "Onion URLs": report.summary.get("onion_urls", 0),
        "BTC Addresses": report.summary.get("btc_addresses", 0),
        "TOX IDs": report.summary.get("tox_ids", 0),
        "Victim IDs": report.summary.get("victim_ids", 0),
        "Other URLs": report.summary.get("urls", 0),
    })

    # Export reports in requested formats.
    formats = set(args.format) if args.format else set(_ALL_FORMATS)

    if "markdown" in formats:
        md_path = output_dir / "ioc_report.md"
        generator.export_markdown(report, md_path)
        print(f"  Markdown report: {md_path}")

    if "csv" in formats:
        csv_path = output_dir / "ioc_report.csv"
        generator.export_csv(report, csv_path)
        print(f"  CSV report:      {csv_path}")

    if "json" in formats:
        json_path = output_dir / "ioc_report.json"
        generator.export_json(report, json_path)
        print(f"  JSON report:     {json_path}")

    if "yara" in formats:
        yara_path = output_dir / "white_rabbit_iocs.yar"
        generator.export_yara(report, yara_path)
        print(f"  YARA rule:       {yara_path}")

    return 0


def _cmd_binary(args: argparse.Namespace) -> int:
    """Handle the ``binary`` sub-command.

    Analyse a PE binary and print the results.
    """
    file_path = Path(args.file_path)
    if not file_path.is_file():
        print(f"Error: {file_path} is not a file")
        return 1

    analyzer = BinaryAnalyzer()
    analysis = analyzer.analyze(file_path)

    if analysis is None:
        print(
            "Binary analysis unavailable. Ensure 'pefile' is installed: "
            "pip install pefile"
        )
        return 1

    # Print findings.
    print_finding("PE Binary Analysis", {
        "File": str(analysis.file_path),
        "Size": format_bytes(analysis.file_size),
        "SHA-256": analysis.sha256,
        "MD5": analysis.md5,
    }, "info")

    if analysis.imphash:
        print_finding("Import Hash", {"imphash": analysis.imphash}, "info")

    if analysis.compile_timestamp:
        print_finding(
            "Compilation Timestamp",
            {"Timestamp": analysis.compile_timestamp},
            "info",
        )

    if analysis.pdb_path:
        print_finding("PDB Path", {"Path": analysis.pdb_path}, "warning")

    if analysis.is_packed:
        print_finding(
            "Packing Detected",
            {"Detail": "High entropy section(s) found -- binary may be packed or encrypted"},
            "warning",
        )

    if analysis.requires_password:
        print_finding(
            "Password Requirement Detected",
            {"Detail": "Command-line password indicators found (White Rabbit behaviour)"},
            "critical",
        )

    if analysis.embedded_rsa_pubkey:
        # Truncate for display.
        key_preview = analysis.embedded_rsa_pubkey[:80] + "..."
        print_finding(
            "Embedded RSA Public Key",
            {"Preview": key_preview},
            "critical",
        )

    # Section summary.
    if analysis.sections:
        section_info: dict[str, object] = {}
        for sec in analysis.sections:
            section_info[sec["name"]] = (
                f"vsize={sec['virtual_size']}  raw={sec['raw_size']}  "
                f"entropy={sec['entropy']}"
            )
        print_finding("PE Sections", section_info, "info")

    # Imported DLLs.
    if analysis.imports:
        print_finding(
            "Imported DLLs",
            {"DLLs": ", ".join(analysis.imports)},
            "info",
        )

    # Interesting strings.
    if analysis.embedded_strings:
        limit = 20
        shown = analysis.embedded_strings[:limit]
        details_str: dict[str, object] = {
            f"String {i+1}": s for i, s in enumerate(shown)
        }
        if len(analysis.embedded_strings) > limit:
            details_str["..."] = (
                f"({len(analysis.embedded_strings) - limit} more strings)"
            )
        print_finding("Interesting Strings", details_str, "warning")

    print_summary("Binary Analysis Summary", {
        "SHA-256": analysis.sha256,
        "Sections": len(analysis.sections),
        "Imports": len(analysis.imports),
        "Interesting Strings": len(analysis.embedded_strings),
        "Packed": analysis.is_packed,
        "Password Required": analysis.requires_password,
        "RSA Key Found": analysis.embedded_rsa_pubkey is not None,
    })

    # Optional JSON output.
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "file_path": str(analysis.file_path),
            "file_size": analysis.file_size,
            "sha256": analysis.sha256,
            "md5": analysis.md5,
            "imphash": analysis.imphash,
            "compile_timestamp": analysis.compile_timestamp,
            "sections": analysis.sections,
            "imports": analysis.imports,
            "embedded_strings": analysis.embedded_strings,
            "embedded_rsa_pubkey": analysis.embedded_rsa_pubkey,
            "is_packed": analysis.is_packed,
            "pdb_path": analysis.pdb_path,
            "requires_password": analysis.requires_password,
        }
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"  JSON output: {output_path}")

    return 0


def _cmd_iocs(args: argparse.Namespace) -> int:
    """Handle the ``iocs`` sub-command.

    Extract and consolidate IOCs from ransom notes into a single output.
    """
    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: {directory} is not a directory")
        return 1

    parser = NoteParser()
    notes = parser.parse_directory(directory)

    if not notes:
        print("No ransom notes found.")
        return 0

    generator = IOCGenerator()
    report = generator.generate_report(notes)

    # Print consolidated IOC list.
    ioc_details: dict[str, object] = {}
    if report.all_emails:
        ioc_details["Emails"] = ", ".join(report.all_emails)
    if report.all_onion_urls:
        ioc_details["Onion URLs"] = ", ".join(report.all_onion_urls)
    if report.all_btc_addresses:
        ioc_details["BTC Addresses"] = ", ".join(report.all_btc_addresses)
    if report.all_tox_ids:
        ioc_details["TOX IDs"] = ", ".join(report.all_tox_ids)
    if report.all_victim_ids:
        ioc_details["Victim IDs"] = ", ".join(report.all_victim_ids)
    if report.all_urls:
        ioc_details["Other URLs"] = ", ".join(report.all_urls)

    print_finding("Consolidated IOCs", ioc_details, "critical")

    print_summary("IOC Summary", {
        "Notes Parsed": report.total_notes_parsed,
        "Total Unique IOCs": sum(report.summary.values()),
        **{k.replace("_", " ").title(): v for k, v in report.summary.items()},
    })

    # Export if an output path is specified.
    if args.output:
        output_path = Path(args.output)
        fmt = args.format or "json"

        if fmt == "json":
            generator.export_json(report, output_path)
        elif fmt == "csv":
            generator.export_csv(report, output_path)
        elif fmt == "markdown":
            generator.export_markdown(report, output_path)
        elif fmt == "yara":
            generator.export_yara(report, output_path)
        else:
            print(f"Unknown format: {fmt}")
            return 1

        print(f"  Output written to: {output_path}")

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with sub-commands."""
    parser = argparse.ArgumentParser(
        prog="white_rabbit_analyzer",
        description=(
            "White Rabbit Artifact Analyzer -- parse ransomware artifacts "
            "for IOC extraction and threat intelligence."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging output.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- parse --
    parse_cmd = subparsers.add_parser(
        "parse",
        help="Parse ransom notes in a directory and generate reports.",
    )
    parse_cmd.add_argument(
        "directory",
        help="Directory containing ransom note files.",
    )
    parse_cmd.add_argument(
        "--output-dir",
        help="Output directory for generated reports (default: <directory>/reports).",
    )
    parse_cmd.add_argument(
        "--format",
        nargs="+",
        choices=_ALL_FORMATS,
        default=None,
        help=(
            "Report formats to generate. Can specify multiple. "
            "Default: all formats."
        ),
    )

    # -- binary --
    binary_cmd = subparsers.add_parser(
        "binary",
        help="Analyse a PE binary sample (requires pefile).",
    )
    binary_cmd.add_argument(
        "file_path",
        help="Path to the PE binary to analyse.",
    )
    binary_cmd.add_argument(
        "--output",
        help="Optional JSON output path for analysis results.",
    )

    # -- iocs --
    iocs_cmd = subparsers.add_parser(
        "iocs",
        help="Extract and consolidate IOCs from ransom notes.",
    )
    iocs_cmd.add_argument(
        "directory",
        help="Directory containing ransom note files.",
    )
    iocs_cmd.add_argument(
        "--output",
        help="Output file path for consolidated IOCs.",
    )
    iocs_cmd.add_argument(
        "--format",
        choices=("json", "csv", "markdown", "yara"),
        default="json",
        help="Output format (default: json).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for the White Rabbit Analyzer."""
    print_banner("White Rabbit Analyzer", _VERSION)

    parser = _build_parser()
    args = parser.parse_args()

    # Configure logging.
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Dispatch to sub-command handler.
    handlers = {
        "parse": _cmd_parse,
        "binary": _cmd_binary,
        "iocs": _cmd_iocs,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    exit_code = handler(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

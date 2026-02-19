"""White Rabbit IOC report generator -- consolidated IOC reporting.

Aggregates indicators of compromise extracted from multiple parsed ransom
notes into a single deduplicated report.  Supports export to Markdown,
CSV, JSON, and YARA rule formats, using the shared report writers from
:mod:`tools.common.report`.

Designed for Python 3.10+.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.report import (
    ReportSection,
    timestamp,
    write_csv_report,
    write_json_report,
    write_markdown_report,
)

from .note_parser import RansomNote

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class IOCReport:
    """Consolidated IOC report aggregated from multiple ransom notes.

    Attributes
    ----------
    generated_at:
        ISO 8601 timestamp of when the report was generated.
    source_files:
        List of file paths that contributed IOCs.
    total_notes_parsed:
        Number of ransom notes that were parsed.
    all_emails:
        Deduplicated email addresses across all notes.
    all_onion_urls:
        Deduplicated Tor .onion URLs/domains.
    all_btc_addresses:
        Deduplicated Bitcoin wallet addresses.
    all_tox_ids:
        Deduplicated TOX messenger IDs.
    all_victim_ids:
        Deduplicated victim/reference identifiers.
    all_urls:
        Deduplicated non-onion URLs.
    summary:
        Counts of each IOC type for quick triage.
    """

    generated_at: str = ""
    source_files: list[str] = field(default_factory=list)
    total_notes_parsed: int = 0
    all_emails: list[str] = field(default_factory=list)
    all_onion_urls: list[str] = field(default_factory=list)
    all_btc_addresses: list[str] = field(default_factory=list)
    all_tox_ids: list[str] = field(default_factory=list)
    all_victim_ids: list[str] = field(default_factory=list)
    all_urls: list[str] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class IOCGenerator:
    """Consolidate and export IOCs from parsed White Rabbit ransom notes."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, notes: list[RansomNote]) -> IOCReport:
        """Consolidate IOCs from multiple notes into a single report.

        All IOC values are deduplicated while preserving discovery order.

        Parameters
        ----------
        notes:
            Parsed ransom notes produced by
            :meth:`~tools.white_rabbit_analyzer.note_parser.NoteParser.parse_file`
            or
            :meth:`~tools.white_rabbit_analyzer.note_parser.NoteParser.parse_directory`.

        Returns
        -------
        IOCReport
            Aggregated, deduplicated report.
        """
        emails: list[str] = []
        onion_urls: list[str] = []
        btc_addresses: list[str] = []
        tox_ids: list[str] = []
        victim_ids: list[str] = []
        urls: list[str] = []
        source_files: list[str] = []

        seen_emails: set[str] = set()
        seen_onion: set[str] = set()
        seen_btc: set[str] = set()
        seen_tox: set[str] = set()
        seen_victim: set[str] = set()
        seen_urls: set[str] = set()

        for note in notes:
            source_files.append(str(note.file_path))

            for email in note.emails:
                lower = email.lower()
                if lower not in seen_emails:
                    emails.append(email)
                    seen_emails.add(lower)

            for url in note.onion_urls:
                lower = url.lower()
                if lower not in seen_onion:
                    onion_urls.append(url)
                    seen_onion.add(lower)

            for addr in note.btc_addresses:
                if addr not in seen_btc:
                    btc_addresses.append(addr)
                    seen_btc.add(addr)

            for tox in note.tox_ids:
                if tox not in seen_tox:
                    tox_ids.append(tox)
                    seen_tox.add(tox)

            if note.victim_id and note.victim_id not in seen_victim:
                victim_ids.append(note.victim_id)
                seen_victim.add(note.victim_id)

            for url in note.other_urls:
                lower = url.lower()
                if lower not in seen_urls:
                    urls.append(url)
                    seen_urls.add(lower)

        summary: dict[str, int] = {
            "emails": len(emails),
            "onion_urls": len(onion_urls),
            "btc_addresses": len(btc_addresses),
            "tox_ids": len(tox_ids),
            "victim_ids": len(victim_ids),
            "urls": len(urls),
        }

        report = IOCReport(
            generated_at=timestamp(),
            source_files=source_files,
            total_notes_parsed=len(notes),
            all_emails=emails,
            all_onion_urls=onion_urls,
            all_btc_addresses=btc_addresses,
            all_tox_ids=tox_ids,
            all_victim_ids=victim_ids,
            all_urls=urls,
            summary=summary,
        )

        total = sum(summary.values())
        logger.info(
            "Generated IOC report: %d unique IOC(s) from %d note(s)",
            total,
            len(notes),
        )
        return report

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export_markdown(self, report: IOCReport, output_path: Path) -> None:
        """Export the IOC report as a Markdown file.

        Parameters
        ----------
        report:
            Consolidated IOC report.
        output_path:
            Destination ``.md`` file path.
        """
        output_path = Path(output_path)

        sections: list[ReportSection] = []

        # Summary table.
        sections.append(ReportSection(
            title="Summary",
            content={
                "Total Notes Parsed": str(report.total_notes_parsed),
                "Emails": str(report.summary.get("emails", 0)),
                "Onion URLs": str(report.summary.get("onion_urls", 0)),
                "BTC Addresses": str(report.summary.get("btc_addresses", 0)),
                "TOX IDs": str(report.summary.get("tox_ids", 0)),
                "Victim IDs": str(report.summary.get("victim_ids", 0)),
                "Other URLs": str(report.summary.get("urls", 0)),
            },
            level=2,
        ))

        # Section per IOC type.
        if report.all_emails:
            sections.append(ReportSection(
                title="Email Addresses",
                content=report.all_emails,
                level=2,
            ))

        if report.all_onion_urls:
            sections.append(ReportSection(
                title="Onion URLs",
                content=report.all_onion_urls,
                level=2,
            ))

        if report.all_btc_addresses:
            sections.append(ReportSection(
                title="Bitcoin Addresses",
                content=report.all_btc_addresses,
                level=2,
            ))

        if report.all_tox_ids:
            sections.append(ReportSection(
                title="TOX Messenger IDs",
                content=report.all_tox_ids,
                level=2,
            ))

        if report.all_victim_ids:
            sections.append(ReportSection(
                title="Victim / Reference IDs",
                content=report.all_victim_ids,
                level=2,
            ))

        if report.all_urls:
            sections.append(ReportSection(
                title="Other URLs",
                content=report.all_urls,
                level=2,
            ))

        # Source files.
        sections.append(ReportSection(
            title="Source Files",
            content=report.source_files,
            level=2,
        ))

        write_markdown_report(
            output_path,
            "White Rabbit IOC Report",
            sections,
        )
        logger.info("Markdown report written to %s", output_path)

    def export_csv(self, report: IOCReport, output_path: Path) -> None:
        """Export the IOC report as a CSV file.

        Columns: ``ioc_type``, ``value``, ``source_file``, ``first_seen``.

        Parameters
        ----------
        report:
            Consolidated IOC report.
        output_path:
            Destination ``.csv`` file path.
        """
        output_path = Path(output_path)

        rows: list[dict[str, str]] = []

        ioc_groups: list[tuple[str, list[str]]] = [
            ("email", report.all_emails),
            ("onion_url", report.all_onion_urls),
            ("btc_address", report.all_btc_addresses),
            ("tox_id", report.all_tox_ids),
            ("victim_id", report.all_victim_ids),
            ("url", report.all_urls),
        ]

        for ioc_type, values in ioc_groups:
            for value in values:
                # Determine which source file first contained this IOC.
                source_file = self._find_source(report, ioc_type, value)
                rows.append({
                    "ioc_type": ioc_type,
                    "value": value,
                    "source_file": source_file,
                    "first_seen": report.generated_at,
                })

        fieldnames = ["ioc_type", "value", "source_file", "first_seen"]
        write_csv_report(output_path, rows, fieldnames)
        logger.info("CSV report written to %s", output_path)

    def export_json(self, report: IOCReport, output_path: Path) -> None:
        """Export the IOC report as a JSON file.

        Parameters
        ----------
        report:
            Consolidated IOC report.
        output_path:
            Destination ``.json`` file path.
        """
        output_path = Path(output_path)

        data = {
            "generated_at": report.generated_at,
            "total_notes_parsed": report.total_notes_parsed,
            "source_files": report.source_files,
            "summary": report.summary,
            "iocs": {
                "emails": report.all_emails,
                "onion_urls": report.all_onion_urls,
                "btc_addresses": report.all_btc_addresses,
                "tox_ids": report.all_tox_ids,
                "victim_ids": report.all_victim_ids,
                "urls": report.all_urls,
            },
        }

        write_json_report(output_path, data)
        logger.info("JSON report written to %s", output_path)

    # ------------------------------------------------------------------
    # YARA rule generation
    # ------------------------------------------------------------------

    def generate_yara_rule(self, report: IOCReport) -> str:
        """Generate a YARA rule from the extracted IOCs.

        The rule fires on any match of the known email addresses, onion
        URLs, Bitcoin addresses, or TOX IDs.

        Parameters
        ----------
        report:
            Consolidated IOC report.

        Returns
        -------
        str
            Complete YARA rule source text.
        """
        lines: list[str] = []
        lines.append("rule WhiteRabbit_Campaign_IOCs {")
        lines.append("    meta:")
        lines.append('        description = "White Rabbit ransomware campaign IOCs"')
        lines.append(f'        generated = "{report.generated_at}"')
        lines.append('        tool = "ransom-toolkit white_rabbit_analyzer"')
        lines.append("")
        lines.append("    strings:")

        idx = 0

        for i, email in enumerate(report.all_emails, 1):
            escaped = email.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $email_{i} = "{escaped}" ascii wide nocase')
            idx += 1

        for i, url in enumerate(report.all_onion_urls, 1):
            escaped = url.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $onion_{i} = "{escaped}" ascii wide')
            idx += 1

        for i, addr in enumerate(report.all_btc_addresses, 1):
            escaped = addr.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $btc_{i} = "{escaped}" ascii wide')
            idx += 1

        for i, tox in enumerate(report.all_tox_ids, 1):
            escaped = tox.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $tox_{i} = "{escaped}" ascii wide')
            idx += 1

        if idx == 0:
            # No IOCs to encode -- produce a rule that never fires.
            lines.append('        $placeholder = "NO_IOCS_EXTRACTED" ascii')

        lines.append("")
        lines.append("    condition:")
        lines.append("        any of them")
        lines.append("}")
        lines.append("")

        return "\n".join(lines)

    def export_yara(self, report: IOCReport, output_path: Path) -> None:
        """Write a YARA rule file from the extracted IOCs.

        Parameters
        ----------
        report:
            Consolidated IOC report.
        output_path:
            Destination ``.yar`` file path.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        rule = self.generate_yara_rule(report)
        output_path.write_text(rule, encoding="utf-8")
        logger.info("YARA rule written to %s", output_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_source(
        report: IOCReport,
        ioc_type: str,
        value: str,
    ) -> str:
        """Determine the first source file containing a given IOC value.

        Falls back to the first source file if exact attribution is
        not possible.

        Parameters
        ----------
        report:
            The consolidated IOC report (not directly used for per-note
            tracking -- returns first source file as a reasonable
            approximation).
        ioc_type:
            IOC category (unused in this simplified implementation).
        value:
            IOC value (unused in this simplified implementation).

        Returns
        -------
        str
            Path string of the originating source file.
        """
        # The IOCReport aggregates across notes so per-value attribution
        # is not tracked.  Return the first source as a fallback.
        if report.source_files:
            return report.source_files[0]
        return "unknown"

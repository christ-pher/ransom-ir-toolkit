"""Unified reporting utilities for ransomware incident response.

This module provides shared terminal output and file-report generation
used across all tools in the incident response toolkit.  Terminal output
relies on the ``rich`` library for colour, tables, and progress bars, but
degrades gracefully to plain :func:`print` when ``rich`` is not installed
so that core analysis can still run in minimal environments.

File reports can be emitted as Markdown, JSON, or CSV.

Designed for Python 3.10+ with ``rich`` as the only external dependency
(optional).
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional rich import -- fall back to plain text helpers when unavailable
# ---------------------------------------------------------------------------

_RICH_AVAILABLE: bool = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.text import Text

    _RICH_AVAILABLE = True
except ImportError:
    pass


# A module-level console instance used by all printing helpers.  When rich
# is unavailable this stays ``None`` and the plain-text fallbacks are used.
_console: Console | None = Console() if _RICH_AVAILABLE else None

# Severity-to-colour mapping for :func:`print_finding`.
_SEVERITY_STYLES: dict[str, str] = {
    "info": "bold cyan",
    "warning": "bold yellow",
    "critical": "bold red",
}


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ReportSection:
    """A single section destined for a file report.

    Attributes
    ----------
    title:
        Section heading text.
    content:
        Body of the section.  Accepts a plain string, a list of strings
        (rendered as bullet points), or a dict (rendered as a key/value
        table).
    level:
        Markdown heading level (1 = ``#``, 2 = ``##``, etc.).
    """

    title: str
    content: str | list[str] | dict[str, Any]
    level: int = 1


# ---------------------------------------------------------------------------
# Terminal output -- rich helpers (with plain-text fallbacks)
# ---------------------------------------------------------------------------

def print_banner(tool_name: str, version: str = "1.0.0") -> None:
    """Print a styled banner identifying the tool and its version.

    Parameters
    ----------
    tool_name:
        Display name of the tool (e.g. ``"Entropy Scanner"``).
    version:
        Version string shown alongside the tool name.
    """
    if _RICH_AVAILABLE and _console is not None:
        title_text = Text(tool_name, style="bold white")
        subtitle = Text(f"v{version}", style="dim")
        panel = Panel(
            title_text,
            subtitle=subtitle,
            border_style="bright_blue",
            expand=False,
            padding=(1, 4),
        )
        _console.print(panel)
    else:
        border = "=" * (len(tool_name) + len(version) + 5)
        print(border)
        print(f" {tool_name}  v{version}")
        print(border)


def print_finding(
    title: str,
    details: dict[str, Any],
    severity: str = "info",
) -> None:
    """Print a formatted finding to the terminal.

    Parameters
    ----------
    title:
        Short description of the finding.
    details:
        Key/value pairs providing additional context.
    severity:
        One of ``"info"``, ``"warning"``, or ``"critical"``.  Controls the
        colour and prefix label of the output.
    """
    severity = severity.lower()
    label = severity.upper()

    if _RICH_AVAILABLE and _console is not None:
        style = _SEVERITY_STYLES.get(severity, "bold cyan")
        header = Text(f"[{label}] {title}", style=style)
        _console.print(header)
        for key, value in details.items():
            _console.print(f"  {key}: {value}")
        _console.print()
    else:
        print(f"[{label}] {title}")
        for key, value in details.items():
            print(f"  {key}: {value}")
        print()


def print_progress_table(items: list[dict], columns: list[str]) -> None:
    """Print a table of items to the terminal.

    Parameters
    ----------
    items:
        Rows of data.  Each dict should contain keys matching *columns*.
    columns:
        Column header names, in display order.
    """
    if _RICH_AVAILABLE and _console is not None:
        table = Table(show_header=True, header_style="bold magenta")
        for col in columns:
            table.add_column(col)
        for item in items:
            table.add_row(*(str(item.get(col, "")) for col in columns))
        _console.print(table)
    else:
        # Plain-text table using fixed-width columns.
        header = " | ".join(f"{col:>16}" for col in columns)
        print(header)
        print("-" * len(header))
        for item in items:
            row = " | ".join(f"{str(item.get(col, '')):>16}" for col in columns)
            print(row)


class _PlainProgress:
    """Minimal plain-text progress fallback when ``rich`` is not installed.

    Implements the subset of the :class:`rich.progress.Progress` API used
    by toolkit scanners: context-manager protocol, ``add_task``, and
    ``update``.  Progress is printed to *stderr* so it doesn't pollute
    piped output.
    """

    def __init__(self, description: str = "Scanning") -> None:
        self._description = description
        self._tasks: dict[int, dict[str, Any]] = {}
        self._next_id = 0

    # -- context manager -----------------------------------------------------
    def __enter__(self) -> "_PlainProgress":
        return self

    def __exit__(self, *_: Any) -> None:
        # Print a final newline so the next output isn't on the same line.
        import sys
        print(file=sys.stderr)

    # -- task API ------------------------------------------------------------
    def add_task(self, description: str, total: float = 0) -> int:
        tid = self._next_id
        self._next_id += 1
        self._tasks[tid] = {
            "description": description,
            "total": total,
            "completed": 0.0,
            "last_pct": -1,
        }
        import sys
        print(f"{description}: 0%", end="", flush=True, file=sys.stderr)
        return tid

    def update(self, task_id: int, advance: float = 0) -> None:
        t = self._tasks[task_id]
        t["completed"] += advance
        if t["total"] > 0:
            pct = int(t["completed"] / t["total"] * 100)
            # Only reprint every 5% to avoid flooding the terminal.
            if pct // 5 != t["last_pct"] // 5:
                t["last_pct"] = pct
                import sys
                print(f"\r{t['description']}: {pct}%", end="", flush=True, file=sys.stderr)


def create_progress(description: str = "Scanning") -> Progress | _PlainProgress:
    """Create a configured :class:`rich.progress.Progress` bar.

    The returned progress bar is suitable for long-running file-scanning
    operations and shows a spinner, description, bar, count, elapsed time,
    and estimated time remaining.

    When ``rich`` is not installed a lightweight plain-text fallback is
    returned instead, so callers never need to handle the missing-dependency
    case themselves.

    Parameters
    ----------
    description:
        Label displayed next to the progress bar.
    """
    if not _RICH_AVAILABLE:
        return _PlainProgress(description)

    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=_console,
        transient=False,
    )


def print_summary(title: str, stats: dict[str, Any]) -> None:
    """Print a summary box with key statistics.

    Parameters
    ----------
    title:
        Heading for the summary panel.
    stats:
        Key/value pairs rendered inside the box.
    """
    if _RICH_AVAILABLE and _console is not None:
        lines: list[str] = []
        for key, value in stats.items():
            lines.append(f"[bold]{key}:[/bold] {value}")
        body = "\n".join(lines)
        panel = Panel(body, title=title, border_style="green", expand=False)
        _console.print(panel)
    else:
        width = max(len(f"{k}: {v}") for k, v in stats.items()) + 4
        border = "+" + "-" * (width + 2) + "+"
        print(border)
        print(f"| {title:^{width}} |")
        print(border)
        for key, value in stats.items():
            line = f"{key}: {value}"
            print(f"| {line:<{width}} |")
        print(border)


# ---------------------------------------------------------------------------
# File report writers
# ---------------------------------------------------------------------------

def write_markdown_report(
    path: Path,
    title: str,
    sections: list[ReportSection],
) -> None:
    """Generate a Markdown report file.

    Parameters
    ----------
    path:
        Destination file path (will be created or overwritten).
    title:
        Top-level document title (rendered as ``# title``).
    sections:
        Ordered list of :class:`ReportSection` objects comprising the
        report body.
    """
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"*Generated: {timestamp()}*")
    lines.append("")

    for section in sections:
        prefix = "#" * min(max(section.level, 1), 6)
        lines.append(f"{prefix} {section.title}")
        lines.append("")

        content = section.content

        if isinstance(content, str):
            lines.append(content)
            lines.append("")

        elif isinstance(content, list):
            for item in content:
                lines.append(f"- {item}")
            lines.append("")

        elif isinstance(content, dict):
            lines.append("| Key | Value |")
            lines.append("|-----|-------|")
            for key, value in content.items():
                lines.append(f"| {key} | {value} |")
            lines.append("")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not handled by the default encoder.

    Converts :class:`datetime.datetime` instances to ISO 8601 strings,
    :class:`pathlib.Path` to their string representation, and ``bytes``
    to hex strings.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def write_json_report(path: Path, data: dict) -> None:
    """Write a JSON report with pretty-printing and datetime serialisation.

    Parameters
    ----------
    path:
        Destination file path (will be created or overwritten).
    data:
        Arbitrary JSON-serialisable data to persist.  Any
        :class:`~datetime.datetime` values are automatically converted to
        ISO 8601 strings.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, default=_json_serial, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_csv_report(
    path: Path,
    rows: list[dict],
    fieldnames: list[str],
) -> None:
    """Write a CSV report.

    Parameters
    ----------
    path:
        Destination file path (will be created or overwritten).
    rows:
        List of dicts, each representing one row.  Keys should match
        *fieldnames*.
    fieldnames:
        Column names in the desired output order.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)

    path.write_text(buf.getvalue(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Formatting utilities
# ---------------------------------------------------------------------------

_BYTE_UNITS: list[tuple[int, str]] = [
    (1 << 40, "TiB"),
    (1 << 30, "GiB"),
    (1 << 20, "MiB"),
    (1 << 10, "KiB"),
]


def format_bytes(n: int) -> str:
    """Return a human-readable byte-size string using IEC binary units.

    Examples: ``"1.5 GiB"``, ``"256 MiB"``, ``"0 B"``.

    Parameters
    ----------
    n:
        Size in bytes (non-negative integer).

    Returns
    -------
    str
        Formatted string with at most one decimal place.
    """
    if n < 0:
        raise ValueError(f"Byte count must be non-negative, got {n}")

    for threshold, unit in _BYTE_UNITS:
        if n >= threshold:
            value = n / threshold
            # Drop the decimal when it would be ".0".
            if value == int(value):
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"

    return f"{n} B"


def format_duration(seconds: float) -> str:
    """Return a human-readable duration string.

    Examples: ``"2m 34s"``, ``"0s"``, ``"1h 5m 0s"``.

    Parameters
    ----------
    seconds:
        Duration in seconds (non-negative).

    Returns
    -------
    str
        Formatted duration.
    """
    if seconds < 0:
        raise ValueError(f"Duration must be non-negative, got {seconds}")

    total = int(seconds)
    h, remainder = divmod(total, 3600)
    m, s = divmod(remainder, 60)

    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def format_percent(value: float, total: float) -> str:
    """Return a percentage string with one decimal place.

    Parameters
    ----------
    value:
        The numerator.
    total:
        The denominator.  If zero, returns ``"0.0%"`` to avoid division
        by zero.

    Returns
    -------
    str
        Formatted percentage (e.g. ``"42.7%"``).
    """
    if total == 0:
        return "0.0%"
    return f"{(value / total) * 100:.1f}%"


def timestamp() -> str:
    """Return the current UTC time as an ISO 8601 string.

    Returns
    -------
    str
        Timestamp in the form ``"2025-01-15T08:30:00+00:00"``.
    """
    return datetime.now(timezone.utc).isoformat()


# Characters that are unsafe or awkward in filenames across platforms.
_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str) -> str:
    """Make *name* safe for use as a filename on common operating systems.

    Replaces characters that are forbidden on Windows, Linux, or macOS
    with underscores, collapses runs of underscores, and strips leading
    and trailing dots and whitespace.

    Parameters
    ----------
    name:
        Raw string to sanitize.

    Returns
    -------
    str
        A filesystem-safe version of the name.  Returns ``"unnamed"`` if
        the result would otherwise be empty.
    """
    cleaned = _UNSAFE_FILENAME_RE.sub("_", name)
    # Collapse consecutive underscores.
    cleaned = re.sub(r"_+", "_", cleaned)
    # Strip leading/trailing dots, underscores, and whitespace.
    cleaned = cleaned.strip(". _")

    return cleaned if cleaned else "unnamed"

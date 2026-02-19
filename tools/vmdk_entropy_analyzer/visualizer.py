"""Text and HTML visualization of VMDK entropy maps.

This module generates human-readable representations of entropy analysis
results to help incident responders quickly identify encrypted vs.
recoverable regions in Mario ransomware-encrypted VMDK files.

Output formats:

    Text map:   A character-based entropy heatmap suitable for terminal
                display or inclusion in plain-text reports.  Each character
                represents a file region coloured by classification.

    HTML report: A standalone HTML page with a colour-coded entropy heatmap,
                 region table, and recovery statistics.  Uses only inline
                 CSS with no external dependencies so the report can be
                 shared as a single file.

    JSON:        Machine-readable output via :func:`write_json_report`.
"""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Any

from tools.common.entropy import COMPRESSED, ENCRYPTED, PLAINTEXT, ZEROED
from tools.common.report import (
    format_bytes,
    format_duration,
    format_percent,
    timestamp,
    write_json_report,
)

from .analyzer import AnalysisResult, RegionInfo

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Character / colour mappings
# ---------------------------------------------------------------------------

_TEXT_CHARS: dict[str, str] = {
    ENCRYPTED: "\u2588",    # Full block
    COMPRESSED: "\u2593",   # Dark shade
    PLAINTEXT: "\u2591",    # Light shade
    ZEROED: "\u00b7",       # Middle dot
}

_HTML_COLOURS: dict[str, str] = {
    ENCRYPTED: "#e74c3c",   # Red
    COMPRESSED: "#e67e22",  # Orange
    PLAINTEXT: "#27ae60",   # Green
    ZEROED: "#95a5a6",      # Gray
}

_CLASSIFICATION_LABELS: dict[str, str] = {
    ENCRYPTED: "Encrypted",
    COMPRESSED: "Compressed",
    PLAINTEXT: "Plaintext",
    ZEROED: "Zeroed/Sparse",
}


# ---------------------------------------------------------------------------
# Text map
# ---------------------------------------------------------------------------


def render_text_map(result: AnalysisResult, width: int = 120) -> str:
    """Generate a text-based entropy map of the file.

    Each character in the map represents a proportional slice of the file.
    The classification of the file region at each character position
    determines the glyph used.

    Parameters
    ----------
    result:
        Analysis result from :class:`VMDKEntropyAnalyzer`.
    width:
        Number of characters per line in the map.

    Returns
    -------
    str
        Multi-line string containing the header, map, legend, and
        region table.
    """
    lines: list[str] = []

    # Header
    lines.append("=" * width)
    lines.append(f"VMDK Entropy Map: {result.file_path.name}")
    lines.append(f"File size: {format_bytes(result.file_size)}")
    lines.append(
        f"Encrypted: {format_bytes(result.total_encrypted)} "
        f"({result.encrypted_percentage:.1f}%) | "
        f"Recoverable: {format_bytes(result.total_plaintext)} "
        f"({result.recovery_percentage:.1f}%)"
    )
    lines.append(
        f"Scan time: {format_duration(result.scan_duration_seconds)} | "
        f"Regions: {len(result.regions)} | "
        f"Coarse blocks: {len(result.coarse_results)} | "
        f"Fine blocks: {len(result.fine_results)}"
    )
    lines.append("=" * width)
    lines.append("")

    # Build the character map
    if result.file_size > 0 and result.regions:
        bytes_per_char = result.file_size / width
        map_chars: list[str] = []

        for i in range(width):
            # Find which region contains the midpoint of this character
            midpoint = int((i + 0.5) * bytes_per_char)
            char_cls = ZEROED  # fallback
            for region in result.regions:
                if region.start_offset <= midpoint < region.end_offset:
                    char_cls = region.classification
                    break
            map_chars.append(_TEXT_CHARS.get(char_cls, "?"))

        lines.append("".join(map_chars))
    else:
        lines.append("(empty file)")

    lines.append("")

    # Legend
    legend_parts: list[str] = []
    for cls, char in _TEXT_CHARS.items():
        label = _CLASSIFICATION_LABELS.get(cls, cls)
        legend_parts.append(f"  {char} = {label}")
    lines.append("Legend:" + "".join(legend_parts))
    lines.append("")

    # Region table
    lines.append("-" * width)
    lines.append(
        f"{'#':>4}  {'Start Offset':>14}  {'End Offset':>14}  "
        f"{'Size':>12}  {'Classification':>14}  "
        f"{'Avg Entropy':>12}  {'Min':>6}  {'Max':>6}"
    )
    lines.append("-" * width)

    for idx, region in enumerate(result.regions, 1):
        lines.append(
            f"{idx:>4}  {region.start_offset:>14,}  {region.end_offset:>14,}  "
            f"{format_bytes(region.size):>12}  {region.classification:>14}  "
            f"{region.avg_entropy:>12.4f}  {region.min_entropy:>6.3f}  "
            f"{region.max_entropy:>6.3f}"
        )

    lines.append("-" * width)
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


def render_html_report(result: AnalysisResult) -> str:
    """Generate a standalone HTML page with an entropy heatmap and region table.

    The HTML uses only inline CSS and contains no external dependencies,
    making it easy to share as a single file or embed in an incident report.

    Parameters
    ----------
    result:
        Analysis result from :class:`VMDKEntropyAnalyzer`.

    Returns
    -------
    str
        Complete HTML document as a string.
    """
    file_name = html.escape(str(result.file_path.name))
    file_path = html.escape(str(result.file_path))
    generated = html.escape(timestamp())

    # Build the heatmap segments
    heatmap_segments: list[str] = []
    if result.file_size > 0 and result.regions:
        for region in result.regions:
            width_pct = (region.size / result.file_size) * 100.0
            if width_pct < 0.01:
                continue  # Skip negligibly small regions in the visual
            colour = _HTML_COLOURS.get(region.classification, "#ccc")
            label = _CLASSIFICATION_LABELS.get(
                region.classification, region.classification
            )
            tooltip = (
                f"{label}: {format_bytes(region.size)} "
                f"(offset {region.start_offset:,} - {region.end_offset:,}), "
                f"entropy {region.avg_entropy:.4f}"
            )
            heatmap_segments.append(
                f'<div class="heatmap-segment" style="width:{width_pct:.4f}%;'
                f'background-color:{colour};" '
                f'title="{html.escape(tooltip)}"></div>'
            )

    heatmap_html = "\n        ".join(heatmap_segments) if heatmap_segments else ""

    # Build the region table rows
    table_rows: list[str] = []
    for idx, region in enumerate(result.regions, 1):
        cls_colour = _HTML_COLOURS.get(region.classification, "#ccc")
        label = _CLASSIFICATION_LABELS.get(
            region.classification, region.classification
        )
        table_rows.append(
            f"""        <tr>
          <td>{idx}</td>
          <td>{region.start_offset:,}</td>
          <td>{region.end_offset:,}</td>
          <td>{format_bytes(region.size)}</td>
          <td><span class="badge" style="background-color:{cls_colour};">{html.escape(label)}</span></td>
          <td>{region.avg_entropy:.4f}</td>
          <td>{region.min_entropy:.4f}</td>
          <td>{region.max_entropy:.4f}</td>
        </tr>"""
        )

    region_table = "\n".join(table_rows)

    # Recovery bar colour
    recovery_pct = result.recovery_percentage
    if recovery_pct >= 50:
        recovery_colour = "#27ae60"  # green
    elif recovery_pct >= 20:
        recovery_colour = "#e67e22"  # orange
    else:
        recovery_colour = "#e74c3c"  # red

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VMDK Entropy Analysis - {file_name}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #1a1a2e; color: #eee; padding: 20px; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ color: #e8e8ff; margin-bottom: 5px; font-size: 1.6em; }}
  .subtitle {{ color: #888; margin-bottom: 20px; font-size: 0.9em; }}
  .card {{ background: #16213e; border-radius: 8px; padding: 20px;
           margin-bottom: 20px; border: 1px solid #0f3460; }}
  .card h2 {{ color: #a8d8ea; margin-bottom: 15px; font-size: 1.2em; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                 gap: 15px; margin-bottom: 20px; }}
  .stat-box {{ background: #0f3460; border-radius: 6px; padding: 15px; text-align: center; }}
  .stat-value {{ font-size: 2em; font-weight: bold; }}
  .stat-label {{ color: #888; font-size: 0.85em; margin-top: 5px; }}
  .recovery-bar-container {{ background: #333; border-radius: 10px; height: 30px;
                             overflow: hidden; margin: 10px 0; }}
  .recovery-bar {{ height: 100%; border-radius: 10px; transition: width 0.3s;
                   display: flex; align-items: center; justify-content: center;
                   font-weight: bold; font-size: 0.9em; min-width: 60px; }}
  .heatmap {{ display: flex; height: 50px; border-radius: 4px; overflow: hidden;
              border: 1px solid #555; margin-bottom: 10px; }}
  .heatmap-segment {{ height: 100%; min-width: 1px; }}
  .legend {{ display: flex; gap: 20px; flex-wrap: wrap; margin-top: 10px; }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.85em; }}
  .legend-colour {{ width: 16px; height: 16px; border-radius: 3px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #0f3460; padding: 10px 8px; text-align: left; cursor: pointer;
       user-select: none; position: sticky; top: 0; }}
  th:hover {{ background: #1a4880; }}
  td {{ padding: 8px; border-bottom: 1px solid #1a3a5c; }}
  tr:hover td {{ background: #1a3a5c; }}
  .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.8em;
            color: #fff; font-weight: 600; white-space: nowrap; }}
  .table-container {{ max-height: 500px; overflow-y: auto; }}
  .info-row {{ display: flex; gap: 30px; flex-wrap: wrap; margin-bottom: 8px;
               font-size: 0.9em; color: #aaa; }}
  .info-row span {{ color: #ddd; }}
</style>
</head>
<body>
<div class="container">
  <h1>VMDK Entropy Analysis</h1>
  <p class="subtitle">Generated {generated}</p>

  <div class="card">
    <h2>File Information</h2>
    <div class="info-row">
      <div>File: <span>{file_name}</span></div>
      <div>Path: <span>{file_path}</span></div>
    </div>
    <div class="info-row">
      <div>Size: <span>{format_bytes(result.file_size)}</span></div>
      <div>Scan time: <span>{format_duration(result.scan_duration_seconds)}</span></div>
      <div>Regions: <span>{len(result.regions)}</span></div>
      <div>Coarse blocks: <span>{len(result.coarse_results)}</span></div>
      <div>Fine blocks: <span>{len(result.fine_results)}</span></div>
    </div>
  </div>

  <div class="card">
    <h2>Recovery Potential</h2>
    <div class="stats-grid">
      <div class="stat-box">
        <div class="stat-value" style="color:{recovery_colour};">{recovery_pct:.1f}%</div>
        <div class="stat-label">Recoverable Data</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color:#e74c3c;">{result.encrypted_percentage:.1f}%</div>
        <div class="stat-label">Encrypted</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color:#27ae60;">{format_bytes(result.total_plaintext)}</div>
        <div class="stat-label">Recoverable Bytes</div>
      </div>
      <div class="stat-box">
        <div class="stat-value" style="color:#e74c3c;">{format_bytes(result.total_encrypted)}</div>
        <div class="stat-label">Encrypted Bytes</div>
      </div>
    </div>
    <div class="recovery-bar-container">
      <div class="recovery-bar" style="width:{recovery_pct:.1f}%;background-color:{recovery_colour};">
        {recovery_pct:.1f}%
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Entropy Heatmap</h2>
    <p style="color:#888;font-size:0.85em;margin-bottom:10px;">
      Each segment represents a file region. Hover for details.
    </p>
    <div class="heatmap">
      {heatmap_html}
    </div>
    <div class="legend">
      <div class="legend-item"><div class="legend-colour" style="background-color:#e74c3c;"></div> Encrypted</div>
      <div class="legend-item"><div class="legend-colour" style="background-color:#e67e22;"></div> Compressed</div>
      <div class="legend-item"><div class="legend-colour" style="background-color:#27ae60;"></div> Plaintext</div>
      <div class="legend-item"><div class="legend-colour" style="background-color:#95a5a6;"></div> Zeroed/Sparse</div>
    </div>
  </div>

  <div class="card">
    <h2>Region Details</h2>
    <div class="table-container">
      <table id="region-table">
        <thead>
          <tr>
            <th onclick="sortTable(0)">#</th>
            <th onclick="sortTable(1)">Start Offset</th>
            <th onclick="sortTable(2)">End Offset</th>
            <th onclick="sortTable(3)">Size</th>
            <th onclick="sortTable(4)">Classification</th>
            <th onclick="sortTable(5)">Avg Entropy</th>
            <th onclick="sortTable(6)">Min Entropy</th>
            <th onclick="sortTable(7)">Max Entropy</th>
          </tr>
        </thead>
        <tbody>
{region_table}
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
function sortTable(colIdx) {{
  const table = document.getElementById("region-table");
  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr"));
  const dir = table.dataset.sortDir === "asc" ? "desc" : "asc";
  table.dataset.sortDir = dir;
  rows.sort((a, b) => {{
    let va = a.cells[colIdx].innerText.replace(/,/g, "");
    let vb = b.cells[colIdx].innerText.replace(/,/g, "");
    const na = parseFloat(va), nb = parseFloat(vb);
    if (!isNaN(na) && !isNaN(nb)) {{ va = na; vb = nb; }}
    if (va < vb) return dir === "asc" ? -1 : 1;
    if (va > vb) return dir === "asc" ? 1 : -1;
    return 0;
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Multi-format report saving
# ---------------------------------------------------------------------------


def save_report(
    result: AnalysisResult,
    output_dir: Path,
    formats: list[str] | None = None,
) -> list[Path]:
    """Save analysis reports in the requested formats.

    Parameters
    ----------
    result:
        Analysis result from :class:`VMDKEntropyAnalyzer`.
    output_dir:
        Directory where report files will be written.  Created if it
        does not exist.
    formats:
        List of format strings: ``"text"``, ``"html"``, and/or ``"json"``.
        Defaults to all three.

    Returns
    -------
    list[Path]
        Paths to the generated report files.
    """
    if formats is None:
        formats = ["text", "html", "json"]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = result.file_path.stem
    saved: list[Path] = []

    for fmt in formats:
        fmt = fmt.lower().strip()

        if fmt == "text":
            text_path = output_dir / f"{stem}_entropy_map.txt"
            text_content = render_text_map(result)
            text_path.write_text(text_content, encoding="utf-8")
            logger.info("Saved text report: %s", text_path)
            saved.append(text_path)

        elif fmt == "html":
            html_path = output_dir / f"{stem}_entropy_report.html"
            html_content = render_html_report(result)
            html_path.write_text(html_content, encoding="utf-8")
            logger.info("Saved HTML report: %s", html_path)
            saved.append(html_path)

        elif fmt == "json":
            json_path = output_dir / f"{stem}_entropy_analysis.json"
            write_json_report(json_path, result.to_dict())
            logger.info("Saved JSON report: %s", json_path)
            saved.append(json_path)

        else:
            logger.warning("Unknown report format: %r (skipping)", fmt)

    return saved

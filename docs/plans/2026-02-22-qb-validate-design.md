# Design: qb-validate Tool

**Date:** 2026-02-22
**Purpose:** Post-carve validation of QuickBooks files from `carve-vmdk` output

## Problem

`carve-vmdk` identifies QBB files by ZIP magic bytes (`PK\x03\x04`), which are shared
by all ZIP-based formats (DOCX, XLSX, PPTX, JAR, APK, ODT, etc.). This produces many
false positives. IIF and OFX files are less noisy but still benefit from content validation.

## Solution

Standalone `qb-validate` tool that scans a carved output directory, validates each
QB-category file, classifies false positives, and copies valid files to a clean output
directory organized by type.

## Architecture

New module following existing tool patterns:

```
tools/qb_validator/
├── __init__.py
├── __main__.py        # python -m tools.qb_validator
├── cli.py             # argparse, banner, handler
└── validator.py       # validation logic
qb-validate            # wrapper script at repo root
```

## CLI Interface

```bash
./qb-validate /output/carved_files/ --output-dir /output/validated_qb/
```

- **Positional:** input directory (carved output from carve-vmdk)
- **`--output-dir`:** destination for valid files (organized into qbb/, iif/, ofx/ subdirs)
- **`-v/--verbose`:** debug logging
- Single-purpose, no subcommands.

## Validation Logic

### QBB Files (.qbb)

1. `zipfile.is_zipfile()` — reject if not valid ZIP
2. Open ZIP, list contents
3. Classify by contents:
   - Contains `[Content_Types].xml` → Office Open XML (DOCX/XLSX/PPTX)
   - Contains `META-INF/MANIFEST.MF` → Java archive (JAR/APK)
   - Contains `.QBW` or `.QBM` file → Valid QBB
   - Contains files with `Intuit` or `QuickBooks` in path → Valid QBB
   - Otherwise → Unknown ZIP (reported as unclassified)
4. For valid QBBs: report QBW filename and uncompressed size

### IIF Files (.iif)

1. Read first 1 KiB
2. Check starts with `!TRNS\t`, `!HDR\t`, or `!ACCNT\t`
3. Verify content is valid ASCII/UTF-8 text
4. Valid if magic matches and text is decodable

### OFX Files (.ofx)

1. Read first 1 KiB
2. Check starts with `OFXHEADER:` or `<?OFX`
3. Valid if header matches

## Data Model

```python
@dataclass
class ValidationResult:
    path: Path
    file_type: str            # "qbb", "iif", "ofx"
    valid: bool
    classification: str       # "quickbooks_backup", "office_document", "java_archive",
                              # "corrupt_zip", "unknown_zip", "valid_iif", "valid_ofx",
                              # "invalid_iif", "invalid_ofx"
    size: int
    details: dict             # ZIP contents for QBBs, QBW name, etc.
    output_path: Path | None  # where copied if valid
```

## Output

### Terminal

Uses existing `print_finding()` and `print_summary()` from `tools.common.report`:
- Per-file: verdict, size, contents summary
- Summary: X valid QBBs, Y Office docs filtered, Z corrupt/unknown

### Files

- Valid files copied to `output_dir/qbb/`, `output_dir/iif/`, `output_dir/ofx/`
- JSON report: `output_dir/validation_report.json`

## Dependencies

- Python stdlib only (`zipfile`, `pathlib`, `shutil`, `json`)
- Existing `tools.common.report` for terminal output
- Existing `tools.common.safe_io` for `ensure_output_dir()`
